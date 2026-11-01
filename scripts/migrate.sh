#!/usr/bin/env bash
# Применяет миграции ClickHouse по порядку имён файлов и записывает
# применённые в argus.schema_migrations. Свежая установка и апгрейд идут
# одним путём, поэтому каждый файл обязан быть идемпотентным
# (CREATE ... IF NOT EXISTS / ADD COLUMN IF NOT EXISTS).
#
# После миграций заводит служебных пользователей с минимальными правами.
# Единственное место, где нужен админ ClickHouse (CLICKHOUSE_USER/PASSWORD):
# остальные сервисы ходят каждый под своим пользователем.
set -euo pipefail

HOST="${CLICKHOUSE_HOST:-clickhouse}"
ADMIN_USER="${CLICKHOUSE_USER:-default}"
DIR="${MIGRATIONS_DIR:-/migrations}"
DEV="${ARGUS_DEV:-0}"

# Пароль админа clickhouse-client берёт из окружения (CLICKHOUSE_PASSWORD),
# в argv он не попадает — /proc/*/cmdline его не покажет.
export CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-}"
ch() {
    clickhouse-client --host "$HOST" --user "$ADMIN_USER" "$@"
}

# ── Отказ на дефолтных паролях ──────────────────────────────────────────
# argus / argus-* / change-me* — значения из старых примеров и документации.
# В бою с ними не стартуем; стенд (ARGUS_DEV=1) только предупреждает.
weak() {
    case "$1" in
        argus|argus-*|change-me*) return 0 ;;
    esac
    return 1
}
bad=()
for v in CLICKHOUSE_PASSWORD CLICKHOUSE_RO_PASSWORD CLICKHOUSE_CONSOLE_PASSWORD \
         CLICKHOUSE_COLLECTOR_PASSWORD CLICKHOUSE_SHIPPER_PASSWORD \
         CLICKHOUSE_POLICYD_PASSWORD CLICKHOUSE_ENGINE_PASSWORD; do
    val="${!v:-}"
    if [ -n "$val" ] && weak "$val"; then bad+=("$v"); fi
done
if [ ${#bad[@]} -gt 0 ]; then
    if [ "$DEV" = "1" ]; then
        echo "migrate: ВНИМАНИЕ — дефолтные пароли (${bad[*]}); допустимо только на стенде (ARGUS_DEV=1)" >&2
    else
        echo "migrate: ОТКАЗ — дефолтные пароли в ${bad[*]}. Сгенерируйте: ./scripts/argus init (или openssl rand -hex 24)" >&2
        exit 1
    fi
fi

echo "migrate: waiting for clickhouse at $HOST ..."
for _ in $(seq 1 60); do
    ch --query "SELECT 1" >/dev/null 2>&1 && break
    sleep 2
done
ch --query "SELECT 1" >/dev/null

ch --query "CREATE DATABASE IF NOT EXISTS argus"
ch --query "CREATE TABLE IF NOT EXISTS argus.schema_migrations
            (name String, applied_at DateTime DEFAULT now())
            ENGINE = MergeTree ORDER BY name"

applied=$(ch --query "SELECT name FROM argus.schema_migrations")

for f in "$DIR"/*.sql; do
    name=$(basename "$f")
    if printf '%s\n' "$applied" | grep -qx "$name"; then
        echo "migrate: skip $name (already applied)"
        continue
    fi
    echo "migrate: apply $name"
    ch --multiquery <"$f"
    ch --query "INSERT INTO argus.schema_migrations (name) VALUES ('$name')"
done

echo "migrate: done"

# ── Служебные пользователи с минимальными правами ─────────────────────────
# Пароль в SQL не попадает: в ClickHouse уходит sha256(password + salt) и
# соль (IDENTIFIED WITH sha256_hash ... SALT). Хеш считается bash-builtin'ом
# printf + sha256sum, поэтому и в argv процессов пароля нет.
# Гранты декларативны: REVOKE ALL, затем ровно перечисленное. SOURCES и
# HOST не задаём: подсеть compose динамическая.
mkuser() {
    local name="$1" pass="$2" settings="$3"; shift 3
    if [ -z "$pass" ]; then
        echo "migrate: $name пропущен (пароль не задан)"
        return
    fi
    local salt hash
    salt=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
    hash=$(printf '%s%s' "$pass" "$salt" | sha256sum | cut -d' ' -f1)
    ch --query "CREATE USER IF NOT EXISTS $name IDENTIFIED WITH sha256_hash BY '$hash' SALT '$salt'"
    ch --query "ALTER USER $name IDENTIFIED WITH sha256_hash BY '$hash' SALT '$salt' SETTINGS $settings"
    ch --query "REVOKE ALL ON *.* FROM $name"
    for g in "$@"; do ch --query "GRANT $g TO $name"; done
    echo "migrate: user $name ok ($# grants)"
}

# Ограничения для пишущих сервисов: DDL закрыт намертво (READONLY),
# время/память — с потолком (MAX): сервис может ужесточить, но не снять.
SVC_LIMITS="allow_ddl = 0 READONLY, max_execution_time = 60 MAX 300, max_memory_usage = 2000000000 MAX 4000000000, max_concurrent_queries_for_user = 8"

# argus_ro — панели дашбордов: только чтение, все лимиты неизменяемы (READONLY).
# При readonly = 1 ClickHouse отклоняет любую настройку в запросе, если её
# значение отличается от профиля («Cannot modify … in readonly mode»). Поэтому
# всё, что нужно панелям, задано здесь: усечение результата (break, а не
# ошибка на 5001-й строке), потолок чтения и формат JSON. Консоль в запросе
# панели настроек не передаёт (web/src/lib/dashboards.ts).
mkuser argus_ro "${CLICKHOUSE_RO_PASSWORD:-}" \
    "readonly = 1 READONLY, allow_ddl = 0 READONLY, allow_introspection_functions = 0 READONLY, max_execution_time = 20 READONLY, max_memory_usage = 2000000000 READONLY, max_rows_to_read = 500000000 READONLY, max_result_rows = 5000 READONLY, result_overflow_mode = 'break' READONLY, output_format_json_quote_64bit_integers = 0 READONLY, max_concurrent_queries_for_user = 4 READONLY" \
    "SELECT ON argus.*"

# Слепая выборка (web/src/lib/blind.ts, engine labels.go): панели и предпросмотр SQL
# пишут любой SELECT от argus_ro — вердикт агента и анализ модели по слепому
# незавершённому инциденту скрываются политиками строк. Хэш тот же: первые два байта
# SHA-256 от incident_id (big-endian) по модулю 100 < 25; «завершён» — статус closed /
# false_positive в incidents_current. Остальные пользователи политик не имеют и видят
# всё (users_without_row_policies_can_read_rows), консоль скрывает сама.
if [ -n "${CLICKHOUSE_RO_PASSWORD:-}" ]; then
    disclosed() {
        echo "reinterpretAsUInt16(reverse(substring(SHA256($1), 1, 2))) % 100 >= 25
          OR $1 IN (SELECT incident_id FROM argus.incidents_current WHERE status IN ('closed', 'false_positive'))"
    }
    ch --query "CREATE ROW POLICY OR REPLACE argus_ro_blind ON argus.incident_verdicts FOR SELECT USING $(disclosed incident_id) TO argus_ro"
    ch --query "CREATE ROW POLICY OR REPLACE argus_ro_blind ON argus.agent_verdicts FOR SELECT USING $(disclosed incident_id) TO argus_ro"
    ch --query "CREATE ROW POLICY OR REPLACE argus_ro_blind ON argus.incident_comments FOR SELECT USING NOT startsWith(author, 'agent:') OR $(disclosed incident_id) TO argus_ro"
    ch --query "CREATE ROW POLICY OR REPLACE argus_ro_blind ON argus.console_audit FOR SELECT USING NOT startsWith(action, 'triage.verdict') OR $(disclosed target) TO argus_ro"
    echo "migrate: argus_ro blind row policies ok"
fi

# argus_console — консоль: чтение argus + INSERT в таблицы, которые ведёт оператор.
# Без readonly (нужны INSERT), DDL закрыт, лимиты с потолком (поиск ставит свои).
# system.parts (пять колонок) — проверка, что проекция p_source_last есть во всех
# непустых партах events, прежде чем /api/sources её читает (web/src/lib/argus-queries.ts,
# SOURCE_LAST_READY); без права запрос падал с 497 и источники отвечали 503.
mkuser argus_console "${CLICKHOUSE_CONSOLE_PASSWORD:-}" \
    "allow_ddl = 0 READONLY, max_execution_time = 30 MAX 60, max_memory_usage = 2000000000 MAX 4000000000, max_result_rows = 20000 MAX 100000, max_concurrent_queries_for_user = 16" \
    "SELECT ON argus.*" \
    "INSERT ON argus.console_rule_mutes" \
    "INSERT ON argus.rule_exceptions" "INSERT ON argus.console_audit" \
    "INSERT ON argus.console_dashboards" "INSERT ON argus.console_settings" \
    "INSERT ON argus.incident_comments" "INSERT ON argus.triage_session_revocations" \
    "INSERT ON argus.triage_verdicts" "INSERT ON argus.triage_verdict_claims" \
    "INSERT ON argus.triage_verdict_claims_v2" "INSERT ON argus.agent_verdicts" \
    "INSERT ON argus.identities" "INSERT ON argus.identity_aliases" \
    "SELECT(database, table, active, rows, projections) ON system.parts"

# argus_collector — приём событий, heartbeat, dead-letter. У collector_health есть MV
# в collector_health_log: ClickHouse требует INSERT на цель MV и SELECT на источник.
mkuser argus_collector "${CLICKHOUSE_COLLECTOR_PASSWORD:-}" "$SVC_LIMITS" \
    "INSERT ON argus.events" \
    "INSERT ON argus.collector_health" "SELECT ON argus.collector_health" "INSERT ON argus.collector_health_log" \
    "INSERT ON argus.ingest_rejects"

# argus_shipper — алерты Wazuh; MV ведут в wazuh_alerts_hourly и events.
mkuser argus_shipper "${CLICKHOUSE_SHIPPER_PASSWORD:-}" "$SVC_LIMITS" \
    "INSERT ON argus.wazuh_alerts" "SELECT ON argus.wazuh_alerts" \
    "INSERT ON argus.wazuh_alerts_hourly" "INSERT ON argus.events"

# argus_policyd — только вердикты политик.
mkuser argus_policyd "${CLICKHOUSE_POLICYD_PASSWORD:-}" "$SVC_LIMITS" \
    "INSERT ON argus.policy_verdicts"

# argus_engine — корреляция: читает всё argus, пишет инциденты/вердикты/журнал
# реагирования, собственную телеметрию в events (disk.usage о диске ClickHouse),
# персоны и алиасы паспорта; system.disks — для сторожа места.
mkuser argus_engine "${CLICKHOUSE_ENGINE_PASSWORD:-}" "$SVC_LIMITS" \
    "SELECT ON argus.*" "INSERT ON argus.events" \
    "INSERT ON argus.incidents" "INSERT ON argus.incident_state_events" "INSERT ON argus.incident_verdicts" "INSERT ON argus.response_log" \
    "INSERT ON argus.risk_report_deliveries" "INSERT ON argus.webhook_deliveries" \
    "INSERT ON argus.identities" "INSERT ON argus.identity_aliases" \
    "SELECT ON system.disks"
