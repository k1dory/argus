#!/usr/bin/env bash
# Сквозной тест: поднять стек, залить записанный трафик, дождаться инцидентов.
#   ./scripts/e2e.sh            → exit 0, если движок создал ≥ 7 инцидентов и вердикты
# Переменные: REGISTRY_MIRROR (зеркало Docker Hub), E2E_TIMEOUT (сек, по умолчанию 240).
# Стенд поднимается с дефолтами .env.dev + docker-compose.dev.yml (ARGUS_DEV=1).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-argus-e2e}"
export ENGINE_POLL_INTERVAL=5s
TIMEOUT="${E2E_TIMEOUT:-240}"
dc() { docker compose --env-file .env.dev -f docker-compose.yml -f docker-compose.dev.yml "$@"; }
cleanup() { dc down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

./scripts/gen-sample.sh >/dev/null
dc up -d --build clickhouse migrator collector engine
# Админ ClickHouse на стенде — из .env.dev; пароль через окружение, не argv.
CLICKHOUSE_PASSWORD="$(grep -E '^CLICKHOUSE_PASSWORD=' .env.dev | cut -d= -f2-)"; export CLICKHOUSE_PASSWORD
q() { dc exec -T -e CLICKHOUSE_PASSWORD clickhouse clickhouse-client --user argus --query "$1"; }

# argus_ro (панели дашбордов): SELECT работает и усекается по профилю,
# readonly = 1 действует, запись, DDL, табличные функции наружу и смена
# настроек в запросе отклоняются именно отказом доступа/readonly.
CLICKHOUSE_RO_PASSWORD="$(grep -E '^CLICKHOUSE_RO_PASSWORD=' .env.dev | cut -d= -f2-)"
# Пароль — через окружение (-e без значения), не через argv docker exec.
qro() { CLICKHOUSE_PASSWORD="$CLICKHOUSE_RO_PASSWORD" dc exec -T -e CLICKHOUSE_PASSWORD clickhouse clickhouse-client --user argus_ro --query "$1" 2>&1; }
# 164 READONLY, 452 SETTING_CONSTRAINT_VIOLATION, 497 ACCESS_DENIED. Другие коды
# (62 синтаксис, 60 нет таблицы, 16 нет столбца…) — сломанная проверка, а не отказ.
RO_DENY_CODES=" 164 452 497 "
ro_check() {
  echo "→ argus_ro: чтение да, запись нет"
  local out code fail=0
  out=$(qro "SELECT count() FROM argus.events") || { echo "FAIL: SELECT от argus_ro: $out"; fail=1; }
  out=$(qro "SELECT getSetting('readonly')") || true
  [ "$out" = "1" ] || { echo "FAIL: readonly у argus_ro = '${out:0:200}', ожидалось 1"; fail=1; }
  # break, а не ошибка: панель получает усечённый результат (по блокам, поэтому < 100000, а не ровно 5000)
  if out=$(qro "SELECT number FROM numbers(100000)"); then
    [ "$(wc -l <<<"$out")" -lt 100000 ] || { echo "FAIL: max_result_rows не действует"; fail=1; }
  else echo "FAIL: большой SELECT от argus_ro: ${out:0:200}"; fail=1; fi
  for sql in "INSERT INTO argus.console_audit (action) VALUES ('e2e')" \
             "ALTER TABLE argus.events DELETE WHERE 1" \
             "CREATE TABLE argus.e2e_ro (x UInt8) ENGINE = Memory" \
             "DROP TABLE argus.console_audit" \
             "SELECT * FROM url('http://127.0.0.1/', CSV, 'x String')" \
             "SELECT 1 SETTINGS max_result_rows = 100000"; do
    if out=$(qro "$sql"); then echo "FAIL: argus_ro выполнил: $sql"; fail=1; continue; fi
    code=$(grep -oE 'Code: [0-9]+' <<<"$out" | head -1 | grep -oE '[0-9]+' || true)
    if [[ "$RO_DENY_CODES" == *" ${code:-none} "* ]]; then echo "ok: отклонено — ${sql:0:40}… (код $code)"
    else echo "FAIL: не тот отказ (код ${code:-?}) на: $sql — ${out:0:200}"; fail=1; fi
  done
  [ "$fail" = 0 ] || exit 1
}

echo "→ жду коллектор"
# Готовность — только по /healthz: busybox в образе коллектора нет, проверка
# через `dc exec … /bin/busybox true` всегда падала и цикл шёл до конца.
ready=0
for _ in $(seq 1 60); do curl -fsS "http://127.0.0.1:8088/healthz" >/dev/null 2>&1 && { ready=1; break; }; sleep 2; done
[ "$ready" = 1 ] || { echo "FAIL: коллектор не ответил на /healthz за 120 с"; dc logs --tail=50 collector; exit 1; }
COLLECTOR_URL=http://127.0.0.1:8088 ARGUS_INGEST_TOKEN="$(grep -E '^ARGUS_INGEST_TOKEN=' .env.dev | cut -d= -f2-)" \
  ./scripts/argus replay fixtures/events/august.ndjson

echo "→ жду инциденты (до ${TIMEOUT}s)"
deadline=$((SECONDS + TIMEOUT))
while [ $SECONDS -lt $deadline ]; do
  n=$(q "SELECT count() FROM (SELECT incident_id FROM argus.incidents GROUP BY incident_id)" 2>/dev/null || echo 0)
  v=$(q "SELECT count() FROM argus.incident_verdicts" 2>/dev/null || echo 0)
  if [ "${n:-0}" -ge 7 ] && [ "${v:-0}" -ge 7 ]; then
    echo "ok: инцидентов $n, вердиктов $v"
    q "SELECT incident_id, argMax(level,updated_at), argMax(rule_id,updated_at), argMax(actor_name,updated_at) FROM argus.incidents GROUP BY incident_id ORDER BY incident_id FORMAT PrettyCompactNoEscapes"
    ro_check
    exit 0
  fi
  sleep 5
done
echo "FAIL: инцидентов ${n:-0}, вердиктов ${v:-0}"
dc logs --tail=50 engine collector
exit 1
