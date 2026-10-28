#!/usr/bin/env bash
# Сквозная проверка пайплайна инцидентов на живом стенде: фикстура NDJSON со сдвигом
# времени на «сейчас» → POST /ingest/events → ожидание инцидента по правилу и субъекту.
#
#   ./scripts/pipeline-check.sh fixtures/events/host-auth.ndjson a41c-auth-031 198.51.100.23
#   ./scripts/pipeline-check.sh FIXTURE RULE_ID ACTOR [--replace OLD=NEW ...] [--wait SEC]
#
# --replace OLD=NEW — заменить строку в фикстуре (например адрес субъекта, чтобы повторный
# прогон дал новый инцидент, а не попал в открытый). Запускать на хосте стенда из каталога
# ARGUS: токен приёма и доступ к ClickHouse берутся из .env (ARGUS_ENV_FILE), ClickHouse — через
# docker compose. Нужен python3 (сдвиг времени).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${ARGUS_ENV_FILE:-$ROOT/.env}"
envget() { [ -f "$ENV_FILE" ] && grep -E "^$1=" "$ENV_FILE" | head -1 | cut -d= -f2- | sed 's/[[:space:]]*#.*$//' || true; }
FIXTURE="${1:?фикстура}"; RULE="${2:?rule id}"; ACTOR="${3:?actor}"; shift 3
WAIT=180; REPL=()
while [ $# -gt 0 ]; do case "$1" in --replace) REPL+=("$2"); shift 2 ;; --wait) WAIT="$2"; shift 2 ;; *) echo "неизвестный аргумент $1"; exit 2 ;; esac; done
INGEST_URL="${ARGUS_INGEST_URL:-http://127.0.0.1:8088}"; INGEST_URL="${INGEST_URL%/}"
TOKEN="${ARGUS_INGEST_TOKEN:-$(envget ARGUS_INGEST_TOKEN)}"
[ -n "$TOKEN" ] || { echo "pipeline-check: ARGUS_INGEST_TOKEN пуст (окружение или $ENV_FILE)"; exit 2; }
CH_USER="${CLICKHOUSE_USER:-$(envget CLICKHOUSE_USER)}"; CH_USER="${CH_USER:-default}"
CH_PASS="${CLICKHOUSE_PASSWORD:-$(envget CLICKHOUSE_PASSWORD)}"
ch() { docker compose --project-directory "$ROOT" exec -T clickhouse clickhouse-client -u "$CH_USER" --password "$CH_PASS" -q "$1"; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
RUN="pc-$(date +%s)"
python3 - "$FIXTURE" "$TMP/events.ndjson" "$RUN" "${REPL[@]}" <<'PY'
import sys, json, datetime
src, dst, run, *repl = sys.argv[1:]
rows = [json.loads(l) for l in open(src, encoding="utf-8") if l.strip()]
fmt = "%Y-%m-%d %H:%M:%S.%f"
ts = [datetime.datetime.strptime(r["ts"], fmt) for r in rows]
shift = datetime.datetime.utcnow() - max(ts) - datetime.timedelta(seconds=5)
out = []
for r, t in zip(rows, ts):
    r["ts"] = (t + shift).strftime(fmt)[:-3]
    r.setdefault("attrs", {})["pipeline_check"] = run
    s = json.dumps(r, ensure_ascii=False)
    for p in repl:
        old, new = p.split("=", 1); s = s.replace(old, new)
    out.append(s)
open(dst, "w", encoding="utf-8").write("\n".join(out) + "\n")
print(f"{len(out)} событий, сдвиг {shift}")
PY
code=$(curl -sS -o "$TMP/resp" -w '%{http_code}' -H "X-Argus-Token: $TOKEN" -H "Content-Type: application/x-ndjson" --data-binary "@$TMP/events.ndjson" "$INGEST_URL/ingest/events" || echo 000)
case "$code" in 2??) echo "POST /ingest/events → $code" ;; *) echo "POST /ingest/events → $code: $(head -c 300 "$TMP/resp")"; exit 1 ;; esac
start=$(date +%s)
while :; do
  got=$(ch "SELECT incident_id, status, event_count FROM argus.incidents FINAL WHERE rule_id = '$RULE' AND actor_name = '$ACTOR' AND created_at >= now() - INTERVAL $((WAIT + 60)) SECOND ORDER BY created_at DESC LIMIT 1 FORMAT TSV" 2>/dev/null || true)
  if [ -n "$got" ]; then echo "инцидент: $got (правило $RULE, субъект $ACTOR, $(( $(date +%s) - start )) с)"; exit 0; fi
  if [ $(( $(date +%s) - start )) -ge "$WAIT" ]; then
    seen=$(ch "SELECT count() FROM argus.events WHERE attrs['pipeline_check'] = '$RUN'" 2>/dev/null || echo '?')
    echo "инцидента нет за $WAIT с: событий прогона в журнале — $seen (правило $RULE, субъект $ACTOR)"; exit 1
  fi
  sleep 10
done
