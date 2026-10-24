#!/bin/sh
# telemetry-sample.sh — пример источника телеметрии для ARGUS без агентов:
# занятость дисков (df -P) и load average (uptime) узла уходят событиями
# единой схемы в коллектор — POST /ingest/events, NDJSON, заголовок X-Argus-Token.
# Числовое измерение — в value/unit (percent, load), action — disk.usage / load.avg1.
#   ARGUS_INGEST_TOKEN=<токен из .env> ./scripts/telemetry-sample.sh
#   ARGUS_INGEST_URL=https://argus.example.org:8089 ARGUS_INGEST_TOKEN=… ./scripts/telemetry-sample.sh
# Переменные: ARGUS_INGEST_URL (по умолчанию https://localhost:8089 — Caddy с
# внутренним CA, поэтому curl -k; стенд ARGUS_DEV=1 принимает без токена),
# ARGUS_INGEST_TOKEN, ARGUS_TELEMETRY_SOURCE (по умолчанию telemetry.sample).
# Запуск по cron раз в минуту даёт ленту в консоли: get_log log=telemetry.
set -eu
URL="${ARGUS_INGEST_URL:-https://localhost:8089}/ingest/events"
SRC="${ARGUS_TELEMETRY_SOURCE:-telemetry.sample}"
NODE="$(hostname)"
TS="$(date -u +'%Y-%m-%d %H:%M:%S.000')"
event() { # $1 action, $2 object, $3 value, $4 unit
  printf '{"ts":"%s","source":"%s","source_class":"telemetry","action":"%s","outcome":"success","severity":1,"node":"%s","object":"%s","value":%s,"unit":"%s"}\n' \
    "$TS" "$SRC" "$1" "$NODE" "$2" "$3" "$4"
}
{
  # df -P: POSIX-формат, одна строка на ФС; 5-я колонка — занято в %, 6-я — точка монтирования.
  df -P | awk 'NR > 1 && $5 ~ /%$/ && $1 !~ /^(tmpfs|devfs|map|overlay|none)$/ { sub("%", "", $5); print $6, $5 }' |
    while read -r mount pct; do event disk.usage "$mount" "$pct" percent; done
  # load average за 1 минуту: последняя тройка чисел в выводе uptime.
  load1="$(uptime | sed 's/.*load average[s]*: *//' | tr -d ',' | awk '{print $1}')"
  [ -n "$load1" ] && event load.avg1 "cpu" "$load1" load
} | curl -ksS -X POST "$URL" -H "Content-Type: application/x-ndjson" -H "X-Argus-Token: ${ARGUS_INGEST_TOKEN:-}" --data-binary @-
echo
