#!/usr/bin/env bash
# api-smoke.sh — сквозная проверка API консоли на живом стенде (make up-dev + make demo):
# версия → приём NDJSON коллектором → событие видно в GET /api/v1/log → сессия разбора
# по демо-инциденту → карточка → граница области → вердикт argus-triage/v3 (и его
# идемпотентный повтор) → резолв алиаса и паспорт субъекта → экспорт закрыт токену сессии
# → живость источников (/api/sources) → MCP за Caddy (при ARGUS_MCP_URL).
#
#   ./scripts/api-smoke.sh                       # стенд make up-dev: дефолты из .env.dev
#   ARGUS_URL=https://argus:8443 ARGUS_API_TOKEN=… ARGUS_TRIAGE_ISSUER_TOKEN=… \
#   ARGUS_INGEST_URL=https://argus:8089 ARGUS_INGEST_TOKEN=… ./scripts/api-smoke.sh
#
# Переменные: ARGUS_URL (консоль, по умолчанию http://127.0.0.1:3001), ARGUS_INGEST_URL
# (коллектор, http://127.0.0.1:8088), ARGUS_API_TOKEN, ARGUS_TRIAGE_ISSUER_TOKEN,
# ARGUS_INGEST_TOKEN (пустые — берутся из ARGUS_ENV_FILE, по умолчанию .env.dev),
# SMOKE_WAIT — сколько секунд ждать событие в журнале (90), SMOKE_PERSON — персона из
# identities.yml (i.petrov), SMOKE_ALIAS — её алиас (i.petrov@example.org).
# Нужны curl и jq. Выход 0 — все шаги PASS; любой FAIL — выход 1. Шаги, для которых нет
# данных (нет инцидентов, не задан ARGUS_TRIAGE_ISSUER_TOKEN), печатаются как SKIP и
# результат не портят. Побочный эффект: по одному демо-инциденту записывается вердикт
# агента api-smoke (комментарий agent:api-smoke); инцидент с уже записанным вердиктом
# пропускается (409 verdict_published), повторный запуск берёт следующий.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${ARGUS_ENV_FILE:-$ROOT/.env.dev}"

envget() { [ -f "$ENV_FILE" ] && grep -E "^$1=" "$ENV_FILE" | head -1 | cut -d= -f2- | sed 's/[[:space:]]*#.*$//' || true; }
ARGUS_URL="${ARGUS_URL:-http://127.0.0.1:3001}"; ARGUS_URL="${ARGUS_URL%/}"
ARGUS_INGEST_URL="${ARGUS_INGEST_URL:-http://127.0.0.1:8088}"; ARGUS_INGEST_URL="${ARGUS_INGEST_URL%/}"
ARGUS_API_TOKEN="${ARGUS_API_TOKEN:-$(envget ARGUS_API_TOKEN)}"
ARGUS_TRIAGE_ISSUER_TOKEN="${ARGUS_TRIAGE_ISSUER_TOKEN:-$(envget ARGUS_TRIAGE_ISSUER_TOKEN)}"
ARGUS_INGEST_TOKEN="${ARGUS_INGEST_TOKEN:-$(envget ARGUS_INGEST_TOKEN)}"
SMOKE_WAIT="${SMOKE_WAIT:-90}"
SMOKE_PERSON="${SMOKE_PERSON:-i.petrov}"
SMOKE_ALIAS="${SMOKE_ALIAS:-i.petrov@example.org}"

for bin in curl jq; do command -v "$bin" >/dev/null || { echo "api-smoke: нужен $bin"; exit 2; }; done
[ -n "$ARGUS_API_TOKEN" ] || { echo "api-smoke: ARGUS_API_TOKEN пуст (окружение или $ENV_FILE)"; exit 2; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
BODY="$TMP/body"
FAILS=0
pass() { echo "PASS $1: $2"; }
fail() { echo "FAIL $1: $2"; FAILS=$((FAILS + 1)); }
skip() { echo "SKIP $1: $2"; }
snippet() { tr -d '\n' <"$BODY" | cut -c1-200; }

# req METHOD URL TOKEN [DATA] → код ответа в stdout, тело в $BODY. Токен — через
# заголовок из файла конфигурации curl, чтобы не светить его в argv (ps).
req() {
  local method="$1" url="$2" token="$3" data="${4:-}" cfg="$TMP/curl.cfg"
  : >"$cfg"
  [ -n "$token" ] && printf 'header = "Authorization: Bearer %s"\n' "$token" >>"$cfg"
  if [ -n "$data" ]; then
    curl -ksS --max-time 30 -o "$BODY" -w '%{http_code}' -X "$method" -K "$cfg" \
      -H "Content-Type: application/json" --data-binary "$data" "$url" || echo 000
  else
    curl -ksS --max-time 30 -o "$BODY" -w '%{http_code}' -X "$method" -K "$cfg" "$url" || echo 000
  fi
}
jget() { jq -r "$1" <"$BODY" 2>/dev/null || true; }

# ── 1. версия ────────────────────────────────────────────────────────────────
code=$(req GET "$ARGUS_URL/api/version" "$ARGUS_API_TOKEN")
if [ "$code" = 200 ] && [ "$(jget .status)" = ok ]; then pass 1 "GET /api/version → 200, версия $(jget '.version // "скрыта"')"
else fail 1 "GET /api/version → $code: $(snippet)"; fi

# ── 2. приём NDJSON коллектором: измерение value/unit и identity.alias ──────────
# Смоук не должен оставлять следов в инцидентах: класс событий smoke не попадает
# ни под одно поставляемое правило, алиас повторяет уже существующий.
RUN="smoke-$(date -u +%Y%m%d%H%M%S)-$$"
TS="$(date -u +'%Y-%m-%d %H:%M:%S.000')"
# identity.alias повторяет алиас, который уже есть в identities.yml у той же
# персоны: снимок идемпотентен, новых сущностей в карте идентичностей не появляется.
# source_class smoke, а не telemetry: иначе правило host-silence (absence по узлу
# класса telemetry) через 10 минут заводило бы инцидент на каждый прогон смоука.
printf '{"ts":"%s","source":"telemetry.smoke","source_class":"smoke","action":"disk.usage","outcome":"success","severity":1,"node":"%s","object":"/smoke","value":42.5,"unit":"percent"}\n' "$TS" "$RUN" >"$TMP/events.ndjson"
printf '{"ts":"%s","source":"idp.smoke","source_class":"identity","action":"identity.alias","outcome":"success","severity":1,"actor_name":"%s","actor_kind":"user","node":"%s","attrs":{"alias_kind":"login","alias_value":"%s","confidence":"1"}}\n' "$TS" "$SMOKE_PERSON" "$RUN" "${SMOKE_PERSON//./}" >>"$TMP/events.ndjson"
printf 'header = "X-Argus-Token: %s"\n' "$ARGUS_INGEST_TOKEN" >"$TMP/ingest.cfg"
code=$(curl -ksS --max-time 30 -o "$BODY" -w '%{http_code}' -X POST -K "$TMP/ingest.cfg" \
  -H "Content-Type: application/x-ndjson" --data-binary "@$TMP/events.ndjson" "$ARGUS_INGEST_URL/ingest/events" || echo 000)
case "$code" in 2??) pass 2 "POST /ingest/events → $code (2 события, node $RUN)"; ingested=1 ;;
  *) fail 2 "POST /ingest/events → $code: $(snippet)"; ingested=0 ;; esac

# ── 3. событие доехало до журнала ────────────────────────────────────────────
if [ "$ingested" = 1 ]; then
  deadline=$((SECONDS + SMOKE_WAIT)); found=0
  while [ $SECONDS -lt $deadline ]; do
    code=$(req GET "$ARGUS_URL/api/v1/log?log=telemetry.smoke&node=$RUN&since=15m" "$ARGUS_API_TOKEN")
    if [ "$code" = 200 ] && [ "$(jget '.count')" -ge 1 ] 2>/dev/null; then found=1; break; fi
    sleep 3
  done
  if [ "$found" = 1 ]; then
    v=$(jget '.items[0].value'); u=$(jget '.items[0].unit')
    if [ "$v" = 42.5 ] && [ "$u" = percent ]; then
      code=$(req GET "$ARGUS_URL/api/v1/log?log=idp.smoke&node=$RUN&action=identity.alias&since=15m" "$ARGUS_API_TOKEN")
      if [ "$code" = 200 ] && [ "$(jget '.count')" -ge 1 ] 2>/dev/null; then pass 3 "GET /api/v1/log: telemetry.smoke value=$v $u и identity.alias найдены за $((SECONDS - deadline + SMOKE_WAIT)) с"
      else fail 3 "событие identity.alias не найдено в журнале → $code: $(snippet)"; fi
    else fail 3 "событие найдено, но value/unit = '$v'/'$u', ожидалось 42.5/percent"; fi
  else fail 3 "событие telemetry.smoke не появилось в GET /api/v1/log за ${SMOKE_WAIT} с (последний ответ $code: $(snippet))"; fi
else skip 3 "приём не прошёл"; fi

# ── 4. список инцидентов ─────────────────────────────────────────────────────
code=$(req GET "$ARGUS_URL/api/incidents" "$ARGUS_API_TOKEN")
INCIDENTS=""
if [ "$code" = 200 ]; then
  INCIDENTS=$(jget '.rows[].incident_id')
  pass 4 "GET /api/incidents → 200, всего $(jget .total)"
else fail 4 "GET /api/incidents → $code: $(snippet)"; fi

# ── 5. сессия разбора по демо-инциденту ──────────────────────────────────────
TRIAGE_TOKEN=""; INC=""
if [ -z "$ARGUS_TRIAGE_ISSUER_TOKEN" ]; then skip 5 "ARGUS_TRIAGE_ISSUER_TOKEN не задан — сессии разбора не выпускаются (шаги 5–8, 11)"
elif [ -z "$INCIDENTS" ]; then skip 5 "инцидентов нет — сначала make demo (шаги 5–8, 11)"
else
  tried=0
  for id in $INCIDENTS; do
    tried=$((tried + 1)); [ $tried -le 30 ] || break
    code=$(req POST "$ARGUS_URL/api/triage/sessions" "$ARGUS_TRIAGE_ISSUER_TOKEN" "{\"incident_id\":\"$id\",\"ttl_sec\":600}")
    case "$code" in
      201) TRIAGE_TOKEN=$(jget .token); INC=$(jget .incident_id); break ;;
      409) continue ;;   # вердикт уже записан (предыдущий прогон) — следующий инцидент
      *) fail 5 "POST /api/triage/sessions $id → $code: $(snippet)"; break ;;
    esac
  done
  if [ -n "$TRIAGE_TOKEN" ]; then pass 5 "POST /api/triage/sessions → 201, сессия по $INC (пропущено с вердиктом: $((tried - 1)))"
  elif [ "$code" = 409 ]; then skip 5 "у всех $tried проверенных инцидентов вердикт уже записан — новая сессия не выдаётся (шаги 6–8, 11)"; fi
fi

# ── 6. карточка инцидента ────────────────────────────────────────────────────
LEVEL=""; RULE=""; ANCHOR=""
if [ -n "$TRIAGE_TOKEN" ]; then
  code=$(req GET "$ARGUS_URL/api/triage/context" "$TRIAGE_TOKEN")
  if [ "$code" = 200 ] && [ "$(jget .incident.incident_id)" = "$INC" ]; then
    LEVEL=$(jget .incident.level); RULE=$(jget .incident.rule_id)
    ANCHOR=$(jget '[.session.anchors[] | select(.kind == "actor" and (.weak | not))][0].value // ""')
    pass 6 "GET /api/triage/context → 200: $INC $LEVEL $RULE, якорей $(jget '.session.anchors | length'), запросов осталось $(jget .session.requests_left)"
  else fail 6 "GET /api/triage/context → $code: $(snippet)"; fi
else skip 6 "нет сессии"; fi

# ── 7. область сессии в /api/v1/log: без якоря — отказ, с якорем — данные ──────
if [ -n "$TRIAGE_TOKEN" ]; then
  code=$(req GET "$ARGUS_URL/api/v1/log?since=24h" "$TRIAGE_TOKEN")
  case "$code" in
    400|403) r7="без фильтра → $code $(jget .error)" ;;
    *) fail 7 "GET /api/v1/log?since=24h токеном сессии → $code, ожидался отказ 400/403: $(snippet)"; r7="" ;;
  esac
  if [ -n "$r7" ]; then
    if [ -n "$ANCHOR" ]; then
      code=$(req GET "$ARGUS_URL/api/v1/log?actor=$(jq -rn --arg v "$ANCHOR" '$v|@uri')&since=24h" "$TRIAGE_TOKEN")
      case "$code" in
        200) pass 7 "GET /api/v1/log токеном сессии: $r7; actor=<якорь> → 200, строк $(jget .count)" ;;
        403) pass 7 "GET /api/v1/log токеном сессии: $r7; actor=<якорь> → 403 $(jget .detail)" ;;
        *) fail 7 "GET /api/v1/log?actor=<якорь> токеном сессии → $code: $(snippet)" ;;
      esac
    else pass 7 "GET /api/v1/log токеном сессии: $r7 (якоря-субъекта у инцидента нет, запрос с якорем пропущен)"; fi
  fi
else skip 7 "нет сессии"; fi

# ── 8. вердикт argus-triage/v3: 201, повтор — 201 с тем же id ────────────────
if [ -n "$TRIAGE_TOKEN" ] && [ -n "$LEVEL" ]; then
  jq -cn --arg inc "$INC" --arg level "$LEVEL" --arg rule "$RULE" --arg ts "$(date -u +'%Y-%m-%d %H:%M:%S')" '{
    agent: "api-smoke", schema: "argus-triage/v3", incident_id: $inc, level: $level, rule_id: $rule,
    verdict: "undetermined", confidence: "low", human_needed: true,
    human_reason: "дымовой тест API, разбор не проводился",
    summary: "Проверка контракта вердикта дымовым тестом api-smoke. Содержательный разбор инцидента не выполнялся.",
    subject: {kind: "unknown", display: "subject"},
    evidence: [{ts: $ts, source: "argus.console", fact: "карточка инцидента получена через GET api triage context",
      provenance: "engine", attacker_control: "none", direction: "neutral", refs: ["card"]}],
    gaps: ["доводы по событиям не собирались"], related: [],
    recommendation: {console_status: "observing", status_reason: "технический вердикт дымового теста, решение за аналитиком", actions: [], exception: null},
    injection_suspected: false, injection_reason: null, injection_fields: [], damaged_values: [],
    engine_verdict: {used: false, disagreement: ""}, pii_seen: false, behavior_assessment: "unclear"
  }' >"$TMP/verdict.json"
  code=$(req POST "$ARGUS_URL/api/triage/verdicts" "$TRIAGE_TOKEN" "@$TMP/verdict.json")
  if [ "$code" = 201 ]; then
    id1=$(jget .id)
    code=$(req POST "$ARGUS_URL/api/triage/verdicts" "$TRIAGE_TOKEN" "@$TMP/verdict.json")
    if [ "$code" = 201 ] && [ "$(jget .id)" = "$id1" ]; then pass 8 "POST /api/triage/verdicts → 201, повтор → 201 с тем же id $id1"
    else fail 8 "повтор POST /api/triage/verdicts → $code, id $(jget .id) (ожидался 201 и $id1): $(snippet)"; fi
  else fail 8 "POST /api/triage/verdicts → $code: $(snippet)"; fi
else skip 8 "нет сессии или карточки"; fi

# ── 9. резолв алиаса из identities.yml ───────────────────────────────────────
code=$(req GET "$ARGUS_URL/api/v1/actors?alias=$(jq -rn --arg v "$SMOKE_ALIAS" '$v|@uri')" "$ARGUS_API_TOKEN")
if [ "$code" = 200 ] && [ "$(jget .status)" = resolved ] && [ "$(jget '.matches[0].person_id')" = "$SMOKE_PERSON" ]; then pass 9 "GET /api/v1/actors?alias=$SMOKE_ALIAS → resolved, $SMOKE_PERSON"
else fail 9 "GET /api/v1/actors?alias=$SMOKE_ALIAS → $code, status $(jget .status): $(snippet) (движок читает identities.yml — IDENTITIES_FILE)"; fi

# ── 10. паспорт субъекта ─────────────────────────────────────────────────────
code=$(req GET "$ARGUS_URL/api/v1/actors/$SMOKE_PERSON?range=7d" "$ARGUS_API_TOKEN")
if [ "$code" = 200 ] && [ "$(jget .person.person_id)" = "$SMOKE_PERSON" ]; then pass 10 "GET /api/v1/actors/$SMOKE_PERSON?range=7d → 200, событий $(jget .summary.events), алиасов $(jget '.aliases | length')"
else fail 10 "GET /api/v1/actors/$SMOKE_PERSON → $code: $(snippet)"; fi

# ── 11. экспорт паспорта закрыт токену сессии разбора ────────────────────────
if [ -n "$TRIAGE_TOKEN" ]; then
  code=$(req GET "$ARGUS_URL/api/v1/actors/$SMOKE_PERSON/report" "$TRIAGE_TOKEN")
  if [ "$code" = 403 ]; then pass 11 "GET /api/v1/actors/$SMOKE_PERSON/report токеном сессии → 403 $(jget .error)"
  else fail 11 "GET /api/v1/actors/$SMOKE_PERSON/report токеном сессии → $code, ожидался 403: $(snippet)"; fi
  # Сессия больше не нужна — закрыть (204); отказ не считается провалом смоука.
  code=$(req DELETE "$ARGUS_URL/api/triage/sessions" "$TRIAGE_TOKEN")
  [ "$code" = 204 ] || echo "warn: DELETE /api/triage/sessions → $code"
else skip 11 "нет сессии"; fi

# ── 12. живость источников: источники за 7 суток, статус по ритму ─────────────
code=$(req GET "$ARGUS_URL/api/sources" "$ARGUS_API_TOKEN")
if [ "$code" = 200 ] && [ "$(jget '.sources | type')" = array ]; then
  n=$(jget '.sources | length'); alive=$(jget '[.sources[] | select(.alive == 1)] | length')
  if [ "$(jget '[.sources[] | select(.source == "telemetry.smoke")] | length')" -ge 1 ]; then
    # Приём шага 2 только что прошёл: источник смоука обязан быть живым и с полями ритма.
    fields=$(jget '.sources[] | select(.source == "telemetry.smoke") | [.alive, .silence_threshold_sec, .silent_for_sec, .events_window] | map(type) | join(",")')
    smoke_alive=$(jget '.sources[] | select(.source == "telemetry.smoke") | .alive')
    if [ "$fields" = number,number,number,number ] && [ "$smoke_alive" = 1 ]; then pass 12 "GET /api/sources → 200: источников $n, живых $alive; telemetry.smoke жив, поля ритма на месте"
    else fail 12 "GET /api/sources: telemetry.smoke alive=$smoke_alive, типы полей ритма: $fields"; fi
  else pass 12 "GET /api/sources → 200: источников $n, живых $alive (источник смоука ещё не в списке)"; fi
else fail 12 "GET /api/sources → $code: $(snippet)"; fi

# ── 13. MCP за Caddy (:8445): инициализация Streamable HTTP с bearer ────────────
# Только при ARGUS_MCP_URL (например https://127.0.0.1:8445) — профиль compose mcp
# на стенде e2e не поднимается. Токен — ARGUS_MCP_HTTP_TOKEN (окружение или .env).
ARGUS_MCP_URL="${ARGUS_MCP_URL:-}"; ARGUS_MCP_HTTP_TOKEN="${ARGUS_MCP_HTTP_TOKEN:-$(envget ARGUS_MCP_HTTP_TOKEN)}"
if [ -n "$ARGUS_MCP_URL" ] && [ -n "$ARGUS_MCP_HTTP_TOKEN" ]; then
  printf 'header = "Authorization: Bearer %s"\n' "$ARGUS_MCP_HTTP_TOKEN" >"$TMP/mcp.cfg"
  code=$(curl -ksS --max-time 30 -o "$BODY" -w '%{http_code}' -X POST -K "$TMP/mcp.cfg" \
    -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
    --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"api-smoke","version":"1"}}}' \
    "${ARGUS_MCP_URL%/}/mcp" || echo 000)
  if [ "$code" = 200 ] && grep -q '"serverInfo"' "$BODY"; then pass 13 "POST $ARGUS_MCP_URL/mcp initialize → 200, сервер $(tr -d '\n' <"$BODY" | grep -o '"serverInfo":{[^}]*}' | head -1)"
  else
    nocode=$(curl -ksS --max-time 15 -o /dev/null -w '%{http_code}' -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' "${ARGUS_MCP_URL%/}/mcp" || echo 000)
    fail 13 "MCP initialize → $code (без bearer → $nocode; 403 от Caddy — адрес клиента не в MCP_ALLOWED_NETS): $(snippet)"
  fi
else skip 13 "ARGUS_MCP_URL не задан — MCP за Caddy не проверяется"; fi

if [ "$FAILS" = 0 ]; then echo "api-smoke: все шаги пройдены"; exit 0; fi
echo "api-smoke: провалено шагов — $FAILS"; exit 1
