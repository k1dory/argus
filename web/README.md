# Консоль ARGUS SIEM (`web/`)

Next.js 16 (App Router, React 19, shadcn/ui, Tailwind 4, Recharts). Стиль — «ascii-console»:
моноширинный, чёрный фон, один оранжевый акцент, нулевые скругления.

## Запуск

```bash
npm ci
npm run dev        # http://localhost:3000, нужен ClickHouse (см. переменные ниже)
npm run build && npm start
```

В составе стенда консоль собирается Dockerfile'ом и стоит за Caddy (`../caddy/Caddyfile`, TLS на :8443).

## Переменные окружения

| Переменная | Назначение |
|---|---|
| `CLICKHOUSE_URL`, `CLICKHOUSE_DB`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD` | хранилище событий, инцидентов, настроек консоли |
| `CLICKHOUSE_RO_USER`, `CLICKHOUSE_RO_PASSWORD` | read-only пользователь для SQL панелей дашбордов (без него панели не выполняются) |
| `DASHBOARDS_DIR` | каталог JSON-дашбордов для провижининга (`../dashboards`) |
| `ENGINE_URL`, `ENGINE_TOKEN` | движок корреляции: правила, реагирование, `/healthz` |
| `COLLECTOR_URL` | коллектор событий |
| `WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASSWORD`, `WAZUH_INSECURE_TLS`, `WAZUH_CA_FILE`, `WAZUH_CERT_SHA256` | Wazuh API для раздела «Управление» (модуль Wazuh) |
| `AUTH_FILE` | файл пользователей и сессий (в compose — `/data/auth.json`, том `web-auth`); стартовый пароль admin — в файле рядом |
| `ARGUS_API_TOKEN` | bearer-токен для `/api/*` (MCP, скрипты; только чтение, ≥32 символов) |
| `ARGUS_TRIAGE_ISSUER_TOKEN`, `ARGUS_TRIAGE_SESSION_REQUESTS`, `ARGUS_TRIAGE_ANCHOR_MAX_SPREAD` | учётка-эмитент сессий разбора (`POST /api/triage/sessions`), бюджет запросов на сессию (100), порог частых значений для якорей (5) |
| `ARGUS_INTEGRATION_WAZUH` | `1` — разделы модуля Wazuh (`/wazuh/*`), индекс `alerts` в поиске |
| `TRUSTED_PROXY`, `SESSION_SECURE` | доверять `X-Forwarded-For` за Caddy; кука без `Secure` для `http://127.0.0.1:3001` на стенде |
| `OIDC_*` | SSO через IdP (см. `src/lib/oidc.ts`) |
| `APP_VERSION` | версия в шапке (build-arg из `VERSION`) |

Секреты в репозиторий и в вики не попадают — только имена переменных.

## Структура

- `src/app/(console)/` — страницы консоли; каждая сама проверяет сессию (`requirePageSession`).
- `src/app/api/` — JSON/CSV API для отчётов, MCP и агентов разбора; спецификация — `../api/openapi.yaml`, консоль отдаёт её как `/openapi.yaml`.
- `src/lib/` — доступ к ClickHouse (`clickhouse.ts`: таймауты, `safeQuery`, короткие ошибки), запросы, server actions.
- `src/lib/shared/` — чистые модули без `server-only`: время (`time.ts`), метки (`labels.ts`), спецификация дашборда, диапазоны.
- `src/components/console/` — компоненты консоли; `src/components/ui/` — shadcn/ui.
- `dashboards/*.json` (в корне репозитория) — провижининг дашбордов, как в Grafana.

## API

Спецификация HTTP API консоли (OpenAPI 3.1) лежит в корне репозитория — `../api/openapi.yaml`,
это единственный источник. На `npm run build` (`prebuild`) скрипт `scripts/sync-openapi.mjs`
копирует её в `public/openapi.yaml`, и консоль отдаёт её без аутентификации по `GET /openapi.yaml`;
`GET /api/version` с сессией или токеном возвращает этот путь в поле `openapi`. Копия в `public/`
хранится в git — контекст сборки Docker ограничен `web/`. Тест `tests/openapi.test.ts` проверяет,
что копия совпадает с источником, каждый `route.ts` в `src/app/api` описан в спецификации (и наоборот),
а встроенная схема вердикта равна `src/lib/shared/triage-verdict.schema.json`. После правки
спецификации — `npm run sync-openapi`.

## Проверки

```bash
npm run lint         # eslint
npm run typecheck    # next typegen + tsc --noEmit
npm test             # node:test через tsx (tests/*.test.ts)
npm run check        # всё вместе
```

Слои `tests/*.test.ts` (node:test через tsx, ClickHouse подменяется по тексту SQL):

- `ux-*` — форматирование времени, ключи серий графиков, спецификация дашборда, метки, `?next=`;
- `auth-*`, `oidc*`, `totp`, `csp`, `console-grants` — вход, роли, SSO, 2FA, заголовки;
- `actors-api`, `log-api`, `triage-*`, `incidents-pagination`, `search-*`, `api-limits` — маршруты
  `src/app/api/*` через `require` после моков `_next-mock.ts`;
- `triage-claim-ch` — живой ClickHouse: конкурентный claim вердикта агента; выполняется при
  `ARGUS_TEST_CLICKHOUSE_URL` (+ `_USER`, `_PASSWORD`, БД `argus`), иначе пропускается — так его
  гоняет CI (`services: clickhouse`).

Без тестов маршрутов: `api/version`, `api/events/tail`, `api/auth/oidc/*` (логика SSO покрыта
`oidc.test.ts` на уровне `lib`). Против живого стенда — `../scripts/api-smoke.sh`.

## Безопасность

- Заголовки (CSP, Referrer-Policy, Permissions-Policy, X-Frame-Options) — `next.config.ts`; Caddy добавляет HSTS.
- SQL панелей дашбордов выполняется только от read-only пользователя ClickHouse с лимитами времени, памяти и строк.
- Текст ошибок ClickHouse пользователю не отдаётся; полный текст — в логе контейнера `web`.
