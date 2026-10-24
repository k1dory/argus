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
| `WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASSWORD`, `WAZUH_INSECURE_TLS` | Wazuh API для раздела «Управление» |
| `AUTH_FILE` | файл пользователей и сессий (`.auth.json`); стартовый пароль admin — в файле рядом |
| `ARGUS_API_TOKEN` | bearer-токен для `/api/*` (MCP, скрипты; только чтение) |
| `OIDC_*` | SSO через IdP (см. `src/lib/oidc.ts`) |
| `APP_VERSION` | версия в шапке (build-arg из `VERSION`) |

Секреты в репозиторий и в вики не попадают — только имена переменных.

## Структура

- `src/app/(console)/` — страницы консоли; каждая сама проверяет сессию (`requirePageSession`).
- `src/app/api/` — JSON/CSV API для отчётов и MCP.
- `src/lib/` — доступ к ClickHouse (`clickhouse.ts`: таймауты, `safeQuery`, короткие ошибки), запросы, server actions.
- `src/lib/shared/` — чистые модули без `server-only`: время (`time.ts`), метки (`labels.ts`), спецификация дашборда, диапазоны.
- `src/components/console/` — компоненты консоли; `src/components/ui/` — shadcn/ui.
- `dashboards/*.json` (в корне репозитория) — провижининг дашбордов, как в Grafana.

## Проверки

```bash
npm run lint         # eslint
npm run typecheck    # next typegen + tsc --noEmit
npm test             # node:test через tsx (tests/*.test.ts)
npm run check        # всё вместе
```

Тесты `tests/ux-*.test.ts` покрывают форматирование времени, безопасные ключи серий графиков,
нормализацию спецификации дашборда, словарь меток и проверку `?next=` при входе.

## Безопасность

- Заголовки (CSP, Referrer-Policy, Permissions-Policy, X-Frame-Options) — `next.config.ts`; Caddy добавляет HSTS.
- SQL панелей дашбордов выполняется только от read-only пользователя ClickHouse с лимитами времени, памяти и строк.
- Текст ошибок ClickHouse пользователю не отдаётся; полный текст — в логе контейнера `web`.
