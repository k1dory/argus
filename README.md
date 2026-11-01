# ARGUS

Единый журнал событий и корреляция на ClickHouse. Коллекторы снимают события с NGFW,
EDR/XDR, Kubernetes, CI/CD, NetFlow, syslog и телеметрии хостов, нормализуют их в одну
схему события (субъект · объект · действие · узел · сеанс · значение) и коррелируют
правилами из git. Правило безопасности и правило эксплуатации пишутся одинаково:
«20 отказов SSH на узле за полчаса» и «диск занят больше 90 % три замера подряд» —
один язык, одна лента инцидентов, одна отработка. Каждый инцидент может получить разбор
языковой модели (локальной, с редакцией ПДн) и разбор внешнего агента через нейтральный
API. Wazuh подключается как модуль, а не как центр системы. Комплаенс — Policy-as-Code
на OPA/Rego.

Поток данных: источники → `collector` (Go) → `argus.events` → `engine` (Go): правила →
инциденты → уведомления, вебхуки, LLM-разбор → консоль `web` (Next.js) за Caddy `:8443`.
Внешние агенты читают журнал через `argus-mcp` или `GET /api/v1/log` и возвращают вердикт
через `POST /api/triage/verdicts`. Поверх журнала строится паспорт сотрудника: срез по человеку
за период с учётом времени действия его алиасов (`/actors`). Схема — в [docs/architecture.svg](docs/architecture.svg).

## Компоненты

- `collector/` — Go. Приёмник событий: syslog RFC 5424/3164 с разбором CEF
  (Check Point, PAN-OS, Kaspersky, CrowdStrike…) и LEEF (UserGate, Ideco), NetFlow v9 /
  IPFIX с кэшем шаблонов, вебхуки Kubernetes audit и GitLab (audit streaming,
  system hooks, pipeline). Всё нормализуется в единую схему `argus.events`
  (субъект · объект · действие · узел · сеанс), источник классифицируется по вендору
  (`collector.yml`), события с e-mail/телефонами и источники с `pii: true`
  помечаются флагом ПДн. Что ClickHouse не принял — в `argus.ingest_rejects` (30 дней).
  Перед отправкой в ClickHouse батчи сохраняются в дисковую очередь
  `collector-state:/state/spool`; после перезапуска незавершённые батчи
  отправляются повторно. Успешный ответ вебхука означает, что батч уже записан
  на диск. При заполнении очереди HTTP возвращает `503` с `Retry-After`, а
  TCP/TLS-источники получают обратное давление. UDP не подтверждает доставку.
  После аварии возможен повтор последнего батча, поэтому при анализе сырых
  событий учитывайте семантику «как минимум один раз».
- `engine/` — Go. Ядро корреляции: Sigma-подобные правила из `rules/*.yml`
  (selection / filter / threshold с окнами и distinct), инциденты со статусами
  отработки, LLM-аналитик по строгой JSON-схеме за интерфейсом `analyst.Backend`
  (бэкенды `openai-compatible` — Ollama, vLLM, OpenAI и совместимые — и `mock`; профиль
  `on-prem-strict` с `egress: deny` проверяет резолв хоста), редакцией ПДн и порогом
  уверенности, Telegram/e-mail и подписанные вебхуки. Материализует события `identity.alias`
  и `identities.yml` в карту идентичностей для паспорта. `argus rules test` гоняет правила по записанному
  трафику (`fixtures/events/*.ndjson`, ожидания в `rules/tests/`).
- `rules/` — правила корреляции как файлы в git: `rules/*.yml` — нейтральные к вендору,
  `rules/ops/` — эксплуатация (диск, тишина узла), `rules/wazuh/` — на алертах Wazuh;
  `fixtures/` — записанный трафик и телеметрия для `argus rules test`.
- `shipper/` — Rust, модуль Wazuh. Тейлит `/var/ossec/logs/alerts/alerts.json` (NDJSON),
  переживает ротацию и усечение файла, ведёт чекпоинт (inode+offset), пишет батчами в
  `argus.wazuh_alerts`.
- `policyd/` — Go, модуль Wazuh. Раз в `POLICY_POLL_INTERVAL` (5m) забирает агентов и SCA-результаты из
  API менеджера (JWT через `POST /security/user/authenticate`), прогоняет через встроенный
  OPA, вердикты (с полем `status`) кладёт в `argus.policy_verdicts` и отдаёт на
  `:8080/verdicts` (bearer `POLICYD_TOKEN`, если задан).
- `policies/` — Rego-политики с юнит-тестами; пороги в `config.json`.
- `clickhouse/migrations/` — версионированная схема: идемпотентные SQL-файлы,
  применяются сервисом `migrator` (журнал — `argus.schema_migrations`). `events` и
  `wazuh_alerts` — TTL 180 дней, `policy_verdicts` — 90, почасовой агрегат
  `wazuh_alerts_hourly` (materialized view) — 2 года.
- `dashboards/` — provisioned-дашборды конструктора консоли (JSON-модель):
  «ARGUS Overview», WAF и, в модуле Wazuh, «Источник Wazuh», FIM, SCA. Свои строятся в консоли:
  панели timeseries / bar / stat / table, SQL к ClickHouse с макросами `$__timeFilter`,
  `$__timeInterval`, сетка 24 колонки, экспорт/импорт JSON. Запросы панелей
  выполняются от пользователя `argus_ro` (`readonly=1`, лимиты неизменяемы).
- `web/` — консоль на Next.js + shadcn/ui: вход (пароль + опциональный TOTP 2FA, SSO),
  обзор, «Инциденты» (лента, карта, вердикты движка и агентов, отработка), «Журнал»
  (все источники, live-tail), «Субъекты» (паспорт сотрудника по алиасам с интервалами), «Поиск», «Источники» (живость коллекторов, EPS, доля ПДн),
  «Правила», «Дашборды», настройки; REST API `/api/*` и `/api/v1/log` для агентов.
  Разделы модуля Wazuh (алерты, CVE, MITRE ATT&CK, политики, агенты, управление
  менеджером) появляются при `ARGUS_INTEGRATION_WAZUH=1`.
- `mcp/` — `argus-mcp`: MCP-сервер для агентов (Claude Code, Cursor) поверх API консоли,
  профили `full` и `triage` (редакция, псевдонимы, область одного инцидента).
- `caddy/` — TLS-терминация: консоль `:8443`, вебхуки коллектора `:8089`.

## Запуск

```sh
./scripts/argus init        # .env (права 600) со всеми секретами + make up
./scripts/argus init --with-wazuh   # то же плюс модуль Wazuh (shipper, policyd, разделы консоли); --without-wazuh — выключить
make demo                   # записанный трафик и неделя субъектов → инциденты и паспорта за полминуты
```

`argus init` генерирует пароли семи пользователей ClickHouse, `ENGINE_TOKEN`,
`ARGUS_INGEST_TOKEN`, `ARGUS_API_TOKEN`, `ARGUS_MCP_HTTP_TOKEN`, `ARGUS_TRIAGE_ISSUER_TOKEN`,
`ARGUS_PSEUDONYM_KEY`, `POLICYD_TOKEN`,
`BACKUP_KEY` (`openssl rand -hex 24`), существующие значения не трогает — его можно
повторять при апгрейде, чтобы дописать новые переменные. Пароль API менеджера Wazuh
(`WAZUH_API_PASSWORD`) при включённом модуле впишите руками. Без секретов compose не стартует
(`${VAR:?}` с подсказкой), а `migrator` отказывает на паролях `argus`, `argus-*`,
`change-me*`. `make up` больше не генерирует демо-данные — это `make demo`.

Консоль: <https://localhost:8443> (Caddy, внутренний CA; без TLS — <http://127.0.0.1:3001>
с `SESSION_SECURE=false`). Открывать по имени или адресу сервера — задайте его в `CONSOLE_HOST`
(`.env`): Caddy выпустит на него сертификат и будет отдавать его клиентам без SNI (`default_sni`),
иначе обращение по IP завершится ошибкой TLS. Пароль пользователя `admin` генерируется при первом старте
и лежит в томе `web-auth`:

```sh
docker compose exec web cat /data/admin-password.txt
```

Смените его на странице «Настройки» — файл после этого удаляется (политика паролей как
у wazuh-passwords-tool: 8–64 символа, заглавная, строчная, цифра и один из `.*+?-`).
Если стартовый пароль утерян, остановите консоль и сбросьте только пароль `admin`
(пользователи и 2FA сохранятся):

```sh
docker compose stop web
docker compose run --rm --no-deps --entrypoint node web /app/reset-admin-password.cjs
docker compose up -d web
docker compose exec web cat /data/admin-password.txt
```

Новый пароль снова потребуется сменить при первом входе. В консоли код 2FA
запрашивается только после верного пароля, если она включена у этого пользователя.

Развёртывание на сервер через Ansible — роль `deploy/ansible/roles/argus` и плейбук
`deploy/ansible/argus.yml` ([описание](deploy/ansible/README.md)): код, тома данных, `.env` с
секретами на хосте, `make up`, ожидание готовности, cron бэкапа.

Стенд без секретов — `make up-dev`: дефолты из `.env.dev` и `docker-compose.dev.yml`
(`ARGUS_DEV=1`: приём без токена, слабые пароли только предупреждение). В бою этот
режим не используется.

Демо-данные — `fixtures/events/*.ndjson` и, для модуля Wazuh, `./sample/alerts.json`; в бою
укажите в `.env` `WAZUH_ALERTS_DIR=/var/ossec/logs/alerts` (каталог, не файл — bind-mount файла
пришпиливает inode и прячет ротацию) и доступ до API менеджера для policyd.
Без живого менеджера policyd просто логирует ошибку и ждёт.

## Пользователи ClickHouse, сети, порты

Админ ClickHouse (`CLICKHOUSE_USER`/`CLICKHOUSE_PASSWORD`) нужен только `migrator`'у.
Он применяет миграции и заводит служебных пользователей (пароли уходят в ClickHouse
как `sha256(password + salt)`, в SQL и argv не попадают; гранты декларативны —
`REVOKE ALL`, затем ровно перечисленное):

| Пользователь | Кто | Права |
|---|---|---|
| `argus_ro` | панели дашбордов | `SELECT argus.*`; `readonly=1`, `max_execution_time=20`, `max_memory_usage=2G`, `max_rows_to_read=500M`, `max_result_rows=5000` + `result_overflow_mode=break`, не больше 4 запросов разом — всё в профиле и неизменяемо; консоль настроек в запросе не передаёт и пускает не больше 3 панелей разом — на один процесс, несколько экземпляров консоли делят лимит 4 |
| `argus_console` | консоль | `SELECT argus.*` + `INSERT` в `incidents`, `console_rule_mutes`, `rule_exceptions`, `console_audit`, `console_dashboards`, `console_settings`; DDL закрыт |
| `argus_collector` | коллектор | `INSERT` в `events`, `collector_health` (+ цель MV `collector_health_log`), `ingest_rejects` |
| `argus_shipper` | шиппер | `INSERT` в `wazuh_alerts` (+ цели MV `wazuh_alerts_hourly`, `events`) |
| `argus_policyd` | policyd | `INSERT` в `policy_verdicts` |
| `argus_engine` | движок | `SELECT argus.*`, `INSERT` в `incidents`, `incident_verdicts`, `response_log`; `SELECT system.disks` |

У пишущих сервисов `allow_ddl=0` и потолки времени/памяти (`MAX`), у которых сервис
может ужесточить, но не снять. `SOURCES`/`HOST` не ограничиваются — подсеть compose
динамическая.

Сети compose: `data` (`internal: true` — ClickHouse и все, кто к нему ходит; наружу
трафика нет), `edge` (Caddy ↔ web / collector), `egress` (движок — Wazuh API,
облачный профиль LLM, Telegram; policyd и web — Wazuh API; collector — pull-источники;
mcp → web). Все сервисы: `cap_drop ALL`, `no-new-privileges`, read-only ФС (кроме
ClickHouse), `tmpfs` под `/tmp`, лимиты pid и памяти. ClickHouse наружу не публикуется —
с хоста к нему `docker compose exec clickhouse clickhouse-client`.

| Порт | Что | Кому |
|---|---|---|
| `8443/tcp` | консоль, TLS (Caddy) | операторы, MCP по `ARGUS_API_TOKEN` |
| `8089/tcp` | `https://…/ingest/*` — вебхуки коллектора, TLS (Caddy → collector:8088) | k8s audit, GitLab, Harbor, Argo CD, NDJSON |
| `5514/udp+tcp` | syslog CEF/LEEF | NGFW, EDR, Jenkins |
| `6514/tcp` | syslog TLS (RFC 5425); включается `SYSLOG_TLS_ADDR=:6514` + сертификат в `./collector/certs` | NGFW с TLS, NXLog/Winlogbeat |
| `2055/udp` | NetFlow v9 / IPFIX (`NETFLOW_EXPORTERS` — allow-list) | роутеры |
| `127.0.0.1:8088` | HTTP коллектора: `/metrics`, `/healthz`, replay | только localhost |
| `127.0.0.1:8090`, `:8080` | `/metrics`/`/healthz` движка, policyd | только localhost |
| `127.0.0.1:3001` | консоль без TLS | только localhost |
| `127.0.0.1:18095` | MCP по HTTP (профиль `mcp`) | только localhost |

`INGEST_BIND` ограничивает интерфейс для 6514/8089 (по умолчанию `0.0.0.0`).

## Коллекторы и правила

### ARGUS и конвейеры доставки: Vector, Fluent Bit, Filebeat

ARGUS не заменяет конвейер доставки логов. Vector, Fluent Bit или Filebeat решают задачу
«собрать с хостов, разобрать, доставить»; ARGUS начинается там, где они заканчивают: единая
схема события, хранение в ClickHouse, корреляция правилами, инциденты с отработкой, паспорт
сотрудника и API для агентов. В контуре, где конвейер уже стоит, правильная связка — он
собирает и приводит события к схеме ARGUS, а в коллектор ARGUS идут только протоколы, которые
конвейер не разбирает: CEF/LEEF от NGFW, NetFlow, вебхуки Kubernetes и CI.

Пример для Vector: `sshd` из journald → схема ARGUS → `POST /ingest/events` (NDJSON, токен приёма).

```toml
[sources.journal]
type = "journald"
include_units = ["ssh"]

[transforms.argus]
type = "remap"
inputs = ["journal"]
source = '''
  . = {
    "ts": format_timestamp!(.timestamp, "%Y-%m-%d %H:%M:%S%.3f"),
    "source": "vector.sshd",
    "source_class": "syslog",
    "vendor": "openssh", "product": "sshd",
    "node": .host,
    "raw": .message,
    "attrs": {}
  }
  m, err = parse_regex(.raw, r'^(?P<outcome>Accepted|Failed) (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)')
  if err == null {
    .action = "auth.ssh"
    .outcome = if m.outcome == "Accepted" { "success" } else { "failure" }
    .actor_name = m.user
    .actor_kind = "user"
    .src_ip = m.ip
    .src_port = to_int!(m.port)
    .attrs.method = m.method
    .severity = if .outcome == "failure" { 5 } else { 2 }
  } else {
    .action = "syslog.sshd"
    .object = .raw
  }
'''

[sinks.argus]
type = "http"
inputs = ["argus"]
uri = "https://argus.example.org:8089/ingest/events"
method = "post"
encoding.codec = "json"
framing.method = "newline_delimited"
batch.max_events = 500
request.headers.X-Argus-Token = "${ARGUS_INGEST_TOKEN}"
tls.ca_file = "/etc/vector/argus-ca.crt"
```

Поля схемы: `ts` (`YYYY-MM-DD HH:MM:SS.mmm`, UTC), `source`, `source_class`, `action`, `outcome`,
`severity` 0–10, `actor_name`/`actor_kind`, `object`, `node`, `session_id`, `src_ip`/`dst_ip`,
`src_port`/`dst_port`, `proto`, `bytes`, `packets`, `value`/`unit`, `pii`, `attrs` (строки), `raw`.
Отсутствующие поля заполняются умолчаниями; телеметрия (`disk.usage` с `value`) и алиасы
(`identity.alias`) идут тем же путём — Vector с источником `host_metrics` или `exec` закрывает
и это без отдельного агента.

```sh
make replay                                   # залить записанный трафик → инциденты за полминуты
./scripts/argus rules test                    # тесты правил (rules/tests/*.yml)
./scripts/argus rules test --replay fixtures/events/august.ndjson
./scripts/argus rules test --replay fixtures/events/telemetry.ndjson
```

Поведение вендоров на стыках (RouterOS, Huawei VRP, Vector, NetBird, Authentik, nftables, PBS) —
в [docs/integrations.md](docs/integrations.md).

Куда направлять источники:

| Источник | Как | Куда |
|---|---|---|
| NGFW / прокси: Check Point (Log Exporter), PAN-OS, UserGate, Ideco, Fortinet | syslog CEF / LEEF | `:5514` UDP/TCP, `:6514` TLS |
| Squid | native access.log через syslog | `:5514` |
| EDR: Kaspersky, Cortex XDR | syslog CEF | `:5514` |
| CrowdStrike Falcon | Streaming API (OAuth2) | `collector.yml → falcon`, `FALCON_*` |
| Sysmon, FIM, SCA, rootcheck | агент Wazuh → менеджер (модуль Wazuh) | `WAZUH_ALERTS_DIR` |
| телеметрия хостов: диск, load, очереди | NDJSON с `value`/`unit` (`scripts/telemetry-sample.sh`) | `POST …:8089/ingest/events` |
| Kubernetes audit | webhook | `POST https://<host>:8089/ingest/k8s-audit` |
| GitLab (audit streaming, system hooks, pipeline) | webhook | `POST https://<host>:8089/ingest/gitlab` |
| Harbor, Argo CD | webhook | `…:8089/ingest/harbor`, `/ingest/argocd` |
| Jenkins Audit Trail | syslog | `:5514` |
| MikroTik RouterOS (вход/выход, firewall с `log=yes`, DHCP, изменения конфигурации) | `/system logging action … target=remote` (7.16: `bsd-syslog=yes`; 7.21: `remote-log-format=syslog`), топики `system,account,firewall,dhcp,error,warning,critical` c `!debug` | `:5514`; потоки — `/ip traffic-flow` v9 на `:2055` |
| Huawei VRP / CloudEngine (вход/выход, команды, конфигурация, линки) | `info-center enable`, `info-center loghost <argus> port 5514 source-ip <mgmt>` | `:5514` |
| Proxmox VE (вход в веб-интерфейс, задачи UPID, изменения ВМ, отказы API) | агент Vector: journald `pvedaemon`/`pveproxy`/`qm`/`pct` + `/var/log/pveproxy/access.log` (каталог 0700 `www-data` — ACL на `vector`) → `auth.login`, `pve.task.*`, `pve.api.write` | `POST …:8089/ingest/events` |
| Caddy, другой reverse proxy в контейнере | агент Vector, источник `docker_logs`: JSON access-лог (`logger: http.log.access`) → `proxy.access` (`src_ip` = `client_ip`), ошибки → `proxy.error`; статика с ответом < 400 отбрасывается | `POST …:8089/ingest/events` |
| Платформа agent-sandbox (песочницы AI-агентов): выход агентов наружу, API, статусы песочниц | агент Vector на шлюзах: журналы подов CRI `/var/log/pods/…/sandboxd/*.log` (slog JSON) → `sandbox.egress` (verdict allow/deny, агент, арендатор, хост), `sandbox.api`, `sandbox.dns`, `sandbox.status`; правила `rules/sandbox-*.yml` | `POST …:8089/ingest/events` |
| Forgejo runner, OpenBao (служебные журналы) | агент Vector: journald `forgejo-runner` (старт задач `ci.task.start`, ошибки), `bao` (seal/unseal, предупреждения) | `POST …:8089/ingest/events` |
| Access-логи reverse proxy (NetBird, любой другой с журналом запросов) | NDJSON `action: proxy.access`, `src_ip` — клиент, `node` — хост сервиса, `object` — хост+путь, `attrs.status`/`country`; правила `rules/proxy-*.yml` | `POST …:8089/ingest/events` |
| Yandex Cloud Audit Trails, VK Cloud | S3-бакет | `collector.yml → s3`, `YC_*` |
| NetFlow v9 / IPFIX | UDP; `INTERNAL_NETS` — свои сети для `attrs.scope` (inbound/outbound/internal/external) и `attrs.syn_only` у TCP-попыток без ответа; `attrs.avg_pkt` — средний размер пакета; `FLOW_NAT_ADDRS` — адреса NAT, их потоки помечаются `attrs.post_nat=1` | `:2055` |
| QNAP QTS / QuTS hero (журнал доступа: входы и действия с файлами по SMB/AFP/FTP/NFS/HTTP; журнал событий: администрирование, диски, RAID) | QuLog Center → «Отправитель журналов» → «Отправить серверу Syslog», TCP, «Журналы событий и доступа»; формат RFC 3164 без пояса — адрес NAS в `SYSLOG_PEER_TZ`. Источник `nas.qnap`: `auth.login`/`auth.logout`, `file.read/write/delete/rename/move`, `system.config`, `storage.event`; правила `rules/nas-*.yml`, `rules/ops/nas-storage-failure.yml` | `:5514` |
| всё остальное (RFC 5424/3164, в том числе ISO-время в заголовке BSD как у rsyslog, сырой текст) | syslog | `:5514` |
| свои события единой схемы | NDJSON | `POST …:8089/ingest/events` |

Вебхуки требуют заголовок `X-Argus-Token: $ARGUS_INGEST_TOKEN` (стенд `ARGUS_DEV=1` — без
него). Запись tcpdump: `docker compose exec collector /collector replay-pcap file.pcap`.
Пропускная способность: `./scripts/bench-ingest.sh 200000` (см. CHANGELOG).

Утечка секрета в CI (`ci-secret-echo`) автоматикой закрывается только отзывом доказанно того
же токена: у утечки и у события `*_revoked` из аудита (`source` `*.audit`) совпадают
неизменяемый `attrs.token_id`, провайдер (`vendor`/`product`) и экземпляр (`attrs.instance`).
Имя секрета (`attrs.secret_id`) выбирает пользователь — оно только находит инцидент. Ротация
(`*_rotated`) не закрывает: GitLab заводит при ней новый токен. Утечка из лога CI знает лишь имя
переменной, поэтому сейчас такие инциденты по ротации или отзыву **не закрываются**, а
эскалируются с пометкой «закрыт автоматикой, нужна проверка» (тег `argus.needs_review`) — это
осознанное решение: однофамилец любого возраста иначе закрыл бы утечку действующего секрета.

LLM-аналитик: профили в `engine/argus.analyst.yml`, ключи только через окружение
(`ARGUS_LLM_LOCAL_ENDPOINT`, `ARGUS_LLM_LOCAL_MODEL`, `ARGUS_LLM_LOCAL_API_KEY`); бэкенд —
любой сервер с API OpenAI (`/chat/completions`): Ollama, vLLM, LM Studio, OpenAI, совместимые
шлюзы. Умолчания для адреса нет: если профиль `on-prem-strict` выбран, а
`ARGUS_LLM_LOCAL_ENDPOINT` пуст, движок не стартует с понятной ошибкой. Новый бэкенд добавляется реализацией интерфейса `analyst.Backend` в
`engine/internal/analyst`, без правок в маршрутизации, редакции и проверке ответа.
Инцидент с ПДн уходит исключительно в `ARGUS_ANALYST_PII_PROFILE`; профиль с
`egress: deny` не отправит запрос на публичный адрес. Параллелизм и суточный потолок —
`ANALYST_CONCURRENCY`, `ANALYST_DAILY_LIMIT` (сверх лимита инциденты создаются без
вердикта). На стенде без модели `ARGUS_ANALYST_FORCE_PROFILE=mock`.

## Хранилище: отдельный диск

Данные ClickHouse держите на отдельном разделе — так же, как `/var/ossec` у
менеджера Wazuh. Переполненный корневой диск кладёт не только ARGUS: ClickHouse
перестаёт принимать вставки, а с ним и приём событий. До первого запуска:

```sh
./scripts/init-storage.sh /srv/argus          # тома compose → /srv/argus/clickhouse, /srv/argus/backups
./scripts/init-storage.sh /srv/argus /mnt/bkp # бэкапы на другой диск
./scripts/argus init
```

Скрипт создаёт именованные тома `argus_clickhouse-data` и `argus_clickhouse-backups`
поверх каталогов на нужном диске; compose использует их как обычно. Если стек
уже поднимали на томах по умолчанию — сначала `./scripts/backup.sh`,
`docker compose down -v`, затем скрипт и `./scripts/restore.sh`.

Оценка места: событие в `events` после сжатия занимает порядка 100–200 байт, то есть
1 000 EPS — это 86,4 млн событий в сутки и **260–520 ГБ за 30 дней** (плюс индексы, merge,
spool и копия сырого события в `raw`; измерьте на своих данных за первую неделю). TTL
`events` и `wazuh_alerts` — 180 дней
(меняется в миграциях). Оставляйте запас: ClickHouse держит свободными
`keep_free_space_bytes` и при нехватке места отклоняет вставки, а не тихо
затирает старое. Движок читает `events` с отставанием в 3 с от текущего времени (устоявшиеся
секунды), последнюю секунду — включительно с дедупликацией по хешу строки, поэтому поздние
вставки той же секунды не теряются; при более 200 000 событий в секунду страницы дочитываются
в том же опросе. Память: лимит контейнера `CLICKHOUSE_MEM_LIMIT` (4g по умолчанию),
ClickHouse берёт 80 % от него (`clickhouse/config.d/memory.xml`).

## Роли, TLS, бэкапы

Консоль публикуется Caddy по TLS на `:8443` (внутренний CA, как у Wazuh dashboard;
свой сертификат — файлы в `./caddy/certs`, `CONSOLE_TLS` в `.env`). Caddy ставит
HSTS (`includeSubDomains`), CSP (та же политика продублирована в `next.config.ts`),
`Permissions-Policy`, лимит тела 16 МБ, access-лог в томе `caddy-data` (ротация 5×50 МБ).
Консоль доверяет `X-Forwarded-For` только за Caddy (`TRUSTED_PROXY=1`).

Роли: наблюдатель (чтение), аналитик (отработка инцидентов, мьюты, управление Wazuh),
администратор (пользователи, 2FA). Пользователей создаёт `admin` в «Настройках»,
пароль показывается один раз. Каждое действие оператора — в `argus.console_audit`.

SSO: при заданных `OIDC_*` на странице входа появляется «Войти через SSO» — OIDC
authorization code + PKCE (Authentik, Keycloak). Роль берётся из групп IdP на
каждом входе (`OIDC_GROUP_ADMIN/ANALYST/VIEWER`), локальная запись не нужна;
без совпавшей группы — отказ (или `OIDC_DEFAULT_ROLE`). Пользователи SSO хранятся
с префиксом `sso:` (`sso:<subject>`), с локальными не пересекаются: локальный `admin`
и `sso:admin` — разные учётки, а локальные правила паролей и TOTP к SSO не применяются.
После первого входа сотрудник SSO появляется в списке пользователей (пометка «SSO», роль
обновляется каждым входом) — ему можно назначать инциденты, как и локальным аналитикам
и администраторам.
Карточка инцидента содержит Markdown-досье: проверенный анализ модели, журнал
переходов и записи аналитиков с автором и временем. Досье можно скачать как
`INC-12.md` через `GET /api/incidents/INC-12/markdown`; JSON остаётся на
`GET /api/incidents/INC-12`. Записи команды хранятся отдельно от вывода модели.

Очередь инцидентов: «Открытые», «Мои», «Без ответственного», «Просрочены».
Лента обновляется кнопкой, чтобы таймер не сбивал прокрутку и ввод. Целевой срок
первичной реакции считается от создания, круглосуточно: critical 15 минут,
high 1 час, medium 4 часа, low 24 часа. Просрочка показывается у инцидентов
со статусом `new`; первое назначение оставляет статус `new` до принятия
аналитиком. Карточка сохраняет время первого `take` из журнала и показывает,
была ли реакция в срок; для инцидентов, обработанных до появления журнала,
историческое время реакции неизвестно.
Аналитик может взять свободный или назначенный ему инцидент в работу. Статус
меняет только текущий ответственный; администратор назначает и передаёт
инциденты локальным аналитикам. Комментарий может добавить любой аналитик в
любой момент, включая завершённый инцидент. Комментарии хранятся отдельно в
`incident_comments` и не переписываются при смене статуса. Для них нужна
миграция `0013_incident_comments.sql` перед запуском новой консоли.
Ручное закрытие и отметка ложного срабатывания требуют причину от 10 до 2000
символов. Автор, время, итоговый статус и причина записываются вместе в
`incident_state_events` (миграция `0016_incident_closure_reason.sql`); для
старых закрытий без такой записи интерфейс показывает, что автор неизвестен.
Переходы статуса и ответственного записываются в `incident_state_events` с
последовательной ревизией через один экземпляр `engine`; `incidents_current`
соединяет их с версиями детекции. Для нескольких реплик `engine` потребуется
транзакционный координатор ревизий. Поле `incidents.updated_at` по-прежнему
имеет секундную точность и описывает снимки детекции, поэтому при совпадении
времени их версия может быть неоднозначной; операторские переходы от него не
зависят. Если запись автоматического закрытия в журнал сбоит после записи
снимка, финальный статус остаётся видимым, но в истории будет пропуск;
`ArgusIncidentStateWriteFailed` требует проверки оператором. Для новых установок
нужны миграции 0013 и 0014 до запуска сервисов.
Регулярный почтовый отчёт по открытым рискам, владельцам и срокам включается
`RISK_REPORT_INTERVAL=24h` (или, например, `168h`) при настроенных
`SMTP_HOST`, `SMTP_FROM`, `SMTP_TO`. После первого включения письмо уходит сразу;
следующий срок считается от подтверждённой отправки, записанной в
`risk_report_deliveries` (миграция 0015), поэтому перезапуск движка не сдвигает
расписание. При ошибке SMTP или ClickHouse повтор — через 5 минут. Если письмо
принято SMTP, а запись о доставке не сохранилась, возможна повторная отправка.
Сводка считает все открытые инциденты, перечисляет до 50 владельцев и 30
приоритетных карточек.

Одна установка ARGUS сейчас рассчитана на одного клиента: роли и SSO
разграничивают действия, но не данные разных клиентов. Для подрядчика с
несколькими клиентами нужны отдельные установки до появления сквозной модели
арендаторов в событиях, инцидентах, поиске, экспортах и управляющих API.

Бэкап: `./scripts/backup.sh` — `BACKUP DATABASE` + тома `web-auth` (пользователи, TOTP —
шифруется), `shipper-state` и `collector-state` (очередь сырых событий — шифруется)
в `BACKUP_DIR` (по умолчанию `/var/backups/argus`, вне
дерева проекта), ротация `BACKUP_KEEP_DAYS` (14). Шифрование: `age`
(`BACKUP_AGE_RECIPIENT`, восстановление — `BACKUP_AGE_IDENTITY`) или, если `age` нет,
`openssl enc -aes-256-cbc -pbkdf2` с `BACKUP_KEY`; без ключа скрипт отказывает. Ключ
храните отдельно от бэкапов. Перед восстановлением остановите `collector`,
`engine`, `web` и `shipper`, затем запустите `./scripts/restore.sh <имя>`.
Не восстанавливайте том очереди при работающем коллекторе: он держит открытые
батчи в памяти. Пароль ClickHouse в URL/argv не попадает: запросы идут через `clickhouse-client` внутри
контейнера с паролем из окружения.

## Реагирование: IPS / IDS

Три режима движка (`ARGUS_RESPOND_MODE`, переключается администратором в «Настройки → Реагирование»,
каждое переключение в аудите): **ids** — только детект, кнопка «Заблокировать» в карточке работает;
**simulate** (по умолчанию) — движок пишет в `argus.response_log`, кого заблокировал бы, исполнителей
не вызывает; **ips** — правила с блоком `respond` блокируют адреса через active-response Wazuh и/или
HTTP-шаблон NGFW на `ttl` (снятие: у NGFW шаблон `unblock`, у Wazuh — таймаут команды на менеджере).
В правиле:

```yaml
respond: { action: block_ip, target: src.ip, min_level: high, ttl: 2h }
```

Ограничители, все — в `.env` движка:

- `ARGUS_RESPOND_NEVER_BLOCK_1..3` — никогда не блокировать: свои внешние адреса,
  балансировщик/прокси перед WAF (иначе в `client_ip` будет он), мониторинг, VPN админов.
  Приватные сети и loopback не блокируются всегда. Старый `ARGUS_RESPOND_ALLOWLIST_*` —
  то же самое.
- `ARGUS_RESPOND_TRUSTED_1..3` — доверенные отправители syslog (CIDR). В режиме `ips`
  автоблокировка выполняется только для событий с доверенным транспортом (файл, HTTP с
  токеном, TLS, pull-источники) или от отправителей из этих сетей: адрес из подделанного
  UDP-syslog с чужого хоста блокировку не вызовет. Правило `waf-rce-critical` требует два
  события подряд.
- `ARGUS_RESPOND_MANUAL_TTL` (24h) — срок ручной блокировки из карточки; `0` — бессрочно.
  Снять раньше — кнопка «Разблокировать» (`POST /respond/unblock` движка, в аудите).
- `ARGUS_RESPOND_TTL` (1h) — срок автоблокировки; при отказе всех исполнителей
  автоблокировка повторяется трижды с паузами 1/5/15 минут.
- `WAZUH_AR_AGENTS` — на каких агентах выполнять active-response (пусто — исполнитель
  Wazuh выключен, `all` — все с предупреждением); `WAZUH_AR_TIMEOUT` равен `<timeout>`
  команды в `ossec.conf`, `WAZUH_AR_UNBLOCK_COMMAND` — команда снятия.
- `ARGUS_MAX_NEW_INCIDENTS` (200) — потолок новых инцидентов за цикл (шторм правил),
  `NOTIFY_*_PER_MINUTE` (20) — rate-limit уведомлений, сверх — одно агрегированное сообщение.

### Склейка сканов по подсети

Сканеры интернета приходят с соседних адресов, а скан портов, обход хостов и долбёжка одного
адреса срабатывают парой. Чтобы лента не забивалась инцидентом на каждый адрес, правило может
склеивать сработки в один инцидент на подсеть источника:

```yaml
threshold: { kind: distinct, field: dst.port, distinct: 50, window: 10m, group_by: src.ip }
collapse: { by: src.net, group: inbound-scan, block_cap: 32, block_cap_window: 1h }
```

- Порог по-прежнему считается на адрес (`group_by: src.ip` обязателен). Инцидент заводится на
  подсеть: `/24` у IPv4, `/48` у IPv6, v4 и v6 не смешиваются. Субъект инцидента — подсеть,
  адреса с первым и последним появлением, числом событий и сработавшими правилами — в карточке
  («Адреса подсети»), со статусом блокировки по каждому.
- `group` — общий ключ нескольких правил: у `net-inbound-portscan`, `-sweep` и
  `-service-hammer` он один, и адрес, который и сканировал, и долбил SSH, даёт один инцидент.
  Инцидент представляет старшее правило группы. `by`, `auto_close` и `block_cap` у правил
  группы должны совпадать, иначе правила не загрузятся.
- Блокировка — по адресу: каждый новый адрес подсети блокируется по своему правилу (адрес,
  по которому сработала только долбёжка без `respond`, не блокируется оттого, что сосед
  сканировал). `block_cap` — не больше стольких новых блоков инцидента за `block_cap_window`
  (по умолчанию 32 за час); сверх — без блока, в журнале «потолок блокировок, решение за
  аналитиком». Место в потолке занимает и блок, который пока не удался (повтор исполнителя
  идёт в счёт того же места); возвращается оно только без блока — allowlist/never_block,
  IDS, адрес уже заблокирован. `ARGUS_RESPOND_NEVER_BLOCK_*` и доверие к транспорту
  действуют как раньше. После рестарта движка решения по адресам и потраченный потолок
  восстанавливаются из `response_log` (один адрес — одно место, сколько бы исполнителей его
  ни блокировали): адрес, который был в инциденте, но не блокировался, после рестарта
  по-прежнему может быть заблокирован, а адрес после сбоя исполнителей — заблокирован при
  новой сработке. Адрес с правилом `respond`, по которому в журнале нет ни одной записи
  (INSERT журнала мог не дойти после блоков на NGFW), считается заблокированным и занимает
  место; если журнал недоступен — все адреса решены и потолок окна исчерпан.
- Открытые инциденты адресов, заведённые до склейки, дописываются как раньше; склеиваются
  только новые сработки. Адреса хранятся в `incidents.members` (миграция 0035, не больше 256
  самых свежих; вытесненные считаются в `members_dropped` по одному разу) и восстанавливаются
  после рестарта движка вместе с `group_key`; история адреса (первое появление, правила)
  только дополняется. В памяти у склеенного инцидента не больше 2000 событий.

Начинайте с `simulate`: неделю смотрите журнал реагирования в «Настройках» и витрине «WAF», затем
включайте `ips`. Режим, выставленный в консоли, хранится в `console_settings`, переживает рестарт
движка и перекрывает `ARGUS_RESPOND_MODE` до кнопки «Вернуть режим из конфига».
Метрики: `argus_engine_respond_mode`, `argus_engine_auto_blocks_total`,
`argus_engine_simulated_blocks_total`, `argus_engine_active_blocks`.

## WAF: ModSecurity и Coraza

Коллектор читает **audit-лог в JSON** (`SecAuditLogFormat JSON`; ModSecurity v3 под nginx/Apache и
Coraza под Caddy/nginx) и **error-лог** (`ModSecurity: …` в nginx/Apache, `Coraza: …` в JSON-логе Caddy):
файлы с хоста монтируются каталогом `WAF_LOG_DIR` → `/logs/waf`, пути задаются `WAF_AUDIT_LOG` и
`WAF_ERROR_LOG`; для агентов без файлового доступа — `POST /ingest/modsecurity` (JSON, NDJSON или
массив). В единой схеме: `source_class=waf`, `action=http.attack`, `outcome=deny|allow` (заблокировано
или только замечено: DetectionOnly, либо score не набран), атрибуты `category` (sqli, xss, rce, lfi…),
`rule_ids`, `anomaly_score`, `status`, `engine_mode`, `host` (заголовок Host из audit-лога), `http_host`
(`[hostname]` error-лога ModSecurity в любом виде, у Coraza — если там имя), `server_addr`, `method`,
`user_agent`. `host` и `http_host` присылает клиент: это справка, не узел, не адрес сервера и не
основание для автоблокировки.
Правила `rules/waf-*.yml`: серия атак с адреса, сканер по нескольким хостам, критичный RCE/LFI
с высоким score — эти три с `respond`; «атака дошла до приложения» (детект + 5xx) — без автоответа,
её разбирает человек. Из error-лога событием считается итоговая строка транзакции (Access denied
или оценка anomaly score 949110/980130), промежуточные Warning по отдельным правилам не считаются.
Витрина — дашборд «WAF · ModSecurity / Coraza». Coraza для Caddy: модуль `coraza-caddy`,
директива `SecAuditLogFormat JSON` и `SecAuditLog /var/log/caddy/coraza_audit.log`.

Узел события WAF коллектор выбирает одинаково для error-лога, файла audit и
`POST /ingest/modsecurity`: имя хоста из заголовка syslog (агент на хосте WAF) → `node:` источника
(`WAF_NODE`) → `server_id` audit-лога → адрес сервера (`host_ip` audit-лога или, только у Coraza,
IP из `[hostname]`) → адрес отправителя. Происхождение `[hostname "…"]` у двух WAF разное:

- у ModSecurity под Apache/nginx это заголовок Host запроса, его подставляет клиент. Он
  недоверенный в любом виде, даже как IP, IPv6 или IP с портом: только `attrs.http_host`, ни
  узлом, ни `dst_ip`/`attrs.server_addr` не становится — иначе атакующий тремя разными Host
  «создал бы» три сервера для правила «сканер по нескольким хостам»;
- Coraza пишет туда сама локальный адрес сокета (внутри Docker — адрес контейнера): IP уходит
  в `dst_ip` и `attrs.server_addr`, узлом напрямую не бывает.

Разные серверы без `server_id` дают разные узлы по доверенному адресу (`host_ip` audit-лога,
адрес отправителя) — на этом держится правило «сканер по нескольким хостам».

Имени контейнера в логе нет: для файла — `attrs: {container: …}` (`WAF_CONTAINER`), для агента на
хосте — SD-элемент RFC 5424 `[argus container="caddy"]` в заголовке строки. Из SD-элемента `argus`
принимаются только `container`, `pod`, `namespace`, `service` (не длиннее 253 байт, с очисткой
управляющих символов); происхождение — `peer`, `peer_cn`, `transport`, `scope`, `server_addr` —
ставит только коллектор, `peer_cn` — только из проверенного клиентского сертификата.

## Вебхуки и подключение агента разбора

ARGUS не знает, какой агент или трекер стоит снаружи. Любой раннер — Claude Code,
Codex, n8n, cron-скрипт — подключается через три нейтральных контракта:

1. **Выход: подписанный вебхук.** Движок отправляет `incident.created` (новый инцидент)
   и `incident.escalated` (аналитик перевёл инцидент в «Эскалирован») во все цели
   `notify.webhooks` из `engine/argus.analyst.yml`. Для `incident.created` уровень должен быть
   не ниже `min_level` цели (по умолчанию `high`). **Ручная эскалация уходит независимо от
   `min_level`**. В конфиге хранятся только **имена** переменных окружения (`url_env`,
   `secret_env`, `token_env`); цель с пустым адресом выключена.
   Запрос: JSON POST, заголовки `X-Argus-Event`, `X-Argus-Delivery` (стабильный id для дедупа),
   `X-Argus-Signature: sha256=<hex HMAC-SHA256 тела>` (секрет ≥32 символов), необязательный
   `Authorization: Bearer`. Тело — `{event, delivery_id, sent_at, incident: {id, level, status,
   rule_id, rule_title, tags, actor, node, sources, event_count, first_ts, last_ts, created_at,
   pii, url, chain?}}`. Субъект, узел и источники пишет атакующий (логин, hostname, User-Agent):
   они уходят как есть в структурированном JSON, приёмник сам отвечает за экранирование.
   Адрес — только `https`; `http` — с `allow_http: true`. Редиректы не выполняются. Ответы 5xx,
   408, 429 и сетевые ошибки повторяются (8 попыток, пауза от 2 с с удвоением и джиттером,
   максимум 5 мин), прочие 4xx — окончательный отказ. Очередь — 1000 событий, сверх неё событие
   отбрасывается с метрикой `dropped`. Дедуп по ключу `инцидент|событие` в
   `argus.webhook_deliveries` (180 дней) переживает перезапуск; семантика — «хотя бы один раз».
2. **Чтение: сессия с областью одного инцидента.** Приёмник вебхука открывает сессию
   `POST /api/triage/sessions {"incident_id": "INC-12", "ttl_sec": 3600}` с bearer
   `ARGUS_TRIAGE_ISSUER_TOKEN` и получает короткоживущий токен, которым агент читает ровно этот
   инцидент и связанные с ним события — через REST (`/api/triage/context`, `/api/search`,
   `/api/v1/log`, `/api/sources`) или через `argus-mcp` в профиле `triage`. Что именно зашито в
   область и как сервер её держит — в разделе «Сессия разбора» ниже.
3. **Запись: вердикт обратно в ARGUS.** Агент сдаёт итог одним вызовом
   `POST /api/triage/verdicts` с тем же токеном сессии: тело — JSON по схеме
   `argus-triage/v3` (`web/src/lib/shared/triage-verdict.schema.json`: вердикт
   `true_positive | benign_true_positive | false_positive | undetermined`, `confidence`,
   `human_needed`, `summary`, `evidence` со ссылками на выданные в сессии события и инциденты,
   `gaps`, `recommendation`, признаки инъекции). Сервер проверяет схему, совпадение инцидента с
   токеном, что все ссылки входят в область сессии, что свободный текст — простой текст (URL,
   HTML, упоминания, обратные кавычки и управляющие символы отклоняются), совпадение `level` и
   `rule_id` с инцидентом, и принимает один вердикт на сессию (`409 verdict_exists`). Отказ —
   `422 {"error":"invalid_verdict","rejections":[{path, code}]}` с кодами `schema`, `incident`,
   `unknown_ref`, `unsafe_text`; тело не больше 64 КБ. Необязательное поле `agent` (имя раннера,
   `[a-z0-9._-]`) попадает в автора комментария. Принятый вердикт ложится в `argus.agent_verdicts`
   (миграция 0024), рендерится в Markdown по фиксированному шаблону и появляется комментарием
   `agent:<имя>` в карточке инцидента; ответ — `201 {id, incident_id, markdown}`.
   Вердикт агента не меняет статус инцидента и не даёт полномочий на блокировку: решение —
   за аналитиком, кнопка «Разрешить повторный разбор» выдаёт новую сессию.

Минимальный приёмник на `curl`:

```sh
# 1. вебхук пришёл: проверить подпись, взять incident.id
# 2. открыть сессию
TOKEN=$(curl -sS -H "Authorization: Bearer $ARGUS_TRIAGE_ISSUER_TOKEN" \
  -d '{"incident_id":"INC-12","ttl_sec":1800}' https://argus/api/triage/sessions | jq -r .token)
# 3. прочитать карточку и журнал источника за сутки
curl -sS -H "Authorization: Bearer $TOKEN" https://argus/api/triage/context
curl -sS -H "Authorization: Bearer $TOKEN" https://argus/api/triage/schema    # JSON Schema вердикта (argus-triage/v3), ETag/304
curl -sS -H "Authorization: Bearer $TOKEN" 'https://argus/api/v1/log?log=ci&level=high&since=24h'
# 4. сдать вердикт
curl -sS -H "Authorization: Bearer $TOKEN" -d @verdict.json https://argus/api/triage/verdicts
```

Для Claude Code тот же путь — через `argus-mcp` (`-e ARGUS_MCP_TRIAGE_TOKEN=$TOKEN`): инструменты
`get_incident`, `search_events`, `get_log`, `sources_health` и `submit`-вызов делает сам
`POST /api/triage/verdicts`. Изоляция раннера (сеть, файловая система, набор инструментов
модели) — ответственность того, кто его запускает; ARGUS ограничивает только то, что агент
видит и что может записать.

### Журнал для агентов: `GET /api/v1/log`

Простой REST поверх `argus.events`, чтобы агент мог спросить «что было в CI критичного за сутки»
одним запросом без языка поиска:

```
GET /api/v1/log?log=ci&level=critical&since=24h
GET /api/v1/log?log=telemetry&node=db-01&action=disk.usage&since=7d&limit=500
GET /api/v1/log?actor=i.petrov&since=30d&format=ndjson
```

| Параметр | Значение |
|---|---|
| `log` | `source` или `source_class` события: `ci`, `k8s`, `ngfw`, `telemetry`, `argus.system`… |
| `level` | нижняя граница: `info` (0–2), `low` (3–4), `medium` (5–6), `high` (7–8), `critical` (9–10) |
| `actor`, `node`, `src_ip`, `action` | точное равенство |
| `since` / `until` | длительность (`15m`, `24h`, `7d`, не больше 30 дней) и верхняя граница RFC 3339 |
| `q` | подстрока по `object` и `raw`, без учёта регистра |
| `limit` | по умолчанию 200, не больше 1000 |
| `format` | `json` (`{"items":[…],"count":n}`) или `ndjson` |

Авторизация — `ARGUS_API_TOKEN` (весь журнал) или токен сессии разбора (только область
инцидента, иначе `403`). В ответе каждое событие несёт `value` и `unit` — числовое измерение,
если источник его передал (см. «Телеметрия хостов»).

## Поиск и MCP для агентов

Страница «Поиск» — аналог Discover: строка запроса по событиям всех источников (и по
алертам Wazuh при включённом модуле), гистограмма, фасеты по полям, раскрытие записи до исходного JSON,
выгрузка CSV/JSON. Синтаксис: `root 203.0.113.5 agent:web-01 level>=10 -group:syscheck
desc:"brute force" srcip:10.0.*`; для событий — `source:k8s.audit actor:oidc:i.petrov attr.rule_groups:sshd`.
То же через API: `GET /api/search?index=events&q=...&range=24h[&format=csv|export&limit=N]`
(`index=alerts` — только с модулем Wazuh); простые выборки без языка запросов — `GET /api/v1/log`.

Свободный текст (слово или фраза без поля) — подстрока без учёта регистра в любом поле
записи: `raw`, субъект, объект, узел, адреса, действие, атрибуты (вместе с ключами). Слова
от 4 байт ускоряет n-граммный индекс `idx_text` (миграция 0030): гранулы, где такой
подстроки заведомо нет, не читаются, поэтому редкое слово или адрес находится за доли
секунды на любом окне. Частое слово (`sshd`) и слова короче 4 байт индекс не сужает —
нужное время задают поля (`source:`, `node:`) и интервал. Страница результатов
показывается сразу; распределение с итогом и поля догружаются отдельно, у каждого свой
бюджет (15 и 10 с): не уложились — страница остаётся, вместо блока причина, пейджер
предлагает следующую страницу, только когда она подтверждена: страница читает на одну
строку больше (51-я строка — `has_more`), а `total` считает лишь доказанные строки. Ссылка
на предыдущую страницу остаётся и на пустой дальней странице. Поля (фасеты) считаются по
последним 10 000 совпадениям. В API то же: `total_exact`, `incomplete`, `notice`,
`facets_sample` в ответе `GET /api/search`.

Индекс получают новые куски таблицы; старые читаются как раньше, пока для них индекс не
построен вручную (тяжёлая мутация, запускать в спокойное время; ~6,5 байт на событие,
~800 МиБ на 120 млн событий):

```sh
docker compose exec clickhouse clickhouse-client --query "ALTER TABLE argus.events MATERIALIZE INDEX idx_text"
docker compose exec clickhouse clickhouse-client --query "ALTER TABLE argus.wazuh_alerts MATERIALIZE INDEX idx_text"
```

«Журнал» (`/events`) — лента событий всех источников с фильтрами по источнику, хосту,
серьёзности и правилу, гистограммой, раскрытием до сырого события, связью с инцидентом
и live-tail (`GET /api/events/tail`, курсор `received_at|id`, только закрытые секунды
`received_at < now() − 2`). Поле `rule` в запросе событий: `rule:5763` — правило Wazuh,
`rule:a41c-auth-030` — события источника и узла его инцидентов внутри окна инцидента.
Ограничения `rule:<правило корреляции>`: берутся 5000 последних инцидентов правила, у
шумного правила старые окна не попадут; на окне 7–30 дней проверка окон идёт по
каждому событию диапазона и может упереться в `max_execution_time` (20 с) — тогда
консоль предложит сузить интервал, добавьте `source:`/`node:` или выберите меньший диапазон.

MCP-сервер `mcp/` отдаёт агентам (Claude Code, Cursor) инструменты `search_alerts`,
`search_events`, `get_log`, `list_incidents`, `get_incident`, `sources_health` и ресурс
`argus://search-syntax`. Это мост к API консоли по bearer-токену `ARGUS_API_TOKEN`
(`.env`, только чтение, ≥32 символов). Локально:

```sh
make mcp                                   # → bin/argus-mcp
ARGUS_URL=https://localhost:8443 ARGUS_INSECURE_TLS=1 ARGUS_API_TOKEN=... bin/argus-mcp   # stdio
docker compose --profile mcp up -d mcp     # Streamable HTTP на 127.0.0.1:18095
```

По HTTP сервер требует `Authorization: Bearer <ARGUS_MCP_HTTP_TOKEN>` — отдельный токен
(≥32 символов, не равный `ARGUS_API_TOKEN`; без него в режиме `-http` сервер не стартует)
и отклоняет запросы с браузерным `Origin`, кроме перечисленных в `ARGUS_MCP_ALLOWED_ORIGINS`.
Лимит — `ARGUS_MCP_RATE_PER_MIN` (300) запросов в минуту на сессию (`Mcp-Session-Id`) или токен,
считается после проверки bearer. Инструменты с `limit` отдают до 500 строк без `raw`.

Наружу MCP публикует Caddy на `:8445` (TLS как у консоли): `MCP_BIND=0.0.0.0` открывает порт,
`MCP_ALLOWED_NETS` — сети клиентов (остальным 403). Клиенты с самого хоста приходят в
контейнер с адреса шлюза Docker; шлюз разрешает `MCP_ALLOW_HOST=1`, по умолчанию — только при
`MCP_BIND` на loopback. В rootless Docker, при userland-proxy и на Docker Desktop с адреса
шлюза приходят все клиенты: там при `MCP_BIND=0.0.0.0` включённый `MCP_ALLOW_HOST` пустил бы
всех, и остался бы только bearer.

Значения из событий (субъект, узел, IP, домен, хеш) передаются точными фильтрами
инструментов поиска (`actor`, `node`, `src_ip`, `dst_ip`, `action`, `source`, `domain`,
`hash`, `rule_id`): каждое валидируется и уходит литералом в кавычках, где ни операторы,
ни `*` не действуют. Подстановка в `query` превратила бы `svc-backup -action:secret_read`
в отрицание.

В строке поиска `*` в кавычках — литерал (`actor:"svc-\*"`), маска — без кавычек
(`srcip:10.0.*`) или, если в маске есть пробелы, `~"…"` (`desc:~"*brute force*"`). Старая
форма маски в кавычках (`desc:"*foo*"`) отклоняется с подсказкой, а не даёт пустую выдачу.

Ответы консоли проходят редакцию (`triage/redact`, общий код с движком). Профиль `full` (по умолчанию) вырезает секреты и канарейки. Профиль `triage` —
для агента разбора с облачной моделью: запросы с `ARGUS_MCP_TRIAGE_TOKEN` (или все при
`ARGUS_MCP_PROFILE=triage`) получают только разрешённые поля, субъекты, владельцы, авторы,
локальные части e-mail, телефоны и имена в домашних каталогах — псевдонимами `subj-…`
(ключ `ARGUS_PSEUDONYM_KEY` сервера argus-mcp; один ключ — одинаковые псевдонимы между сессиями;
псевдоним принимается фильтром `actor`), ссылки обезврежены (`hxxps://`), у строк с `pii=1`
свободный текст скрыт; свободный `query` и `include_raw` сервер отклоняет. Чтобы поиск
не стал оракулом по нередактированным данным, в triage `actor` принимает только псевдоним
`subj-…` из ответов MCP, `node` — только имя, которое MCP уже выдал открытым, или псевдоним
`host-…` (узел `ws-ivanov` или `srv-<фамилия из логина>` в ответе — псевдоним), `domain` ищется
равенством `attr.domain` (полное имя с буквенным TLD), а не подстрокой по записи, `hash`
отклоняется (поля хеша в схеме нет), `list_incidents.q` — только `INC-N`; в текстах ошибок
консоли процитированное скрыто. Псевдонимы разрешает только тот процесс argus-mcp, который
их выдал: псевдоним из внешней задачи агент сначала получает заново через `get_incident`. Редакция по
шаблонам — не гарантия: имена людей в тексте ловит только словарь `ARGUS_REDACT_NAMES_FILE`,
флаг `pii` — дополнительный сигнал. Запись словаря заменяется целиком и каждым своим словом
длиннее трёх букв («Сидорова Анна» ловит «Анна Сидорова» и «Сидорова»), но словоформы
(«Сидоровой», «Анне») — только отдельными записями. Что шаблоны сознательно не ловят —
в `triage/redact/doc.go`.

Claude Code: `claude mcp add argus -e ARGUS_URL=https://localhost:8443 -e ARGUS_INSECURE_TLS=1 -e ARGUS_API_TOKEN=... -- ./bin/argus-mcp`
(для агента с облачной моделью — `-e ARGUS_MCP_PROFILE=triage` и `-e ARGUS_PSEUDONYM_KEY=...`).

### Сессия разбора (`triage-session`)

Агент разбора читает ARGUS по короткоживущему токену, а сервер сам ограничивает, что ему видно.
Изоляция живёт на сервере, а не в промпте.

- **Выпуск.** `POST /api/triage/sessions {"incident_id": "INC-12", "ttl_sec": 3600}` с bearer
  `ARGUS_TRIAGE_ISSUER_TOKEN` (учётка `triage-issuer`, ≥32 символов, не равна `ARGUS_API_TOKEN`;
  читать ей ничего нельзя). Срок — не больше 60 минут. Ответ: `token`, `session_id`,
  `incident_id`, `expires_at`, `related_ids`. Выпуск пишется в журнал (`triage.session`).
- **Область**, зашитая в токен: свой инцидент; связанные — общий субъект (`same_subject`), узел
  (`same_node`), IP (`same_remote_ip`, в цепочке — по границам адреса, не подстрокой) или
  домен/хеш (`same_ioc`) в окне ±7 дней, не больше 20; сущности инцидента с видом — субъект
  (поле `actor`), узел (`node`), IP (`src`/`dst`) и атрибуты `domain`, `hash`, `md5`, `sha1`,
  `sha256`, `token_id`, `secret_id` (`attr.<имя>`) его событий в окне ±1 ч.
- **Привязка строк — граница изоляции.** В каждый запрос поиска сессии сервер добавляет
  обязательный предикат: события — только своего субъекта или своего узла
  (`actor_name IN (…) OR node IN (…)`). Привязка зашита в токен при выпуске; нечем привязать —
  предикат `0`, поиск пуст. Якоря ниже только сужают запрос внутри этой привязки.
- **Частые значения — не якоря.** Распространённость считается один раз при выпуске за всё окно
  поиска (от `first_ts − 30 дней` до момента выпуска). Значение, которое встречается больше чем у
  `ARGUS_TRIAGE_ANCHOR_MAX_SPREAD` (по умолчанию **5**) разных субъектов или узлов, в область не
  попадает: DNS-сервер, шлюз, прокси, общий реестр образов видят все машины. Субъект и узел самого
  инцидента проверяются так же: частые (`root`, общий сервер) — якорь только в паре с сущностью
  другого вида. Подсчёт ограничен 10 с: не уложился — сессия выдаётся, но значения не становятся
  якорями (отказ безопасный, не 503). Значения сравниваются точно, с учётом регистра.
- **Что доступно.** `GET /api/triage/context` — карточка, история, комментарии, вердикт движка,
  связанные и `rule_history` (90 дней, только счётчики). `GET /api/incidents/INC-N` — свой
  полностью, связанный сводкой, остальные — `403 {"error":"out_of_scope"}`. `GET /api/search` и
  `GET /api/v1/log` — только равенство по полям (без свободного текста, отрицаний и масок),
  **каждое** поле-сущность — значение своего вида из области (иначе `403`), окно не раньше
  `first_ts − 30 дней`, до 200 строк, без `raw` и без фасетов. `GET /api/sources`.
  `POST /api/triage/verdicts` — один вердикт на сессию. `DELETE /api/triage/sessions` — закрыть
  сессию. Список инцидентов, markdown, выгрузка — `403`. Новый маршрут API для такого токена
  закрыт, пока явно не разрешён в `apiGuard`.
- **Лимит** — `ARGUS_TRIAGE_SESSION_REQUESTS` (100) запросов за сессию, затем
  `429 {"error":"budget_exhausted"}`, плюс 60 в минуту у каждой сессии отдельно.
- **Отзыв** (`DELETE /api/triage/sessions`) пишется в `argus.triage_session_revocations`
  (миграция 0019, TTL) и переживает рестарт консоли. Список отзывов читается один раз на процесс:
  это верно, пока `web` — одна реплика. **Ограничение:** счётчик бюджета — в памяти процесса,
  после рестарта `web` он начинается заново; при нескольких репликах бюджет считается в каждой.

## Телеметрия хостов и единые правила

Правило ИБ и правило эксплуатации пишутся одинаково: событие с полями, `selection`,
`threshold` с окном и `group_by`. Разница только в источнике. Чтобы числовые измерения
(заполнение диска, load, очередь) жили в том же журнале, у события есть `value` (Float64) и
`unit`. Любой экспортер шлёт их NDJSON в `POST /ingest/events`:

```json
{"ts":"2026-10-24 18:00:00.000","source":"telemetry.node","source_class":"telemetry",
 "action":"disk.usage","node":"db-01","object":"/var/lib/clickhouse","value":91.4,"unit":"percent"}
```

`scripts/telemetry-sample.sh` — образец на `df`/`uptime` для cron раз в минуту
(`ARGUS_INGEST_URL`, `ARGUS_INGEST_TOKEN`, `ARGUS_TELEMETRY_SOURCE`). Рядом лежат два правила,
которые читаются одинаково:

```yaml
# rules/wazuh/ssh-bruteforce.yml            # rules/ops/disk-usage-high.yml
detection:                                   detection:
  selection:                                   selection:
    source: wazuh.agents                         source.class: telemetry
    event.action: rule.5763                      action: disk.usage
  threshold:                                     value: '>= 90'
    count: 20                                  reset:
    window: 30m                                  action: disk.usage
    group_by: node                               value: '< 90'
                                               threshold:
                                                 kind: consecutive
                                                 count: 3
                                                 window: 15m
                                                 group_by: node
                                               close_on:
                                                 action: disk.usage
                                                 value: '< 85'
```

Собственный сторож диска ClickHouse устроен так же: движок раз в минуту пишет событие
`source: argus.system, action: disk.usage, value: <занято, %>` и инцидент
`argus-disk-low` создаёт обычное правило `rules/ops/argus-disk-low.yml`, которое можно
править или отключить. `rules/ops/host-silence.yml` — узел перестал присылать телеметрию
(`threshold.kind: absence`). `threshold.kind: consecutive` — N нарушений подряд, а не любые N
за окно: серию обрывает событие `detection.reset` (тот же синтаксис, что `selection`), для
диска это замер ниже порога, поэтому 91 → 89 → 92 → 89 → 93 инцидента не даёт, а 91 → 92 → 93 —
даёт. `close_on` (`value: '< 85'`, гистерезис) закрывает инцидент только замером позже последнего
нарушения: старый нормальный замер перед серией инцидент не закрывает. Агрегаций по значению
(среднее, максимум за окно) в движке нет.

## Паспорт сотрудника

Паспорт — представление над журналом, а не отдельная база: срез по человеку за период — входы,
хосты и сеансы, сеть, приложения, изменения, инциденты. Ключ — идентичность с учётом времени
действия: «кто сидел на 10.77.0.42 пятнадцатого числа» восстанавливается из истории алиасов, а не
из текущего снимка.

**Откуда ARGUS знает, кто есть кто.** Три источника, все пишут в `argus.identities` и
`argus.identity_aliases` (миграция 0026; алиас действует при `valid_from ≤ ts < valid_to`):

1. **События `identity.alias`** от любого экспортера — IdP, VPN-контроллер, каталог — обычным
   NDJSON в `POST /ingest/events`; движок материализует их в таблицу и оставляет в журнале как
   факт «кто когда получил адрес». Снимок раз в пять минут — просто повтор того же события:
   без `valid_from` при уже действующем таком же алиасе новый интервал не открывается, явный
   `valid_from` — новая выдача с известным началом; `identity.alias.revoke` закрывает алиас. Не записанные из-за недоступного хранилища события
   движок повторяет на следующих циклах; очередь повтора живёт в памяти (до 10 000 событий, при
   рестарте теряется) — это не фатально: экспортеры повторяют снимки, дубли схлопывает
   ReplacingMergeTree.
   ```json
   {"ts":"2026-10-24 10:00:00.000","source":"vpn.example","source_class":"identity",
    "action":"identity.alias","actor_name":"i.petrov","outcome":"success",
    "attrs":{"alias_kind":"ip","alias_value":"10.77.0.42","confidence":"1"}}
   ```
2. **`identities.yml`** (`IDENTITIES_FILE`, монтируется как `cmdb.yml`) — ручная карта: персоны, их
   e-mail, логины, uid, адреса с интервалами `from`/`to`. Файл перечитывается при изменении,
   удалённые из файла алиасы помечаются удалёнными.
3. **`PUT /api/v1/identities`** — тот же документ в JSON от внешнего скрипта синхронизации;
   `DELETE /api/v1/identities/{person}/aliases?kind=&value=` закрывает алиас.

Виды алиасов: `email`, `login`, `uid`, `phone`, `ip`, `host`, `sid`, `peer`; `ip` сопоставляется с
`src_ip`, `host` — с `node`, остальные — с `actor_name`. `email`, `login` и `host` сравниваются без
учёта регистра, `uid`, `sid`, `peer`, `ip` — точно. `phone` — номер в E.164: пробелы, дефисы и скобки
убираются, обязателен ведущий `+` и 8–15 цифр («+7 (999) 123-45-67» → «+79991234567»); им
представляются субъекты OTP-шлюзов и телефонии. Алиас, который в одном окне принадлежит двум
персонам, показывается как «неоднозначно», а не приписывается первому попавшемуся; субъект без
действующего алиаса — «не привязан» и виден в списке на `/actors` с действием «Привязать» (admin).

**Политики алиасов: чему доверять и как часто можно меняться.** Блок `policies` в `identities.yml`
ограничивает алиасы, которые приходят событиями `identity.alias` (источник `event:*`); файл и API
пишет администратор, к ним политики не применяются. Ключ — вид алиаса, вид без политики не ограничен:

```yaml
policies:
  ip:    { sources: ["event:vpn.*"], max_open: 3, churn: { max: 20, window: 24h }, on_violation: flag }
  host:  { sources: ["event:mdm.*"], max_open: 1, churn: { max: 1, window: 30d }, on_violation: hold }
  email: { sources: ["event:idp.*"], churn: { max: 1, window: 90d }, on_violation: reject }
  phone: { sources: ["event:idp.*", "event:otp.*"], max_open: 2, on_violation: flag }
```

`sources` — глобы допустимых источников (пустой список запрещает события для вида),
`max_open` — не больше одновременно действующих алиасов вида у персоны, `churn: {max, window}` —
не больше новых интервалов за окно (`24h`, `30d`, `2w`). `on_violation`: `flag` — записать с
пометкой `policy:<rule>` (по умолчанию); `hold` — записать с `confidence: 0.3`: консоль показывает
алиас «на удержании», но не использует его для склейки событий и резолва, пока admin не подтвердит;
`reject` — не записывать. Повтор уже известного интервала нарушением не считается: экспортеры
повторяют снимки. Так выражается «доверять смене IP, но не устройства»: разные источники и пороги
на разные виды, без отдельного механизма.

Каждое нарушение — обычное событие в журнале: `source: argus.identity`,
`action: identity.policy.violation`, `actor_name` — персона, `object` — `вид:значение`,
`attrs.rule` — `sources | max_open | churn`, `attrs.action_taken`, `value` — наблюдённое число.
По нему работают те же правила, что и для ИБ: `rules/ops/identity-device-churn.yml` (medium) и
`rules/ops/identity-untrusted-source.yml` (high); счётчик — `argus_engine_identity_policy_total{rule,action}`.
Проверить: `REPLAY_REBASE=0 ./scripts/argus rules test --replay fixtures/events/identity-policy.ndjson`.

**Консоль.** «Субъекты» (`/actors`) — персоны с активностью за период и не привязанные субъекты;
`/actors/<person>` — паспорт с переключателем периода (24h / 7d / 30d, не больше 30 дней за
запрос) и экспортом в Markdown (`GET /api/v1/actors/<person>/report`). Ссылка на субъект в карточке
инцидента, поиске и источниках ведёт в паспорт через `/actors/by-alias?v=…`. «Кому принадлежит»
(`/actors/lookup?v=…`, форма на странице «Субъекты») — по почте, логину, телефону, IP, хосту или id
персоны: кому значение принадлежит сейчас, все прошлые интервалы владения (включая закрытые и
удержанные), где оно встречалось в журнале за период; для IP — ещё и какие клиенты VPN подключались
с этого внешнего адреса (`attrs.connection_ip`). Каждый поиск — `actor.lookup` в журнале действий. Доступ — роли `analyst`
и `admin`; каждый показ и экспорт пишется в журнал действий (`actor.view`, `actor.export`), и без
записи в журнал данные не отдаются.

**Для агентов.** `GET /api/v1/actors?alias=<значение>&at=<время>` — резолв алиаса в персону
(`resolved | unbound | ambiguous`), `GET /api/v1/actors/<person>?range=7d` — паспорт в JSON, в
`argus-mcp` — инструмент `get_actor`. Токен сессии разбора получает паспорт только субъекта своего
инцидента и только в окне области, с той же редакцией, что у `search_events`; экспорт Markdown
(`/report`) такому токену закрыт. Алиас, который в окне делят две персоны, попадает в поле
`ambiguous`, а не приписывается одной из них.

Чего паспорт не покрывает: что приложение прочитало внутри себя (какая запись открыта) — это уровень
логов самого приложения; SSO и сеть этого не видят. Выборки паспорта отсекают гранулы bloom-индексом
`idx_actor_keys` (миграция 0032) по массиву всех ключей поиска — `actor_name`, `lowerUTF8(actor_name)`,
`src_ip`, `lowerUTF8(node)`: предфильтр `hasAny(…)` работает для любой смеси видов алиасов, в том
числе login ИЛИ адрес, где отдельные индексы `idx_actor`/`idx_src_ip` бессильны. Индекс получают новые
куски таблицы; по старым его строят один раз вручную — фоновая мутация по всей `events`, запускать в
спокойное время (повтор миграции её не ставит). Сначала проверьте, не поставила ли её прежняя 0032 (до
PR #28 миграция материализовала индекс сама): строка с `is_done = 1` — индекс уже построен, шаг не
нужен; `is_done = 0` — мутация ещё идёт, ждать; пусто — запустить. Засчитывается только команда
целиком: `… IN PARTITION …` строит индекс по одной партиции, а похожее имя (`idx_actor_keys_v2`) —
другой индекс. ClickHouse хранит лишь последние завершённые мутации, поэтому пусто бывает и после
очень старой материализации — повтор тогда только лишняя работа, не ошибка:

```sh
docker compose exec clickhouse clickhouse-client --query "SELECT command, create_time, parts_to_do, is_done, latest_fail_reason FROM system.mutations WHERE database = 'argus' AND table = 'events' AND trimBoth(command) = 'MATERIALIZE INDEX idx_actor_keys' ORDER BY create_time"
docker compose exec clickhouse clickhouse-client --query "ALTER TABLE argus.events MATERIALIZE INDEX idx_actor_keys"
```

Ход — тем же первым запросом (`parts_to_do`, `is_done`).

## Модуль Wazuh

Wazuh — популярный open-source HIDS, поэтому его поддержка остаётся, но как модуль, а не
центр системы. Включение: `./scripts/argus init --with-wazuh` или в `.env`
`ARGUS_INTEGRATION_WAZUH=1` и `COMPOSE_PROFILES=wazuh`. Модуль добавляет:

- `shipper/` (Rust) — тейлит `/var/ossec/logs/alerts/alerts.json`, пишет в `argus.wazuh_alerts`,
  откуда MV копирует алерты в `argus.events` как `source: wazuh.agents`, `action: rule.<id>`;
- `policyd/` (Go + OPA) — агенты и SCA из REST API менеджера → `argus.policy_verdicts`;
- в консоли — «Алерты Wazuh», «Уязвимости» (CVE), «MITRE ATT&CK», «Политики», «Агенты»,
  «Управление» (группы, `agent.conf`, кастомные правила менеджера через `WAZUH_API_*`),
  индекс `alerts` в поиске, дашборды `wazuh-*`; пути — `/wazuh/*`;
- правила корреляции на алертах Wazuh — `rules/wazuh/`.

Без модуля ничего из этого не поднимается и не показывается; таблицы в ClickHouse создаются
миграциями в любом случае и остаются пустыми. `./scripts/argus init --without-wazuh` (или ответ
«нет» на вопрос) ставит `ARGUS_INTEGRATION_WAZUH=0`, убирает профиль `wazuh` и комментирует
`WAZUH_API_URL` и заглушку `WAZUH_API_PASSWORD`: без модуля движку не нужны ни адрес менеджера,
ни пароль — исполнитель active-response не настраивается, переменные `WAZUH_*` не проверяются.
С `--with-wazuh` движок отказывается стартовать с паролем-заглушкой `change-me` (кроме стенда
`ARGUS_DEV=1`). Включить модуль позже: `./scripts/argus init --with-wazuh --no-up`, затем вписать
`WAZUH_API_URL`, `WAZUH_API_PASSWORD`, `WAZUH_ALERTS_DIR`. Механика Wazuh не меняется: регистрация агентов,
доставка `agent.conf` и применение правил — штатные. Для разработки без менеджера:
`node scripts/mock-wazuh-api.mjs` и `WAZUH_API_URL=http://localhost:55001`.

## Прод: чек-лист перед выкаткой

1. **Диск** — данные ClickHouse на отдельном разделе (`scripts/init-storage.sh`, раздел выше).
   Движок раз в минуту пишет событие `argus.system / disk.usage` с процентом занятого места,
   а правило `rules/ops/argus-disk-low.yml` заводит инцидент при 90 % и закрывает его, когда
   место вернётся; порог меняется в правиле.
2. **Секреты** — `./scripts/argus init`: семь паролей ClickHouse, `ENGINE_TOKEN`,
   `ARGUS_INGEST_TOKEN`, `ARGUS_API_TOKEN`, `ARGUS_MCP_HTTP_TOKEN`, `ARGUS_TRIAGE_ISSUER_TOKEN`,
   `ARGUS_PSEUDONYM_KEY`, `POLICYD_TOKEN`, `BACKUP_KEY`; `WAZUH_API_PASSWORD` — руками. `.env` с правами `600`, в git не попадает.
   `ARGUS_DEV` в бою не задаётся. Пароль `admin` — из `/data/admin-password.txt`, сменить
   в «Настройках», включить TOTP или SSO.
3. **Память** — `CLICKHOUSE_MEM_LIMIT` под машину (4g по умолчанию; ClickHouse берёт
   80 % от лимита), остальным сервисам лимиты заданы в compose.
4. **Сертификаты** — свой вместо внутреннего CA: файлы в `./caddy/certs`,
   `CONSOLE_TLS="/certs/console.crt /certs/console.key"`; syslog TLS — `SYSLOG_TLS_ADDR=:6514`
   и сертификат в `./collector/certs`; менеджер Wazuh — `WAZUH_CA_FILE` или
   `WAZUH_CERT_SHA256` вместо `WAZUH_INSECURE_TLS`.
5. **Сеть** — syslog/NetFlow по UDP не аутентифицируются: закрывайте файрволом по адресам
   источников, `NETFLOW_EXPORTERS` — allow-list экспортеров, `INGEST_BIND` — интерфейс
   для TLS-портов. Вебхуки — только через `:8089` (TLS + `X-Argus-Token`).
6. **Бэкап** — `./scripts/backup.sh` по cron (`0 3 * * * cd /opt/argus && ./scripts/backup.sh`),
   `BACKUP_DIR` на другом диске, ключ (`BACKUP_KEY` / `BACKUP_AGE_RECIPIENT`) — отдельно
   от бэкапов; раз в квартал — тестовое `restore.sh` на стенде.
7. **Реагирование** — `ARGUS_RESPOND_NEVER_BLOCK_*` (свои адреса, балансировщик),
   `ARGUS_RESPOND_TRUSTED_*` (адреса коллекторов), неделя в `simulate` перед `ips`.
8. **Мониторинг** — `/metrics` коллектора (8088) и движка (8090, Bearer `METRICS_TOKEN`), готовые алерты
   `ops/prometheus-alerts.yml`, scrape — `ops/prometheus-scrape.yml`; `docker compose ps`
   показывает healthcheck'и всех сервисов, включая шиппер (`/healthz` на `shipper:9101` —
   503, если файл алертов недоступен или ClickHouse не принимает батч дольше 5 минут;
   `/metrics` там же доступен только из internal-сети `data`). Разбор типовых отказов —
   ниже, «Раннбук дежурного».
9. **Образы** — `make deploy` проверяет подписи cosign (`COSIGN_PUBKEY` в `.env`);
   базовые образы пришпилены по digest, релиз не выходит с HIGH/CRITICAL в trivy.
10. **Windows-хосты** — через агент Wazuh (модуль Wazuh, мастер «Добавить агента» на
    странице «Управление») либо NXLog/Winlogbeat → syslog CEF в коллектор (6514/tcp с TLS).
11. **Агенты разбора** — `ARGUS_TRIAGE_ISSUER_TOKEN` отдельно от `ARGUS_API_TOKEN`; приёмник
    вебхука проверяет `X-Argus-Signature`; изоляция самого раннера (сеть, файлы, инструменты
    модели) — на стороне раннера, ARGUS ограничивает только область чтения и формат вердикта.

## Раннбук дежурного

| Симптом | Что проверить | Что сделать |
|---|---|---|
| Событий нет, источники «молчат» на `/sources` | `docker compose logs collector`, `curl -s localhost:8088/metrics \| grep spool` | переполнен spool → место на диске `collector-state`; источник не доходит → файрвол, `INGEST_BIND`, токен `X-Argus-Token` |
| Инциденты не появляются при живом потоке | `docker compose logs engine`, `GET :8090/rules` (ошибки загрузки правил) | `./scripts/argus rules test`; `POST :8090/reload` с `ENGINE_TOKEN` после правки правил |
| Инцидент `a41c-ops-062` (диск ClickHouse) | `df -h` на томе `clickhouse-data`, `SELECT * FROM system.disks` | расширить раздел или снизить TTL в миграции; ClickHouse при нехватке места отклоняет вставки, не затирает старое |
| Консоль отвечает 503 «хранилище недоступно» | `docker compose ps clickhouse`, `docker compose logs migrator` | `migrator` отказывает на слабых паролях; после восстановления ClickHouse консоль поднимается сама |
| Паспорт не открывается, «журнал действий недоступен» | таблица `argus.console_audit` и права `argus_console` | без записи в журнал ПДн не отдаются намеренно; восстановить ClickHouse, затем повторить |
| Агент получает `403 out_of_scope` | `GET /api/triage/context` с токеном сессии — поля `session.anchors` и `bind` | это граница изоляции, не ошибка: запрос вышел за субъект/узел инцидента или окно `first_ts − 30 д` |
| Агент получает `429 budget_exhausted` | `ARGUS_TRIAGE_SESSION_REQUESTS` (100) | выпустить новую сессию по тому же инциденту; бюджет сбрасывается при рестарте `web` |
| Не доставляются вебхуки | `argus_engine_webhook_*` в `/metrics`, лог `webhook:` движка | 4xx — окончательный отказ (проверить подпись у приёмника), 5xx/сеть — ретраи до 5 мин; очередь 1000 |
| Пароль `admin` утерян | — | `docker compose stop web && docker compose run --rm --no-deps --entrypoint node web /app/reset-admin-password.cjs` |
| Восстановление из бэкапа | список архивов в `BACKUP_DIR` | `./scripts/restore.sh <имя-архива>`; прогон на стенде раз в квартал; при `down -v` сначала `backup.sh` |

## Обновление

Два пути. **Из исходников** (одна инсталляция, есть docker на хосте):

```sh
git pull                 # или распаковать новый релиз
./scripts/argus init     # допишет новые секреты в .env, если появились; затем make up
```

**Из реестра** (релизный конвейер `.github/workflows/release.yml` собирает образы по
тегу `vX.Y.Z`; на хосте ничего не компилируется):

```sh
# .env: ARGUS_IMAGE_PREFIX=ghcr.io/k1dory/argus, COSIGN_PUBKEY=./cosign.pub (ключ лежит в корне репозитория)
git fetch --tags && git checkout v1.0.0-rc3   # compose, миграции, правила, дашборды нужной версии
make deploy                                # cosign verify + pull образов версии из VERSION + up без сборки
```

Версия стека — в `VERSION` (показывается в шапке консоли), изменения — в `CHANGELOG.md`.
Миграции идемпотентны и журналируются в `argus.schema_migrations` — свежая
установка и апгрейд идут одним путём, руками DDL не применяется; `migrator` при каждом
запуске сверяет пароли и гранты служебных пользователей. Откат: `git checkout`
предыдущего тега + `make deploy`; миграции только добавляют (таблицы, колонки, MV),
поэтому старый код работает на новой схеме.

## CI

`.github/workflows/ci.yml` на каждый push/PR: gofmt/vet/test с `-race` для Go-модулей
(collector, engine, policyd, mcp, triage), тесты правил на записанном трафике, `cargo fmt/clippy/test`
шиппера, eslint/тесты/сборка консоли, тесты политик OPA, валидация compose и скриптов
(`docker compose config`, `bash -n`, shellcheck), сборка образов, сквозной e2e (replay →
инциденты → API-смоук консоли) на push в main. Аудит зависимостей блокирующий: `govulncheck`,
`npm audit --audit-level=high`, `cargo audit`. Actions пришпилены по SHA коммита, базовые
образы Dockerfile — по digest. `make lint` и `make check` — то же локально.
Релиз — `release.yml` по тегу: проверка `VERSION`/`CHANGELOG`, сборка образов,
`trivy` (HIGH/CRITICAL с исправлением — стоп), push в `ghcr.io`, подпись `cosign` (секрет
`COSIGN_PRIVATE_KEY`), бинарники `argus-mcp` под все ОС, заметки релиза из CHANGELOG.

Ревью PR: `.github/workflows/claude-review.yml` на каждый PR в `main` (кроме черновиков и
форков) запускает Claude Code с inline-комментариями P1/P2. Нужен секрет `ANTHROPIC_API_KEY`
или `CLAUDE_CODE_OAUTH_TOKEN` и установленное Claude GitHub App. Изменения попадают в `main`
только через PR.

## Тесты

Пять слоёв, от быстрых к медленным. Цифры — число тестов на момент rc28.

| Слой | Сколько | Что проверяет | Как запустить |
|---|---|---|---|
| юнит | Go 531, консоль 354, шиппер 26, OPA 20 | Go-модули (`collector`, `engine`, `policyd`, `mcp`, `triage`): парсеры и нормализация, приёмники на реальных сокетах, правила корреляции (каждый оператор и ветка валидации), жизненный цикл инцидентов, реагирование, уведомления и шторм через httptest и мини-SMTP, pull-коллекторы Falcon/S3 на имитации API, обогащение; `main()` коллектора и policyd запускаются в процессе целиком (конфиг с `${ENV}`, приёмники, spool, `/healthz`, `/metrics`, SIGTERM), раунд policyd — на имитации Wazuh API с настоящим Rego; шиппер на Rust; Rego-политики; консоль — чистые модули `web/src/lib/shared/*`, все маршруты `web/src/app/api/*` с подменённым ClickHouse по схемам OpenAPI, OIDC-вход с проверкой `id_token` по JWKS, аутентификация и RBAC на реальном файле `auth.json`, каждая страница и компонент консоли с ролями, пустыми состояниями, 404 и недоступным хранилищем | `make test`; `cd web && npm test` |
| правила | 31 сценарий | правила корреляции на записанном трафике `fixtures/events/*.ndjson`, ожидания (число инцидентов, субъект, в том числе отрицательные) в `rules/tests/` | `./scripts/argus rules test` |
| интеграция | 3 файла | живой ClickHouse: все миграции с нуля по порядку и повторно (идемпотентность), затем каждый SQL консоли (`web/tests/queries-ch.test.ts`) и каждый запрос хранилища движка — события и курсор, инциденты и журнал состояний, ответы, исключения, отчёт о рисках, паспорт, доставки вебхуков (`engine/internal/store/live_test.go`); конкурентный claim вердикта агента (`web/tests/triage-claim-ch.test.ts`). Без `ARGUS_TEST_CLICKHOUSE_URL` пропускаются; в CI сервис `clickhouse` у job `go` и `web` | `docker run -d -p 8123:8123 -e CLICKHOUSE_DB=argus -e CLICKHOUSE_PASSWORD=x clickhouse/clickhouse-server:24.8`, затем `ARGUS_TEST_CLICKHOUSE_URL=http://localhost:8123 ARGUS_TEST_CLICKHOUSE_PASSWORD=x npm test` (консоль) и то же окружение для `go test ./internal/store/` в `engine` |
| API-смоук | 13 шагов | живой стенд: `GET /api/version`, приём NDJSON коллектором (`value`/`unit`, `identity.alias`), событие в `GET /api/v1/log`, сессия разбора по демо-инциденту, карточка, граница области, вердикт `argus-triage/v3` и его идемпотентный повтор, резолв алиаса и паспорт субъекта, запрет экспорта токену сессии, живость источников `GET /api/sources` (статус по ритму), MCP за Caddy `:8445` (при `ARGUS_MCP_URL`) | `make up-dev && make demo && ./scripts/api-smoke.sh` (параметры `ARGUS_URL`, `ARGUS_API_TOKEN`, `ARGUS_TRIAGE_ISSUER_TOKEN`, `ARGUS_INGEST_URL`, `ARGUS_INGEST_TOKEN`, `ARGUS_MCP_URL`; по умолчанию — `.env.dev`) |
| e2e | 1 сценарий | стек с нуля в compose (`argus-e2e`): replay → ≥ 7 инцидентов и вердиктов движка, `argus_ro` только читает, затем API-смоук; с плагином buildx поднимаются и `mcp` + `caddy` (шаг 13 — MCP за TLS); в CI — на push в `main` | `./scripts/e2e.sh` (`E2E_TIMEOUT`, сек) |

```sh
make test          # cargo test + go vet/test (Rego-политики гоняются через встроенный OPA)
make policy-test   # то же через бинарник opa, если установлен
make check         # compose config, bash -n, shellcheck
cd web && npm test && npm run lint && npm run typecheck   # консоль
./scripts/api-smoke.sh                                    # API консоли на живом стенде
```

Покрытие на rc28: движок — `rules` 99,7 %, `incidents` 99 %, `store` 89 %, `cmd/engine` 74 %
(без покрытия только циклы `run`/`loop`/`pollEvents` — их проверяет e2e); коллектор — `pull` 98 %,
`listen` 94 %, `sink` 91 %, `cmd/collector` 79 %; policyd — 84–98 %; `mcp` 90 %; консоль —
88 % операторов, страницы 88–100 %, компоненты 87 %. Слабее прочих: обработчики кликов в
клиентских компонентах (`event-feed.tsx`, `download-button.tsx` — их чистая логика вынесена в
`lib/shared/tail-poll.ts` и `download.ts` и покрыта), корневой `app/layout.tsx` (`next/font`),
`main()` движка. Посмотреть: `go test -cover ./...` в модуле, `cd web && npx c8 --include 'src/**' npm test`.

Спецификация REST API консоли — OpenAPI 3.1 в `api/openapi.yaml` (валидна по официальной
схеме: swagger-parser, Redocly); консоль отдаёт её же как `/openapi.yaml`. Тест
`web/tests/openapi.test.ts` следит, что каждый маршрут описан и копия совпадает с источником;
смоук и тесты маршрутов проверяют описанное в ней поведение.

## Участие и безопасность

Исходный код ARGUS распространяется по [GNU AGPL-3.0](LICENSE). Условия участия —
в [CONTRIBUTING.md](CONTRIBUTING.md), порядок передачи сведений об уязвимостях —
в [SECURITY.md](SECURITY.md).
