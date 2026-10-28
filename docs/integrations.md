# Стыки с источниками: что ожидать от вендоров

Заметки с первого промышленного стенда (2026-10). Всё ниже — не про ARGUS, а про то, как
ведут себя продукты по ту сторону: без этого каждый стык стоил часы. Схема события и порты —
в [README](../README.md#коллекторы-и-правила).

## Vector как агент на хостах

- **`${VAR}` из окружения не подставляется** при `vector --config-dir` (0.60): в конфиг уходит
  буквальная строка `${ARGUS_INGEST_TOKEN}`, коллектор отвечает 401. Токен приёма кладите в
  сам файл конвейера (0640, владелец root, группа `vector`), а не в `EnvironmentFile`.
- Unit из deb-пакета делает `ExecStartPre=vector validate` на демо-`/etc/vector/vector.yaml`
  (там нет источников — старт падает). Override должен сбросить **оба** шага:
  `ExecStartPre=` / `ExecStartPre=/usr/bin/vector validate --config-dir …` и так же `ExecStart`.
- Дисковый буфер `http`-приёмника: `max_size` не меньше 256 МиБ + 32 байта (268 435 488).
- Sink `http`: `healthcheck.enabled: false` — `/ingest/events` принимает только POST, GET-проверка
  даёт ложный отказ.
- `apt.vector.dev` стоит за CloudFront; с части узлов тело пакета в некоторые сети не
  приходит (TLS есть, данных нет). Держите `.deb` в своём репозитории или ставьте с управляющей
  машины.
- VRL, на чём спотыкаются конфиги:
  - raw-строки только в одинарных кавычках `r'…'`; одинарная кавычка внутри — `\x27`;
  - `parse_regex` принимает только regex-литерал, не строку;
  - `if … { } else { }` нельзя внутри литерала объекта — считайте в переменную;
  - `a ?? "" == b` разбирается как `a ?? ("" == b)` (ошибка «non-boolean predicate») —
    сравнение отдельной строкой;
  - ключи с дефисом (`remote-address`) у переменной читаются через `get(kv, ["remote-address"])`;
  - массив в `.` на выходе `remap` — несколько событий из одного (так рождаются алиасы паспорта).
  Проверяйте отрендеренный конфиг `vector validate --config-dir <tmp>` до рестарта службы.

## MikroTik RouterOS

- Параметры удалённого syslog различаются по версиям: 7.16 — `bsd-syslog=yes
  syslog-time-format=iso8601`; 7.21 — `remote-log-format=syslog remote-protocol=udp
  syslog-time-format=iso8601`. Формат ISO даёт `2026-10-27T23:42:55.0019+0300` (четыре знака
  дробной части, зона без двоеточия) — коллектор это разбирает.
- **С BSD-форматом роутер не шлёт список топиков** (`system,info,account …`), только текст.
  Коллектор узнаёт RouterOS по характерным строкам (`user … logged in from … via …`,
  `… assigned … for <MAC>`, `in:… out:… proto …`), но свои правила по `attrs.topics` не стройте.
- Топик `dhcp` без `!debug,!packet` присылает дампы DHCP-пакетов построчно (`Server-Id = …`,
  `Msg-Type = ack`); `system` и `firewall` — с `!debug`.
- `firewall` пишет только правила с `log=yes`; префикс правила (`drop-input:`) коллектор
  кладёт в `attrs.prefix`, по словам drop/reject/deny ставит `outcome: deny`.
- `/ip traffic-flow` (NetFlow v9): задайте `src-address` явно; на 7.21 часть пакетов всё равно
  уходит с адреса исходящего интерфейса — пускайте на коллектор оба адреса. Один роутер за
  граничным даёт одни и те же потоки дважды (граница + шлюз LAN): это не ошибка, но считайте.

## Huawei VRP (CloudEngine)

- SSH не исполняет команду из аргумента: `ssh -tt`, команды через stdin, первой
  `screen-length 0 temporary`; ключи только RSA/ECC, изменения — `commit`.
- `info-center loghost <argus> port 5514 source-ip <mgmt>` — без `source-ip` отправка идёт с
  адреса исходящего интерфейса, который фаервол по пути может не знать.
- Формат: `<189>Oct 27 2026 21:47:12 host %%01CLI/5/LOGOUT(s):CID=…;текст (Key=Value, …)` —
  год в дате и модуль/уровень/мнемоника в теле; коллектор разбирает оба.

## NetBird

- **API-токен**: роль Auditor читает пиров, пользователей, аудит и access-логи reverse proxy
  — Admin для коллектора не нужен. Под User `/api/events/audit` и `/api/users` закрыты.
- У `/api/events/audit` нет ни пагинации, ни фильтра по времени — курсор ведёт коллектор.
- У пира нет email, только `user_id` (хэшированный `sub` IdP): сшивать с IdP по почте через
  `/api/users`, не по `user_id`.
- **Reverse proxy в режиме TLS passthrough не отдаёт бэкенду адрес клиента** — заголовков
  нет в принципе, PROXY protocol бэкенд должен уметь сам. Контейнер прокси пишет в stdout
  только ошибки TLS-рукопожатий. Настоящие адреса — `GET /api/events/proxy`
  (`source_ip`, `host`, `path`, `status_code`, `country_code`; у L4-сервисов `status_code: 0`),
  с фильтрами `start_date`/`end_date` и пагинацией — отсюда коллектор делает `proxy.access`.
- Ограничения на сервисе (`access_restrictions`: страны, CIDR) проверяются до аутентификации —
  дешёвый способ срезать сканеры у публикации, которую нельзя закрыть логином.

## Authentik

- Для Bearer нужен токен с intent `api`; `app_password` даёт 403.
- Для intent `api` сервер **игнорирует `expires`** и ставит `default_token_duration`
  (30 минут); долгоживущий токен — только `expiring: false`.
- `PATCH /core/tokens/{id}` без поля `user` молча перевешивает токен на пользователя,
  который делает запрос (у суперпользователя — на суперпользователя); вернуть назад нельзя
  («User cannot be changed»). Проверяйте `user` в ответе и права двумя запросами:
  `/events/events/` → 200, `/core/users/` → 403.
- В событиях `login_failed` «email» — это то, что ввели в форму: не делайте алиас паспорта из
  строки без `@` или с пробелами.
- OIDC для консоли: scope `profile` уже несёт `groups`; `sub_mode: user_username` даёт
  читаемые учётки `sso:<логин>` вместо хэшей.

## nftables на Linux-роутере

- `nft list ruleset` переписывает правила: `$WAN` → имя интерфейса, множества сортируются.
  Проверять применение нужно регулярным выражением, а не текстом исходного правила.
- Для журнала отказов — `log prefix "…" limit rate N/second` перед `policy drop`; строки
  приходят в journald с `SYSLOG_IDENTIFIER=kernel`, их разбирает агент (`net.firewall`/`deny`).
  Широковещательный DHCP провайдерского сегмента (`0.0.0.0 → 255.255.255.255`) — шум.

## Proxmox VE

- Вход в веб-интерфейс и API — в journald `pvedaemon`: `<root@pam> successful auth for user 'x@pam'`,
  `authentication failure; rhost=::ffff:1.2.3.4 user=x@pam msg=…` (адрес с префиксом `::ffff:`,
  его надо срезать). Задачи — `<user> starting task UPID:node:pid:pstart:start:type:id:user:` и
  `<user> end task UPID:… OK` (иначе текст ошибки); прочие действия от имени пользователя —
  `<user> update VM 100: -memory 2048`.
- Шум в `pvedaemon`/`pveproxy`: `worker N started/finished`, `starting N worker(s)`, `received
  signal HUP`/`restarting server` (ротация логов), `VM N qga command failed … got timeout` каждые
  минуты у ВМ без guest-agent.
- `/var/log/pveproxy/access.log` — Common Log Format с пользователем (`root@pam!token`), но
  почти целиком опрос интерфейса (`GET /api2/extjs/cluster/resources` раз в секунды). Берите
  `POST /api2/*/access/ticket` (вход: 200 успех, 401 отказ), `POST`/`PUT`/`DELETE` (изменения)
  и любые ответы ≥ 400; `GET` с кодом < 400 отбрасывайте на агенте.
- Каталог `/var/log/pveproxy` — `0700 www-data`: группой `www-data` файл не прочитать. Нужен
  POSIX ACL (`setfacl -m u:vector:rx /var/log/pveproxy`, `-d -m u:vector:r` для новых файлов
  после logrotate `create 640`); пакет `acl` на гипервизорах по умолчанию не стоит.

## Caddy и другие прокси в контейнерах

- Источник Vector `docker_logs` читает stdout контейнера через сокет Docker — пользователь
  `vector` должен состоять в группе `docker` (после добавления — рестарт службы).
- Access-лог Caddy — JSON с `logger: http.log.access` (у именованных логов — `http.log.access.<name>`):
  `request.client_ip` (с учётом `trusted_proxies`), `request.remote_ip`, `request.host`,
  `request.uri`, `status`, `request.headers.User-Agent` — массив, `request.tls.server_name`.
  Предупреждения `http.handlers.reverse_proxy` («aborting with incomplete response» у gRPC-стримов
  NetBird) — не события.
- Страны в логе Caddy нет: правило `proxy-foreign-access` требует известную страну
  (`attrs.country|regex: '^[A-Za-z]{2}$'`) — иначе оператор `not RU` совпал бы с пустым значением.
  Это общее свойство матчера: `not X` истинен для отсутствующего поля, добавляйте проверку
  на наличие.

## Forgejo runner и OpenBao

- `forgejo-runner` пишет logfmt в journald: `level=info msg="task N repo is org/repo …"` — старт
  задачи, `level=error msg="failed to fetch task" error="unavailable: 502 Bad Gateway"` — сервер
  Forgejo недоступен. Остальное (сети job'ов, poller) — шум.
- OpenBao без включённого audit device — только служебный журнал (`SYSLOG_IDENTIFIER=bao`):
  `… [INFO]  core: vault is unsealed`, `[WARN]`, `[ERROR]`. Кто что читал из хранилища — только
  через audit device (`bao audit enable file …`), это отдельный источник.

## Proxmox Backup Server

- Журнал аутентификации — `/var/log/proxmox-backup/api/auth.log`
  (`successful auth for user 'x@pam'`, `authentication failure; rhost=… user=…`), права на
  чтение — группа `backup`.
- journald `proxmox-backup-proxy`: `rrd journal …` каждые секунды — шум; `TASK ERROR …` —
  провал бэкапа; `Upload backup log … vm/NNN` — окончание бэкапа каждой ВМ.

## Движок ARGUS на реальных объёмах

- NetFlow с границы — сотни тысяч потоков в час. Движок читает хвост постранично, но буфер
  кандидатов живёт два максимальных окна правил: широкая селекция (`beacon` на всём исходящем)
  держит сотни тысяч событий — закладывайте `ENGINE_MEM_LIMIT` от 2–3 ГиБ.
- Правила «периодический маячок» и «DNS-туннель» без направления потока ловят внешние сканеры
  и обычные запросы к форвардеру: всегда задавайте `INTERNAL_NETS` и `attrs.scope`.
