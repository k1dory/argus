- **Роль `argus`: результат миграций проверяется при выкатке.** Миграции и гранты
  применяет одноразовый сервис `migrator` на каждом `make deploy`; теперь роль проверяет его
  код выхода (с хвостом лога при ошибке), печатает последнюю применённую миграцию и ждёт
  фоновые мутации `MATERIALIZE` в `system.mutations` (до часа: `argus_mutations_retries` ×
  `argus_mutations_delay_sec`). Сбой мутации (`latest_fail_reason`) роняет прогон сразу.
  Подъём стека и проверка — блоки с общим `rescue`: при отказе (compose падает раньше
  проверки) печатается код и хвост лога `migrator`, значения после `BY`/`SALT`/`PASSWORD`
  маскируются (clickhouse-client печатает упавший `ALTER USER` с хешем и солью). У проб —
  `timeout` (`argus_probe_timeout_sec`, 60 с). Регрессии роли — job `ansible` в CI.
