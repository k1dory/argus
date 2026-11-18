- **ClickHouse больше не копит служебные журналы и держит NetFlow 30 дней.** Служебные
  таблицы `system.*_log` по умолчанию не имели TTL и на argus1 за три недели заняли ~32 ГБ —
  столько же, сколько сами события. Теперь `query_log`, `part_log`, `query_views_log`,
  `asynchronous_insert_log`, `metric_log`, `asynchronous_metric_log` и `text_log` живут 7 дней,
  `error_log` — 30; `text_log` пишет только warning и выше, `trace_log` и
  `processors_profile_log` отключены (`clickhouse/config.d/system-logs.xml`, нужен перезапуск
  ClickHouse). При смене TTL ClickHouse оставляет прежние данные в `system.<имя>_0` — их
  удаляют вручную: `DROP TABLE system.<имя>_0`, а отключённые таблицы — `DROP TABLE
  system.trace_log` и `system.processors_profile_log`. Миграция `0040` ставит `argus.events`
  TTL 30 дней для `source_class = 'netflow'` (~93 % строк; правила смотрят в окна до часа),
  остальным — по-прежнему 180; фоновая мутация переписывает старые части, выкатка ждёт её
  как обычный MATERIALIZE.
