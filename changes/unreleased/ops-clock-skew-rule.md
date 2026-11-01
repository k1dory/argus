- **Правило `a41c-ops-067`: часы источника ушли вперёд** (`rules/ops/collector-clock-skew.yml`, low).
  - Срабатывает на сводку коллектора `collector.clock_skew` (только `attrs.transport: internal`).
  - Склейка по `attrs.peer`, `dedupe: 24h` — один инцидент на устройство за сутки.
  - Подсказка оператору: RFC 3164 без пояса → `SYSLOG_PEER_TZ`, иначе NTP на устройстве.
  - Тест на фикстуре `fixtures/events/collector-clock-skew.ndjson`.
  - Адрес устройства — в `object` сводки `collector.clock_skew`: его видно в цепочке
    инцидента и уведомлении (`node` остаётся `argus-collector`).
- **Коллектор: `attrs.peer` у событий по HTTP — адрес соединения.** Присланные в `/ingest/*`
  `peer` и `peer_cn` не принимаются, как у syslog: держатель ingest-токена больше не может
  приписать сдвиг часов (и любое событие) чужому устройству.
