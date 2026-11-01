- **Коллектор: стоп-сигнал застрявшей записи.** Батч, который возвращается в очередь без
  прогресса (полумёртвый ClickHouse: 241 на группу, таймаут на каждую строку), отмечается с
  первого такого прохода: метрики `argus_collector_spool_head_stuck_seconds` и
  `argus_collector_sink_stalled_passes_total`, а дольше `SINK_STALL_AFTER` (10m) — ERROR и
  событие `argus.collector` / `collector.sink_stalled` мимо очереди; правило
  `ops/collector-sink-stalled` (`a41c-ops-066`) заводит инцидент, `collector.sink_recovered`
  его закрывает. Вместо ротации остатка бисекции (закрытый #47): строки не выбираются хитрее,
  застревание видит оператор.
