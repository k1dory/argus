-- Время успешной передачи периодического отчёта SMTP-серверу переживает
-- перезапуск движка. Повтор после принятия письма, но до записи здесь,
-- возможен: доставка имеет семантику at least once.
CREATE TABLE IF NOT EXISTS argus.risk_report_deliveries
(
    report_id UUID,
    sent_at   DateTime64(3, 'UTC')
)
ENGINE = MergeTree
ORDER BY (sent_at, report_id);
