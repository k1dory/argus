-- Собственные дашборды (конструктор как в Grafana): спецификация панелей в
-- JSON, версии по updated_at, удаление — флагом.
CREATE TABLE IF NOT EXISTS argus.console_dashboards
(
    id          String,
    updated_at  DateTime DEFAULT now(),
    title       String,
    spec        String,                  -- JSON: {panels: [...], refresh, description}
    updated_by  String,
    provisioned UInt8 DEFAULT 0,         -- из каталога dashboards/ (перезаписывается при апдейте файла)
    deleted     UInt8 DEFAULT 0
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY id;
