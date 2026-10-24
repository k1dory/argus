// Узкий реэкспорт для API-маршрутов: chQuery здесь — с серверными лимитами
// (max_execution_time / max_memory_usage), а не сырой клиент ClickHouse.
export { chQuery, incidentComments, incidentFirstResponse, incidentGet, incidentStateHistory, verdictGet } from "./argus-queries";
