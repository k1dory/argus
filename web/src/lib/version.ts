// Версия приложения: передаётся build-арг ом APP_VERSION из файла VERSION
// в корне репозитория (см. docker-compose.yml и Makefile).
export const APP_VERSION = process.env.APP_VERSION ?? "dev";

/** Путь к спецификации API — копия api/openapi.yaml в public/ (scripts/sync-openapi.mjs). */
export const OPENAPI_PATH = "/openapi.yaml";
