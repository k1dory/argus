// Версия приложения: передаётся build-арг ом APP_VERSION из файла VERSION
// в корне репозитория (см. docker-compose.yml и Makefile).
export const APP_VERSION = process.env.APP_VERSION ?? "dev";
