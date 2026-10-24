/* eslint-disable @typescript-eslint/no-require-imports -- делегат подменяет модуль в CJS-кэше tsx */
// Делегат wazuh-api для тестов: экспорты tsx — неконфигурируемые геттеры,
// напрямую функцию не подменить, а сам модуль после загрузки из кэша не
// вытеснить. _next-mock перенаправляет резолв «./wazuh-api» сюда (кроме
// запроса из этого файла), а тест кладёт подмены в `overrides`.
type WazuhApi = typeof import("../src/lib/wazuh-api");

const real = require("../src/lib/wazuh-api") as WazuhApi;

export const overrides: Partial<WazuhApi> = {};

for (const key of Object.keys(real) as (keyof WazuhApi)[]) {
  const value = real[key];
  const delegated = typeof value === "function" && !/^[A-Z]/.test(key)
    ? (...args: unknown[]) => ((overrides[key] ?? value) as (...a: unknown[]) => unknown)(...args)
    : value;
  Object.defineProperty(module.exports, key, { value: delegated, enumerable: true });
}
