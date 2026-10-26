// Копирует единственный источник спецификации API — ../api/openapi.yaml (корень
// репозитория) — в public/openapi.yaml, откуда консоль отдаёт её по GET /openapi.yaml.
// Запускается на prebuild (npm run build). Контекст сборки Docker — только web/,
// источника там нет: тогда остаётся уже скопированный файл (он лежит в git, а
// tests/openapi.test.ts следит, чтобы копия не расходилась с источником).
import { copyFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const src = fileURLToPath(new URL("../../api/openapi.yaml", import.meta.url));
const dst = fileURLToPath(new URL("../public/openapi.yaml", import.meta.url));

if (existsSync(src)) {
  copyFileSync(src, dst);
  console.log(`openapi: ${src} → ${dst}`);
} else if (existsSync(dst)) {
  console.log(`openapi: источник ${src} недоступен, оставлена копия ${dst}`);
} else {
  console.error(`openapi: нет ни ${src}, ни ${dst} — спецификация не будет отдаваться`);
  process.exit(1);
}
