// Тесты идут в обычном Node без React-server-рантайма, а модули консоли
// начинаются с `import "server-only"` (защита от импорта в клиентские
// компоненты). Подменяем его на пустой модуль пакета только для тестов.
import { register } from "node:module";
import { pathToFileURL } from "node:url";

register(
  "data:text/javascript," +
    encodeURIComponent(`
      export async function resolve(specifier, context, next) {
        if (specifier === "server-only") return { url: ${JSON.stringify(pathToFileURL(new URL("../node_modules/server-only/empty.js", import.meta.url).pathname).href)}, shortCircuit: true };
        return next(specifier, context);
      }
    `),
  import.meta.url,
);
