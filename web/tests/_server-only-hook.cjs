// CJS-половина подмены `server-only` (tsx грузит .ts через require):
// см. _server-only-hook.mjs для ESM-загрузчика.
const Module = require("node:module");
const path = require("node:path");
const empty = path.join(__dirname, "../node_modules/server-only/empty.js");
const orig = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === "server-only") return empty;
  return orig.call(this, request, ...rest);
};
