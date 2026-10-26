// Спецификация API (api/openapi.yaml) не расходится с кодом: каждый route.ts в
// src/app/api описан (путь и методы) и наоборот, у операций есть security и
// успешный ответ, все $ref разрешаются, встроенная схема вердикта равна
// triage-verdict.schema.json, копия в public/ совпадает с источником, а
// /api/version отдаёт путь к ней.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { installNextMocks, loadAuth } from "./_next-mock";
import verdictSchema from "../src/lib/shared/triage-verdict.schema.json";
import { OPENAPI_PATH } from "../src/lib/version";

loadAuth();
installNextMocks();
const API = "a".repeat(40);
process.env.ARGUS_API_TOKEN = API;

/* eslint-disable @typescript-eslint/no-require-imports -- js-yaml — транзитивная зависимость без типов; маршрут грузится после моков */
const yaml = require("js-yaml") as { load: (s: string) => unknown };
const versionRoute = require("../src/app/api/version/route") as { GET: (req: Request) => Promise<Response> };
/* eslint-enable @typescript-eslint/no-require-imports */

const WEB = path.resolve(__dirname, "..");
const SPEC = path.resolve(WEB, "../api/openapi.yaml");
const COPY = path.join(WEB, "public/openapi.yaml");
const API_DIR = path.join(WEB, "src/app/api");
const METHODS = ["get", "post", "put", "delete", "patch", "head", "options"] as const;

type Operation = { security?: unknown[]; responses?: Record<string, unknown> };
type Spec = { openapi: string; paths: Record<string, Record<string, Operation>>; components: { schemas: Record<string, unknown>; [k: string]: unknown } };

const specText = fs.readFileSync(SPEC, "utf8");
const spec = yaml.load(specText) as Spec;

/** Маршруты Next: каталог → путь спецификации ([id] → {id}), методы — из экспортов route.ts. */
function routes(): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  const walk = (dir: string) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.name === "route.ts") {
        const rel = path.relative(API_DIR, dir).split(path.sep).join("/");
        const url = "/api/" + rel.replace(/\[([^\]]+)\]/g, "{$1}");
        const src = fs.readFileSync(full, "utf8");
        const methods = new Set([...src.matchAll(/^export\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b/gm)].map((m) => m[1].toLowerCase()));
        out.set(url, methods);
      }
    }
  };
  walk(API_DIR);
  return out;
}

test("спецификация: OpenAPI 3.1, пути и методы совпадают с route.ts в обе стороны", () => {
  assert.match(spec.openapi, /^3\.1\./);
  const code = routes();
  const specPaths = Object.keys(spec.paths);
  assert.deepEqual(specPaths.sort(), [...code.keys()].sort(), "набор путей");
  for (const [url, methods] of code) {
    const ops = Object.keys(spec.paths[url]).filter((k) => (METHODS as readonly string[]).includes(k));
    assert.deepEqual(ops.sort(), [...methods].sort(), `методы ${url}`);
  }
});

test("каждая операция: security задан явно, есть успешный ответ (2xx или перенаправление), ответы — с описанием", () => {
  for (const [url, item] of Object.entries(spec.paths)) {
    for (const m of METHODS) {
      const op = item[m];
      if (!op) continue;
      assert.ok(Array.isArray(op.security), `${m.toUpperCase()} ${url}: security`);
      const codes = Object.keys(op.responses ?? {});
      assert.ok(codes.some((c) => /^[23]\d\d$/.test(c)), `${m.toUpperCase()} ${url}: нет успешного ответа (${codes.join(", ")})`);
      for (const [c, r] of Object.entries(op.responses ?? {})) {
        const rr = r as Record<string, unknown>;
        assert.ok("$ref" in rr || typeof rr.description === "string", `${m.toUpperCase()} ${url} ${c}: description`);
      }
    }
  }
});

test("все $ref разрешаются внутри документа", () => {
  const refs: string[] = [];
  const walk = (v: unknown) => {
    if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object") {
      for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
        if (k === "$ref" && typeof x === "string") refs.push(x);
        else walk(x);
      }
    }
  };
  walk(spec);
  assert.ok(refs.length > 50, "ссылок достаточно много");
  for (const ref of refs) {
    assert.ok(ref.startsWith("#/"), `внешняя ссылка ${ref}`);
    let cur: unknown = spec;
    for (const seg of ref.slice(2).split("/")) {
      const key = seg.replace(/~1/g, "/").replace(/~0/g, "~");
      assert.ok(cur && typeof cur === "object" && Object.hasOwn(cur as object, key), `не разрешается ${ref} (сегмент ${key})`);
      cur = (cur as Record<string, unknown>)[key];
    }
  }
});

test("встроенная схема вердикта равна triage-verdict.schema.json (ссылки переадресованы в компонент)", () => {
  const back = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(back);
    if (v && typeof v === "object") {
      return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, k === "$ref" && typeof x === "string" ? x.replace("#/components/schemas/TriageVerdict/$defs/", "#/$defs/") : back(x)]));
    }
    return v;
  };
  const source: Record<string, unknown> = { ...verdictSchema };
  delete source.$schema;
  delete source.$id;
  assert.deepEqual(back(spec.components.schemas.TriageVerdict), source, "схема изменилась — пересоберите компонент TriageVerdict в api/openapi.yaml");
});

test("копия public/openapi.yaml совпадает с api/openapi.yaml, /api/version указывает на неё", async () => {
  assert.ok(fs.existsSync(COPY), "нет public/openapi.yaml — выполните npm run sync-openapi");
  assert.equal(fs.readFileSync(COPY, "utf8"), specText, "копия устарела — выполните npm run sync-openapi");
  assert.equal(OPENAPI_PATH, "/openapi.yaml");
  const anon = await (await versionRoute.GET(new Request("http://x/api/version"))).json();
  assert.deepEqual(anon, { status: "ok" }, "анониму — только живость");
  const res = await versionRoute.GET(new Request("http://x/api/version", { headers: { authorization: `Bearer ${API}` } }));
  const body = await res.json();
  assert.equal(body.openapi, "/openapi.yaml");
  assert.equal(body.name, "argus-console");
  assert.ok(typeof body.version === "string" && body.version.length > 0);
});
