import { test } from "node:test";
import assert from "node:assert/strict";
import { cspHeader } from "../src/proxy";

test("CSP: script-src с nonce и strict-dynamic, без unsafe-inline для скриптов; остальное — только свой origin", () => {
  const csp = cspHeader("abc123==");
  const d = Object.fromEntries(csp.split("; ").map((x) => { const [k, ...v] = x.split(" "); return [k, v.join(" ")]; }));
  assert.equal(d["default-src"], "'self'");
  assert.match(d["script-src"], /^'self' 'nonce-abc123==' 'strict-dynamic'/);
  assert.ok(!/unsafe-inline/.test(d["script-src"]), "скрипты — только с nonce");
  assert.equal(d["style-src"], "'self' 'unsafe-inline'");
  assert.equal(d["img-src"], "'self' data:");
  assert.equal(d["font-src"], "'self'");
  assert.match(d["connect-src"], /^'self'/);
  assert.equal(d["frame-ancestors"], "'none'");
  assert.equal(d["object-src"], "'none'");
  assert.equal(d["base-uri"], "'self'");
  assert.equal(d["form-action"], "'self'");
  // Тесты идут не в development: dev-послабления отсутствуют
  assert.ok(!/unsafe-eval|ws:/.test(csp));
});

test("CSP: nonce разный на каждый запрос и попадает и в request (x-nonce), и в response", async () => {
  const { proxy } = await import("../src/proxy");
  const { NextRequest } = await import("next/server");
  const seen = new Set<string>();
  for (let i = 0; i < 3; i++) {
    const req = new NextRequest("http://localhost/login?next=%2Fincidents", { headers: { "x-nonce": "spoofed", "x-argus-path": "/spoofed" } });
    const res = proxy(req);
    const csp = res.headers.get("content-security-policy") ?? "";
    const nonce = /'nonce-([^']+)'/.exec(csp)?.[1];
    assert.ok(nonce && nonce.length >= 22, "nonce — base64 от 16 байт");
    seen.add(nonce);
    // Переопределённые request-заголовки Next кладёт в x-middleware-request-*
    assert.equal(res.headers.get("x-middleware-request-x-nonce"), nonce, "клиентский x-nonce затёрт");
    assert.equal(res.headers.get("x-middleware-request-content-security-policy"), csp, "Next читает nonce из request CSP");
    assert.equal(res.headers.get("x-middleware-request-x-argus-path"), "/login?next=%2Fincidents", "клиентский x-argus-path затёрт");
  }
  assert.equal(seen.size, 3);
});
