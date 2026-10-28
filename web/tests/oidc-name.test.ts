import { test } from "node:test";
import assert from "node:assert/strict";
import { consoleUrl, mapRole, ssoUserName, SSO_PREFIX } from "../src/lib/oidc";

test("ssoUserName: префикс sso: ровно один раз, нижний регистр, обрезка пробелов и длины", () => {
  assert.equal(SSO_PREFIX, "sso:");
  assert.equal(ssoUserName("i.petrov"), "sso:i.petrov");
  assert.equal(ssoUserName("sso:i.petrov"), "sso:i.petrov", "уже префиксованное не дублируется");
  assert.equal(ssoUserName("SSO:I.Petrov"), "sso:i.petrov", "регистр префикса и имени приводится");
  assert.equal(ssoUserName("  I.Petrov@Example.ORG  "), "sso:i.petrov@example.org");
  assert.equal(ssoUserName("sso:sso:x"), "sso:sso:x", "снимается только один префикс — дальше это часть имени");
  assert.equal(ssoUserName("a".repeat(200)).length, SSO_PREFIX.length + 120, "длина имени ограничена 120");
});

test("ssoUserName: пустое имя и пустой остаток после префикса → sso:user", () => {
  assert.equal(ssoUserName(""), "sso:user");
  assert.equal(ssoUserName("   "), "sso:user");
  assert.equal(ssoUserName("sso:"), "sso:user");
  assert.equal(ssoUserName("sso:   "), "sso:user");
  assert.equal(ssoUserName("SSO:"), "sso:user");
});

test("ssoUserName никогда не совпадает с локальным именем: результат всегда начинается с sso:", () => {
  for (const raw of ["admin", "sso:admin", "Admin", "", "sso:", "x".repeat(300)]) {
    assert.ok(ssoUserName(raw).startsWith(SSO_PREFIX), raw);
  }
});

test("mapRole: сильнейшая из совпавших; без совпадений — defaultRole или null; пустые списки", () => {
  const cfg = { groups: { admin: ["argus-admins"], analyst: ["argus-analysts", "soc"], viewer: ["everyone"] }, defaultRole: null as null };
  assert.equal(mapRole(["everyone", "soc", "argus-admins"], cfg), "admin");
  assert.equal(mapRole(["everyone", "soc"], cfg), "analyst");
  assert.equal(mapRole(["everyone"], cfg), "viewer");
  assert.equal(mapRole([], cfg), null);
  assert.equal(mapRole(["hr"], cfg), null);
  assert.equal(mapRole(["hr"], { ...cfg, defaultRole: "viewer" }), "viewer");
  assert.equal(mapRole(["argus-admins"], { ...cfg, defaultRole: "viewer" }), "admin", "совпадение сильнее default");
  assert.equal(mapRole(["Argus-Admins"], cfg), null, "имена групп сравниваются точно, без приведения регистра");
  assert.equal(mapRole(["x"], { groups: { admin: [], analyst: [], viewer: [] }, defaultRole: null }), null, "пустые списки никого не пускают");
});

test("consoleUrl: редиректы строятся от origin OIDC_REDIRECT_URL, а не от адреса прослушивания Next", () => {
  const cfg = { redirectUrl: "https://192.168.0.170:8443/api/auth/oidc/callback" };
  assert.equal(consoleUrl(cfg, "/login?sso=state"), "https://192.168.0.170:8443/login?sso=state");
  assert.equal(consoleUrl(cfg, "/"), "https://192.168.0.170:8443/");
  assert.equal(consoleUrl({ redirectUrl: "https://argus.corp.local/api/auth/oidc/callback" }, "/login?sso=denied"), "https://argus.corp.local/login?sso=denied");
});
