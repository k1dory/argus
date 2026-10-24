import { test } from "node:test";
import assert from "node:assert/strict";
import { mapRole } from "../src/lib/oidc";

const cfg = { groups: { admin: ["argus-admins"], analyst: ["argus-analysts", "soc"], viewer: ["everyone"] }, defaultRole: null as null };

test("группы IdP → роль: сильнейшая из совпавших, без совпадений — отказ", () => {
  assert.equal(mapRole(["everyone", "soc"], cfg), "analyst");
  assert.equal(mapRole(["argus-admins", "soc"], cfg), "admin");
  assert.equal(mapRole(["everyone"], cfg), "viewer");
  assert.equal(mapRole(["hr"], cfg), null);
  assert.equal(mapRole(["hr"], { ...cfg, defaultRole: "viewer" }), "viewer");
});
