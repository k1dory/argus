import { test } from "node:test";
import assert from "node:assert/strict";
import { memberBlockState, parseMembers } from "../src/lib/shared/incident-members";

test("parseMembers: строка JSON из incidents.members", () => {
  const raw = JSON.stringify([
    { ip: "203.0.113.20", first: "2026-11-01 10:00:00.000", last: "2026-11-01 10:05:00.000", events: 5, rules: ["a41c-net-071"] },
    { ip: "203.0.113.10", first: "2026-11-01 09:59:00.000", last: "2026-11-01 10:01:00.000", events: 9, rules: ["a41c-net-070", "a41c-net-072"] },
  ]);
  const got = parseMembers(raw);
  assert.equal(got.length, 2);
  assert.deepEqual(got[1].rules, ["a41c-net-070", "a41c-net-072"]);
});

test("parseMembers: пусто и не та форма — пустой список, без частичных строк", () => {
  assert.deepEqual(parseMembers(""), []);
  assert.deepEqual(parseMembers(undefined), []);
  assert.deepEqual(parseMembers("not json"), []);
  assert.deepEqual(parseMembers(JSON.stringify({ ip: "x" })), []);
  assert.deepEqual(parseMembers(JSON.stringify([{ ip: "203.0.113.1", first: "a", last: "b", events: "5", rules: [] }])), []);
  assert.deepEqual(parseMembers(JSON.stringify([{ ip: "203.0.113.1", first: "a", last: "b", events: 1, rules: [1] }])), []);
});

test("memberBlockState: категории по последней записи журнала (тексты — из движка)", () => {
  const base = { ip: "203.0.113.10", mode: "ips", dry_run: 0, ok: 1, detail: "" };
  assert.equal(memberBlockState(undefined), "none");
  assert.equal(memberBlockState({ ...base, executor: "ngfw.edge" }), "blocked");
  assert.equal(memberBlockState({ ...base, executor: "ngfw.edge", ok: 0, detail: "HTTP 500 <html>…" }), "failed");
  assert.equal(memberBlockState({ ...base, executor: "ngfw.edge", mode: "simulate" }), "simulated");
  assert.equal(memberBlockState({ ...base, executor: "argus", detail: "потолок блокировок инцидента: 32 новых адресов за 1h0m0s (collapse.block_cap) — адрес не заблокирован, решение за аналитиком" }), "capped");
  assert.equal(memberBlockState({ ...base, executor: "argus", mode: "ids", detail: "режим IDS: автоответ выключен" }), "ids");
  assert.equal(memberBlockState({ ...base, executor: "argus", detail: "ожидание: доверенных событий 0 из 1 (respond.min_events)" }), "waiting");
  assert.equal(memberBlockState({ ...base, executor: "argus", detail: "203.0.113.10 в allowlist" }), "refused");
});
