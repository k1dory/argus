// Консоль → движок: POST /incidents/{id}/workflow. Движок декодирует тело с
// DisallowUnknownFields, поэтому в теле только поля workflowRequest
// (engine/cmd/engine/workflow.go); id — в пути. До rc28 консоль клала id и в
// тело, и каждая смена статуса из карточки получала 400 «некорректная операция».
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { incidentTransition } from "../src/lib/argus-queries";

function engineFields(): Set<string> {
  const src = fs.readFileSync(path.resolve(__dirname, "../../engine/cmd/engine/workflow.go"), "utf8");
  const block = src.match(/type workflowRequest struct \{([\s\S]*?)\n\}/);
  assert.ok(block, "workflowRequest в движке");
  return new Set([...block[1].matchAll(/json:"([a-z_]+)"/g)].map((m) => m[1]));
}

test("тело workflow — только поля, которые принимает движок; id в пути", async (t) => {
  const allowed = engineFields();
  const seen: { url: string; body: Record<string, unknown> }[] = [];
  t.mock.method(globalThis, "fetch", async (url: unknown, init?: RequestInit) => {
    seen.push({ url: String(url), body: JSON.parse(String(init?.body ?? "{}")) });
    return new Response("{}", { status: 200 });
  });
  await incidentTransition({ id: "INC-42", kind: "take", actor: "alice", role: "analyst" });
  await incidentTransition({ id: "INC-42", kind: "status", status: "closed", reason: "проверено, ложное", actor: "alice", role: "analyst" });
  await incidentTransition({ id: "INC-42", kind: "assign", owner: "bob", actor: "alice", role: "admin" });
  assert.equal(seen.length, 3);
  for (const { url, body } of seen) {
    assert.match(url, /\/incidents\/INC-42\/workflow$/);
    for (const k of Object.keys(body)) assert.ok(allowed.has(k), `поле ${k} движок отвергнет`);
  }
  assert.equal(seen[1].body.status, "closed");
});
