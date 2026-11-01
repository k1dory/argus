import { test } from "node:test";
import assert from "node:assert/strict";
import { memberBlockState, type MemberBlockRow } from "../src/lib/shared/incident-members";

const block: MemberBlockRow = {
  ip: "203.0.113.7", executor: "ngfw.edge", mode: "ips", dry_run: 0, ok: 1,
  detail: "POST http://ngfw.fixture/block",
};

// Responder.release emits executor + ".unblock" both for a successful
// operator unblock and for TTL expiry. The panel reads the latest log row.
test("PR49: successful unblock must not be presented as an active block", () => {
  assert.equal(memberBlockState(block), "blocked", "positive control: successful block");
  for (const row of [
    { ...block, executor: "ngfw.edge.unblock", detail: "разблокирован 203.0.113.7" },
    { ...block, executor: "wazuh.unblock", detail: "TTL истёк для 203.0.113.7: снят таймаутом <timeout>=3600 с на менеджере Wazuh" },
  ]) {
    assert.notEqual(memberBlockState(row), "blocked", `${row.executor}: a successful release was labelled as a block`);
  }
});

// Auto returns executor=argus for an IP already blocked by another incident
// or an operator. This is not an allowlist or never_block refusal.
test("PR49: an already active block must not be presented as an allowlist refusal", () => {
  const row = { ...block, executor: "argus", detail: "уже заблокирован до 2026-11-01T12:00:00Z (оператор)" };
  assert.equal(memberBlockState(row), "blocked");
});
