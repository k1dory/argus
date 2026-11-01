import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { blockCandidatesFor } from "../src/lib/argus-queries";

type ClockSkewEvent = {
  ts: string;
  source: string;
  action: string;
  actor_name: string;
  node: string;
  object?: string;
  value: number;
  unit: string;
  attrs: Record<string, string>;
};

test("PR80: clock-skew telemetry must not offer its sender for blocking", (t) => {
  const previousNets = process.env.INTERNAL_NETS;
  process.env.INTERNAL_NETS = "";
  t.after(() => {
    if (previousNets === undefined) delete process.env.INTERNAL_NETS;
    else process.env.INTERNAL_NETS = previousNets;
  });

  const raw = fs.readFileSync(path.join(__dirname, "../../fixtures/events/collector-clock-skew.ndjson"), "utf8");
  const event = JSON.parse(raw.trim().split("\n")[0]) as ClockSkewEvent;
  assert.equal(event.source, "argus.collector");
  assert.equal(event.action, "collector.clock_skew");
  assert.equal(event.node, "argus-collector");
  assert.equal(event.attrs.transport, "internal");

  // A remote syslog exporter may have a public address. Keep the shipped
  // fixture's fields, changing only the example peer (no real network calls).
  // On d80c0e0 the fixture has no object, so the chain contains no such IP.
  const sender = "198.51.100.77";
  event.object = event.object?.replace(event.attrs.peer, sender);
  event.attrs.peer = sender;

  // Persisted chain wire format from engine/internal/incidents.chain: the
  // fixed prefix includes node truncated to 14 characters (argus-collect…).
  // Read the detail from the fixture to cover the producer change in this PR.
  const detail = `${event.object || event.actor_name} ${event.value} ${event.unit}`;
  const incident = {
    rule_id: "a41c-ops-067",
    tags: ["argus.system", "ops.ingest", "ops.time"],
    sources: [event.source],
    actor_name: event.actor_name,
    node: event.node,
    chain: [`${event.ts.slice(11, 19)}  argus.collector  argus-collect… collector.clock_skew     ${detail}`],
  };

  // Both the incident page's buttons and blockIpAction's server-side allowlist
  // use this function. Normal incident response must remain available.
  const attack = {
    rule_id: "a41c-auth-031", tags: ["attack.credential_access"],
    sources: ["host.sshd"], actor_name: "203.0.113.40", node: "ssh-fixture", chain: [],
  };
  assert.deepEqual(blockCandidatesFor(attack), ["203.0.113.40"]);
  assert.deepEqual(blockCandidatesFor(incident), [],
    `the exporter ${sender} is the source of clock telemetry, not an attack target; its clock-skew incident must not authorize blocking it`);
});
