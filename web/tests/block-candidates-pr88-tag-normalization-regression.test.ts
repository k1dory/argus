/* eslint-disable @typescript-eslint/no-require-imports -- capture the real query helper before installing the action mocks */
import { after, beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { formData, installNextMocks, loadAuth } from "./_next-mock";
import { ruleTactics, ruleTechniques } from "../src/lib/shared/attack";

// _next-mock's default blockCandidatesFor delegates directly to the old raw
// IP extractor. Keep the production helper so the new ops gate is exercised
// both as the card uses it and through the real server action.
const { blockCandidatesFor } = require("../src/lib/argus-queries") as typeof import("../src/lib/argus-queries");
const mocks = installNextMocks();
mocks.queries.blockCandidatesFor = blockCandidatesFor;
const auth = loadAuth();
const { blockIpAction } = require("../src/lib/incident-actions") as typeof import("../src/lib/incident-actions");

const previousNets = process.env.INTERNAL_NETS;
const ip = "203.0.113.40";
const actor = "sso:pr88-reviewer";
let requests: unknown[][] = [];
let incident = { incident_id: "INC-88001", actor_name: ip, chain: [] as string[], tags: [] as string[] };

beforeEach(async () => {
  process.env.INTERNAL_NETS = "";
  requests = [];
  mocks.audit.length = 0;
  incident = { incident_id: "INC-88001", actor_name: ip, chain: [], tags: [] };
  mocks.queries.incidentGet = async () => incident;
  mocks.queries.requestBlockIp = async (...args) => {
    requests.push(args);
    return { results: [{ executor: "fixture", ok: true, detail: "recorded locally" }] };
  };
  await auth.createSession(actor, "analyst", true);
});

after(() => {
  if (previousNets === undefined) delete process.env.INTERNAL_NETS;
  else process.env.INTERNAL_NETS = previousNets;
  fs.rmSync(path.dirname(mocks.authFile), { recursive: true, force: true });
});

const variants = [
  { name: "canonical control", tactic: "attack.credential_access", technique: "attack.t1110.001" },
  { name: "uppercase", tactic: "ATTACK.CREDENTIAL_ACCESS", technique: "ATTACK.T1110.001" },
  { name: "mixed case", tactic: "Attack.Credential_Access", technique: "Attack.T1110.001" },
  { name: "surrounding whitespace", tactic: " attack.credential_access ", technique: " attack.t1110.001 " },
];

for (const variant of variants) {
  const tags = ["ops.identity", variant.tactic, variant.technique];

  test(`PR88: card candidate survives a recognized ATT&CK tag (${variant.name})`, () => {
    // The existing ATT&CK readers (also mirrored in Go) explicitly accept
    // these spellings. This is a mixed security rule, not a pure ops rule.
    assert.deepEqual(ruleTactics(tags), ["credential-access"]);
    assert.deepEqual(ruleTechniques(tags), ["T1110.001"]);
    assert.deepEqual(blockCandidatesFor({ ...incident, tags }), [ip],
      "a recognized attack tag must preserve the same block candidate as its canonical spelling");
  });

  test(`PR88: blockIpAction accepts a recognized ATT&CK tag (${variant.name})`, async () => {
    incident.tags = tags;
    const result = await blockIpAction({ error: null }, formData({
      incident_id: incident.incident_id, ip, reason: "Confirmed fixture attack",
    }));
    assert.deepEqual(requests, [[incident.incident_id, ip, `Confirmed fixture attack (оператор ${actor})`, actor]],
      `recognized attack evidence must reach the local executor stub; action returned ${JSON.stringify(result)}`);
    assert.equal(result.error, null);
  });
}

test("PR88 control: submitted attack tags cannot override stored ops-only tags", async () => {
  incident.tags = ["argus.system", "ops.ingest", "ops.time"];
  assert.deepEqual(blockCandidatesFor(incident), []);
  const result = await blockIpAction({ error: null }, formData({
    incident_id: incident.incident_id, ip, reason: "Untrusted form metadata",
    tags: JSON.stringify(["attack.t1110.001"]), rule_id: "a41c-auth-031",
  }));
  assert.match(result.error ?? "", /не относится/);
  assert.deepEqual(requests, [], "form fields must not authorize blocking an ops peer");
  assert.deepEqual(mocks.audit, [], "rejection happens before response audit and execution");
});

test("PR88 control: shipped security rules keep candidates; shipped ops rules do not", () => {
  const yaml = require("js-yaml") as { load: (text: string) => unknown };
  const root = path.resolve(__dirname, "../../rules");
  function ruleFiles(dir: string): string[] {
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
      entry.isDirectory() ? entry.name === "tests" ? [] : ruleFiles(path.join(dir, entry.name))
        : /\.ya?ml$/.test(entry.name) ? [path.join(dir, entry.name)] : []);
  }
  let security = 0, ops = 0;
  for (const file of ruleFiles(root)) {
    const rule = yaml.load(fs.readFileSync(file, "utf8")) as { tags?: string[] };
    const isOpsRule = path.relative(root, file).startsWith(`ops${path.sep}`);
    if (isOpsRule) ops++; else security++;
    assert.deepEqual(blockCandidatesFor({ ...incident, tags: rule.tags }), isOpsRule ? [] : [ip], file);
  }
  assert.ok(security > 0 && ops > 0, "both shipped rule families must be checked");
});
