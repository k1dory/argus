// Справочник ATT&CK и кандидаты техники для формы закрытия: по настоящим правилам
// репозитория и по справочнику, без подмены.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import dictionary from "../src/lib/shared/attack-enterprise.json";
import {
  ATTACK_MAX_CANDIDATES, ATTACK_OTHER, ATTACK_TACTICS, attackFormOptions, attackTechnique, defaultTactic,
  isAttackTactic, isAttackTechnique, ruleTactics, ruleTechniques, techniqueCandidates,
} from "../src/lib/shared/attack";

/* eslint-disable @typescript-eslint/no-require-imports -- как в openapi.test.ts: транзитивный js-yaml без типов */
const yaml = require("js-yaml") as { load: (s: string) => unknown };
/* eslint-enable @typescript-eslint/no-require-imports */

const ROOT = path.resolve(__dirname, "../..");

function ruleFiles(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? ruleFiles(path.join(dir, e.name)) : e.name.endsWith(".yml") ? [path.join(dir, e.name)] : []);
}
const rules = ruleFiles(path.join(ROOT, "rules")).map((f) => ({ file: path.relative(ROOT, f), ...(yaml.load(fs.readFileSync(f, "utf8")) as { tags?: string[] }) }));

test("справочник: версия, источник, тактики в порядке матрицы, техники с тактиками", () => {
  assert.match(dictionary.version, /^\d+\.\d+$/);
  assert.match(dictionary.url, /^https:\/\/raw\.githubusercontent\.com\/mitre-attack\/attack-stix-data\//);
  assert.match(dictionary.sha256, /^[0-9a-f]{64}$/);
  assert.equal(Object.keys(ATTACK_TACTICS)[0], "reconnaissance");
  assert.equal(Object.keys(ATTACK_TACTICS).at(-1), "impact");
  for (const t of dictionary.techniques) {
    assert.match(t.id, /^T\d{4}(\.\d{3})?$/);
    assert.ok(t.tactics.length > 0 && t.tactics.every((x) => Object.hasOwn(ATTACK_TACTICS, x)), t.id);
  }
  assert.equal(new Set(dictionary.techniques.map((t) => t.id)).size, dictionary.techniques.length, "ID уникальны");
  assert.ok(isAttackTactic(ATTACK_OTHER) && isAttackTechnique(ATTACK_OTHER));
  assert.ok(!isAttackTactic("toString") && !isAttackTechnique("constructor"), "ключи прототипа — не значения");
});

test("теги правил: каждая техника из attack.tNNNN есть в справочнике", () => {
  const missing = rules.flatMap((r) => (r.tags ?? []).filter((t) => /^attack\.t\d{4}/i.test(t))
    .filter((t) => !ruleTechniques([t]).length).map((t) => `${r.file}: ${t}`));
  assert.deepEqual(missing, [], "обновите справочник или тег правила");
  assert.ok(rules.filter((r) => ruleTechniques(r.tags ?? []).length).length >= 20, "контроль: правила с техниками найдены");
});

test("кандидаты: для каждого правила и тактики — не больше 20, без повторов, теги правила первыми", () => {
  for (const r of rules) {
    const tags = r.tags ?? [];
    const tagged = ruleTechniques(tags);
    for (const tactic of ["", ATTACK_OTHER, ...Object.keys(ATTACK_TACTICS)]) {
      const ids = techniqueCandidates(tags, tactic).map((t) => t.id);
      assert.ok(ids.length <= ATTACK_MAX_CANDIDATES, `${r.file}/${tactic}: ${ids.length}`);
      assert.equal(new Set(ids).size, ids.length, `${r.file}/${tactic}: повторы`);
      assert.deepEqual(ids.slice(0, tagged.length), tagged.slice(0, ATTACK_MAX_CANDIDATES), `${r.file}/${tactic}: теги правила первыми`);
      if (Object.hasOwn(ATTACK_TACTICS, tactic)) {
        for (const id of ids.slice(tagged.length)) assert.ok(attackTechnique(id)!.tactics.includes(tactic), `${r.file}/${tactic}: ${id} из другой тактики`);
      }
    }
  }
});

test("кандидаты: подтехника из тега — сначала её родитель и соседние подтехники", () => {
  const ids = techniqueCandidates(["attack.credential_access", "attack.t1110.001"], "credential-access").map((t) => t.id);
  assert.deepEqual(ids.slice(0, 5), ["T1110.001", "T1110", "T1110.002", "T1110.003", "T1110.004"]);
  assert.equal(ids.length, ATTACK_MAX_CANDIDATES);
  // Без техник в тегах — по выбранной тактике: сначала техники, потом подтехники.
  const impact = techniqueCandidates([], "impact").map((t) => t.id);
  assert.ok(impact.length === ATTACK_MAX_CANDIDATES && impact.every((id) => attackTechnique(id)!.tactics.includes("impact")));
  assert.ok(impact.findIndex((id) => id.includes(".")) === -1 || impact.slice(0, impact.findIndex((id) => id.includes("."))).every((id) => !id.includes(".")));
  assert.deepEqual(techniqueCandidates([], ATTACK_OTHER), [], "ни тегов, ни тактики — только «другое»");
});

test("тактика по умолчанию — из тегов attack.<tactic>; иначе общая тактика техник", () => {
  assert.deepEqual(ruleTactics(["attack.credential_access", "attack.t1110", "attack.Credential_Access"]), ["credential-access"]);
  assert.equal(defaultTactic(["attack.command_and_control", "attack.t1071.004"]), "command-and-control");
  assert.equal(defaultTactic(["attack.t1071.004"]), "command-and-control");
  assert.equal(defaultTactic(["ops.storage"]), "");
  // defense_evasion в v20 разделена на stealth и defense-impairment: подставлять нечего.
  assert.equal(defaultTactic(["attack.defense_evasion"]), Object.hasOwn(ATTACK_TACTICS, "defense-evasion") ? "defense-evasion" : "");
  const opts = attackFormOptions(["attack.credential_access", "attack.t1110"]);
  assert.equal(opts.defaultTactic, "credential-access");
  assert.deepEqual(Object.keys(opts.candidates), [...Object.keys(ATTACK_TACTICS), ATTACK_OTHER]);
  assert.equal(opts.candidates["credential-access"][0].id, "T1110");
  assert.equal(opts.version, dictionary.version);
});
