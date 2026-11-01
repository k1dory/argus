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
  assert.match(dictionary.released, /^\d{4}-\d{2}-\d{2}$/);
  assert.equal(Object.keys(ATTACK_TACTICS).length, 15, "v20: Defense Evasion разделена на Stealth и Defense Impairment");
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
  const staleTactics = rules.flatMap((r) => (r.tags ?? []).filter((t) => /^attack\.[a-z_]+$/.test(t) && !ruleTactics([t]).length).map((t) => `${r.file}: ${t}`));
  assert.deepEqual(staleTactics, [], "тег тактики не из справочника: тактика по умолчанию не подставится");
  const missing = rules.flatMap((r) => (r.tags ?? []).filter((t) => /^attack\.t\d{4}/i.test(t))
    .filter((t) => !ruleTechniques([t]).length).map((t) => `${r.file}: ${t}`));
  assert.deepEqual(missing, [], "обновите справочник или тег правила");
  assert.ok(rules.filter((r) => ruleTechniques(r.tags ?? []).length).length >= 20, "контроль: правила с техниками найдены");
});

test("теги правил: техника относится к одной из тактик правила, у правил ИБ техника есть", () => {
  const byId = new Map(dictionary.techniques.map((t) => [t.id, t]));
  const mismatched = rules.flatMap((r) => {
    const tactics = ruleTactics(r.tags ?? []);
    if (!tactics.length) return [];
    return ruleTechniques(r.tags ?? []).filter((id) => !byId.get(id)?.tactics.some((x) => tactics.includes(x)))
      .map((id) => `${r.file}: ${id} (${byId.get(id)?.tactics.join(", ")}) не в ${tactics.join(", ")}`);
  });
  assert.deepEqual(mismatched, [], "техника из чужой тактики: кандидаты и тактика по умолчанию разойдутся");
  // Эксплуатационные правила (ops.*) — без ATT&CK; правилу ИБ без техники форма
  // закрытия подбирает кандидатов только по тактике.
  // rules/tests/ — описания тестов правил, а не правила (у них нет тегов).
  const noTechnique = rules.filter((r) => !r.file.startsWith("rules/tests/") && !(r.tags ?? []).some((t) => t.startsWith("ops.")) && !ruleTechniques(r.tags ?? []).length).map((r) => r.file);
  assert.deepEqual(noTechnique, [], "правило ИБ без attack.tNNNN");
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
  assert.equal(defaultTactic(["attack.defense_impairment", "attack.t1489"]), "defense-impairment");
  const opts = attackFormOptions(["attack.credential_access", "attack.t1110"]);
  assert.equal(opts.defaultTactic, "credential-access");
  assert.deepEqual(Object.keys(opts.candidates), [...Object.keys(ATTACK_TACTICS), ATTACK_OTHER]);
  assert.equal(opts.candidates["credential-access"][0].id, "T1110");
  assert.equal(opts.version, dictionary.version);
});

// Общий golden-файл кандидатов: тот же подбор строит конвейер датасета на Go
// (engine/internal/dataset), и он сверяется с этим же файлом. Перегенерация после правки
// правил или справочника — UPDATE_GOLDEN=1 и этот тест.
const GOLDEN = path.join(ROOT, "testdata/attack-candidates.json");

function goldenCases(): string[][] {
  const seen = new Set<string>();
  const cases: string[][] = [];
  const add = (tags: string[]) => {
    const key = JSON.stringify(tags);
    if (!seen.has(key)) {
      seen.add(key);
      cases.push(tags);
    }
  };
  for (const r of [...rules].sort((a, b) => a.file.localeCompare(b.file))) add(r.tags ?? []);
  add([]); // пустые теги
  add(["attack.credential_access"]); // только тактика
  add(["attack.t9999", "attack.t1110.999"]); // техники, которых нет в справочнике
  add(["ATTACK.T1110.001", "Attack.Credential_Access"]); // прописные
  add(["attack.t1046", "attack.t1071.004", "attack.t1486"]); // разные тактики
  add(["attack.t1595.002"]); // подтехника без родителя в тегах
  add(["attack.defense_evasion"]); // тактика, которой нет в v20
  return cases;
}

test("golden: кандидаты и тактика по умолчанию совпадают с testdata/attack-candidates.json", () => {
  const actual = {
    version: dictionary.version,
    max: ATTACK_MAX_CANDIDATES,
    cases: goldenCases().map((tags) => {
      const opts = attackFormOptions(tags);
      return { tags, default_tactic: opts.defaultTactic, candidates: Object.fromEntries(Object.entries(opts.candidates).map(([k, v]) => [k, v.map((t) => t.id)])) };
    }),
  };
  if (process.env.UPDATE_GOLDEN === "1") {
    fs.mkdirSync(path.dirname(GOLDEN), { recursive: true });
    fs.writeFileSync(GOLDEN, JSON.stringify(actual, null, 1) + "\n");
  }
  const golden = JSON.parse(fs.readFileSync(GOLDEN, "utf8"));
  assert.deepEqual(actual, golden, "подбор кандидатов изменился — UPDATE_GOLDEN=1 npx tsx … --test tests/attack-candidates.test.ts");
});
