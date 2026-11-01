import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { Script } from "node:vm";
import ts from "typescript";
import dictionary from "../src/lib/shared/attack-enterprise.json";
import * as attack from "../src/lib/shared/attack";

// Проверяем сам новый guard из PR, не копию его условия. Загружаем исходный
// test-модуль с другим корнем правил и перехватываем только регистрацию тестов.
// Файлы репозитория и golden не меняются, остальные callbacks не выполняются.
const suiteFile = path.join(__dirname, "attack-candidates.test.ts");
const suiteRequire = createRequire(suiteFile);
const guardName = "теги правил: техника относится к одной из тактик правила, у правил ИБ техника есть";
const compiled = ts.transpileModule(fs.readFileSync(suiteFile, "utf8"), {
  fileName: suiteFile,
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, esModuleInterop: true },
}).outputText;
const loadSuite = new Script(`(function(require, __dirname, exports) {\n${compiled}\n})`, {
  filename: suiteFile,
}).runInThisContext() as (load: (id: string) => unknown, dirname: string, exports: object) => void;

function guardFor(t: TestContext, files: Record<string, string>): () => void {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "argus-attack-coverage-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const [relative, body] of Object.entries(files)) {
    const full = path.join(root, "rules", relative);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, body);
  }
  const callbacks = new Map<string, () => void>();
  loadSuite((id) => {
    if (id === "node:test") return { test: (name: string, callback: () => void) => callbacks.set(name, callback) };
    if (id === "../src/lib/shared/attack-enterprise.json") return dictionary;
    if (id === "../src/lib/shared/attack") return attack;
    return suiteRequire(id);
  }, path.join(root, "web", "tests"), {});
  const guard = callbacks.get(guardName);
  assert.ok(guard, "ATT&CK coverage guard must be registered");
  return guard;
}

function rule(tags: string[]): string {
  return `title: Coverage fixture\nid: coverage-fixture\nlevel: low\ntags: ${JSON.stringify(tags)}\ndetection:\n  selection:\n    action: fixture.event\n  condition: selection\n`;
}

const valid = rule(["attack.reconnaissance", "attack.t1595"]);

test("ATT&CK guard: корректная техника и тактика проходят", (t) => {
  assert.doesNotThrow(guardFor(t, { "valid.yml": valid }));
});

// rules.Files в Go принимает и .yml, и .yaml. Расширение не должно позволять
// пропустить ни чужую тактику, ни отсутствие техники у правила ИБ.
for (const extension of ["yml", "yaml"]) {
  for (const fixture of [
    { name: "чужая тактика", tags: ["attack.reconnaissance", "attack.t1046"], error: /техника из чужой тактики/ },
    { name: "нет техники", tags: ["attack.reconnaissance"], error: /правило ИБ без attack\.tNNNN/ },
  ]) {
    test(`ATT&CK guard: ${fixture.name} отклоняется в .${extension}`, (t) => {
      const guard = guardFor(t, { "valid.yml": valid, [`invalid.${extension}`]: rule(fixture.tags) });
      assert.throws(guard, fixture.error);
    });
  }
}

// rules.Files пропускает подкаталог tests на любом уровне, а не только rules/tests.
for (const directory of ["tests", "wazuh/tests", "ops/tests"]) {
  test(`ATT&CK guard: ${directory} содержит описание теста, а не правило ИБ`, (t) => {
    const guard = guardFor(t, {
      "valid.yml": valid,
      [`${directory}/fixture.yml`]: "rule: coverage-fixture\nfixture: events.ndjson\nexpect_incidents: 1\n",
    });
    assert.doesNotThrow(guard);
  });
}
