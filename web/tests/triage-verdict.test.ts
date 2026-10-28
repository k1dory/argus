// Вердикт агента (argus-triage/v3): валидатор подмножества JSON Schema, сверка
// с областью сессии, свободный текст, Markdown. Чистые функции без БД.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  badFreeText, badRunes, checkVerdict, code, plain, plainText, renderVerdictMarkdown, schemaValid, validateVerdictSchema, VERDICT_SCHEMA, VERDICT_SCHEMA_VERSION, type VerdictDoc,
} from "../src/lib/shared/triage-verdict";
import { VERDICT_OK, verdictWith } from "./_verdict-fixture";

const scope = { incidentId: "INC-7", related: { "INC-5": "same_subject" as const } };
const incident = { level: "high", rule_id: "a41c-cicd-007" };
const paths = (doc: unknown) => validateVerdictSchema(doc).map((r) => `${r.path}:${r.code}`);

test("валидатор: ключевые слова подмножества схемы", () => {
  assert.equal(schemaValid({ type: "string", minLength: 2, maxLength: 3, pattern: "^a+$" }, "aa"), true);
  assert.equal(schemaValid({ type: "string", minLength: 2 }, "a"), false);
  assert.equal(schemaValid({ type: "string", maxLength: 1 }, "é"), true, "длина — в кодовых точках");
  assert.equal(schemaValid({ type: ["string", "null"] }, null), true);
  assert.equal(schemaValid({ const: "x" }, "y"), false);
  assert.equal(schemaValid({ enum: [1, "a", null] }, null), true);
  assert.equal(schemaValid({ type: "array", items: { type: "string" }, minItems: 1, maxItems: 2, uniqueItems: true }, ["a", "a"]), false);
  assert.equal(schemaValid({ type: "array", contains: { const: 2 } }, [1, 2]), true);
  assert.equal(schemaValid({ type: "object", required: ["a"], properties: { a: { type: "boolean" } }, additionalProperties: false }, { a: true }), true);
  assert.equal(schemaValid({ type: "object", additionalProperties: false, properties: { a: {} } }, { a: 1, b: 2 }), false);
  assert.equal(schemaValid({ anyOf: [{ const: 1 }, { const: 2 }] }, 2), true);
  assert.equal(schemaValid({ oneOf: [{ type: "number" }, { const: 1 }] }, 1), false, "oneOf — ровно одна");
  assert.equal(schemaValid({ not: { const: 1 } }, 1), false);
  assert.equal(schemaValid({ if: { const: 1 }, then: { type: "string" } }, 1), false);
  assert.equal(schemaValid({ if: { const: 1 }, then: { type: "string" }, else: { type: "number" } }, 2), true);
  assert.equal(schemaValid({ $ref: "#/$defs/incident_id" }, "INC-12"), true);
  assert.equal(schemaValid({ $ref: "#/$defs/incident_id" }, "inc-12"), false);
  assert.throws(() => schemaValid({ $ref: "#/$defs/nope" }, 1), /неизвестная ссылка/);
});

test("схема вердикта: эталон проходит, отклонения дают путь до поля", () => {
  assert.deepEqual(paths(VERDICT_OK), []);
  assert.deepEqual(paths("x"), [":schema"]);
  assert.deepEqual(paths(verdictWith({ extra: 1 })), ["/extra:schema"]);
  assert.deepEqual(paths(verdictWith({ "очень длинный ключ с пробелами и кириллицей, который не повторяем": 1 })), ["/?:schema"]);
  const { summary: _s, ...noSummary } = VERDICT_OK;
  void _s;
  assert.deepEqual(paths(noSummary), ["/summary:schema"]);
  assert.deepEqual(paths(verdictWith({ schema: "argus-triage/v2" })), ["/schema:schema"]);
  assert.deepEqual(paths(verdictWith({ summary: "x".repeat(601) })), ["/summary:schema"]);
  assert.deepEqual(paths(verdictWith({ gaps: ["ok", "плохо <b>"] })), ["/gaps/1:schema"], "элемент массива");
  assert.deepEqual(paths(verdictWith({ evidence: [] })), ["/evidence:schema"]);
  assert.deepEqual(paths(verdictWith({ subject: { kind: "person", display: "i.petrov" } })), ["/subject:schema"], "человек — только слово subject");
  assert.deepEqual(paths(verdictWith({ recommendation: { ...VERDICT_OK.recommendation, exception: { field: "node", value: "x" } } })), [":schema"], "исключение при TP — условие корня");
  assert.deepEqual(paths(verdictWith({ verdict: "undetermined", human_needed: false })), [":schema"]);
  assert.deepEqual(paths(verdictWith({ verdict: "false_positive" })), [":schema"], "FP без benign-довода");
  const fp = verdictWith({
    verdict: "false_positive", human_needed: false, level: "medium",
    evidence: [{ ...VERDICT_OK.evidence[0], direction: "benign", provenance: "engine", attacker_control: "none" }],
    recommendation: { ...VERDICT_OK.recommendation, console_status: "false_positive" },
  });
  delete fp.human_reason;
  assert.deepEqual(paths(fp), []);
  assert.deepEqual(paths(verdictWith({ injection_suspected: true })), [":schema"], "подозрение без причины и полей");
  assert.deepEqual(paths(verdictWith({ injection_suspected: true, injection_reason: "текст обращён к модели и просит вывести секрет", injection_fields: ["comments"] })), []);
});

test("safe_text: ссылки, разметка, кодированные строки — отказ схемы", () => {
  for (const bad of ["см. https://a.example.org", "www.example.org", "a%20b", "A".repeat(24), "f".repeat(32), "x <b>", "x [y]", "x `y`", "x {y}", "a; b", "a\nb"]) {
    assert.deepEqual(paths(verdictWith({ summary: bad })), ["/summary:schema"], bad);
  }
  assert.deepEqual(paths(verdictWith({ summary: "Обычный текст: 2 узла, 10.0.0.1, REGISTRY_TOKEN." })), []);
});

test("checkVerdict: инцидент сессии, ссылки области, свободный текст", () => {
  const doc = VERDICT_OK as unknown as VerdictDoc;
  assert.deepEqual(checkVerdict(doc, { scope, incident }), []);
  assert.deepEqual(checkVerdict({ ...doc, incident_id: "INC-9" }, { scope, incident }), [{ path: "/incident_id", code: "incident" }]);
  assert.deepEqual(checkVerdict({ ...doc, level: "low", rule_id: "other" }, { scope, incident }), [{ path: "/level", code: "incident" }, { path: "/rule_id", code: "incident" }]);
  assert.deepEqual(checkVerdict(doc, { scope, incident: null }), [], "без строки инцидента уровень и правило не сверяются");
  assert.deepEqual(checkVerdict({ ...doc, related: [{ incident_id: "INC-9", relation: "same_node" }] }, { scope, incident }), [{ path: "/related/0/incident_id", code: "unknown_ref" }]);
  assert.deepEqual(checkVerdict({ ...doc, evidence: [{ ...doc.evidence[0], refs: ["INC-5", "INC-9"] }] }, { scope, incident }), [{ path: "/evidence/0/refs/1", code: "unknown_ref" }]);
  assert.deepEqual(checkVerdict({ ...doc, gaps: ["см. INC-5 и INC-7"] }, { scope, incident }), [], "свой и связанный в тексте — можно");
  assert.deepEqual(checkVerdict({ ...doc, gaps: ["см. inc-9"] }, { scope, incident }), [{ path: "/gaps/0", code: "unknown_ref" }]);
  assert.deepEqual(checkVerdict({ ...doc, summary: "см. mention:ops" }, { scope, incident }), [{ path: "/summary", code: "unsafe_text" }]);
  assert.deepEqual(checkVerdict({ ...doc, summary: "субъект subj-0123456789" }, { scope, incident }), [{ path: "/summary", code: "unsafe_text" }], "псевдоним в тексте");
  assert.deepEqual(checkVerdict({ ...doc, summary: "скры​тый" }, { scope, incident }), [{ path: "/summary", code: "unsafe_text" }], "ZWSP");
  assert.deepEqual(checkVerdict({ ...doc, summary: "é́́" }, { scope, incident }), [{ path: "/summary", code: "unsafe_text" }], "три знака диакритики");
  assert.deepEqual(checkVerdict({ ...doc, summary: "中文" }, { scope, incident }), [{ path: "/summary", code: "unsafe_text" }], "письменность вне латиницы и кириллицы");
  assert.deepEqual(checkVerdict({ ...doc, rule_id: "a41c-cicd-007", subject: { kind: "service_account", display: "bot​" } }, { scope, incident }), [{ path: "/subject/display", code: "schema" }], "невидимый в структурном поле");
});

test("свободный текст и структурные поля: разрешающие списки", () => {
  assert.equal(badFreeText("Обычный текст — с тире, ёлочками «» и цифрами 10.0.0.1!"), false);
  assert.equal(badFreeText("é ё"), false, "одна диакритика на букву");
  assert.equal(badFreeText("a b"), true, "неразрывный пробел");
  assert.equal(badFreeText("a‮b"), true, "bidi");
  assert.equal(badFreeText("\u{1F170}"), true, "буквы в рамках");
  assert.equal(badFreeText("a�b"), true);
  assert.equal(badRunes("ok-token_1"), false);
  assert.equal(badRunes("a‍b"), true);
  assert.equal(badRunes("a\tb"), true, "в структурном поле и табуляция — отказ");
});

test("Markdown: фиксированный шаблон, текст очищен и экранирован, ссылок нет", () => {
  const md = renderVerdictMarkdown(VERDICT_OK as unknown as VerdictDoc, "triage-bot", "sess-1");
  const lines = md.split("\n");
  assert.equal(lines[0], "**Вердикт агента: подтверждённая атака (true positive) · нужен человек: да. утечка секрета требует ротации и проверки использования**");
  assert.ok(md.includes("- Инцидент: `INC-7`, уровень `high`, правило `a41c-cicd-007`"));
  assert.ok(md.includes("### Итог\n\nСборка CI вывела значение REGISTRY\\_TOKEN в журнал"), "подчёркивание экранировано");
  assert.ok(md.includes("1. 2026-10-12 04:01:38 · `gitlab.ci` · event\\_other\\_source, контроль атакующего low, attack — строка журнала сборки содержит значение секрета (`card`, `ev-1`)"));
  assert.ok(md.includes("### Пробелы\n\n- нет подтверждения"));
  assert.ok(md.includes("- `INC-5` — same\\_subject: тот же бот неделей раньше"));
  assert.ok(md.includes("- Статус в консоли: эскалирован — секрет в журнале сборки, нужна ротация"));
  assert.ok(md.includes("- Действие: `revoke_secret` → `subject`"));
  assert.ok(md.endsWith("Записал агент `triage-bot` через API консоли, сессия `sess-1`, схема `argus-triage/v3`. Текст проверен и очищен консолью.\n"));
  assert.ok(!/https?:\/\//.test(md));
  const inj = renderVerdictMarkdown({ ...(VERDICT_OK as unknown as VerdictDoc), injection_suspected: true, injection_reason: "текст просит вывести секрет", injection_fields: ["comments"], pii_seen: true } as VerdictDoc, "a", "s");
  assert.ok(inj.includes("⚠️ подозрение на prompt injection") && inj.includes("### Подозрение на prompt injection\n\nтекст просит вывести секрет\n\nПоля: `comments`") && inj.includes("есть ПДн"));
});

test("plain/plainText/code: второй рубеж против разметки", () => {
  assert.equal(plainText("см. [тут](http://x.example.org) и ![img](http://y) <b>x</b>  http://z.example.org/a www.q.example mention://u"), "см. тут и x [ссылка удалена] [ссылка удалена] [ссылка удалена]");
  assert.equal(plainText("a\u0000b‍c\n\nd"), "a b c d");
  assert.equal(plain("-- line *em* _u_ `c` # h"), "\\-- line \\*em\\* \\_u\\_ \\`c\\` \\# h", "ведущий дефис экранирован — строка не станет линией");
  assert.equal(plain("//evil.example.org/x"), "\\[ссылка удалена\\]");
  assert.equal(code("a`b\u0001c"), "`abc`");
});

test("VERDICT_SCHEMA: схема для GET /api/triage/schema — та же, по которой проверяется вердикт, версия в const", () => {
  const sch = VERDICT_SCHEMA as { $id?: string; properties?: Record<string, { const?: string }> };
  assert.match(sch.$id ?? "", /argus-triage-verdict-v3/);
  assert.equal(sch.properties?.schema?.const, VERDICT_SCHEMA_VERSION);
  assert.equal(VERDICT_SCHEMA_VERSION, "argus-triage/v3");
});
