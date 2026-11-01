// Контракт CI: живые Go-тесты хранилища запускаются с ClickHouse только у engine.
// Остальные четыре модуля не должны ждать контейнер, которым не пользуются.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";

/* eslint-disable @typescript-eslint/no-require-imports -- как в openapi.test.ts: транзитивный js-yaml без типов */
const yaml = require("js-yaml") as { load: (s: string) => unknown };
/* eslint-enable @typescript-eslint/no-require-imports */

type Step = { run?: string; env?: Record<string, string> };
type Job = {
  strategy?: { matrix: { module: string[]; include?: { module: string; clickhouse?: string }[] } };
  services?: { clickhouse?: { image: string } };
  steps: Step[];
};
const workflow = yaml.load(readFileSync(path.resolve(__dirname, "../../.github/workflows/ci.yml"), "utf8")) as { jobs: Record<string, Job> };

test("CI: ClickHouse включён только для engine в матрице Go, живые тесты не пропускаются", () => {
  const job = workflow.jobs.go;
  const matrix = job.strategy?.matrix;
  assert.ok(matrix);
  assert.deepEqual([...matrix.module].sort(), ["collector", "engine", "mcp", "policyd", "triage"]);
  const withServer = matrix.module.filter((module) => matrix.include?.some((row) => row.module === module && row.clickhouse));
  assert.deepEqual(withServer, ["engine"], "дорогой сервис нужен только модулю с живыми тестами");
  assert.equal(job.services?.clickhouse?.image.replace(/\s+/g, ""), "${{matrix.clickhouse||''}}", "пустой image отключает сервис в остальных строках матрицы");
  const testStep = job.steps.find((step) => /go test\b/.test(step.run ?? ""));
  assert.ok(testStep, "Go-тесты запускаются");
  assert.match(testStep.run!, /go test[^\n]*\.\/\.\.\./, "в прогон входит internal/store/live_test.go");
  assert.equal((testStep.env?.ARGUS_TEST_CLICKHOUSE_URL ?? "").replace(/\s+/g, ""), "${{matrix.clickhouse&&'http://localhost:8123'||''}}");
  assert.ok(testStep.env?.ARGUS_TEST_CLICKHOUSE_PASSWORD, "живым тестам передан пароль CI-сервиса");
});

test("CI: web сохраняет ClickHouse для проверок production SQL ритма", () => {
  const job = workflow.jobs.web;
  assert.match(job.services?.clickhouse?.image ?? "", /^clickhouse\/clickhouse-server:/);
  const testStep = job.steps.find((step) => /npm test\b/.test(step.run ?? ""));
  assert.equal(testStep?.env?.ARGUS_TEST_CLICKHOUSE_URL, "http://localhost:8123");
  assert.ok(testStep?.env?.ARGUS_TEST_CLICKHOUSE_PASSWORD);
});
