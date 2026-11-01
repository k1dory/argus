// PR #51: настоящий SQL, реальные миграции и production ROW POLICY из _ro-blind.
// Нужен одноразовый локальный ClickHouse (ARGUS_TEST_CLICKHOUSE_URL).
// Ответы SQL не эмулируются. Удаляются только собственные случайные fixture IDs.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomInt, randomUUID } from "node:crypto";
import { applyAllMigrations, ch, liveSkip as skip, serializeLiveFile } from "./_ch-live";
import { createBlindRo, queryAs } from "./_ro-blind";
import { isBlindIncident } from "../src/lib/blind";
import { chTs } from "../src/lib/shared/log-query";
import { assembleAgreement, type AgreementSqlRow, type AgreementWindow } from "../src/lib/shared/blind-metrics";

serializeLiveFile({
  before,
  // Уборка должна завершиться ДО снятия общей межпроцессной блокировки.
  after: (release) => after(async () => {
    try { await cleanupFixtures(); } finally { release(); }
  }),
});

/* eslint-disable @typescript-eslint/no-require-imports -- _ch-live задаёт env до загрузки запросов */
const metrics = () => require("../src/lib/blind-metrics") as typeof import("../src/lib/blind-metrics");
const queries = () => require("../src/lib/argus-queries") as typeof import("../src/lib/argus-queries");
/* eslint-enable @typescript-eslint/no-require-imports */

const run = randomBytes(6).toString("hex");
const now = Date.now();
const DAY = 86_400_000;
const ids: string[] = [];
let serial = randomInt(100_000_000, 800_000_000);
const rule = (name: string) => `agreement-review-${run}-${name}`;

before(async () => { if (!skip) await applyAllMigrations(); });
async function cleanupFixtures(): Promise<void> {
  if (skip || ids.length === 0) return;
  for (const table of ["agent_verdicts", "incident_state_events", "incidents"]) {
    await ch().chCommand(`ALTER TABLE ${table} DELETE WHERE has(splitByChar(',', {ids:String}), incident_id) SETTINGS mutations_sync = 1`,
      { ids: ids.join(",") });
  }
}

async function incident(ruleId: string, blind = true): Promise<string> {
  let id: string;
  do { id = `INC-${++serial}`; } while (isBlindIncident(id) !== blind);
  ids.push(id);
  await ch().chCommand(`INSERT INTO incidents
    (incident_id, created_at, updated_at, rule_id, rule_title, level, tags, status, first_ts, last_ts)
    SELECT {id:String}, parseDateTime64BestEffort({at:String}, 3, 'UTC'), parseDateTime64BestEffort({at:String}, 3, 'UTC'),
      {rule:String}, 'Agreement review fixture', 'high', [], 'new',
      parseDateTime64BestEffort({at:String}, 3, 'UTC'), parseDateTime64BestEffort({at:String}, 3, 'UTC')`,
  { id, rule: ruleId, at: chTs(now - 45 * DAY) });
  return id;
}

async function state(id: string, revision: number, at: number, status: string, disposition = ""): Promise<void> {
  await ch().chCommand(`INSERT INTO incident_state_events
    (event_id, incident_id, revision, changed_at, actor, kind, status, owner, reason,
     disposition, escalate, severity_correct, blind, labeled_by_human)
    SELECT {event:UUID}, {id:String}, {revision:UInt64}, parseDateTime64BestEffort({at:String}, 3, 'UTC'),
      {actor:String}, 'status', {status:String}, {actor:String}, 'Review fixture closure',
      {disposition:String}, false, true, {blind:Bool}, {human:Bool}`,
  { event: randomUUID(), id, revision, at: chTs(at), actor: `review-${run}`, status, disposition,
    blind: String(isBlindIncident(id)), human: String(disposition !== "") });
}

async function verdict(id: string, session: string, at: number, value: string): Promise<void> {
  // Сырые дубли допустимы схемой MergeTree. INSERT без idempotency token
  // моделирует уже существующую историю / повторную загрузку. Читатели обязаны
  // соблюдать тот же контракт «первая строка сессии», что agentVerdictsFor.
  const row = {
    incident_id: id, session_id: session, agent: "review-fixture", created_at: chTs(at),
    verdict: value, confidence: 0.9, human_needed: 0,
    verdict_json: JSON.stringify({ schema: "argus-triage/v3", incident_id: id, verdict: value }),
    markdown: "Review fixture",
  };
  await ch().chCommand(`INSERT INTO agent_verdicts FORMAT JSONEachRow\n${JSON.stringify(row)}`);
}

test("agreement: поздний дубль старой сессии не заменяет последний принятый вердикт", { skip }, async () => {
  const ruleId = rule("session-dedup");
  const id = await incident(ruleId);
  const older = randomUUID(), newer = randomUUID();
  await verdict(id, older, now - 5 * DAY, "true_positive");
  await verdict(id, newer, now - 3 * DAY, "false_positive");
  await verdict(id, older, now - 2 * DAY, "true_positive");
  await state(id, 1, now - DAY, "closed", "malicious");

  const canonical = await queries().agentVerdictsFor(id);
  assert.equal(canonical.length, 2, "контроль: два вердикта сессий, а не три сырые строки");
  assert.equal(canonical[0].session_id, newer);
  assert.equal(canonical[0].verdict, "false_positive");
  assert.equal((await queries().agentVerdictBySession(id, older))?.created_at, chTs(now - 5 * DAY));

  const result = await metrics().agreementMetrics("7d", now);
  const row = result.rules.find((r) => r.rule_id === ruleId);
  assert.ok(row);
  assert.equal(row.blind.agreement.n, 1);
  assert.equal(row.blind.agreement.k, 0,
    "последний канонический вердикт false_positive не согласуется с malicious; сырой дубль старой сессии не является новым вердиктом");
});

test("agreement: последняя закрывающая метка и последний вердикт до неё, включая равное время меток", { skip }, async (t) => {
  for (const sameTimestamp of [false, true]) {
    await t.test(sameTimestamp ? "порядок revision при равном времени" : "повторное закрытие", async () => {
      const ruleId = rule(`last-close-${sameTimestamp}`);
      const id = await incident(ruleId);
      const closeAt = now - 2 * DAY;
      await state(id, 1, sameTimestamp ? closeAt : now - 10 * DAY, "false_positive", "false_positive");
      await state(id, 2, sameTimestamp ? closeAt : now - 5 * DAY, "in_progress");
      await state(id, 3, closeAt, "closed", "benign_authorized");
      await verdict(id, randomUUID(), now - 11 * DAY, "false_positive");
      await verdict(id, randomUUID(), closeAt - 1, "benign_true_positive");
      await verdict(id, randomUUID(), closeAt + 1, "true_positive");

      for (const window of ["7d", "30d"] as const) {
        const result = await metrics().agreementMetrics(window, now);
        const row = result.rules.find((r) => r.rule_id === ruleId);
        assert.ok(row);
        assert.deepEqual([row.labeled, row.false_positive.k, row.blind.agreement.k, row.blind.agreement.n], [1, 0, 1, 1]);
      }
    });
  }
});

test("agreement: открытый/переоткрытый слепой вердикт не влияет на n=1, разность 30d−7d и правило без закрытых", { skip }, async () => {
  const smallRule = rule("n1"), windowRule = rule("windows"), onlyOpenRule = rule("only-open");
  const smallClosed = await incident(smallRule);
  const recent = await incident(windowRule), older = await incident(windowRule);
  const smallOpen = await incident(smallRule), reopened = await incident(windowRule), onlyOpen = await incident(onlyOpenRule);
  for (const [id, ago] of [[smallClosed, DAY], [recent, DAY], [older, 10 * DAY]] as const) {
    await state(id, 1, now - ago, "closed", "malicious");
    await verdict(id, randomUUID(), now - ago - DAY, "true_positive");
  }
  await state(reopened, 1, now - 4 * DAY, "closed", "malicious");
  await state(reopened, 2, now - 2 * DAY, "in_progress");
  const hidden = [smallOpen, reopened, onlyOpen];
  for (const id of hidden) await verdict(id, randomUUID(), now - 6 * DAY, "undetermined");

  const user = `agreement_review_ro_${run}`, policy = `agreement_review_ro_${run}`;
  const password = `fixture-${randomBytes(16).toString("hex")}`;
  const cleanup = await createBlindRo(user, policy, password);
  try {
    const selected = new Set([smallRule, windowRule, onlyOpenRule]);
    const project = (value: ReturnType<typeof assembleAgreement>) => ({
      rules: value.rules.filter((r) => selected.has(r.rule_id)), total: value.total,
    });
    const snapshot = async (window: AgreementWindow) => {
      const result = await metrics().agreementMetrics(window, now);
      const params = metrics().agreementParams(window, now);
      const ro = assembleAgreement(await queryAs<AgreementSqlRow>(user, password, metrics().AGREEMENT_SQL, params));
      // any(rule_title) у чужих fixture-правил может выбирать разные заголовки;
      // сравниваем свои правила и все численные итоги, не чужие заголовки.
      assert.deepEqual(project(ro), project(result), "политики RO не меняют выборку завершённых");
      return project(result);
    };
    const before7 = await snapshot("7d"), before30 = await snapshot("30d");
    assert.equal(before7.rules.find((r) => r.rule_id === smallRule)?.blind.agreement.n, 1);
    assert.equal(before7.rules.find((r) => r.rule_id === windowRule)?.blind.agreement.n, 1);
    assert.equal(before30.rules.find((r) => r.rule_id === windowRule)?.blind.agreement.n, 2);
    assert.ok(!before30.rules.some((r) => r.rule_id === onlyOpenRule), "правило с одним открытым инцидентом не даёт строку");

    // Все новые вердикты раньше старой метки reopened: одного v.created_at <=
    // closed_at недостаточно. Именно текущий статус должен исключить инцидент.
    for (const [i, value] of ["true_positive", "false_positive", "benign_true_positive"].entries()) {
      for (const id of hidden) await verdict(id, randomUUID(), now - 5 * DAY + i, value);
      assert.deepEqual(await snapshot("7d"), before7, value);
      assert.deepEqual(await snapshot("30d"), before30, value);
    }
    const [raw] = await queryAs<{ n: number | string }>(user, password,
      "SELECT count() AS n FROM agent_verdicts WHERE has(splitByChar(',', {ids:String}), incident_id)", { ids: hidden.join(",") });
    assert.equal(Number(raw.n), 0, "_ro-blind: никакой сырой агрегат не включает скрытые вердикты");
  } finally {
    await cleanup();
  }
});

test("agreementMetrics: настоящий транспорт работает под профилем argus_ro, как контрольный queryAs", { skip }, async (t) => {
  const ruleId = rule("ro-transport");
  const id = await incident(ruleId);
  await state(id, 1, now - DAY, "closed", "malicious");
  await verdict(id, randomUUID(), now - 2 * DAY, "true_positive");
  const user = `agreement_review_transport_${run}`, policy = `agreement_review_transport_${run}`;
  const password = `fixture-${randomBytes(16).toString("hex")}`;
  const cleanup = await createBlindRo(user, policy, password);
  const nativeFetch = globalThis.fetch;
  try {
    const [principal] = await queryAs<{ name: string }>(user, password, "SELECT currentUser() AS name");
    assert.equal(principal.name, user);
    const control = assembleAgreement(await queryAs<AgreementSqlRow>(user, password, metrics().AGREEMENT_SQL,
      metrics().agreementParams("7d", now)));
    assert.equal(control.rules.find((r) => r.rule_id === ruleId)?.blind.agreement.k, 1);

    // Меняем только credentials. URL, настройки, SQL и ответ — настоящие.
    const transport = t.mock.method(globalThis, "fetch", (input: URL | string | Request, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      headers.set("Authorization", "Basic " + Buffer.from(`${user}:${password}`).toString("base64"));
      return nativeFetch(input, { ...init, headers });
    });
    try {
      const actual = await metrics().agreementMetrics("7d", now);
      assert.deepEqual({ rules: actual.rules, total: actual.total }, control);
    } finally {
      transport.mock.restore();
    }
  } finally {
    await cleanup();
  }
});
