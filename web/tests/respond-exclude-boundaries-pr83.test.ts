/* eslint-disable @typescript-eslint/no-require-imports -- реальные запросы сохраняются до установки Next mocks */
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { formData, installNextMocks, isRedirect, loadAuth } from "./_next-mock";

// Никаких живых сервисов: fetch целиком подменяется в каждом подтесте.
process.env.CLICKHOUSE_URL = "http://127.0.0.1:9";
process.env.CLICKHOUSE_USER = "pr83-fixture";
process.env.CLICKHOUSE_PASSWORD = "pr83-fixture-password";
process.env.ENGINE_TOKEN = "pr83-fixture-engine-token";
const realQueries = require("../src/lib/argus-queries") as typeof import("../src/lib/argus-queries");
const mocks = installNextMocks();
// authorize, audit, chCommand и обе HTTP-обёртки остаются настоящими.
mocks.queries.audit = realQueries.audit;
mocks.queries.requestExcludeIp = realQueries.requestExcludeIp;
mocks.queries.requestRevokeExclusion = realQueries.requestRevokeExclusion;
const auth = loadAuth();
const actions = require("../src/lib/respond-actions") as typeof import("../src/lib/respond-actions");

const ip = "203.0.113.83";
const user = "sso:pr83-admin";
const reason = "согласованное окно сканирования";
const until = "2026-11-02 10:00:00";
const operations = [
  {
    name: "исключение", endpoint: "/respond/exclude", auditAction: "respond.exclude_ip",
    run: actions.excludeIpAction,
    unavailable: "журнал реагирования недоступен — исключение не применено, повторите позже",
  },
  {
    name: "отзыв", endpoint: "/respond/exclude/revoke", auditAction: "respond.exclude_revoke",
    run: actions.revokeExclusionAction,
    unavailable: "журнал реагирования недоступен — исключение не отозвано, повторите позже",
  },
] as const;

type RequestRecord = { kind: "audit" | "engine"; url: URL; body: string };

function transport(t: TestContext, opts: {
  audit?: (n: number) => Promise<Response>;
  engine?: () => Response;
} = {}): RequestRecord[] {
  const calls: RequestRecord[] = [];
  let audits = 0;
  t.mock.method(console, "error", () => undefined);
  t.mock.method(globalThis, "fetch", async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const body = String(init?.body ?? "");
    assert.equal(init?.method, "POST");
    if (url.pathname === "/respond/exclude" || url.pathname === "/respond/exclude/revoke") {
      calls.push({ kind: "engine", url, body });
      assert.equal(new Headers(init?.headers).get("X-Argus-Token"), process.env.ENGINE_TOKEN);
      return opts.engine?.() ?? Response.json({ ip, until });
    }
    assert.match(body, /^\s*INSERT INTO console_audit\b/, "разрешён только ожидаемый запрос аудита");
    calls.push({ kind: "audit", url, body });
    assert.equal(url.searchParams.get("wait_end_of_query"), "1");
    return opts.audit ? opts.audit(++audits) : new Response("");
  });
  return calls;
}

async function login(role: "viewer" | "analyst" | "admin") {
  mocks.jar.clear();
  await auth.createSession(`sso:pr83-${role}`, role, true);
}

function validForm() {
  return formData({ ip, ttl: "24h", reason });
}

test("PR83: границы исключения и отзыва через реальные auth/audit/HTTP-обёртки", async (t) => {
  t.after(() => fs.rmSync(path.dirname(mocks.authFile), { recursive: true, force: true }));

  for (const op of operations) {
    for (const role of ["viewer", "analyst"] as const) {
      await t.test(`${op.name}: ${role} не может вызвать действие напрямую`, async (t) => {
        await login(role);
        const calls = transport(t);
        const result = await op.run(validForm());
        assert.match(result.error ?? "", /Недостаточно прав/);
        assert.equal(calls.length, 0, "отказ до аудита и движка");
      });
    }

    await t.test(`${op.name}: без сессии нет побочных эффектов`, async (t) => {
      mocks.jar.clear();
      const calls = transport(t);
      await assert.rejects(op.run(validForm()), isRedirect);
      assert.equal(calls.length, 0);
    });

    await t.test(`${op.name}: нужно дождаться записи аудита`, { timeout: 5000 }, async (t) => {
      await login("admin");
      let signalStarted!: () => void;
      let releaseAudit!: () => void;
      const started = new Promise<void>((resolve) => { signalStarted = resolve; });
      const committed = new Promise<void>((resolve) => { releaseAudit = resolve; });
      const calls = transport(t, {
        audit: async (n) => {
          if (n === 1) {
            signalStarted();
            await committed;
          }
          return new Response("");
        },
      });
      const form = validForm();
      form.set("user", "forged-user");
      form.set("role", "viewer");
      form.set("reason", `  ${reason}  `);
      const pending = op.run(form);
      try {
        await started;
        assert.deepEqual(calls.map((c) => c.kind), ["audit"], "незавершённый INSERT не разрешает вызов движка");
      } finally {
        releaseAudit();
      }
      assert.deepEqual(await pending, { error: null, ok: true });
      assert.deepEqual(calls.map((c) => c.kind), ["audit", "engine", "audit"]);
      assert.equal(calls[0].url.searchParams.get("param_user"), user, "автор берётся из сессии");
      assert.equal(calls[0].url.searchParams.get("param_action"), op.auditAction);
      assert.equal(calls[0].url.searchParams.get("param_target"), ip);
      assert.ok(calls[0].url.searchParams.get("param_detail")?.includes(reason));
      assert.equal(calls[1].url.pathname, op.endpoint);
      assert.deepEqual(JSON.parse(calls[1].body), {
        ip, user, reason, ...(op.endpoint === "/respond/exclude" ? { ttl: "24h" } : {}),
      });
    });

    await t.test(`${op.name}: сбой настоящего INSERT аудита останавливает действие`, async (t) => {
      await login("admin");
      const marker = "pr83-private-clickhouse-error";
      const calls = transport(t, {
        audit: async () => new Response(`Code: 241. DB::Exception: ${marker}`, {
          status: 500, headers: { "X-ClickHouse-Exception-Code": "241" },
        }),
      });
      const result = await op.run(validForm());
      assert.match(result.error ?? "", /журнал действий недоступен/);
      assert.equal(result.ok, undefined);
      assert.ok(!JSON.stringify(result).includes(marker), "тело ошибки хранилища не уходит клиенту");
      assert.deepEqual(calls.map((c) => c.kind), ["audit"]);
    });

    await t.test(`${op.name}: причина обязательна на сервере`, async (t) => {
      await login("admin");
      const calls = transport(t);
      for (const invalid of [null, "", " \t\r\n ", "ab"]) {
        const form = validForm();
        if (invalid === null) form.delete("reason");
        else form.set("reason", invalid);
        const result = await op.run(form);
        assert.match(result.error ?? "", /причин/);
      }
      assert.equal(calls.length, 0);
    });

    await t.test(`${op.name}: текст 503 доходит через транспорт, посторонние поля — нет`, async (t) => {
      await login("admin");
      const marker = "pr83-private-debug-field";
      const calls = transport(t, {
        engine: () => Response.json({ error: op.unavailable, debug: marker }, { status: 503 }),
      });
      const result = await op.run(validForm());
      assert.deepEqual(result, { error: op.unavailable });
      assert.ok(!JSON.stringify(result).includes(marker));
      assert.deepEqual(calls.map((c) => c.kind), ["audit", "engine", "audit"]);
      assert.equal(calls[2].url.searchParams.get("param_detail"), op.unavailable);
    });
  }

  await t.test("срок: произвольная длительность и отсутствие значения отвергаются до записи", async (t) => {
    await login("admin");
    const calls = transport(t);
    for (const ttl of [null, "", "1m", "5m", "2h", "0", "-1h", "721h", "24h ", "86400s"]) {
      const form = validForm();
      if (ttl === null) form.delete("ttl");
      else form.set("ttl", ttl);
      const result = await actions.excludeIpAction(form);
      assert.match(result.error ?? "", /срок/);
    }
    assert.equal(calls.length, 0);
  });

  await t.test("срок: все пять разрешённых значений передаются движку без преобразования", async (t) => {
    await login("admin");
    const calls = transport(t);
    const ttls = ["1h", "24h", "72h", "168h", "720h"];
    for (const ttl of ttls) {
      const result = await actions.excludeIpAction(formData({ ip, ttl, reason }));
      assert.deepEqual(result, { error: null, ok: true });
    }
    assert.deepEqual(calls.filter((c) => c.kind === "engine").map((c) => JSON.parse(c.body).ttl), ttls);
  });
});
