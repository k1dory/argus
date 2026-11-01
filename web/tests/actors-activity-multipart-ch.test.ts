// Параметры больше PARAMS_IN_URL_MAX уходят телом multipart/form-data: настоящий
// ClickHouse 24.8 принимает запрос с ~1,3 МБ параметров (тысяча персон по пять uid
// длиной 128) — без HTTP 414, одним запросом, со счётом как у предиката.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readdirSync } from "node:fs";
import { MIGRATIONS_DIR, ch, liveSkip as skip, migrationStatements, serializeLiveFile } from "./_ch-live";
import { chTs } from "../src/lib/shared/log-query";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- ClickHouse env установлен _ch-live до загрузки actors */
const actors = () => require("../src/lib/actors") as typeof import("../src/lib/actors");
/* eslint-enable @typescript-eslint/no-require-imports */

test("listPersons: тысяча персон — параметры телом multipart, без 414, счёт верный", { skip, timeout: 120_000 }, async (t) => {
  const db = `argus_actors_multipart_${randomBytes(6).toString("hex")}`;
  let database = "default", created = false;
  const events: { contentType: string; uriBytes: number; bodyBytes: number }[] = [];
  const nativeFetch = globalThis.fetch;
  t.mock.method(globalThis, "fetch", (input: URL | string | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    url.searchParams.set("database", database);
    const body = String(init?.body ?? "");
    if (body.includes("GROUP BY hits")) {
      events.push({ contentType: String(new Headers(init?.headers).get("content-type")), uriBytes: Buffer.byteLength(url.pathname + url.search), bodyBytes: Buffer.byteLength(body) });
    }
    return nativeFetch(url, init);
  });
  const now = Date.now();
  try {
    created = true;
    await ch().chCommand(`CREATE DATABASE ${db}`);
    database = db;
    for (const file of readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith(".sql")).sort()) {
      for (const sql of migrationStatements(file)) {
        if (/^CREATE DATABASE\b/i.test(sql)) continue;
        await ch().chCommand(sql.replaceAll("argus.", `${db}.`));
      }
    }
    const json = (rows: object[]) => rows.map((r) => JSON.stringify(r)).join("\n");
    const persons = Array.from({ length: 1000 }, (_, i) => `person-${String(i).padStart(4, "0")}`);
    const value = (p: string, i: number) => `${p}-${i}-`.padEnd(128, "x");
    await ch().chCommand(`INSERT INTO identities FORMAT JSONEachRow\n${json(persons.map((p) => ({ person_id: p, display: p, kind: "person", team: "", note: "", updated_at: chTs(now - 1000), deleted: 0 })))}`);
    await ch().chCommand(`INSERT INTO identity_aliases FORMAT JSONEachRow\n${json(persons.flatMap((p) => [0, 1, 2, 3, 4].map((i) => ({
      person_id: p, alias_kind: "uid", alias_value: value(p, i), valid_from: chTs(now - 30 * 86_400_000), valid_to: null,
      source: "fixture", confidence: 1, note: "", updated_at: chTs(now - 1000), deleted: 0 }))))}`);
    // События у трёх персон: 3, 1 и 2 (одна строка — по двум uid одной персоны? нет: uid разные строки).
    const ev = [["person-0000", 0], ["person-0000", 3], ["person-0000", 4], ["person-0500", 2], ["person-0999", 1], ["person-0999", 1]] as const;
    await ch().chCommand(`INSERT INTO events (ts, source, source_class, actor_name, action, outcome) FORMAT JSONEachRow\n${json(ev.map(([p, i], n) => ({
      ts: chTs(now - 3_600_000 + n * 1000), source: "fixture", source_class: "identity", actor_name: value(p, i), action: "auth.login", outcome: "success" })))}`);
    const list = await actors().listPersons("7d", now);
    assert.equal(list.length, 1000);
    assert.equal(events.length, 1, "активность — одним запросом");
    assert.match(events[0].contentType, /^multipart\/form-data; boundary=argus-/, "параметры — телом");
    assert.ok(events[0].uriBytes < 4096 && events[0].bodyBytes > 1024 * 1024, `URI ${events[0].uriBytes} байт, тело ${events[0].bodyBytes} байт`);
    const by = Object.fromEntries(list.map((p) => [p.person_id, p.events]));
    assert.deepEqual([by["person-0000"], by["person-0500"], by["person-0999"], by["person-0001"]], [3, 1, 2, 0]);
  } finally {
    database = "default";
    if (created) await ch().chCommand(`DROP DATABASE IF EXISTS ${db} SYNC`);
  }
});
