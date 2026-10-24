import { test } from "node:test";
import assert from "node:assert/strict";
import { panelCacheGet, panelCachePut, panelCacheStats, type PanelData } from "../src/lib/dashboards";

const data = (rows: number, width = 10): PanelData => ({
  columns: ["v"],
  rows: Array.from({ length: rows }, (_, i) => ({ v: "x".repeat(width) + i })),
  ms: 1,
});

test("panelCache: TTL, замена по ключу, результат > 2000 строк не кэшируется", () => {
  const now = 1_000_000;
  assert.equal(panelCachePut("k1", data(3), now), true);
  assert.deepEqual(panelCacheGet("k1", 30_000, now + 29_999)?.rows.length, 3);
  assert.equal(panelCacheGet("k1", 30_000, now + 30_000), null, "TTL истёк");
  assert.equal(panelCacheGet("nope", 30_000, now), null);
  const before = panelCacheStats();
  assert.equal(panelCachePut("k1", data(5), now), true);
  assert.equal(panelCacheStats().entries, before.entries, "замена по ключу не плодит записи");
  assert.equal(panelCacheGet("k1", 30_000, now)?.rows.length, 5);
  assert.equal(panelCachePut("big", data(2001, 1), now), false, "2001 строка — мимо кэша");
  assert.equal(panelCacheGet("big", 30_000, now), null);
  assert.equal(panelCachePut("edge", data(2000, 1), now), true, "ровно 2000 — можно");
});

test("panelCache: суммарный размер ≤ 64 МБ — старые записи вытесняются, учёт байт сходится", () => {
  const now = 2_000_000;
  // ~1 МБ на запись: 1000 строк по ~1 КБ
  const mb = () => data(1000, 1000);
  const one = JSON.stringify(mb()).length;
  assert.ok(one > 1_000_000 && one < 1_100_000);
  for (let i = 0; i < 70; i++) assert.equal(panelCachePut(`mb-${i}`, mb(), now + i), true);
  const st = panelCacheStats();
  assert.ok(st.bytes <= 64 * 1024 * 1024, `байт в кэше ${st.bytes}`);
  assert.ok(st.entries < 70 && st.entries >= 60, `записей ${st.entries}`);
  assert.equal(panelCacheGet("mb-0", 1e9, now), null, "самая старая вытеснена");
  assert.ok(panelCacheGet("mb-69", 1e9, now), "самая свежая на месте");
  // Одна запись больше потолка — не кэшируется и ничего не вытесняет
  const huge: PanelData = { columns: ["v"], rows: [{ v: "y".repeat(65 * 1024 * 1024) }], ms: 1 };
  const before = panelCacheStats();
  assert.equal(panelCachePut("huge", huge, now), false);
  assert.deepEqual(panelCacheStats(), before);
});
