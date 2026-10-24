import { test } from "node:test";
import assert from "node:assert/strict";
import { fetchAllItems, WazuhApiError } from "../src/lib/wazuh-api";

test("управление получает все 800 агентов по страницам", async () => {
  const paths: string[] = [];
  const rows = Array.from({ length: 800 }, (_, i) => ({ id: String(i) }));
  const got = await fetchAllItems("/agents?sort=%2Bid", async (path) => {
    paths.push(path);
    const url = new URL(path, "https://wazuh.example.org");
    const offset = Number(url.searchParams.get("offset"));
    const limit = Number(url.searchParams.get("limit"));
    return { data: { affected_items: rows.slice(offset, offset + limit), total_affected_items: rows.length } };
  });
  assert.equal(got.length, 800);
  assert.equal(got[799].id, "799");
  assert.deepEqual(paths.map((p) => new URL(p, "https://wazuh.example.org").searchParams.get("offset")), ["0", "500"]);
});

test("частичный ответ Wazuh не выглядит полным списком", async () => {
  await assert.rejects(
    fetchAllItems("/agents", async () => ({ data: { affected_items: [], total_affected_items: 800 } })),
    WazuhApiError,
  );
});
