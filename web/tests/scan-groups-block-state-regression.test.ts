import { test } from "node:test";
import assert from "node:assert/strict";
import { BLOCK_LABEL, blockState } from "../src/lib/shared/scan-groups";

test("PR65: отказ снятия не выдаётся за отсутствие успешной блокировки", () => {
  // release() вызывается для уже активного Block. На ошибке/unsupported
  // Responder.Expire и Unblock сохраняют исполнителя в active[ip].
  for (const detail of [
    "HTTP 503 — повтор через 5 мин",
    "снятие не настроено (unblock) — блок остаётся постоянным, снимите на NGFW вручную",
  ]) {
    const state = blockState({ executor: "ngfw.edge.unblock", mode: "ips", dry_run: 0, ok: 0, detail });
    assert.notEqual(BLOCK_LABEL[state], "блокировка не выполнена",
      "неудачное снятие оставляет блок активным; подпись должна отражать блок/ошибку снятия");
    assert.notEqual(state, "released");
    assert.notEqual(state, "none");
  }
});
