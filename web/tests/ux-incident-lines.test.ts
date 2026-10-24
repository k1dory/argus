import { test } from "node:test";
import assert from "node:assert/strict";
import { parseChainLine, parseSimilarLine } from "../src/lib/shared/incident-lines";

// Формат движка: fmt.Sprintf("%s  %-16s %-14s %-24s %s", ts, source, node, action, detail)
const line = (ts: string, src: string, node: string, action: string, detail: string) =>
  `${ts}  ${src.padEnd(16)} ${node.padEnd(14)} ${action.padEnd(24)} ${detail}`;

test("строка цепочки режется по фиксированным позициям", () => {
  const s = parseChainLine(line("18:05:07", "k8s.audit", "prod-node-1", "pod.exec", "kubectl exec -it web-0 -- sh"));
  assert.deepEqual(s, { kind: "event", ts: "18:05:07", source: "k8s.audit", node: "prod-node-1", action: "pod.exec", detail: "kubectl exec -it web-0 -- sh" });
});

test("пробелы внутри узла/действия не ломают разбор (позиции, а не split)", () => {
  const s = parseChainLine(line("00:00:01", "waf", "edge 1", "http attack", "203.0.113.5:443"));
  assert.equal(s.kind, "event");
  if (s.kind === "event") {
    assert.equal(s.node, "edge 1");
    assert.equal(s.action, "http attack");
    assert.equal(s.detail, "203.0.113.5:443");
  }
});

test("примечание движка и сырые строки", () => {
  assert.deepEqual(parseChainLine("→ 5 событий за 60 с"), { kind: "note", text: "5 событий за 60 с" });
  assert.deepEqual(parseChainLine("что-то без формата"), { kind: "raw", text: "что-то без формата" });
});

test("похожие инциденты: заголовок правила может содержать « · », заметка — последняя", () => {
  const s = parseSimilarLine("INC-12 · 2026-09-01 · closed · SSH · brute force · ложное, адрес партнёра");
  assert.deepEqual(s, { id: "INC-12", date: "2026-09-01", status: "closed", title: "SSH · brute force", note: "ложное, адрес партнёра" });
  assert.deepEqual(parseSimilarLine("INC-7 · 2026-08-30 · false_positive · Правило · "), { id: "INC-7", date: "2026-08-30", status: "false_positive", title: "Правило", note: "" });
});

test("похожие: усечённый формат и мусор", () => {
  assert.deepEqual(parseSimilarLine("INC-3 · что-то"), { id: "INC-3", date: "", status: "", title: "что-то", note: "" });
  assert.equal(parseSimilarLine("мусор"), null);
});
