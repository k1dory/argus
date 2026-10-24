// Разбор строк инцидента, которые движок хранит текстом: цепочка событий
// («ts  источник  узел  действие  деталь», ширины фиксированы: Go %-16s %-14s
// %-24s) и похожие инциденты («INC-12 · дата · статус · правило · заметка»).
// Не split по разделителю: заголовок правила и заметка сами могут содержать « · ».

export type ChainStep =
  | { kind: "event"; ts: string; source: string; node: string; action: string; detail: string }
  | { kind: "note"; text: string }
  | { kind: "raw"; text: string };

const TS_RE = /^\d{2}:\d{2}:\d{2}\s{2}/;
const LOOSE_RE = /^(\d{2}:\d{2}:\d{2})\s{2}(\S+)\s+(\S+)\s+(\S+)\s+(.*)$/;

export function parseChainLine(line: string): ChainStep {
  if (line.startsWith("→ ")) return { kind: "note", text: line.slice(2).trim() };
  const chars = [...line];
  // Поля выравнены пробелами до фиксированной ширины — режем по позициям,
  // а не по пробелам: узел или действие могут содержать пробел.
  if (TS_RE.test(line) && chars.length >= 8 + 2 + 16 + 1 + 14 + 1 + 24 + 1) {
    const at = (a: number, b: number) => chars.slice(a, b).join("").trim();
    return { kind: "event", ts: at(0, 8), source: at(10, 26), node: at(27, 41), action: at(42, 66), detail: at(67, chars.length) };
  }
  const m = LOOSE_RE.exec(line);
  if (m) return { kind: "event", ts: m[1], source: m[2], node: m[3], action: m[4], detail: m[5].trim() };
  return { kind: "raw", text: line };
}

export type SimilarIncident = { id: string; date: string; status: string; title: string; note: string };

const SIMILAR_RE = /^(INC-\d{1,9}) · (\d{4}-\d{2}-\d{2}) · ([a-z_]+) · ([\s\S]*)$/;

export function parseSimilarLine(line: string): SimilarIncident | null {
  const m = SIMILAR_RE.exec(line.trimStart());
  if (!m) {
    const id = /^(INC-\d{1,9})/.exec(line)?.[1];
    return id ? { id, date: "", status: "", title: line.slice(id.length).replace(/^\s*·\s*/, ""), note: "" } : null;
  }
  // Пустая заметка даёт хвост « · » (или « ·» после trim) — считаем его пустой заметкой.
  const rest = m[4].replace(/ ·\s*$/, " · ");
  // Заметка — последний фрагмент после « · »; заголовок правила может содержать разделитель.
  const idx = rest.lastIndexOf(" · ");
  return { id: m[1], date: m[2], status: m[3], title: (idx >= 0 ? rest.slice(0, idx) : rest).trim(), note: (idx >= 0 ? rest.slice(idx + 3) : "").trim() };
}
