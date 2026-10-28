// Вердикт агента разбора (argus-triage/v3): проверка документа по схеме,
// сверка с областью сессии, проверка свободного текста и сборка Markdown.
// Чистые функции — без БД и Next: их гоняют тесты и маршрут
// POST /api/triage/verdicts. Схема — triage-verdict.schema.json рядом.
import schemaJson from "./triage-verdict.schema.json";
import type { TriageScope } from "./triage";

export const VERDICT_SCHEMA_ID = "argus-triage/v3";
/** Потолок тела запроса с вердиктом, байт. */
export const VERDICT_MAX_BYTES = 64 * 1024;
/** Имя агента в комментарии (author = agent:<имя>). */
export const AGENT_NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
export const DEFAULT_AGENT = "agent";

export type Rejection = { path: string; code: "schema" | "incident" | "unknown_ref" | "unsafe_text" };

type Json = string | number | boolean | null | Json[] | { [k: string]: Json };
type Schema = {
  $ref?: string;
  type?: string | string[];
  const?: Json;
  enum?: Json[];
  pattern?: string;
  minLength?: number;
  maxLength?: number;
  minItems?: number;
  maxItems?: number;
  uniqueItems?: boolean;
  items?: Schema;
  contains?: Schema;
  required?: string[];
  properties?: Record<string, Schema>;
  additionalProperties?: boolean;
  allOf?: Schema[];
  anyOf?: Schema[];
  oneOf?: Schema[];
  not?: Schema;
  if?: Schema;
  then?: Schema;
  else?: Schema;
  $defs?: Record<string, Schema>;
};

const ROOT = schemaJson as unknown as Schema;

/** Схема вердикта как есть — для GET /api/triage/schema: агент берёт актуальную версию
 *  с сервера, а не копию в своих инструкциях. Версия — const поля schema_version. */
export const VERDICT_SCHEMA: unknown = schemaJson;
export const VERDICT_SCHEMA_VERSION = "argus-triage/v3";

/* ===== Маленький валидатор подмножества JSON Schema 2020-12, которым
   написана схема вердикта: type, const, enum, pattern, min/maxLength,
   min/maxItems, uniqueItems, items, contains, required, properties,
   additionalProperties: false, allOf/anyOf/oneOf/not, if/then/else, $ref на
   #/$defs/*. Лишняя зависимость ради одной схемы не нужна. ===== */

const regexCache = new Map<string, RegExp>();
function regex(pattern: string): RegExp {
  let re = regexCache.get(pattern);
  if (!re) {
    try {
      re = new RegExp(pattern, "u");
    } catch {
      re = new RegExp(pattern);
    }
    regexCache.set(pattern, re);
  }
  return re;
}

function deref(s: Schema): Schema {
  if (!s.$ref) return s;
  const m = /^#\/\$defs\/([A-Za-z0-9_]+)$/.exec(s.$ref);
  const target = m ? ROOT.$defs?.[m[1]] : undefined;
  if (!target) throw new Error(`схема вердикта: неизвестная ссылка ${s.$ref}`);
  return deref(target);
}

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

function typeOk(t: string, v: unknown): boolean {
  switch (t) {
    case "object": return isObj(v);
    case "array": return Array.isArray(v);
    case "string": return typeof v === "string";
    case "boolean": return typeof v === "boolean";
    case "null": return v === null;
    case "number": return typeof v === "number" && Number.isFinite(v);
    case "integer": return typeof v === "number" && Number.isInteger(v);
    default: return false;
  }
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((x, i) => deepEqual(x, b[i]));
  if (isObj(a) && isObj(b)) {
    const ka = Object.keys(a).sort();
    const kb = Object.keys(b).sort();
    return deepEqual(ka, kb) && ka.every((k) => deepEqual(a[k], b[k]));
  }
  return false;
}

/** Длина строки в кодовых точках, как считает JSON Schema. */
const cpLength = (s: string): number => [...s].length;

export function schemaValid(s0: Schema, v: unknown): boolean {
  const s = deref(s0);
  if (s.type !== undefined) {
    const types = Array.isArray(s.type) ? s.type : [s.type];
    if (!types.some((t) => typeOk(t, v))) return false;
  }
  if ("const" in s && !deepEqual(v, s.const)) return false;
  if (s.enum && !s.enum.some((e) => deepEqual(e, v))) return false;
  if (typeof v === "string") {
    if (s.minLength !== undefined && cpLength(v) < s.minLength) return false;
    if (s.maxLength !== undefined && cpLength(v) > s.maxLength) return false;
    if (s.pattern !== undefined && !regex(s.pattern).test(v)) return false;
  }
  if (Array.isArray(v)) {
    if (s.minItems !== undefined && v.length < s.minItems) return false;
    if (s.maxItems !== undefined && v.length > s.maxItems) return false;
    if (s.uniqueItems && v.some((x, i) => v.slice(0, i).some((y) => deepEqual(x, y)))) return false;
    if (s.items && !v.every((x) => schemaValid(s.items!, x))) return false;
    if (s.contains && !v.some((x) => schemaValid(s.contains!, x))) return false;
  }
  if (isObj(v)) {
    if (s.required && !s.required.every((k) => Object.hasOwn(v, k))) return false;
    if (s.properties) {
      for (const [k, ps] of Object.entries(s.properties)) if (Object.hasOwn(v, k) && !schemaValid(ps, v[k])) return false;
    }
    if (s.additionalProperties === false) {
      const known = s.properties ?? {};
      if (Object.keys(v).some((k) => !Object.hasOwn(known, k))) return false;
    }
  }
  if (s.allOf && !s.allOf.every((x) => schemaValid(x, v))) return false;
  if (s.anyOf && !s.anyOf.some((x) => schemaValid(x, v))) return false;
  if (s.oneOf && s.oneOf.filter((x) => schemaValid(x, v)).length !== 1) return false;
  if (s.not && schemaValid(s.not, v)) return false;
  if (s.if) {
    const branch = schemaValid(s.if, v) ? s.then : s.else;
    if (branch && !schemaValid(branch, v)) return false;
  }
  return true;
}

const PLAIN_KEY_RE = /^[A-Za-z0-9_]+$/;
/** Имя чужого ключа в ответ не повторяем: длинное или странное — «?». */
const pointerKey = (k: string): string => (k.length > 32 || !PLAIN_KEY_RE.test(k) ? "?" : k);

/** Шаг 1: схема. Пути — до свойства верхнего уровня или элемента массива;
 *  условия между полями (allOf корня) — путь «». */
export function validateVerdictSchema(doc: unknown): Rejection[] {
  if (!isObj(doc)) return [{ path: "", code: "schema" }];
  const out: Rejection[] = [];
  const props = ROOT.properties ?? {};
  for (const k of Object.keys(doc).sort()) {
    if (!Object.hasOwn(props, k)) {
      out.push({ path: "/" + pointerKey(k), code: "schema" });
      continue;
    }
    const ps = props[k];
    if (schemaValid(ps, doc[k])) continue;
    const items = deref(ps).items;
    let found = false;
    if (items && Array.isArray(doc[k])) {
      (doc[k] as unknown[]).forEach((it, i) => {
        if (!schemaValid(items, it)) {
          out.push({ path: `/${k}/${i}`, code: "schema" });
          found = true;
        }
      });
    }
    if (!found) out.push({ path: "/" + k, code: "schema" });
  }
  for (const r of ROOT.required ?? []) if (!Object.hasOwn(doc, r)) out.push({ path: "/" + r, code: "schema" });
  if (out.length === 0 && !schemaValid(ROOT, doc)) out.push({ path: "", code: "schema" });
  return out;
}

/* ===== Шаги 2–5: инцидент сессии, ссылки, свободный текст ===== */

export type VerdictDoc = {
  schema: string;
  incident_id: string;
  level: string;
  rule_id: string;
  verdict: "true_positive" | "benign_true_positive" | "false_positive" | "undetermined";
  confidence: "high" | "medium" | "low";
  human_needed: boolean;
  human_reason?: string;
  summary: string;
  subject: { kind: string; display: string };
  evidence: { ts: string; source: string; fact: string; provenance: string; attacker_control: string; direction: string; refs: string[] }[];
  gaps: string[];
  related: { incident_id: string; relation: string; note?: string }[];
  recommendation: { console_status: string; status_reason: string; actions: { action: string; target?: string }[]; exception: { field: string; value: string } | null };
  injection_suspected: boolean;
  injection_reason: string | null;
  injection_fields: string[];
  damaged_values: { field: string; reason: string }[];
  engine_verdict: { used: boolean; disagreement: string };
  pii_seen: boolean;
  behavior_assessment: string;
};

const INCIDENT_ID_RE = /^INC-[0-9]{1,9}$/;
const INCIDENT_IN_TEXT_RE = /\bINC-([0-9]{1,9})\b/gi;
const PSEUDONYM_IN_TEXT_RE = /\b(?:subj|host)-[0-9a-f]{10}\b/i;
/** Ссылки и схемы, которые свободный текст не содержит никогда (второй рубеж после схемы). */
const LINK_IN_TEXT_RE = /:\/\/|\bwww\.|(^|\s)\/\/\S|\b(?:javascript|vbscript|data|mention|mailto):|!\[|<[^>]*>|`/i;

const MAX_MARKS = 2;
const DEFAULT_IGNORABLE_RE = /\p{Default_Ignorable_Code_Point}/u;
const MARK_RE = /[\p{Mn}\p{Mc}]/u;
const MARK_SCRIPT_RE = /[\p{Script=Inherited}\p{Script=Latin}\p{Script=Cyrillic}]/u;
const ALLOWED_CAT_RE = /[\p{L}\p{N}\p{P}\p{S}\p{Zs}]/u;
const ALLOWED_SCRIPT_RE = /[\p{Script=Latin}\p{Script=Cyrillic}\p{Script=Common}]/u;
const BASE_RE = /[\p{L}\p{N}]/u;

/** Запрещённые символы Common: блок Musical Symbols (в нём невидимый U+1D159),
 *  U+FFFC и Enclosed Alphanumeric Supplement (буквы в рамках, флаговые буквы). */
function bannedRune(cp: number): boolean {
  return (cp >= 0x1d100 && cp <= 0x1d1ff) || cp === 0xfffc || (cp >= 0x1f100 && cp <= 0x1f1ff);
}

/** Управляющие и форматные символы (ZWSP, bidi, BOM), невидимые и запрещённые блоки — для структурных полей. */
export function badRunes(v: string): boolean {
  for (const ch of v) {
    const cp = ch.codePointAt(0)!;
    if (cp === 0xfffd || bannedRune(cp) || /[\p{Cc}\p{Cf}\p{Cs}]/u.test(ch) || DEFAULT_IGNORABLE_RE.test(ch)) return true;
  }
  return false;
}

/** Свободный текст вердикта — разрешающий список: буквы, цифры, знаки и
 *  пробел латиницы, кириллицы и Common; диакритика — не больше двух знаков
 *  на букву; никаких управляющих, форматных, частных и неназначенных символов,
 *  не-ASCII пробелов и невидимых. */
export function badFreeText(v: string): boolean {
  let marks = 0;
  let base = false;
  for (const ch of v) {
    const cp = ch.codePointAt(0)!;
    if (ch === "\n" || ch === "\t") {
      base = false;
      continue;
    }
    if (cp === 0xfffd || bannedRune(cp) || DEFAULT_IGNORABLE_RE.test(ch)) return true;
    if (ch !== " " && /\p{Zs}/u.test(ch)) return true;
    if (MARK_RE.test(ch)) {
      marks++;
      if (!base || marks > MAX_MARKS || !MARK_SCRIPT_RE.test(ch)) return true;
      continue;
    }
    if (!ALLOWED_CAT_RE.test(ch)) return true;
    if (!ALLOWED_SCRIPT_RE.test(ch)) return true;
    marks = 0;
    base = BASE_RE.test(ch);
  }
  return false;
}

/** Пути свободного текста (остальные строки — структурные: токены, enum, даты). */
function freeTextPaths(doc: VerdictDoc): [string, string][] {
  const out: [string, string][] = [];
  const add = (path: string, v: unknown) => { if (typeof v === "string") out.push([path, v]); };
  add("/summary", doc.summary);
  add("/human_reason", doc.human_reason);
  add("/injection_reason", doc.injection_reason);
  add("/recommendation/status_reason", doc.recommendation?.status_reason);
  add("/engine_verdict/disagreement", doc.engine_verdict?.disagreement);
  (doc.gaps ?? []).forEach((g, i) => add(`/gaps/${i}`, g));
  (doc.evidence ?? []).forEach((e, i) => add(`/evidence/${i}/fact`, e?.fact));
  (doc.related ?? []).forEach((r, i) => add(`/related/${i}/note`, r?.note));
  return out;
}

function walkStrings(v: unknown, path: string, fn: (path: string, s: string) => void): void {
  if (typeof v === "string") fn(path, v);
  else if (Array.isArray(v)) v.forEach((x, i) => walkStrings(x, `${path}/${i}`, fn));
  else if (isObj(v)) for (const [k, x] of Object.entries(v)) walkStrings(x, `${path}/${pointerKey(k)}`, fn);
}

export type VerdictContext = {
  scope: Pick<TriageScope, "incidentId" | "related">;
  /** Инцидент сессии из хранилища: уровень и правило вердикта должны совпасть. */
  incident?: { level: string; rule_id: string } | null;
};

/** Шаги 2–5 контракта после схемы: инцидент сессии; INC-ссылки доводов и
 *  related — только свой и связанные из токена; строки без управляющих
 *  символов; свободный текст — без ссылок, разметки, псевдонимов и чужих
 *  номеров инцидентов. Первое отклонение каждого шага прерывает проверку. */
export function checkVerdict(doc: VerdictDoc, ctx: VerdictContext): Rejection[] {
  const out: Rejection[] = [];
  if (doc.incident_id !== ctx.scope.incidentId) out.push({ path: "/incident_id", code: "incident" });
  if (ctx.incident) {
    if (doc.level !== ctx.incident.level) out.push({ path: "/level", code: "incident" });
    if (doc.rule_id !== ctx.incident.rule_id) out.push({ path: "/rule_id", code: "incident" });
  }
  if (out.length) return out;

  const known = (id: string) => id === ctx.scope.incidentId || Object.hasOwn(ctx.scope.related, id);
  doc.evidence.forEach((e, i) => e.refs.forEach((r, j) => {
    if (INCIDENT_ID_RE.test(r) && !known(r)) out.push({ path: `/evidence/${i}/refs/${j}`, code: "unknown_ref" });
  }));
  doc.related.forEach((r, i) => {
    if (!INCIDENT_ID_RE.test(r.incident_id) || !known(r.incident_id)) out.push({ path: `/related/${i}/incident_id`, code: "unknown_ref" });
  });
  if (out.length) return out.slice(0, 10);

  const free = new Set(freeTextPaths(doc).map(([p]) => p));
  walkStrings(doc, "", (path, v) => {
    if (free.has(path)) return;
    if (badRunes(v)) out.push({ path, code: "schema" });
  });
  for (const [path, v] of freeTextPaths(doc)) {
    if (badFreeText(v) || LINK_IN_TEXT_RE.test(v)) {
      out.push({ path, code: "unsafe_text" });
      continue;
    }
    const nfkc = v.normalize("NFKC");
    if (PSEUDONYM_IN_TEXT_RE.test(v) || PSEUDONYM_IN_TEXT_RE.test(nfkc)) {
      out.push({ path, code: "unsafe_text" });
      continue;
    }
    const foreign = [v, nfkc].some((f) => [...f.matchAll(INCIDENT_IN_TEXT_RE)].some((m) => !known("INC-" + m[1])));
    if (foreign) out.push({ path, code: "unknown_ref" });
  }
  return out.slice(0, 10);
}

/* ===== Шаг 6: Markdown по фиксированному шаблону ===== */

const URL_RE = /\b[a-z][a-z0-9+.-]{1,15}:\/{1,}\S*|\b(?:javascript|vbscript|data|mention|mailto):\S*|\bwww\.\S+/gi;
const PROTO_REL_URL_RE = /(^|\s)\/\/\S+/g;
const HTML_RE = /<[^>]*>?/g;
const IMAGE_RE = /!\[[^\]]*\]\([^)]*\)?/g;
const MD_LINK_RE = /\[([^\]]*)\]\([^)]*\)?/g;
const MD_ESC_RE = /[\\`*_{}[\]()#+!|<>~@=$&;]/g;
const REMOVED = "[ссылка удалена]";

/** Простой текст без ссылок, картинок, HTML и управляющих символов, в одну строку. */
export function plainText(s: string): string {
  let out = "";
  for (const ch of s) out += /[\p{Cc}\p{Cf}]/u.test(ch) ? " " : ch;
  out = out.replace(IMAGE_RE, "").replace(MD_LINK_RE, "$1").replace(URL_RE, REMOVED).replace(PROTO_REL_URL_RE, `$1${REMOVED}`).replace(HTML_RE, "");
  return out.trim().replace(/\s+/g, " ");
}

/** plainText с экранированием спецсимволов Markdown. */
export function plain(s: string): string {
  let out = plainText(s).replace(MD_ESC_RE, (m) => "\\" + m);
  if (out.startsWith("-")) out = "\\" + out; // «---» в начале строки стал бы линией
  return out;
}

/** Значение в обратных кавычках: только проверенные схемой токены. */
export function code(s: string): string {
  let out = "";
  for (const ch of s) if (ch !== "`" && !/\p{Cc}/u.test(ch)) out += ch;
  return "`" + out + "`";
}

export const VERDICT_RU: Record<string, string> = {
  true_positive: "подтверждённая атака (true positive)",
  benign_true_positive: "срабатывание верное, поведение легитимное",
  false_positive: "ложное срабатывание",
  undetermined: "не определено",
};
const CONFIDENCE_RU: Record<string, string> = { high: "высокая", medium: "средняя", low: "низкая" };
const STATUS_RU: Record<string, string> = { escalated: "эскалирован", observing: "наблюдение", closed: "закрыт", false_positive: "ложное срабатывание" };
/** Уверенность вердикта числом для таблицы agent_verdicts. */
export const CONFIDENCE_NUM: Record<string, number> = { high: 0.9, medium: 0.6, low: 0.3 };

const ru = (m: Record<string, string>, k: string): string => m[k] ?? plain(k);

/** Markdown комментария: первая строка — вердикт и нужен ли человек, затем
 *  итог, доводы со ссылками, пробелы, связанные, рекомендация. Ссылок нет,
 *  псевдонимы не раскрываются. */
export function renderVerdictMarkdown(doc: VerdictDoc, agent: string, sessionId: string): string {
  const b: string[] = [];
  const inj = doc.injection_suspected === true;
  const human = doc.human_needed === true ? `нужен человек: да. ${plain(doc.human_reason ?? "")}`.trimEnd() : "нужен человек: нет.";
  b.push(`**Вердикт агента: ${ru(VERDICT_RU, doc.verdict)} · ${human}**${inj ? " ⚠️ подозрение на prompt injection" : ""}`, "");
  b.push(`- Инцидент: ${code(doc.incident_id)}, уровень ${code(doc.level)}, правило ${code(doc.rule_id)}`);
  b.push(`- Уверенность: ${ru(CONFIDENCE_RU, doc.confidence)}`);
  if (doc.subject) b.push(`- Субъект: ${plain(doc.subject.kind)} ${code(doc.subject.display)}`);
  if (doc.behavior_assessment) b.push(`- Поведение: ${plain(doc.behavior_assessment)}`);
  b.push("", "### Итог", "", plain(doc.summary));
  if (doc.evidence.length) {
    b.push("", "### Доводы", "");
    doc.evidence.forEach((e, i) => {
      const refs = e.refs.map(code).join(", ");
      b.push(`${i + 1}. ${plain(e.ts)} · ${code(e.source)} · ${plain(e.provenance)}, контроль атакующего ${plain(e.attacker_control)}, ${plain(e.direction)} — ${plain(e.fact)} (${refs})`);
    });
  }
  if (doc.gaps.length) {
    b.push("", "### Пробелы", "");
    for (const g of doc.gaps) b.push(`- ${plain(g)}`);
  }
  if (doc.related.length) {
    b.push("", "### Связанные", "");
    for (const r of doc.related) b.push(`- ${code(r.incident_id)} — ${plain(r.relation)}${r.note ? ": " + plain(r.note) : ""}`);
  }
  const rec = doc.recommendation;
  if (rec) {
    b.push("", "### Рекомендация", "");
    b.push(`- Статус в консоли: ${ru(STATUS_RU, rec.console_status)} — ${plain(rec.status_reason)}`);
    for (const a of rec.actions ?? []) b.push(`- Действие: ${code(a.action)}${a.target ? " → " + code(a.target) : ""}`);
    if (rec.exception) b.push(`- Исключение: ${code(rec.exception.field)} = ${code(rec.exception.value)}`);
  }
  if (inj) {
    b.push("", "### Подозрение на prompt injection", "", plain(doc.injection_reason ?? ""));
    if (doc.injection_fields.length) b.push("", `Поля: ${doc.injection_fields.map(code).join(", ")}`);
  }
  if (doc.damaged_values.length) {
    b.push("", "### Повреждённые значения", "");
    for (const d of doc.damaged_values) b.push(`- ${code(d.field)}: ${plain(d.reason)}`);
  }
  if (doc.engine_verdict?.disagreement) b.push("", "### Расхождение с вердиктом движка", "", plain(doc.engine_verdict.disagreement));
  if (doc.pii_seen === true) b.push("", "В данных инцидента есть ПДн — смотреть в консоли.");
  b.push("", "---", `Записал агент ${code(agent)} через API консоли, сессия ${code(sessionId)}, схема ${code(VERDICT_SCHEMA_ID)}. Текст проверен и очищен консолью.`);
  return b.join("\n") + "\n";
}

/** Детерминированный UUID комментария агента по сессии разбора: повтор той же
 *  сессии пишет тот же comment_id, а не второй комментарий. Четыре 32-битных
 *  FNV-1a с разными солями дают 128 бит; версия 4 и вариант 8 выставлены,
 *  чтобы строка была валидным UUID для колонки UUID. Чистая функция. */
export function agentCommentId(sessionId: string): string {
  const h = [0, 1, 2, 3].map((i) => fnv1a32Hex(`agent-comment:${i}:${sessionId}`)).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

/** FNV-1a 32 бит → 8 hex-символов. */
function fnv1a32Hex(s: string): string {
  let h = 0x811c9dc5;
  for (const b of new TextEncoder().encode(s)) {
    h ^= b;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}
