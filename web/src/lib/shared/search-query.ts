// Разбор строки поиска (аналог Discover): свободный текст, field:value,
// кавычки, отрицание, сравнения. Чистая функция — общая для сервера и тестов.
//
//   root 203.0.113.5                → оба слова где угодно в записи
//   agent:web-01 level:>=10         → поле = значение, сравнение
//   -group:syscheck  group!=sca     → отрицание
//   desc:"brute force" srcip:10.0.*  → фраза, маска; внутри кавычек \" — кавычка
//   actor:"svc-\*"                   → в кавычках «*» — литерал (\* — так пишут точные фильтры MCP)
//   desc:~"*brute force*"            → маска с пробелами: ~ перед кавычками
// Старая форма desc:"*foo*" (маска в кавычках) больше не маска: сервер
// отвечает подсказкой, а не пустой выдачей (starInQuotes).
export type Op = "=" | "!=" | ">" | ">=" | "<" | "<=";
/** quoted — значение в кавычках: точное; mask — ~"…": «*» в нём — маска;
 *  starInQuotes — в обычных кавычках есть неэкранированная «*» (старая маска). */
export type Term = { field: string | null; op: Op; value: string; negate: boolean; quoted?: true; mask?: true; starInQuotes?: true };

const OPS: Op[] = [">=", "<=", "!=", ">", "<", "="];
const FIELD_RE = /^([A-Za-z_][\w.]*)(?:(!=|>=|<=|>|<|=)?:|(!=|>=|<=|>|<))/;

type Value = { value: string; quoted?: true; mask?: true; starInQuotes?: true };

export function parseQuery(input: string): Term[] {
  const terms: Term[] = [];
  const s = input.trim();
  let i = 0;
  const readValue = (): Value => {
    const mask = s[i] === "~" && s[i + 1] === '"';
    if (mask) i++;
    if (s[i] === '"') {
      let out = "";
      let star = false;
      i++;
      while (i < s.length && s[i] !== '"') {
        if (s[i] === "\\" && i + 1 < s.length && (s[i + 1] === '"' || s[i + 1] === "\\" || s[i + 1] === "*")) {
          i++;
        } else if (s[i] === "*") {
          star = true;
        }
        out += s[i++];
      }
      i++; // закрывающая кавычка (или конец строки — незакрытая фраза читается до конца)
      const v: Value = { value: out, quoted: true };
      if (mask) v.mask = true;
      else if (star) v.starInQuotes = true;
      return v;
    }
    const start = i;
    while (i < s.length && !/\s/.test(s[i])) i++;
    return { value: s.slice(start, i) };
  };
  while (i < s.length) {
    while (i < s.length && /\s/.test(s[i])) i++;
    if (i >= s.length) break;
    let negate = false;
    if (s[i] === "-" && i + 1 < s.length && !/\s/.test(s[i + 1])) {
      negate = true;
      i++;
    }
    // Формы: field:value, field:>=5, field>=5, field!=x, field>=:5
    const m = FIELD_RE.exec(s.slice(i));
    if (m) {
      i += m[0].length;
      let op: Op = ((m[2] ?? m[3]) as Op | undefined) ?? "=";
      // оператор после двоеточия: field:>=5, field:=5
      const after = OPS.find((o) => s.startsWith(o, i));
      if (after && op === "=") {
        op = after;
        i += after.length;
      }
      const { value, ...flags } = readValue();
      if (value !== "") terms.push({ field: normalizeField(m[1]), op, value, negate, ...flags });
      continue;
    }
    const { value, ...flags } = readValue();
    if (value !== "") terms.push({ field: null, op: "=", value, negate, ...flags });
  }
  return terms;
}

/** Имя поля — без учёта регистра, но ключ атрибута (attr.<ключ>) — как написан:
 *  ключи Map в событиях приходят из CEF/LEEF как есть (filePath, cs1Label). */
export function normalizeField(field: string): string {
  const dot = field.indexOf(".");
  if (dot > 0 && field.slice(0, dot).toLowerCase() === "attr") return "attr." + field.slice(dot + 1);
  return field.toLowerCase();
}

const NEEDS_QUOTES = /^(!=|>=|<=|>|<|=|-|~)|[\s"]/;

/** Обратно в строку — чтобы дописать фильтр в URL. Значение в кавычках —
 *  литерал: «*» экранируется (\*); маска с пробелами — ~"…". */
export function termToString(t: Term): string {
  const esc = (v: string, star: boolean) => v.replace(/[\\"]/g, "\\$&").replace(/\*/g, star ? "\\*" : "*");
  let v: string;
  if (t.mask) v = `~"${esc(t.value, false)}"`;
  else if (NEEDS_QUOTES.test(t.value) || t.value === "" || (t.quoted && t.value.includes("*"))) v = `"${esc(t.value, true)}"`;
  else v = t.value;
  const op = t.op === "=" ? "" : t.op;
  return `${t.negate ? "-" : ""}${t.field ? `${t.field}${op}:` : ""}${v}`;
}

/** Дописать условие field=value. По умолчанию — как набрано: «*» остаётся
 *  маской (журнал: rule a41c-*). literal — значение из данных (фасет):
 *  «*» в нём буквальная. */
export function appendTerm(query: string, field: string, value: string, opts: { literal?: boolean } = {}): string {
  const exists = parseQuery(query).some((t) => t.field === field && t.op === "=" && !t.negate && t.value === value);
  if (exists) return query;
  const term: Term = { field, op: "=", value, negate: false };
  if (opts.literal) term.quoted = true;
  return `${query} ${termToString(term)}`.trim();
}
