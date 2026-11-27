// Поля языка запросов по индексам: имя в запросе, подпись по-русски, пример.
// Один источник для шпаргалки синтаксиса (журнал и поиск), подписей фасетов и
// подписей полей в детали события. Таблица колонок и типов — в lib/search
// (INDEXES); тест сверяет, что набор имён там и здесь один и тот же.

export type QueryField = { field: string; label: string; example: string };

export const QUERY_FIELDS: Record<"events" | "alerts", QueryField[]> = {
  events: [
    { field: "source", label: "источник", example: "source:linux.auth" },
    { field: "class", label: "класс источника", example: "class:netflow" },
    { field: "vendor", label: "производитель", example: "vendor:mikrotik" },
    { field: "product", label: "продукт", example: "product:routeros" },
    { field: "action", label: "действие", example: "action:auth.login" },
    { field: "outcome", label: "исход", example: "outcome:failure" },
    { field: "severity", label: "серьёзность, 0–10", example: "severity>=5" },
    { field: "actor", label: "субъект", example: "actor:i.petrov" },
    { field: "object", label: "объект", example: 'object:"/etc/passwd"' },
    { field: "node", label: "хост", example: "node:web-01" },
    { field: "src", label: "IP источника", example: "src:10.20.*" },
    { field: "dst", label: "IP назначения", example: "dst:203.0.113.9" },
    { field: "sport", label: "порт источника", example: "sport:51515" },
    { field: "dport", label: "порт назначения", example: "dport:22" },
    { field: "proto", label: "протокол", example: "proto:tcp" },
    { field: "pii", label: "персональные данные, 0/1", example: "pii:1" },
    { field: "attr", label: "атрибут источника", example: "attr.rule_groups:sshd" },
    { field: "rule", label: "правило Wazuh или инцидент", example: "rule:5763" },
  ],
  alerts: [
    { field: "agent", label: "агент", example: "agent:web-01" },
    { field: "agent.id", label: "номер агента", example: "agent.id:003" },
    { field: "agent.ip", label: "IP агента", example: "agent.ip:10.0.0.5" },
    { field: "rule", label: "правило", example: "rule:5712" },
    { field: "level", label: "уровень правила, 0–15", example: "level>=10" },
    { field: "desc", label: "описание правила", example: 'desc:"brute force"' },
    { field: "group", label: "группа правила", example: "group:sshd" },
    { field: "mitre", label: "техника MITRE", example: "mitre:T1110" },
    { field: "tactic", label: "тактика MITRE", example: 'tactic:"Credential Access"' },
    { field: "decoder", label: "декодер", example: "decoder:sshd" },
    { field: "location", label: "файл журнала", example: "location:/var/log/auth.log" },
    { field: "srcip", label: "IP источника", example: "srcip:203.0.113.*" },
    { field: "manager", label: "менеджер Wazuh", example: "manager:wazuh-01" },
    { field: "log", label: "полный текст лога", example: 'log:"Failed password"' },
  ],
};

/** Операторы языка — для шпаргалки; пример кликабелен и дописывается в запрос. */
export const QUERY_OPERATORS: { op: string; label: string; example: string }[] = [
  { op: "слово", label: "слово где угодно в событии", example: "sshd" },
  { op: "-", label: "исключить условие", example: "-outcome:allow" },
  { op: "*", label: "маска", example: "src:10.20.*" },
  { op: '"…"', label: "точная фраза или значение с пробелом", example: 'object:"/etc/passwd"' },
  { op: ">= <=", label: "сравнение чисел", example: "severity>=5" },
  { op: "!=", label: "не равно", example: "outcome!=success" },
];

/** Подпись поля по имени в запросе (attr.<ключ> — «атрибут <ключ>»). */
export function queryFieldLabel(index: "events" | "alerts", field: string): string {
  if (index === "events" && field.startsWith("attr.")) return field.slice(5);
  return QUERY_FIELDS[index].find((f) => f.field === field)?.label ?? field;
}

/** Дописать пример из шпаргалки к запросу: через пробел, без повторов. */
export function addQueryTerm(q: string, term: string): string {
  const parts = q.trim().split(/\s+/).filter(Boolean);
  return parts.includes(term) ? q : [...parts, term].join(" ");
}
