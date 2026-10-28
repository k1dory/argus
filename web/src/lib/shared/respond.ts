// Режимы реагирования — общие для сервера и клиента (без импорта server-only модулей).
export const RESPOND_MODES = {
  ids: { label: "IDS — только детект", hint: "автоматика ничего не блокирует; кнопка оператора в карточке работает" },
  simulate: { label: "Симуляция", hint: "движок пишет в журнал, кого заблокировал бы, но исполнителей не вызывает" },
  ips: { label: "IPS — автоблокировка", hint: "правила с блоком respond блокируют адреса на TTL через Wazuh/NGFW; allowlist не трогается" },
} as const;
export type RespondMode = keyof typeof RESPOND_MODES;
export type RespondModeFrom = "config" | "console";
export const isRespondMode = (x: unknown): x is RespondMode => x === "ids" || x === "simulate" || x === "ips";

/** IPv4 dotted-quad с октетами 0–255. Границы — не цифра и не точка: в
 *  «10.0.0.1.5» или «1.2.3.4.5» адреса нет. Для проверки ввода на сервере
 *  используйте net.isIP — здесь только извлечение из текста. */
const IPV4_IN_TEXT_RE = /(?<![\d.])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?![\d.])/g;
/** «version 4.7.2.1», «v4.7.2.1», «ver. 4.7.2.1» — четырёхчастная версия, синтаксически неотличимая от адреса. */
const VERSION_PREFIX_RE = /\bv(?:er(?:sion)?)?\.?\s?$/i;

/** Адрес, который нет смысла блокировать на периметре: частные (RFC 1918),
 *  loopback, link-local, CGNAT (100.64/10), multicast, reserved, broadcast, 0/8. */
export function isNonRoutableIpv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return true;
  const [a, b] = parts;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a >= 224 // 224/4 multicast, 240/4 reserved, 255.255.255.255
  );
}

/** Публичные IPv4 из цепочки инцидента — единственные кандидаты на блокировку
 *  оператором: адрес не приходит из формы как есть, а выбирается из этого
 *  списка. Не больше пяти — после фильтра, чтобы частные адреса не вытесняли публичные. */
export function publicIpsFromChain(chain: string[]): string[] {
  const out = new Set<string>();
  for (const line of chain) {
    for (const m of line.matchAll(IPV4_IN_TEXT_RE)) {
      if (VERSION_PREFIX_RE.test(line.slice(Math.max(0, m.index - 10), m.index))) continue;
      if (!isNonRoutableIpv4(m[1])) out.add(m[1]);
      if (out.size >= 5) return [...out];
    }
  }
  return [...out];
}

const IPV4_EXACT_RE = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

/** Строка цепочки: «HH:MM:SS  source  node  action  object» (колонки через два и
 *  более пробела). Узел — наблюдатель (экспортёр NetFlow, хост агента), а не
 *  участник: его адрес из кандидатов на блокировку убираем. */
function stripNodeColumn(line: string): string {
  const cols = line.split(/\s{2,}/);
  if (cols.length < 4) return line;
  return [...cols.slice(0, 2), ...cols.slice(3)].join("  ");
}

/** Кандидаты на блокировку из карточки инцидента. Если субъект — публичный
 *  адрес (правила с group_by по src.ip/dst.ip: сканы, перебор), предлагается
 *  только он: остальные адреса цепочки — наши цели и экспортёры. Иначе —
 *  публичные адреса из цепочки без колонки узла. */
export function blockCandidates(actor: string, chain: string[]): string[] {
  const a = actor.trim();
  if (IPV4_EXACT_RE.test(a)) return isNonRoutableIpv4(a) ? [] : [a];
  return publicIpsFromChain(chain.map(stripNodeColumn));
}
