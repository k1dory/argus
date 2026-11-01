// Режимы реагирования — общие для сервера и клиента (без импорта server-only модулей).
export const RESPOND_MODES = {
  ids: { label: "IDS — только детект", hint: "автоматика ничего не блокирует; кнопка оператора в карточке работает" },
  simulate: { label: "Симуляция", hint: "движок пишет в журнал, кого заблокировал бы, но исполнителей не вызывает" },
  ips: { label: "IPS — автоблокировка", hint: "правила с блоком respond блокируют адреса на TTL через Wazuh/NGFW; allowlist не трогается" },
} as const;
export type RespondMode = keyof typeof RESPOND_MODES;
export type RespondModeFrom = "config" | "console";
export const isRespondMode = (x: unknown): x is RespondMode => x === "ids" || x === "simulate" || x === "ips";

/** Сроки исключения адреса из автоблокировки в консоли (движок принимает 1m–720h). */
export const EXCLUDE_TTLS = [
  { value: "1h", label: "1 час" },
  { value: "24h", label: "сутки" },
  { value: "72h", label: "3 суток" },
  { value: "168h", label: "неделя" },
  { value: "720h", label: "30 суток" },
] as const;

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

function ipv4ToInt(ip: string): number | null {
  if (!IPV4_EXACT_RE.test(ip)) return null;
  return ip.split(".").reduce((acc, o) => acc * 256 + Number(o), 0);
}

/** Адрес входит в сеть «a.b.c.d/len» (или равен адресу без маски). Неразборчивая
 *  запись сети — false: список INTERNAL_NETS приходит из .env и может быть пустым. */
export function ipv4InCidr(ip: string, cidr: string): boolean {
  const [net, lenRaw] = cidr.trim().split("/");
  const a = ipv4ToInt(ip), n = ipv4ToInt(net);
  if (a === null || n === null) return false;
  const len = lenRaw === undefined ? 32 : Number(lenRaw);
  if (!Number.isInteger(len) || len < 0 || len > 32) return false;
  if (len === 0) return true;
  const mask = (0xffffffff << (32 - len)) >>> 0;
  return ((a & mask) >>> 0) === ((n & mask) >>> 0);
}

/** Строка цепочки движка: «HH:MM:SS  source(16) node(14) action(24) detail» —
 *  фиксированные колонки через один пробел (engine/internal/incidents, cut/%-Ns).
 *  Узел — наблюдатель (экспортёр NetFlow, хост агента), а не участник: его
 *  колонку из кандидатов на блокировку убираем. Если ширина не сходится (строка
 *  не от движка) — колонки по двум и более пробелам, как в свободном тексте. */
const CHAIN_TS_RE = /^\d\d:\d\d:\d\d  /;
const NODE_COL_START = 27, NODE_COL_END = 41; // 8 (ts) + 2 + 16 (source) + 1 … + 14 (node)
function stripNodeColumn(line: string): string {
  if (CHAIN_TS_RE.test(line) && line.length > NODE_COL_END && line[NODE_COL_START - 1] === " " && line[NODE_COL_END] === " ") {
    return line.slice(0, NODE_COL_START - 1) + "  " + line.slice(NODE_COL_END + 1);
  }
  const cols = line.split(/\s{2,}/);
  if (cols.length < 4) return line;
  return [...cols.slice(0, 2), ...cols.slice(3)].join("  ");
}

/** Инцидент эксплуатации (теги ops.* без attack.*): диск, молчание узла, часы источника.
 *  Адреса в его цепочке — наши устройства и экспортёры телеметрии, а не атакующие:
 *  блокировать их нечего (устройство с убежавшими часами блокировать нельзя). */
export function isOpsIncident(tags: readonly string[] | undefined): boolean {
  if (!tags?.length) return false;
  // Теги — как их читают ruleTactics/ruleTechniques: без учёта регистра и пробелов по краям.
  const norm = tags.map((t) => t.trim().toLowerCase());
  return norm.some((t) => t.startsWith("ops.")) && !norm.some((t) => t.startsWith("attack."));
}

/** Кандидаты на блокировку из карточки инцидента.
 *  - Субъект — публичный адрес (правила с group_by по src.ip/dst.ip: сканы, перебор
 *    снаружи): предлагается только он — остальные адреса цепочки наши цели и экспортёры.
 *  - Субъект — свой адрес (частный или из ownNets = INTERNAL_NETS: исходящие правила —
 *    маячок, DNS-туннель, запрет egress) или логин: публичные адреса цепочки без колонки
 *    узла и без собственных сетей — то, куда стучит заражённый хост.
 *  Без INTERNAL_NETS своими считаются только частные диапазоны (как attrs.scope у коллектора). */
export function blockCandidates(actor: string, chain: string[], ownNets: readonly string[] = []): string[] {
  const own = (ip: string) => isNonRoutableIpv4(ip) || ownNets.some((n) => ipv4InCidr(ip, n));
  const a = actor.trim();
  if (IPV4_EXACT_RE.test(a) && !own(a)) return [a];
  return publicIpsFromChain(chain.map(stripNodeColumn)).filter((ip) => !own(ip));
}

/** Кандидаты на блокировку для инцидента: у инцидентов эксплуатации их нет, иначе —
 *  blockCandidates по субъекту и цепочке. Карточка и серверная проверка blockIpAction —
 *  через blockCandidatesFor (argus-queries), он подставляет ownNets из INTERNAL_NETS. */
export function blockCandidatesForIncident(inc: { actor_name: string; chain: string[]; tags?: string[] }, ownNets: readonly string[] = []): string[] {
  if (isOpsIncident(inc.tags)) return [];
  return blockCandidates(inc.actor_name, inc.chain, ownNets);
}
