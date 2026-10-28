// Статус источника «жив/молчит» по его собственному ритму, а не по общему порогу.
// Ритм — сколько минут в среднем приходится на одну «активную» минуту (минуту, в
// которую было хоть одно событие) за окно наблюдения: размах окна / число активных
// минут. Считается по активным минутам, а не по среднему интервалу между событиями:
// иначе один залп (агент при первом старте вычитывает весь журнал) делает интервал
// нулевым, и редкий источник выглядит непрерывным. Окно — 7 суток: чем больше
// выборка, тем точнее; у нового источника окно — от его первого события.
// Порог тишины — три ритма, но не меньше SILENCE_MIN_SEC: непрерывный источник
// (NetFlow, телеметрия) молчит уже через пять минут, редкий (входы по SSH, журнал
// CI) — когда пауза втрое длиннее обычной. Работает с первого события: пока
// активная минута одна, порог — минимальный.
export const SILENCE_MIN_SEC = 300;
export const SILENCE_FACTOR = 3;
export const RHYTHM_WINDOW_DAYS = 7;

/** Ритм источника в секундах на активную минуту; null, если активная минута одна. */
export function rhythmSec(activeMinutes: number, spanSec: number): number | null {
  if (!Number.isFinite(activeMinutes) || activeMinutes < 2) return null;
  if (!Number.isFinite(spanSec) || spanSec < 0) return null;
  return Math.max(60, spanSec) / activeMinutes;
}

/** Порог тишины: max(SILENCE_MIN_SEC, SILENCE_FACTOR × ритм). */
export function silenceThresholdSec(activeMinutes: number, spanSec: number): number {
  const r = rhythmSec(activeMinutes, spanSec);
  if (r === null) return SILENCE_MIN_SEC;
  return Math.max(SILENCE_MIN_SEC, Math.round(SILENCE_FACTOR * r));
}

export function isAlive(nowSec: number, lastSec: number, thresholdSec: number): boolean {
  return nowSec - lastSec <= thresholdSec;
}

/** «непрерывно», «раз в 4 мин», «раз в 2,5 ч», «раз в 1,2 сут». */
export function formatRhythm(sec: number | null): string {
  if (sec === null) return "одно событие";
  if (sec <= 90) return "непрерывно";
  const one = (v: number, unit: string) => `раз в ${v.toLocaleString("ru-RU", { maximumFractionDigits: 1 })} ${unit}`;
  if (sec < 90 * 60) return one(sec / 60, "мин");
  if (sec < 36 * 3600) return one(sec / 3600, "ч");
  return one(sec / 86400, "сут");
}

export function formatThreshold(sec: number): string {
  if (sec < 3600) return `${Math.round(sec / 60)} мин`;
  if (sec < 86400) return `${(sec / 3600).toLocaleString("ru-RU", { maximumFractionDigits: 1 })} ч`;
  return `${(sec / 86400).toLocaleString("ru-RU", { maximumFractionDigits: 1 })} сут`;
}
