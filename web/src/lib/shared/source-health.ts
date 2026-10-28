// Статус источника «жив/молчит» по его собственному ритму, а не по общему порогу.
// Ритм — типичный разрыв между активными минутами (минутами, в которые было хоть
// одно событие) по журналу heartbeat коллектора за окно RHYTHM_WINDOW_DAYS: берётся
// квантиль RHYTHM_QUANTILE разрывов. Почему квантиль, а не среднее и не размах:
// - среднее «размах / число активных минут» занижает период пачечных источников
//   (CI пишет 5 минут раз в сутки → 35 активных минут за неделю → «раз в 4 часа»);
// - максимум одного разрыва (сбой коллектора на двое суток) превратил бы
//   непрерывный источник в «раз в двое суток» на всё окно;
// - 90-й процентиль у непрерывного источника — минута, у суточного CI — сутки,
//   у недельной выгрузки — неделя (за 30 суток разрывов хватает).
// Порог тишины — SILENCE_FACTOR ритмов, но не меньше SILENCE_MIN_SEC: непрерывный
// источник молчит через пять минут, суточный — через трое суток. Пока активная
// минута одна (разрывов нет), ритм неизвестен — порог минимальный, в UI «мало данных».
export const SILENCE_MIN_SEC = 300;
export const SILENCE_FACTOR = 3;
/** Окно ритма — по collector_health_log (TTL 90 суток), а не по таблице событий. */
export const RHYTHM_WINDOW_DAYS = 30;
export const RHYTHM_QUANTILE = 0.9;

/** Ритм по разрывам между активными минутами (с): квантиль RHYTHM_QUANTILE, не меньше 60; null — разрывов нет. */
export function rhythmFromGaps(gapsSec: readonly number[]): number | null {
  const gaps = gapsSec.filter((g) => Number.isFinite(g) && g > 0).sort((a, b) => a - b);
  if (gaps.length === 0) return null;
  const idx = Math.min(gaps.length - 1, Math.ceil(RHYTHM_QUANTILE * gaps.length) - 1);
  return Math.max(60, gaps[Math.max(0, idx)]);
}

/** Порог тишины: max(SILENCE_MIN_SEC, SILENCE_FACTOR × ритм); ритм неизвестен — минимум. */
export function silenceThresholdSec(rhythmSec: number | null): number {
  if (rhythmSec === null || !Number.isFinite(rhythmSec) || rhythmSec <= 0) return SILENCE_MIN_SEC;
  return Math.max(SILENCE_MIN_SEC, Math.round(SILENCE_FACTOR * rhythmSec));
}

export function isAlive(nowSec: number, lastSec: number, thresholdSec: number): boolean {
  return nowSec - lastSec <= thresholdSec;
}

/** Длительность по-русски: «45 с», «4 мин», «2,5 ч», «1,2 сут». */
export function formatDuration(sec: number): string {
  const one = (v: number, unit: string) => `${v.toLocaleString("ru-RU", { maximumFractionDigits: 1 })} ${unit}`;
  if (!Number.isFinite(sec) || sec < 0) return "—";
  if (sec < 60) return `${Math.round(sec)} с`;
  if (sec < 90 * 60) return one(sec / 60, "мин");
  if (sec < 36 * 3600) return one(sec / 3600, "ч");
  return one(sec / 86400, "сут");
}

/** «мало данных» (одна активная минута), «непрерывно», «раз в 4 мин», «раз в 2,5 ч», «раз в 1,2 сут». */
export function formatRhythm(sec: number | null): string {
  if (sec === null) return "мало данных";
  if (sec <= 90) return "непрерывно";
  return `раз в ${formatDuration(sec)}`;
}

export const formatThreshold = formatDuration;

/** Подсказка статуса — из констант, чтобы текст не расходился с расчётом. */
export function describeThreshold(thresholdSec: number, silentForSec: number): string {
  return `порог тишины для этого источника: ${formatDuration(thresholdSec)} (${SILENCE_FACTOR} × ритм, не меньше ${formatDuration(SILENCE_MIN_SEC)}); с последнего события: ${formatDuration(silentForSec)}`;
}
