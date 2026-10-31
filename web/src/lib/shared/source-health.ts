// Статус источника «жив/молчит» по его собственному ритму, а не по общему порогу.
// Ритм — типичный разрыв между пачками событий по журналу heartbeat коллектора за
// окно RHYTHM_WINDOW_DAYS. Считается одним SQL в sourcesHealthReport (argus-queries.ts),
// тесты гоняют этот SQL на живом ClickHouse:
// - разрывы между соседними активными минутами (минутами, в которые было хоть одно
//   событие); самый длинный разрыв отбрасывается — одиночный сбой коллектора или
//   простой источника не растягивает ритм непрерывного источника на всё окно;
// - квантиль RHYTHM_QUANTILE взвешен длительностью разрыва — это доля времени, а не
//   доля разрывов. Квантиль по числу разрывов давал пачечному источнику минуту: CI,
//   пишущий 15 минут раз в сутки, — 14 разрывов по минуте на один суточный, и источник
//   горел красным почти весь день. По времени суточный разрыв занимает 99 % суток;
// - итог: непрерывный источник — минута, CI раз в сутки — около суток, рабочие часы —
//   ночь (≈ 15 ч), недельная выгрузка — неделя (после трёх недель истории: с одним
//   разрывом ритм неизвестен, его отбрасывает правило самого длинного).
// Порог тишины — SILENCE_FACTOR ритмов, но не меньше SILENCE_MIN_SEC: непрерывный
// источник молчит через пять минут, суточный — через трое суток. Пока разрывов меньше
// двух, ритм неизвестен — порог минимальный, в UI «мало данных». Источники мимо
// коллектора (телеметрия движка argus.system) heartbeat не имеют — у них тоже порог
// минимальный, но в списке они остаются (проекция p_source_last, миграция 0031).
export const SILENCE_MIN_SEC = 300;
export const SILENCE_FACTOR = 3;
/** Окно ритма — по collector_health_log (TTL 90 суток), а не по таблице событий. */
export const RHYTHM_WINDOW_DAYS = 30;
export const RHYTHM_QUANTILE = 0.9;

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

/** «мало данных» (меньше двух разрывов), «непрерывно», «раз в 4 мин», «раз в 2,5 ч», «раз в 1,2 сут». */
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
