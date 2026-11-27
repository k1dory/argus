// Склонение существительного после числа по-русски: 1 источник, 2 источника, 5 источников.

/** forms — [один, несколько (2–4), много (5–20)]. */
export function plural(n: number, forms: readonly [string, string, string]): string {
  const a = Math.abs(Math.trunc(n));
  const d10 = a % 10;
  const d100 = a % 100;
  if (d10 === 1 && d100 !== 11) return forms[0];
  if (d10 >= 2 && d10 <= 4 && (d100 < 12 || d100 > 14)) return forms[1];
  return forms[2];
}

/** «3 источника» — число с разделителями и склонённым словом. */
export function countOf(n: number, forms: readonly [string, string, string]): string {
  return `${n.toLocaleString("ru-RU")} ${plural(n, forms)}`;
}

export const SOURCES_FORMS = ["источник", "источника", "источников"] as const;
export const INCIDENTS_FORMS = ["инцидент", "инцидента", "инцидентов"] as const;
export const PANELS_FORMS = ["панель", "панели", "панелей"] as const;
