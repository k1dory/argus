// Общие константы для сервера и клиента: без кредов и fetch.
export type RangeKey = "1h" | "24h" | "7d" | "30d";

export const RANGES: Record<RangeKey, { label: string; hours: number; bucketMinutes: number }> = {
  "1h": { label: "1 час", hours: 1, bucketMinutes: 2 },
  "24h": { label: "24 часа", hours: 24, bucketMinutes: 30 },
  "7d": { label: "7 дней", hours: 24 * 7, bucketMinutes: 240 },
  "30d": { label: "30 дней", hours: 24 * 30, bucketMinutes: 720 },
};

export function parseRange(value: string | undefined): RangeKey {
  // Только собственные ключи: "constructor"/"toString"/"__proto__" есть у любого объекта через прототип.
  return isRangeKey(value) ? value : "24h";
}

export function isRangeKey(value: unknown): value is RangeKey {
  return typeof value === "string" && Object.prototype.hasOwnProperty.call(RANGES, value);
}
