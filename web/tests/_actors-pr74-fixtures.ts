import { chTs } from "../src/lib/shared/log-query";
import type { Alias, Window } from "../src/lib/shared/actors";

export const PR74_NOW = Date.UTC(2026, 10, 1, 12);
export const PR74_WINDOW: Window = { fromMs: PR74_NOW - 7 * 86_400_000, toMs: PR74_NOW };

// ClickHouse 24.8: http_max_field_value_size = 128 * 1024, в байтах.
// https://github.com/ClickHouse/ClickHouse/blob/v24.8.14.39-lts/src/Core/Settings.h#L366
export const FORM_VALUE_MAX_BYTES = 128 * 1024;

export type ActivityFixture = { id: string; aliases: Alias[] }[];

export function fixtureAlias(person: string, kind: Alias["kind"], value: string, fromMs = PR74_WINDOW.fromMs): Alias {
  return { person_id: person, kind, value, valid_from: chTs(fromMs), valid_to: null,
    source: "pr74.fixture", confidence: 1, note: "" };
}

export function unicodeFixture(): ActivityFixture {
  return [{ id: "unicode", aliases: Array.from({ length: 240 }, (_, i) =>
    fixtureAlias("unicode", "uid", "漢".repeat(252) + String(i).padStart(4, "0"))) }];
}

export function largeClassFixture(): ActivityFixture {
  // 25 персон × 1000 алиасов — допустимый импорт. Разные valid_from дают
  // 25 000 классов одного значения; это один элемент Array(Array(UInt32)).
  // IP исключён из подсчёта инцидентов, поэтому огромный OR там не нужен.
  return Array.from({ length: 25 }, (_, p) => {
    const id = `owner-${p}`;
    return { id, aliases: Array.from({ length: 1000 }, (_, i) =>
      fixtureAlias(id, "ip", "192.0.2.7", PR74_WINDOW.fromMs + p * 1000 + i)) };
  });
}

export function longIncidentQueryFixture(): ActivityFixture {
  // Один обычный пакет listPersons: 100 персон × 8 uid. SQL ~138 КБ,
  // параметры ~131 КБ в URI: SQL помещался в max_query_size=256 КиБ,
  // но после перехода на multipart поле query превышает 128 КиБ.
  return Array.from({ length: 100 }, (_, p) => {
    const id = `person-${String(p).padStart(3, "0")}`;
    return { id, aliases: Array.from({ length: 8 }, (_, i) =>
      fixtureAlias(id, "uid", `${id}-uid-${i}`.padEnd(64, "x"))) };
  });
}

export function importDocument(fixture: ActivityFixture) {
  return { persons: Object.fromEntries(fixture.map((p) => [p.id, {
    display: p.id,
    aliases: p.aliases.map((a) => ({ kind: a.kind, value: a.value,
      from: a.valid_from.replace(" ", "T") + "Z", confidence: a.confidence })),
  }])) };
}
