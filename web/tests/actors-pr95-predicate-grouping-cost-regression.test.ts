// Повторные выдачи одного значения с разными valid_from — разные строки
// identity_aliases. Построение предиката выполняется синхронно в web-процессе:
// стоимость группировки не должна становиться квадратичной для такого ввода.
// Считаем посещения записей интервалов вместо нестабильного wall-clock timeout.
import { test } from "node:test";
import assert from "node:assert/strict";
import { aliasPredicate, parseIdentitiesDoc, type Alias, type Predicate } from "../src/lib/shared/actors";
import { chTs } from "../src/lib/shared/log-query";

const W = { fromMs: Date.UTC(2026, 9, 25), toMs: Date.UTC(2026, 10, 1) };
const COUNT = 1000; // допустимое число алиасов в одном документе импорта

function fixture(repeated: boolean): Alias[] {
  const parsed = parseIdentitiesDoc({ persons: { "pr95-grouping": {
    aliases: Array.from({ length: COUNT }, (_, i) => ({
      kind: "uid", value: repeated ? "vpn-user" : `vpn-user-${i}`,
      // Раздельные интервалы нельзя просто выкинуть как дубликаты или слить
      // через промежутки, в которые значение не принадлежало персоне.
      from: new Date(W.fromMs + i * 2000).toISOString(),
      to: new Date(W.fromMs + i * 2000 + 1000).toISOString(),
    })),
  } } });
  assert.ok(parsed.ok, "фикстура проходит штатный разбор импорта");
  return parsed.persons[0].aliases.map((a) => ({
    ...a, person_id: "pr95-grouping", source: "api",
    valid_from: a.valid_from ?? chTs(W.fromMs),
  }));
}

function buildWithVisitBudget(aliases: Alias[]): Predicate {
  const nativeIterator = Array.prototype[Symbol.iterator];
  const budget = 16 * aliases.length;
  let visits = 0;
  // Инструментируем только время синхронного вызова. Обычный обход и несколько
  // линейных проходов укладываются в запас; повторное копирование растущих
  // массивов исчерпывает его. Прерывание ограничивает и стоимость самого теста.
  // t.mock.method не принимает Array.prototype (он сам — экземпляр Array, Node 26 отвечает
  // ERR_INVALID_ARG_TYPE), поэтому итератор подменяется дескриптором и восстанавливается в finally.
  const descriptor = Object.getOwnPropertyDescriptor(Array.prototype, Symbol.iterator)!;
  Object.defineProperty(Array.prototype, Symbol.iterator, { ...descriptor, value: function* (this: unknown[]) {
    for (const value of nativeIterator.call(this)) {
      if (value !== null && typeof value === "object"
        && "fromMs" in value && "toMs" in value
        && typeof value.fromMs === "number" && typeof value.toMs === "number") {
        visits++;
        if (visits > budget) throw new Error(`interval visit budget exceeded: ${visits} > ${budget}`);
      }
      yield value;
    }
  } });
  try {
    return aliasPredicate(aliases, W);
  } finally {
    Object.defineProperty(Array.prototype, Symbol.iterator, descriptor);
  }
}

for (const repeated of [false, true]) {
  test(`PR #95: бюджет построения предиката — ${repeated ? "одно значение в 1000 интервалах" : "1000 разных значений (контроль)"}`, () => {
    const aliases = fixture(repeated);
    assert.doesNotThrow(() => {
      const predicate = buildWithVisitBudget(aliases);
      assert.notEqual(predicate.sql, "0");
      assert.ok(Object.keys(predicate.params).length > 0);
    }, "повторяющееся значение не должно вызывать повторный обход всех накопленных интервалов");
  });
}
