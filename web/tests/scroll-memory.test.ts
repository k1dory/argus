// Память прокрутки консоли: после F5 список инцидентов (и любая страница консоли)
// возвращается туда, где его оставили, даже если таблица дорисовывается потоком.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  loadScroll, restoreStep, saveScroll, scrollKey, shouldRestore,
  SCROLL_MAX_AGE_MS, SCROLL_MAX_ENTRIES, SCROLL_RESTORE_TIMEOUT_MS, SCROLL_STORE_KEY,
} from "../src/lib/shared/scroll-memory";

function memStorage(init: Record<string, string> = {}) {
  const m = new Map(Object.entries(init));
  return {
    getItem: (k: string) => (m.has(k) ? m.get(k)! : null),
    setItem: (k: string, v: string) => void m.set(k, v),
    raw: m,
  };
}

test("ключ — путь и query, фильтры различаются", () => {
  assert.equal(scrollKey("/incidents", "?level_max=critical"), "/incidents?level_max=critical");
  assert.equal(scrollKey("/incidents", "level_max=critical"), "/incidents?level_max=critical");
  assert.equal(scrollKey("/incidents", ""), "/incidents");
  assert.equal(scrollKey("/incidents", "?"), "/incidents");
  assert.notEqual(scrollKey("/incidents", "?level_max=critical"), scrollKey("/incidents", "?level_max=high"));
});

test("сохранили — после перезагрузки того же адреса получили обратно", () => {
  const s = memStorage();
  const k = scrollKey("/incidents", "?level_max=critical");
  saveScroll(s, k, 2400.6, 1_000);
  assert.equal(loadScroll(s, k, 2_000), 2401);
  assert.equal(loadScroll(s, scrollKey("/incidents", ""), 2_000), null, "другой адрес — своя прокрутка");
});

test("прокрутка наверх стирает запись; отрицательное и NaN не пишутся", () => {
  const s = memStorage();
  saveScroll(s, "/a", 500, 1);
  saveScroll(s, "/a", 0, 2);
  assert.equal(loadScroll(s, "/a", 3), null);
  saveScroll(s, "/b", -5, 1);
  saveScroll(s, "/b", Number.NaN, 1);
  assert.equal(loadScroll(s, "/b", 2), null);
});

test("старая запись и запись из будущего не восстанавливаются", () => {
  const s = memStorage();
  saveScroll(s, "/a", 900, 0);
  assert.equal(loadScroll(s, "/a", SCROLL_MAX_AGE_MS + 1), null);
  saveScroll(s, "/b", 900, 10 * 60_000);
  assert.equal(loadScroll(s, "/b", 0), null);
});

test("хранится не больше SCROLL_MAX_ENTRIES адресов, вытесняются самые старые", () => {
  const s = memStorage();
  for (let i = 0; i < SCROLL_MAX_ENTRIES + 5; i++) saveScroll(s, `/p${i}`, 100 + i, i);
  const store = JSON.parse(s.raw.get(SCROLL_STORE_KEY)!);
  assert.equal(Object.keys(store).length, SCROLL_MAX_ENTRIES);
  assert.equal(store["/p0"], undefined);
  assert.equal(loadScroll(s, `/p${SCROLL_MAX_ENTRIES + 4}`, SCROLL_MAX_ENTRIES + 5), 100 + SCROLL_MAX_ENTRIES + 4);
});

test("битое или чужое содержимое хранилища не ломает страницу", () => {
  for (const raw of ["{", "[]", "null", '"x"', '{"/a":{"y":"9","at":1}}', '{"/a":{"y":-1,"at":1}}']) {
    const s = memStorage({ [SCROLL_STORE_KEY]: raw });
    assert.equal(loadScroll(s, "/a", 2), null, raw);
    assert.doesNotThrow(() => saveScroll(s, "/a", 10, 2));
  }
  const throwing = { getItem: () => { throw new Error("denied"); }, setItem: () => { throw new Error("quota"); } };
  assert.equal(loadScroll(throwing, "/a", 1), null);
  assert.doesNotThrow(() => saveScroll(throwing, "/a", 10, 1));
});

test("восстанавливаем только при перезагрузке и «назад/вперёд», не при обычном переходе", () => {
  assert.equal(shouldRestore("reload"), true);
  assert.equal(shouldRestore("back_forward"), true);
  assert.equal(shouldRestore("navigate"), false);
  assert.equal(shouldRestore("prerender"), false);
  assert.equal(shouldRestore(undefined), false);
});

test("пока поток не дорисовал таблицу — ждём; дорос — прокручиваем ровно на место", () => {
  let max = 300; // скелет: страница короткая
  let t = 0;
  const calls: number[] = [];
  const env = { maxScroll: () => max, scrollTo: (y: number) => void calls.push(y), now: () => t };
  assert.equal(restoreStep(env, 2400, 0), false);
  assert.deepEqual(calls, [], "на короткой странице не прыгаем на середину");
  max = 5000; t = 400; // пришли строки инцидентов
  assert.equal(restoreStep(env, 2400, 0), true);
  assert.deepEqual(calls, [2400]);
});

test("по таймауту прокручиваем, насколько позволяет документ (список стал короче)", () => {
  const calls: number[] = [];
  const env = { maxScroll: () => 1200, scrollTo: (y: number) => void calls.push(y), now: () => SCROLL_RESTORE_TIMEOUT_MS };
  assert.equal(restoreStep(env, 2400, 0), true);
  assert.deepEqual(calls, [1200]);
  const none: number[] = [];
  assert.equal(restoreStep({ maxScroll: () => 0, scrollTo: (y) => void none.push(y), now: () => SCROLL_RESTORE_TIMEOUT_MS }, 2400, 0), true);
  assert.deepEqual(none, [], "страница без прокрутки — ничего не делаем");
});
