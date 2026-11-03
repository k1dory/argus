// PR #104: проверяем эффекты настоящего ScrollMemory, а не копию алгоритма.
// Запуск тем же tsx/node:test, что и остальные tests/*.test.ts.
// DOM, часы и очередь кадров детерминированы; React/Next не рендерим.
// Это модель жизненного цикла, не браузерный e2e и не ОС-песочница.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { createContext, Script } from "node:vm";
import ts from "typescript";
import * as memory from "../src/lib/shared/scroll-memory";

const componentFile = path.resolve(__dirname, "../src/components/console/scroll-memory.tsx");
const componentJS = ts.transpileModule(readFileSync(componentFile, "utf8"), {
  fileName: componentFile,
  compilerOptions: {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.CommonJS,
    jsx: ts.JsxEmit.ReactJSX,
  },
}).outputText;

const EPOCH = Date.UTC(2026, 10, 3, 12);
const INITIAL_URL = "/incidents?queue=open";
const USER_EVENTS = ["wheel", "touchstart", "keydown", "mousedown"] as const;
type Cleanup = undefined | (() => void);
type Effect = { deps?: readonly unknown[]; cleanup?: Cleanup };
type Listener = (event: { type: string; persisted?: boolean }) => void;

function fixture(options: {
  href?: string;
  navigation?: "reload" | "back_forward" | "navigate";
  maxScroll?: number;
  storage?: Map<string, string>;
} = {}) {
  const storage = options.storage ?? new Map<string, string>();
  const sessionStorage = {
    getItem: (key: string) => storage.get(key) ?? null,
    setItem: (key: string, value: string) => { storage.set(key, value); },
  };
  let elapsed = 0;
  let clockOffset = 0;
  let nextID = 0;
  const frames = new Map<number, FrameRequestCallback>();
  const timers = new Map<number, { due: number; callback: () => void }>();
  const listeners = new Map<string, { callback: Listener; capture: boolean }[]>();
  const observers = new Set<FakeResizeObserver>();
  const scrollCalls: number[] = [];
  const effects = new Map<number, Effect>();
  const refs = new Map<number, { current: unknown }>();
  let hookIndex = 0;
  let pendingEffects: { index: number; setup: () => Cleanup; deps?: readonly unknown[] }[] = [];

  function capture(options?: boolean | { capture?: boolean }) {
    return typeof options === "boolean" ? options : options?.capture === true;
  }
  function emit(type: string, persisted?: boolean) {
    for (const { callback } of [...(listeners.get(type) ?? [])]) callback({ type, persisted });
  }
  const document = {
    body: {},
    documentElement: { scrollHeight: (options.maxScroll ?? 300) + 800 },
  };
  const window = {
    location: new URL(options.href ?? INITIAL_URL, "https://argus.invalid"),
    innerHeight: 800,
    scrollY: 0,
    scrollTo({ top }: ScrollToOptions) {
      assert.equal(typeof top, "number", "прокрутка получает число, а не URL/ключ");
      scrollCalls.push(top!);
      const y = Math.min(Math.max(0, document.documentElement.scrollHeight - window.innerHeight), Math.max(0, top!));
      if (y !== window.scrollY) {
        window.scrollY = y;
        // Реальный scroll доставляется асинхронно, после scrollTo.
        queueTimer(() => emit("scroll"), 0);
      }
    },
    addEventListener(type: string, callback: Listener, options?: boolean | AddEventListenerOptions) {
      const list = listeners.get(type) ?? [];
      const useCapture = capture(options);
      if (!list.some((entry) => entry.callback === callback && entry.capture === useCapture)) {
        list.push({ callback, capture: useCapture });
      }
      listeners.set(type, list);
    },
    removeEventListener(type: string, callback: Listener, options?: boolean | EventListenerOptions) {
      const useCapture = capture(options);
      listeners.set(type, (listeners.get(type) ?? []).filter((entry) =>
        entry.callback !== callback || entry.capture !== useCapture));
    },
  };
  function queueTimer(callback: () => void, delay = 0) {
    const id = ++nextID;
    timers.set(id, { due: elapsed + delay, callback });
    return id;
  }
  class FixtureDate extends Date {
    static now() { return EPOCH + elapsed + clockOffset; }
  }
  class FakeResizeObserver {
    constructor(readonly callback: () => void) {}
    observe(target: unknown) {
      assert.equal(target, document.body);
      observers.add(this);
    }
    disconnect() { observers.delete(this); }
  }
  const dependencies: Record<string, unknown> = {
    react: {
      useEffect(setup: () => Cleanup, deps?: readonly unknown[]) {
        const index = hookIndex++;
        const previous = effects.get(index);
        if (!previous || !deps || !previous.deps || deps.length !== previous.deps.length ||
            deps.some((value, i) => !Object.is(value, previous.deps![i]))) {
          pendingEffects.push({ index, setup, deps });
        }
      },
      useRef(initial: unknown) {
        const index = hookIndex++;
        if (!refs.has(index)) refs.set(index, { current: initial });
        return refs.get(index);
      },
    },
    "next/navigation": {
      usePathname: () => window.location.pathname,
      useSearchParams: () => window.location.searchParams,
    },
    "@/lib/shared/scroll-memory": memory,
  };
  const context = createContext({
    window, document, sessionStorage, Date: FixtureDate, URL,
    performance: {
      now: () => elapsed,
      getEntriesByType: () => [{ type: options.navigation ?? "reload" }],
    },
    ResizeObserver: FakeResizeObserver,
    requestAnimationFrame: (callback: FrameRequestCallback) => {
      const id = ++nextID;
      frames.set(id, callback);
      return id;
    },
    cancelAnimationFrame: (id: number) => { frames.delete(id); },
    setTimeout: queueTimer,
    clearTimeout: (id: number) => { timers.delete(id); },
  });
  const mod = { exports: {} };
  const evaluate = new Script(`(function(require, module, exports) {\n${componentJS}\n})`, {
    filename: componentFile,
  }).runInContext(context, { timeout: 1000 });
  evaluate((name: string) => {
    assert.ok(Object.hasOwn(dependencies, name), `неожиданный импорт ${name}`);
    return dependencies[name];
  }, mod, mod.exports);
  const { ScrollMemory } = mod.exports as { ScrollMemory: () => null };

  function render() {
    hookIndex = 0;
    pendingEffects = [];
    ScrollMemory();
    for (const { index } of pendingEffects) effects.get(index)?.cleanup?.();
    for (const { index, setup, deps } of pendingEffects) {
      effects.set(index, { deps, cleanup: setup() });
    }
  }
  function unmount() {
    for (const { cleanup } of effects.values()) cleanup?.();
    effects.clear();
    refs.clear();
  }
  function frame(ms = 16) {
    elapsed += ms;
    for (const [id, timer] of [...timers]) {
      if (timer.due <= elapsed && timers.delete(id)) timer.callback();
    }
    // Новый rAF из callback выполняется только в следующем кадре.
    for (const id of [...frames.keys()]) {
      const callback = frames.get(id);
      if (callback) {
        frames.delete(id);
        callback(elapsed);
      }
    }
  }
  function resize(maxScroll: number) {
    document.documentElement.scrollHeight = maxScroll + window.innerHeight;
    for (const observer of [...observers]) observer.callback();
  }
  function resources() {
    return {
      frames: frames.size,
      observers: observers.size,
      inputListeners: USER_EVENTS.reduce((n, type) => n + (listeners.get(type)?.length ?? 0), 0),
    };
  }
  return {
    storage, window, scrollCalls, emit, frame, render, unmount, resize, resources,
    seed(href = INITIAL_URL, y = 2400) {
      const url = new URL(href, "https://argus.invalid");
      memory.saveScroll(sessionStorage, memory.scrollKey(url.pathname, url.search), y, FixtureDate.now());
    },
    turnClockBack(ms: number) { clockOffset -= ms; },
    navigate(href: string, restoredY: number) {
      // Кнопка Back в панели браузера не генерирует mousedown/keydown в window.
      // Next меняет адрес и обновляет pathname, сохраняя общий console layout.
      window.location = new URL(href, window.location);
      emit("popstate");
      document.documentElement.scrollHeight = 5000 + window.innerHeight;
      render();
      window.scrollY = restoredY;
    },
    listenerCount: () => [...listeners.values()].reduce((n, list) => n + list.length, 0),
  };
}

// P2: замыкание восстановления живёт до unmount, хотя адрес уже другой.
for (const destination of ["/sources", "/incidents?queue=closed"]) {
  test(`PR104: Back на ${destination} отменяет восстановление предыдущего адреса`, (t) => {
    const f = fixture();
    t.after(f.unmount);
    f.seed();
    // Эта запись тоже не должна восстанавливаться при SPA-навигации:
    // за позицию новой history entry уже отвечает роутер/браузер.
    f.seed(destination, 1200);
    f.render();
    assert.equal(f.resources().frames, 1, "сначала действительно ждём длинную страницу");
    f.navigate(destination, 600);
    f.resize(5000);
    f.frame();
    assert.deepEqual(f.scrollCalls, [], "цель старого reload не должна прокручивать новый адрес");
    assert.equal(f.window.scrollY, 600, "сохраняется положение, выставленное роутером");
    assert.deepEqual(f.resources(), { frames: 0, observers: 0, inputListeners: 0 });
  });
}

// P2: pagehide сохраняет высоту скелета вместо ещё не восстановленной цели.
for (const interimY of [0, 300]) {
  test(`PR104: повторный reload во время ожидания не заменяет цель 2400 на ${interimY}`, (t) => {
    const first = fixture();
    t.after(first.unmount);
    first.seed();
    first.render();
    assert.equal(first.resources().frames, 1);
    // Пользователь не прокручивал страницу. При interimY=300 браузер успел
    // восстановить лишь доступную часть короткого документа.
    first.window.scrollY = interimY;
    first.emit("pagehide", false); // повторный reload кнопкой браузера
    first.unmount();

    const second = fixture({ storage: first.storage, maxScroll: 5000 });
    t.after(second.unmount);
    second.render();
    assert.equal(second.window.scrollY, 2400,
      "до завершения восстановления повторный reload должен сохранять исходную цель");
  });
}

// P3: 8 секунд должны отсчитываться монотонными часами, независимо от Date.now.
test("PR104: перевод часов назад не продлевает rAF/ResizeObserver за пределы 8 секунд", (t) => {
  const f = fixture();
  t.after(f.unmount);
  f.seed();
  f.render();
  f.frame(1000);
  f.turnClockBack(60 * 60 * 1000);
  f.frame(memory.SCROLL_RESTORE_TIMEOUT_MS - 1000);
  assert.deepEqual(f.resources(), { frames: 0, observers: 0, inputListeners: 0 },
    "после 8 реальных секунд ожидание должно завершиться даже при коррекции системных часов");
  assert.equal(f.window.scrollY, 300, "по таймауту используется доступная высота");
});

// Контроли модели: не превращаем штатную очистку или обычный таймаут в находку.
for (const event of USER_EVENTS) {
  test(`ScrollMemory: ${event} останавливает ожидание и освобождает ресурсы`, (t) => {
    const f = fixture();
    t.after(f.unmount);
    f.seed();
    f.render();
    f.emit(event);
    f.resize(5000);
    f.frame();
    assert.deepEqual(f.scrollCalls, []);
    assert.deepEqual(f.resources(), { frames: 0, observers: 0, inputListeners: 0 });
    f.unmount();
    assert.equal(f.listenerCount(), 0);
  });
}

test("ScrollMemory: observer и rAF не размножают очередь; штатный таймаут очищает ожидание", (t) => {
  const f = fixture();
  t.after(f.unmount);
  f.seed();
  f.render();
  for (let i = 0; i < 10; i++) {
    f.resize(300);
    f.frame(100);
    assert.deepEqual(f.resources(), { frames: 1, observers: 1, inputListeners: 4 });
  }
  f.frame(memory.SCROLL_RESTORE_TIMEOUT_MS - 1000);
  assert.deepEqual(f.scrollCalls, [300]);
  assert.deepEqual(f.resources(), { frames: 0, observers: 0, inputListeners: 0 });
});

test("ScrollMemory: размонтирование во время ожидания удаляет все обработчики и кадры", () => {
  const f = fixture();
  f.seed();
  f.render();
  f.unmount();
  f.resize(5000);
  f.frame();
  assert.deepEqual(f.scrollCalls, []);
  assert.deepEqual(f.resources(), { frames: 0, observers: 0, inputListeners: 0 });
  assert.equal(f.listenerCount(), 0);
});

for (const navigation of ["navigate", "reload", "back_forward"] as const) {
  test(`ScrollMemory: тип загрузки ${navigation} соблюдает контракт восстановления`, (t) => {
    const f = fixture({ navigation });
    t.after(f.unmount);
    f.seed();
    f.render();
    f.resize(5000);
    f.frame();
    assert.deepEqual(f.scrollCalls, navigation === "navigate" ? [] : [2400]);
    assert.deepEqual(f.resources(), { frames: 0, observers: 0, inputListeners: 0 });
  });
}
