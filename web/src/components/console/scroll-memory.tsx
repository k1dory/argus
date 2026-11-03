"use client";

import { useEffect, useRef } from "react";
import { usePathname } from "next/navigation";
import { loadScroll, restoreStep, saveScroll, scrollKey, shouldRestore } from "@/lib/shared/scroll-memory";

function currentKey(): string {
  return scrollKey(window.location.pathname, window.location.search);
}

function navigationType(): string | undefined {
  try {
    const nav = performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined;
    return nav?.type;
  } catch {
    return undefined;
  }
}

/** Монотонные часы для таймаута: перевод системного времени не продлевает ожидание. */
function monotonicNow(): number {
  return typeof performance !== "undefined" && typeof performance.now === "function" ? performance.now() : Date.now();
}

/**
 * Помнит прокрутку страниц консоли и возвращает её после F5: страница приходит
 * потоком (скелет → данные), и браузер сам не успевает. Переходы внутри консоли
 * не трогает — их прокрутку ведёт роутер Next.
 */
export function ScrollMemory() {
  const pathname = usePathname();
  // Пока восстановление не закончено, промежуточная прокрутка (скелет, частичное
  // восстановление браузера) не должна перезаписать сохранённую цель.
  const pendingRef = useRef(false);

  // Восстановление — один раз на полную загрузку документа.
  useEffect(() => {
    if (!shouldRestore(navigationType())) return;
    let target: number | null = null;
    const key = currentKey();
    try {
      target = loadScroll(sessionStorage, key, Date.now());
    } catch {
      return;
    }
    if (target == null) return;
    const goal = target;
    const startedAt = monotonicNow();
    let done = false;
    let raf = 0;
    let observer: ResizeObserver | null = null;
    const stop = () => {
      if (done) return;
      done = true;
      pendingRef.current = false;
      cancelAnimationFrame(raf);
      observer?.disconnect();
      for (const ev of USER_EVENTS) window.removeEventListener(ev, onUser, { capture: true });
      window.removeEventListener("popstate", stop);
    };
    // F5, Ctrl/Cmd+R и одиночные модификаторы — это не «пользователь листает»,
    // а начало перезагрузки: цель должна пережить её (pendingRef не снимаем).
    const onUser = (ev: Event) => {
      if (ev.type === "keydown" && isReloadOrModifier(ev as KeyboardEvent)) return;
      stop();
    };
    const env = {
      maxScroll: () => document.documentElement.scrollHeight - window.innerHeight,
      scrollTo: (y: number) => window.scrollTo({ top: y, behavior: "instant" as ScrollBehavior }),
      now: monotonicNow,
    };
    const tick = () => {
      if (done) return;
      // Ушли на другой адрес (Back, переход роутера) — прокрутку ведёт уже он.
      if (currentKey() !== key) {
        stop();
        return;
      }
      cancelAnimationFrame(raf);
      if (restoreStep(env, goal, startedAt)) stop();
      else raf = requestAnimationFrame(tick);
    };
    pendingRef.current = true;
    // Пользователь начал листать сам или ушёл назад — больше не мешаем.
    for (const ev of USER_EVENTS) window.addEventListener(ev, onUser, { capture: true, passive: true });
    window.addEventListener("popstate", stop);
    observer = typeof ResizeObserver === "function" ? new ResizeObserver(() => tick()) : null;
    observer?.observe(document.body);
    tick();
    return stop;
  }, []);

  // Сохранение: по прокрутке (раз в кадр) и при уходе со страницы.
  useEffect(() => {
    let raf = 0;
    const save = () => {
      if (pendingRef.current) return;
      try {
        saveScroll(sessionStorage, currentKey(), window.scrollY, Date.now());
      } catch {
        // sessionStorage выключен — просто не помним.
      }
    };
    const onScroll = () => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(save);
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("pagehide", save);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("pagehide", save);
    };
  }, [pathname]);

  return null;
}

const USER_EVENTS = ["wheel", "touchstart", "keydown", "mousedown"] as const;

const MODIFIER_KEYS = new Set(["Control", "Meta", "Shift", "Alt", "AltGraph", "OS"]);

function isReloadOrModifier(ev: Pick<KeyboardEvent, "key" | "code" | "ctrlKey" | "metaKey">): boolean {
  if (MODIFIER_KEYS.has(ev.key)) return true;
  if (ev.key === "F5" || ev.code === "F5" || ev.key === "BrowserRefresh") return true;
  const r = ev.code === "KeyR" || ev.key === "r" || ev.key === "R" || ev.key === "к" || ev.key === "К";
  return r && (ev.ctrlKey === true || ev.metaKey === true);
}
