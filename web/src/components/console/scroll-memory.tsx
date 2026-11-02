"use client";

import { useEffect } from "react";
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

/**
 * Помнит прокрутку страниц консоли и возвращает её после F5: страница приходит
 * потоком (скелет → данные), и браузер сам не успевает. Переходы внутри консоли
 * не трогает — их прокрутку ведёт роутер Next.
 */
export function ScrollMemory() {
  const pathname = usePathname();

  // Восстановление — один раз на полную загрузку документа.
  useEffect(() => {
    if (!shouldRestore(navigationType())) return;
    let target: number | null = null;
    try {
      target = loadScroll(sessionStorage, currentKey(), Date.now());
    } catch {
      return;
    }
    if (target == null) return;
    const goal = target;
    const startedAt = Date.now();
    let done = false;
    let raf = 0;
    let observer: ResizeObserver | null = null;
    const stop = () => {
      done = true;
      cancelAnimationFrame(raf);
      observer?.disconnect();
      for (const ev of USER_EVENTS) window.removeEventListener(ev, stop, { capture: true });
    };
    const env = {
      maxScroll: () => document.documentElement.scrollHeight - window.innerHeight,
      scrollTo: (y: number) => window.scrollTo({ top: y, behavior: "instant" as ScrollBehavior }),
      now: () => Date.now(),
    };
    const tick = () => {
      if (done) return;
      cancelAnimationFrame(raf);
      if (restoreStep(env, goal, startedAt)) stop();
      else raf = requestAnimationFrame(tick);
    };
    // Пользователь начал листать сам — больше не мешаем.
    for (const ev of USER_EVENTS) window.addEventListener(ev, stop, { capture: true, passive: true });
    observer = typeof ResizeObserver === "function" ? new ResizeObserver(() => tick()) : null;
    observer?.observe(document.body);
    tick();
    return stop;
  }, []);

  // Сохранение: по прокрутке (раз в кадр) и при уходе со страницы.
  useEffect(() => {
    let raf = 0;
    const save = () => {
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
