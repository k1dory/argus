"use client";

import { useCallback, useEffect, useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Pause, Play } from "lucide-react";
import { Button } from "@/components/ui/button";

/**
 * Обновление серверных данных по таймеру: router.refresh перерисовывает RSC
 * без полной перезагрузки. Индикатор интервала и обратный отсчёт, пауза
 * кнопкой и автоматически в фоновой вкладке, положение прокрутки сохраняется.
 */
export function AutoRefresh({ seconds, label = "автообновление" }: { seconds: number; label?: string }) {
  const router = useRouter();
  const [pending, start] = useTransition();
  const [paused, setPaused] = useState(false);
  const [hidden, setHidden] = useState(false);
  const [left, setLeft] = useState(seconds);
  const scrollRef = useRef<number | null>(null);
  const valid = Number.isFinite(seconds) && seconds >= 5;
  const active = valid && !paused && !hidden;

  const refresh = useCallback(() => {
    scrollRef.current = window.scrollY;
    start(() => router.refresh());
  }, [router]);

  // После обновления возвращаем прокрутку туда, где была (DOM — внешняя система).
  useEffect(() => {
    if (!pending && scrollRef.current != null) {
      const y = scrollRef.current;
      scrollRef.current = null;
      window.scrollTo({ top: y });
    }
  }, [pending]);

  // Фоновая вкладка — пауза; возврат во вкладку — сразу обновить и начать отсчёт заново.
  const pausedRef = useRef(paused);
  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);
  useEffect(() => {
    if (!valid) return;
    const onVis = () => {
      const h = document.visibilityState === "hidden";
      setHidden(h);
      if (!h && !pausedRef.current) {
        refresh();
        setLeft(seconds);
      }
    };
    document.addEventListener("visibilitychange", onVis);
    return () => document.removeEventListener("visibilitychange", onVis);
  }, [valid, refresh, seconds]);

  // Обратный отсчёт: updater чистый, без побочных эффектов — в StrictMode
  // React вызывает его дважды. Обновление уходит отдельным эффектом при 0.
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => setLeft((v) => (v <= 0 ? seconds : v - 1)), 1000);
    return () => clearInterval(t);
  }, [active, seconds]);
  useEffect(() => {
    if (active && left === 0) refresh();
  }, [active, left, refresh]);

  if (!valid) return null;
  const state = paused ? "пауза" : hidden ? "фон · пауза" : pending ? "обновляю…" : `через ${left} с`;
  return (
    <div className="flex items-center gap-2 text-[12px] text-muted-foreground" role="status" aria-live="off">
      <span className={pending ? "ascii-spin" : undefined} aria-hidden />
      <span>
        {label} {seconds} с · {state}
      </span>
      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        onClick={() => {
          setPaused((p) => !p);
          setLeft(seconds);
        }}
        aria-pressed={paused}
        aria-label={paused ? "Возобновить автообновление" : "Приостановить автообновление"}
        title={paused ? "Возобновить" : "Пауза"}
      >
        {paused ? <Play strokeWidth={1.5} /> : <Pause strokeWidth={1.5} />}
      </Button>
    </div>
  );
}
