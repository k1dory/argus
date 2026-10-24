"use client";

import { useEffect, useRef, useTransition } from "react";
import { useRouter } from "next/navigation";
import { RotateCw } from "lucide-react";
import { Button } from "@/components/ui/button";

/** Обновление по запросу оператора без таймера, который сбивает работу с лентой. */
export function RefreshDataButton() {
  const router = useRouter();
  const [pending, start] = useTransition();
  const scroll = useRef<number | null>(null);
  useEffect(() => {
    if (!pending && scroll.current !== null) {
      const y = scroll.current;
      scroll.current = null;
      requestAnimationFrame(() => window.scrollTo({ top: y, behavior: "instant" }));
    }
  }, [pending]);
  return <Button type="button" variant="secondary" size="sm" disabled={pending} onClick={() => {
    scroll.current = window.scrollY;
    start(() => router.refresh());
  }}>
    {pending ? <span className="ascii-spin" aria-hidden /> : <RotateCw strokeWidth={1.5} />}
    {pending ? "Обновляю…" : "Обновить"}
  </Button>;
}
