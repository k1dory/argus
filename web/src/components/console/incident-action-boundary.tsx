"use client";

import { useEffect } from "react";

/** После server action новая RSC-карточка может менять высоту блоков выше формы. */
export function IncidentActionBoundary({ id, revision, children }: { id: string; revision: string; children: React.ReactNode }) {
  const key = `argus-incident-scroll:${id}`;
  useEffect(() => {
    try {
      const raw = sessionStorage.getItem(key);
      if (!raw) return;
      sessionStorage.removeItem(key);
      const saved = JSON.parse(raw) as { y: number; at: number };
      if (Date.now() - saved.at > 30_000 || !Number.isFinite(saved.y)) return;
      requestAnimationFrame(() => window.scrollTo({ top: saved.y, behavior: "instant" }));
    } catch {
      // Старая или повреждённая запись прокрутки не должна ломать карточку.
    }
  }, [key, revision]);
  return <div className="contents" onSubmitCapture={() => {
    try {
      sessionStorage.setItem(key, JSON.stringify({ y: window.scrollY, at: Date.now() }));
    } catch {
      // Browser storage may be disabled; submitting the form must still work.
    }
  }}>{children}</div>;
}
