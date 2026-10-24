"use client";

import { useEffect } from "react";
import Link from "next/link";

/**
 * Ошибка корневого layout: здесь нет ни globals.css, ни шрифтов — только
 * встроенные стили в духе консоли. Текст ошибки не показываем.
 */
export default function GlobalError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    console.error(error);
  }, [error]);
  return (
    <html lang="ru">
      <body style={{ margin: 0, background: "#0a0b0d", color: "#c5c9d0", fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif", minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center" }}>
        <main style={{ border: "1px solid #1e2127", borderRadius: 12, background: "#101216", padding: 24, maxWidth: 520, width: "100%" }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: "#e6e8eb", borderBottom: "1px solid #1e2127", paddingBottom: 8, marginBottom: 16 }}>
            ARGUS SIEM · ошибка
          </div>
          <p style={{ margin: 0, fontSize: 14, color: "#e6e8eb" }}>Консоль не смогла отрисовать страницу.</p>
          <p style={{ marginTop: 8, fontSize: 13, color: "#9ba1ac" }}>
            Повторите попытку; если ошибка повторяется — смотрите журнал контейнера web{error.digest ? ` (digest ${error.digest})` : ""}.
          </p>
          <div style={{ marginTop: 20, display: "flex", gap: 8 }}>
            <button type="button" onClick={reset} style={{ background: "#e6e8eb", color: "#0a0b0d", border: "1px solid #e6e8eb", borderRadius: 8, padding: "8px 14px", fontFamily: "inherit", fontSize: 13, cursor: "pointer" }}>
              Повторить
            </button>
            <Link href="/" style={{ color: "#e6e8eb", padding: "8px 14px", fontSize: 13, textDecoration: "none", border: "1px solid #2a2e37", borderRadius: 8 }}>
              На обзор
            </Link>
          </div>
        </main>
      </body>
    </html>
  );
}
