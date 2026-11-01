"use client";

import { useState } from "react";
import { Download } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { fetchDownload, saveBlob } from "@/lib/shared/download";

/**
 * Скачивание с состоянием: fetch → blob → a.download. Пока идёт загрузка —
 * кнопка недоступна и крутит ASCII-спиннер; ошибка сервера — тостом, а не
 * пустой вкладкой.
 */
export function DownloadButton({
  href,
  filename,
  children,
  size = "sm",
  variant = "secondary",
}: {
  href: string;
  filename: string;
  children: React.ReactNode;
  size?: "sm" | "default" | "lg";
  variant?: "secondary" | "ghost" | "default";
}) {
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    try {
      saveBlob(await fetchDownload(href), filename);
      toast.success("Файл готов", { description: filename });
    } catch (e) {
      toast.error("Экспорт не выполнен", { description: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Button type="button" variant={variant} size={size} onClick={run} disabled={busy} aria-busy={busy}>
      {busy ? <span className="ascii-spin" aria-hidden /> : <Download strokeWidth={1.5} />}
      {busy ? "Готовлю…" : children}
    </Button>
  );
}
