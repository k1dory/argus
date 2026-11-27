"use client";

import { useTransition } from "react";
import { useRouter } from "next/navigation";
import { RotateCw } from "lucide-react";

/** «Проверить снова»: перезапрашивает серверную часть страницы без перезагрузки. */
export function RetryButton({ label = "Проверить снова" }: { label?: string }) {
  const router = useRouter();
  const [pending, start] = useTransition();
  return (
    <button
      type="button"
      disabled={pending}
      onClick={() => start(() => router.refresh())}
      className="inline-flex items-center gap-1.5 text-[13px] text-[var(--ring)] underline-offset-4 hover:underline disabled:text-muted-foreground"
    >
      {pending ? <span className="ascii-spin" aria-hidden /> : <RotateCw className="size-3.5" strokeWidth={1.5} aria-hidden />}
      {pending ? "Проверяю…" : label}
    </button>
  );
}
