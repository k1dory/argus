"use client";

import { useState, useTransition } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { RANGES, type RangeKey } from "@/lib/shared/ranges";

/** Переключатель диапазона времени; активная «клавиша» остаётся вдавленной, нажатая — крутит спиннер.
 *  На время перехода кнопки не disabled (фокус остался бы на body), а aria-disabled с игнором клика. */
export function RangePicker({ value }: { value: RangeKey }) {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const [pending, start] = useTransition();
  const [target, setTarget] = useState<RangeKey | null>(null);

  const select = (key: RangeKey) => {
    const next = new URLSearchParams(params);
    next.set("range", key);
    next.delete("page"); // новый диапазон — с первой страницы
    setTarget(key);
    start(() => router.push(`${pathname}?${next.toString()}`));
  };

  return (
    <div className="flex gap-2" role="group" aria-label="Диапазон времени" aria-busy={pending}>
      {(Object.keys(RANGES) as RangeKey[]).map((key) => {
        const loading = pending && target === key;
        return (
          <Button
            key={key}
            variant="secondary"
            size="sm"
            aria-pressed={value === key}
            aria-busy={loading || undefined}
            aria-disabled={pending || undefined}
            className={pending && !loading ? "opacity-60" : undefined}
            onClick={() => {
              if (!pending) select(key);
            }}
          >
            {loading && <span className="ascii-spin" aria-hidden />}
            {RANGES[key].label}
          </Button>
        );
      })}
    </div>
  );
}
