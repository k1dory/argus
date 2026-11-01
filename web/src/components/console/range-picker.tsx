"use client";

import { useState, useTransition } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { RANGES, type RangeKey } from "@/lib/shared/ranges";

const ALL = "__all";

/** Переключатель диапазона времени; активная «клавиша» остаётся вдавленной, нажатая — крутит спиннер.
 *  На время перехода кнопки не disabled (фокус остался бы на body), а aria-disabled с игнором клика.
 *  Пресет заменяет точный интервал (from/to): ни одна клавиша не вдавлена, пока он задан.
 *  anyLabel — клавиша «без ограничения» (снимает range) для списков без окна по умолчанию. */
export function RangePicker({ value, keys, anyLabel }: { value?: RangeKey; keys?: readonly RangeKey[]; anyLabel?: string }) {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const [pending, start] = useTransition();
  const [target, setTarget] = useState<string | null>(null);
  const exact = Boolean(params.get("from") || params.get("to"));
  const current = exact ? null : value ?? ALL;

  const select = (key: string) => {
    const next = new URLSearchParams(params);
    if (key === ALL) next.delete("range");
    else next.set("range", key);
    for (const k of ["period", "from", "to", "page"]) next.delete(k); // новый диапазон — с первой страницы
    setTarget(key);
    const qs = next.toString();
    start(() => router.push(qs ? `${pathname}?${qs}` : pathname));
  };

  const items: [string, string][] = [
    ...(anyLabel ? [[ALL, anyLabel] as [string, string]] : []),
    ...(keys ?? (Object.keys(RANGES) as RangeKey[])).map((k) => [k, RANGES[k].label] as [string, string]),
  ];

  return (
    <div className="flex flex-wrap gap-2" role="group" aria-label="Диапазон времени" aria-busy={pending}>
      {items.map(([key, label]) => {
        const loading = pending && target === key;
        return (
          <Button
            key={key}
            variant="secondary"
            size="sm"
            aria-pressed={current === key}
            aria-busy={loading || undefined}
            aria-disabled={pending || undefined}
            className={pending && !loading ? "opacity-60" : undefined}
            onClick={() => {
              if (!pending) select(key);
            }}
          >
            {loading && <span className="ascii-spin" aria-hidden />}
            {label}
          </Button>
        );
      })}
    </div>
  );
}
