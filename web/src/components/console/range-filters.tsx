"use client";

import { useState, useTransition } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import type { RangeField } from "@/lib/shared/filters";

export type { RangeField };

const ANY = "__any"; // Radix Select не принимает пустое значение пункта

function keysOf(f: RangeField): [string, string] {
  return f.kind === "datetime" ? [`${f.key}_from`, `${f.key}_to`] : [`${f.key}_min`, `${f.key}_max`];
}

/**
 * Общая панель диапазонов для списков консоли. Значения — из URL (ссылкой
 * можно поделиться), применяются кнопкой или Enter; страница и устаревшие
 * параметры (legacy, например точный level) сбрасываются. Разбор и проверка —
 * на сервере (lib/shared/filters): форма только собирает строку запроса.
 * time — точный интервал from/to (UTC); пресеты — RangePicker рядом.
 */
export function RangeFilters(props: { time?: boolean; timeLabel?: string; fields?: RangeField[]; legacy?: string[]; idPrefix?: string }) {
  const params = useSearchParams();
  // Ключ — строка запроса: после навигации поля берут значения из нового URL.
  return <RangeFiltersForm key={params.toString()} {...props} />;
}

function RangeFiltersForm({ time = false, timeLabel = "Точный интервал, UTC", fields = [], legacy = [], idPrefix = "rf" }: { time?: boolean; timeLabel?: string; fields?: RangeField[]; legacy?: string[]; idPrefix?: string }) {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const [pending, start] = useTransition();
  const all: string[] = [...(time ? ["from", "to"] : []), ...fields.flatMap(keysOf)];
  const [values, setValues] = useState<Record<string, string>>(() => Object.fromEntries(all.map((k) => [k, params.get(k) ?? ""])));
  const set = (k: string, v: string) => setValues((s) => ({ ...s, [k]: v }));
  const active = all.some((k) => params.get(k)) || legacy.some((k) => params.get(k));

  const go = (vals: Record<string, string>, reset = false) => {
    const next = new URLSearchParams(params);
    const val = (k: string) => {
      const v = (vals[k] ?? "").trim();
      return v && v !== ANY ? v : "";
    };
    for (const k of all) {
      const v = val(k);
      if (v) next.set(k, v);
      else next.delete(k);
    }
    // Устаревший параметр (level=…) снимается, только когда его заменяет новое значение
    // того же поля (level_min/level_max) или при сбросе: применение одного времени его сохраняет.
    for (const k of legacy) {
      const f = fields.find((x) => x.key === k);
      const superseded = f ? keysOf(f).some((key) => val(key)) : false;
      if (reset || superseded) next.delete(k);
    }
    next.delete("page");
    // Точный интервал главнее пресета: пресет снимается, чтобы ссылка читалась однозначно.
    if (time && (next.get("from") || next.get("to"))) {
      next.delete("range");
      next.delete("period");
    }
    const qs = next.toString();
    start(() => router.push(qs ? `${pathname}?${qs}` : pathname));
  };

  return (
    <form
      className="flex flex-wrap items-end gap-3"
      role="search"
      aria-label="Фильтры по диапазону"
      aria-busy={pending}
      onSubmit={(e) => {
        e.preventDefault();
        if (!pending) go(values);
      }}
    >
      {time && <DateRange id={`${idPrefix}-time`} legend={timeLabel} from={values.from} to={values.to} onFrom={(v) => set("from", v)} onTo={(v) => set("to", v)} />}
      {fields.map((f) => {
        const [lo, hi] = keysOf(f);
        const id = `${idPrefix}-${f.key}`;
        if (f.kind === "datetime") {
          return <DateRange key={f.key} id={id} legend={`${f.label}, UTC`} from={values[lo]} to={values[hi]} onFrom={(v) => set(lo, v)} onTo={(v) => set(hi, v)} />;
        }
        return (
          <fieldset key={f.key} className="flex min-w-0 flex-col gap-1.5">
            <legend className="c-label mb-1.5">{f.label}{f.kind === "number" && f.unit ? `, ${f.unit}` : ""}</legend>
            <div className="flex items-center gap-1.5">
              {f.kind === "number" ? (
                <>
                  <NumberBound id={`${id}-min`} label={`${f.label}: от`} placeholder={`от ${f.min}`} value={values[lo]} onChange={(v) => set(lo, v)} f={f} />
                  <span className="text-[var(--text-tertiary)]" aria-hidden>—</span>
                  <NumberBound id={`${id}-max`} label={`${f.label}: до`} placeholder={`до ${f.max}`} value={values[hi]} onChange={(v) => set(hi, v)} f={f} />
                </>
              ) : (
                <>
                  <OrdinalBound id={`${id}-min`} label={`${f.label}: не ниже`} any="не ниже…" value={values[lo]} onChange={(v) => set(lo, v)} options={f.options} prefix="≥" />
                  <OrdinalBound id={`${id}-max`} label={`${f.label}: не выше`} any="не выше…" value={values[hi]} onChange={(v) => set(hi, v)} options={f.options} prefix="≤" />
                </>
              )}
            </div>
          </fieldset>
        );
      })}
      <Button type="submit" variant="secondary" className="min-h-9" aria-busy={pending || undefined} aria-disabled={pending || undefined}>
        {pending ? <span className="ascii-spin" aria-hidden /> : null}
        Применить
      </Button>
      {active && (
        <Button
          type="button"
          variant="ghost"
          className="min-h-9"
          onClick={() => {
            if (!pending) go({}, true);
          }}
        >
          сбросить диапазоны
        </Button>
      )}
    </form>
  );
}

function DateRange({ id, legend, from, to, onFrom, onTo }: { id: string; legend: string; from: string; to: string; onFrom: (v: string) => void; onTo: (v: string) => void }) {
  const cls = "h-9 min-w-0 rounded-lg border border-[var(--border-strong)] bg-background px-2 font-mono text-[12px] text-foreground [color-scheme:dark]";
  return (
    <fieldset className="flex min-w-0 flex-col gap-1.5">
      <legend className="c-label mb-1.5">{legend}</legend>
      <div className="flex items-center gap-1.5">
        <input id={`${id}-from`} type="datetime-local" value={from} onChange={(e) => onFrom(e.target.value)} aria-label={`${legend}: начало`} className={cls} />
        <span className="text-[var(--text-tertiary)]" aria-hidden>—</span>
        <input id={`${id}-to`} type="datetime-local" value={to} onChange={(e) => onTo(e.target.value)} aria-label={`${legend}: конец`} className={cls} />
      </div>
    </fieldset>
  );
}

function NumberBound({ id, label, placeholder, value, onChange, f }: { id: string; label: string; placeholder: string; value: string; onChange: (v: string) => void; f: { min: number; max: number; step?: number } }) {
  return (
    <>
      <Label htmlFor={id} className="sr-only">{label}</Label>
      <Input id={id} type="number" inputMode="decimal" min={f.min} max={f.max} step={f.step ?? 1} value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} className="h-9 w-24 px-2 font-mono text-[13px]" />
    </>
  );
}

function OrdinalBound({ id, label, any, value, onChange, options, prefix }: { id: string; label: string; any: string; value: string; onChange: (v: string) => void; options: { value: string; label: string }[]; prefix: string }) {
  const v = value || ANY;
  return (
    <>
      <Label htmlFor={id} className="sr-only">{label}</Label>
      <Select value={v} onValueChange={onChange}>
        <SelectTrigger id={id} aria-label={label} className="h-9 w-40 text-[13px]">
          <SelectValue>{v === ANY ? any : `${prefix} ${options.find((o) => o.value === v)?.label ?? v}`}</SelectValue>
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectItem value={ANY}>{any.replace("…", "")} — любой</SelectItem>
            {options.map((o) => <SelectItem key={o.value} value={o.value}>{prefix} {o.label}</SelectItem>)}
          </SelectGroup>
        </SelectContent>
      </Select>
    </>
  );
}
