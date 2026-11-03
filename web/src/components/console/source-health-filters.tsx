"use client";

import { useRef, useState, useTransition } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { ChevronDown, SlidersHorizontal, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Field, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { patchHref } from "@/lib/shared/filters";
import { SOURCE_HEALTH_FIELDS, sourceHealthChips, type SourceRanges } from "@/lib/shared/page-filters";
import { cn } from "@/lib/utils";

const groups = {
  time: ["seen_from", "seen_to"],
  events: ["events_min", "events_max"],
  eps: ["eps_min", "eps_max"],
} as const;
const keys = Object.values(groups).flat();
const number = new Intl.NumberFormat("ru-RU");
type Props = { shown: number; total: number; ranges: SourceRanges };

/** URL is the applied state; edits in the disclosure are a separate draft. */
export function SourceHealthFilters(props: Props) {
  const params = useSearchParams();
  return <SourceHealthFiltersForm key={params.toString()} {...props} />;
}

function SourceHealthFiltersForm({ shown, total, ranges }: Props) {
  const params = useSearchParams();
  const pathname = usePathname();
  const router = useRouter();
  const [pending, start] = useTransition();
  const [open, setOpen] = useState(false);
  const initial = () => Object.fromEntries(keys.map((key) => [key, params.get(key) ?? ""]));
  const [draft, setDraft] = useState<Record<string, string>>(initial);
  const trigger = useRef<HTMLButtonElement>(null);
  // Applied ranges come from the server, exactly as used to filter the table.
  const chips = sourceHealthChips(ranges);
  const active = keys.some((key) => params.get(key)?.trim());
  const activity = ranges.events.max === 0 && ranges.events.min === undefined ? "empty"
    : ranges.events.min === 1 && ranges.events.max === undefined ? "active"
      : ranges.events.min === undefined && ranges.events.max === undefined ? "all" : "";

  const close = () => {
    setOpen(false);
    setDraft(initial());
    trigger.current?.focus();
  };
  const navigate = (patch: Record<string, string | undefined>) => {
    if (pending) return;
    close();
    start(() => router.push(patchHref(pathname, params, patch), { scroll: false }));
  };
  const clear = (names: readonly string[]) => navigate(Object.fromEntries(names.map((key) => [key, undefined])));
  const set = (key: string, value: string) => setDraft((current) => ({ ...current, [key]: value }));

  return (
    <div className="flex min-w-0 flex-col gap-3" aria-busy={pending}>
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="flex min-w-0 flex-col gap-2">
          <span id="src-health-activity-label" className="text-xs text-muted-foreground">События за час</span>
          <ToggleGroup
            type="single"
            value={activity}
            onValueChange={(value) => {
              if (!value) return;
              navigate({ events_min: value === "active" ? "1" : undefined, events_max: value === "empty" ? "0" : undefined });
            }}
            disabled={pending}
            aria-labelledby="src-health-activity-label"
            variant="outline"
            size="lg"
            spacing={0}
          >
            <ToggleGroupItem value="all">Все</ToggleGroupItem>
            <ToggleGroupItem value="active">Есть события</ToggleGroupItem>
            <ToggleGroupItem value="empty">Без событий</ToggleGroupItem>
          </ToggleGroup>
        </div>
        <div className="flex w-full flex-wrap items-center justify-between gap-2 sm:w-auto sm:justify-start sm:gap-3">
          <span className="text-xs tabular-nums text-muted-foreground" role="status" aria-live="polite" aria-atomic="true">
            {pending ? "Обновляем список…" : `Показано ${number.format(shown)} из ${number.format(total)}`}
          </span>
          <Button
            ref={trigger}
            type="button"
            variant="outline"
            size="lg"
            aria-expanded={open}
            aria-controls="src-health-conditions"
            disabled={pending}
            onClick={() => open ? close() : setOpen(true)}
          >
            <SlidersHorizontal data-icon="inline-start" aria-hidden="true" />
            Фильтры
            {chips.length > 0 && <Badge variant="outline">{chips.length}<span className="sr-only"> активных условий</span></Badge>}
            <ChevronDown data-icon="inline-end" aria-hidden="true" className={cn(open && "rotate-180")} />
          </Button>
        </div>
      </div>

      {active && (
        <div className="flex flex-wrap items-center gap-2" aria-label="Применённые фильтры коллекторов">
          {chips.map((chip) => {
            const label = chip.key === "events" && activity === "empty" ? "Без событий за час"
              : chip.key === "events" && activity === "active" ? "Есть события за час"
                : `${chip.label}: ${chip.value}`;
            return (
              <Button
                key={chip.key}
                type="button"
                variant="secondary"
                size="sm"
                className="h-auto min-h-8 max-w-full whitespace-normal text-left"
                disabled={pending}
                aria-label={`Убрать условие: ${label}`}
                onClick={() => clear(groups[chip.key as keyof typeof groups])}
              >
                <span className="min-w-0">{label}</span>
                <X data-icon="inline-end" aria-hidden="true" />
              </Button>
            );
          })}
          <Button type="button" variant="ghost" size="sm" disabled={pending} onClick={() => clear(keys)}>
            Сбросить всё
          </Button>
        </div>
      )}

      <div id="src-health-conditions" hidden={!open}>
        <form
          role="search"
          aria-label="Точные фильтры коллекторов"
          className="rounded-xl border bg-background p-4"
          onKeyDown={(event) => {
            if (event.key === "Escape") {
              event.preventDefault();
              close();
            }
          }}
          onSubmit={(event) => {
            event.preventDefault();
            navigate(Object.fromEntries(keys.map((key) => [key, draft[key].trim() || undefined])));
          }}
        >
          <fieldset disabled={pending} className="flex min-w-0 flex-col gap-5">
            <legend className="sr-only">Точные условия</legend>
            <div className="grid min-w-0 gap-6 md:grid-cols-2 xl:grid-cols-[1.5fr_1fr_1fr]">
              {SOURCE_HEALTH_FIELDS.map((field) => (
                <FieldSet key={field.key} className={cn("min-w-0 gap-2", field.kind === "datetime" && "md:col-span-2 xl:col-span-1")}>
                  <FieldLegend variant="label">{field.label}{field.kind === "datetime" ? ", UTC" : ""}</FieldLegend>
                  <FieldGroup className={cn("grid grid-cols-2 gap-3", field.kind === "datetime" && "grid-cols-1 sm:grid-cols-2")}>
                    {(field.kind === "datetime" ? ["from", "to"] : ["min", "max"]).map((bound, index) => {
                      const name = `${field.key}_${bound}`;
                      const id = `src-health-${field.key}-${bound}`;
                      return (
                        <Field key={bound} className="min-w-0">
                          <FieldLabel htmlFor={id} className="text-xs text-muted-foreground">{index === 0 ? "От" : "До"}</FieldLabel>
                          <Input
                            id={id}
                            name={name}
                            type={field.kind === "datetime" ? "datetime-local" : "number"}
                            aria-label={`${field.label}${field.kind === "datetime" ? ", UTC" : ""}: ${index === 0 ? "от" : "до"}`}
                            autoComplete="off"
                            inputMode={field.kind === "number" ? "decimal" : undefined}
                            min={field.kind === "number" ? field.min : undefined}
                            max={field.kind === "number" ? field.max : undefined}
                            step={field.kind === "number" ? field.step ?? 1 : draft[name].length > 16 ? 1 : undefined}
                            value={draft[name]}
                            placeholder={field.kind === "number" ? "—" : undefined}
                            onChange={(event) => set(name, event.target.value)}
                            className="h-9 min-w-0 [color-scheme:dark]"
                          />
                        </Field>
                      );
                    })}
                  </FieldGroup>
                  {field.kind === "datetime" && <p className="text-xs text-muted-foreground">Если задано только «До», берутся сутки перед этой датой.</p>}
                  {field.key === "eps" && <p className="text-xs text-muted-foreground">Событий в секунду за последние 60 с.</p>}
                </FieldSet>
              ))}
            </div>
            <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
              <p className="text-xs text-muted-foreground">Пустое поле — без ограничения. 0 — нулевой порог.</p>
              <div className="flex items-center gap-2">
                <Button type="button" variant="ghost" size="lg" onClick={close}>Отмена</Button>
                <Button type="submit" size="lg">Применить</Button>
              </div>
            </div>
          </fieldset>
        </form>
      </div>
    </div>
  );
}
