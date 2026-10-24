"use client";

// Редактор дашборда: панели с SQL, размеры сетки, проверка запроса, JSON-модель.
import { useActionState, useEffect, useId, useState, useTransition } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { ArrowDown, ArrowUp, Play, Plus, Save, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { previewPanelAction, saveDashboardAction, type PreviewState, type SaveState } from "@/lib/dashboard-actions";
import { parseDashboardJson, SPEC_LIMITS, type DashboardSpec, type Panel, type PanelType } from "@/lib/shared/dashboard-spec";
import { parseRange, RANGES } from "@/lib/shared/ranges";
import { fmtMs } from "@/lib/shared/time";
import { Button } from "@/components/ui/button";
import { Panel as Win } from "@/components/console/panel";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

const TYPES: { v: PanelType; l: string }[] = [
  { v: "timeseries", l: "временной ряд" }, { v: "bar", l: "столбцы" }, { v: "stat", l: "число" }, { v: "table", l: "таблица" },
];

const MACROS = [
  { m: "$__timeFilter(col)", d: "col в выбранном диапазоне" },
  { m: "$__timeInterval(col)", d: "toStartOfInterval по шагу диапазона" },
  { m: "$__from / $__to", d: "границы диапазона" },
  { m: "$__interval", d: "INTERVAL n MINUTE" },
];

/** Проверка SQL живёт внутри формы сохранения, поэтому это не <form>
 *  (вложенные формы HTML не допускает), а кнопка с server action в transition.
 *  Диапазон — текущий из URL (?range=), как на странице дашборда. */
function PreviewButton({ sql }: { sql: string }) {
  const params = useSearchParams();
  const range = parseRange(params.get("range") ?? undefined);
  const [state, setState] = useState<PreviewState>({ data: null, error: null });
  const [pending, start] = useTransition();
  const run = () =>
    start(async () => {
      const fd = new FormData();
      fd.set("sql", sql);
      fd.set("range", range);
      setState(await previewPanelAction(state, fd));
    });
  return (
    <div className="space-y-2">
      <Button type="button" variant="secondary" size="sm" disabled={pending} aria-busy={pending} onClick={run}>
        {pending ? <span className="ascii-spin" aria-hidden /> : <Play strokeWidth={1.5} />}
        {pending ? "Выполняю…" : `Проверить запрос (${RANGES[range].label})`}
      </Button>
      {state.error && <pre role="alert" className="max-h-40 overflow-auto whitespace-pre-wrap font-mono text-xs text-destructive">{state.error}</pre>}
      {state.data && !state.error && (
        <div className="c-well max-h-48 overflow-auto p-2 font-mono text-[11px]">
          <div className="text-muted-foreground">{state.data.rows.length} строк · {fmtMs(state.data.ms)} · колонки: {state.data.columns.join(", ") || "—"}</div>
          {state.data.rows.slice(0, 8).map((r, i) => <div key={i} className="truncate">{JSON.stringify(r)}</div>)}
        </div>
      )}
    </div>
  );
}

export function DashboardEditor({ initial }: { initial: DashboardSpec }) {
  const router = useRouter();
  const uid = useId();
  const [spec, setSpec] = useState<DashboardSpec>(initial);
  const [saved, setSaved] = useState<string>(JSON.stringify(initial));
  const [json, setJson] = useState<string>("");
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [state, save, pending] = useActionState(saveDashboardAction, { error: null } as SaveState);
  const dirty = JSON.stringify(spec) !== saved;
  // Снимок, который ушёл на сервер: после успеха именно он считается сохранённым,
  // даже если пользователь продолжил править во время запроса.
  const [submitted, setSubmitted] = useState<string>(saved);
  const submit = (fd: FormData) => {
    setSubmitted(String(fd.get("spec") ?? ""));
    save(fd);
  };
  // Результат action пришёл — подстраиваем «сохранённый» снимок прямо в рендере
  // (паттерн «adjust state on prop change»), чтобы «Сохранено» сбрасывалось при первой же правке.
  const [seenState, setSeenState] = useState(state);
  if (state !== seenState) {
    setSeenState(state);
    if (state.ok) setSaved(submitted);
  }
  useEffect(() => {
    if (state.ok) toast.success("Дашборд сохранён");
    else if (state.error) toast.error(state.error);
  }, [state]);

  // Несохранённые правки — предупреждение при закрытии вкладки.
  useEffect(() => {
    if (!dirty) return;
    const onUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault();
    };
    window.addEventListener("beforeunload", onUnload);
    return () => window.removeEventListener("beforeunload", onUnload);
  }, [dirty]);

  const upd = (i: number, patch: Partial<Panel>) =>
    setSpec((s) => ({ ...s, panels: s.panels.map((p, j) => (j === i ? { ...p, ...patch } : p)) }));
  const move = (i: number, d: -1 | 1) =>
    setSpec((s) => {
      const p = [...s.panels];
      const j = i + d;
      if (j < 0 || j >= p.length) return s;
      [p[i], p[j]] = [p[j], p[i]];
      return { ...s, panels: p };
    });
  const add = () =>
    setSpec((s) => (s.panels.length >= SPEC_LIMITS.maxPanels ? s : { ...s, panels: [...s.panels, { id: `p${Date.now().toString(36)}`, title: "Новая панель", type: "table", w: 12, h: 8, sql: "SELECT source, count() AS events FROM events WHERE $__timeFilter(ts) GROUP BY source ORDER BY events DESC LIMIT 10" }] }));
  const remove = (i: number) => setSpec((s) => ({ ...s, panels: s.panels.filter((_, j) => j !== i) }));

  const applyJson = () => {
    const parsed = parseDashboardJson(json, spec.id);
    if (!parsed.ok) {
      setJsonError(parsed.error);
      return;
    }
    setJsonError(null);
    setSpec(parsed.spec);
    setJson("");
    toast.success("JSON применён в редактор", { description: `${parsed.spec.panels.length} панелей` });
  };

  const showSaved = state.ok && !dirty;

  return (
    <div className="space-y-6">
      <form action={submit} className="space-y-6" aria-busy={pending}>
        <input type="hidden" name="id" value={spec.id} />
        <input type="hidden" name="spec" value={JSON.stringify(spec)} />
        <div className="grid gap-4 sm:grid-cols-[1fr_auto_auto] sm:items-end">
          <div className="space-y-2">
            <Label htmlFor={`${uid}-title`} className="c-label">Название</Label>
            <Input id={`${uid}-title`} value={spec.title} maxLength={120} onChange={(e) => setSpec({ ...spec, title: e.target.value })} className="h-10 px-3" />
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${uid}-refresh`} className="c-label">Автообновление</Label>
            <Input id={`${uid}-refresh`} value={spec.refresh ?? ""} onChange={(e) => setSpec({ ...spec, refresh: e.target.value || undefined })} placeholder="30s" pattern="^\d{2,4}s$" title={`число секунд и «s», не чаще ${SPEC_LIMITS.minRefreshSec}s`} className="h-10 w-28 px-3" />
          </div>
          <Button type="submit" disabled={pending || !dirty} className="min-h-10">
            {pending ? <span className="ascii-spin" aria-hidden /> : <Save strokeWidth={1.5} />}
            {pending ? "Сохранение…" : dirty ? "Сохранить" : "Сохранено"}
          </Button>
        </div>
        <p className="text-xs text-muted-foreground" aria-live="polite">
          {dirty ? <span className="text-[var(--status-warn)]">есть несохранённые правки</span> : showSaved ? <span className="text-[var(--status-ok)]">Сохранено · <button type="button" className="underline" onClick={() => router.push(`/dashboards/${spec.id}`)}>открыть дашборд</button></span> : <>панелей: {spec.panels.length} из {SPEC_LIMITS.maxPanels}</>}
        </p>
        {state.error && <p role="alert" className="text-sm text-destructive">{state.error}</p>}

        {spec.panels.map((p, i) => (
          <Win
            key={p.id}
            label={`панель ${i + 1}`}
            bodyClassName="grid gap-4 lg:grid-cols-[1fr_1.2fr]"
            meta={
              <span className="flex gap-1">
                <Button type="button" variant="ghost" size="icon" disabled={i === 0} onClick={() => move(i, -1)} aria-label={`Панель ${i + 1}: переместить выше`} title="выше"><ArrowUp strokeWidth={1.5} /></Button>
                <Button type="button" variant="ghost" size="icon" disabled={i === spec.panels.length - 1} onClick={() => move(i, 1)} aria-label={`Панель ${i + 1}: переместить ниже`} title="ниже"><ArrowDown strokeWidth={1.5} /></Button>
                <Button type="button" variant="ghost" size="icon" onClick={() => remove(i)} aria-label={`Панель ${i + 1}: удалить`} title="удалить"><Trash2 strokeWidth={1.5} /></Button>
              </span>
            }
          >
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-2 sm:col-span-2">
                  <Label htmlFor={`${uid}-${p.id}-title`} className="c-label">Заголовок</Label>
                  <Input id={`${uid}-${p.id}-title`} value={p.title} maxLength={120} onChange={(e) => upd(i, { title: e.target.value })} className="h-9 px-3" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor={`${uid}-${p.id}-type`} className="c-label">Тип</Label>
                  <Select value={p.type} onValueChange={(v) => upd(i, { type: v as PanelType })}>
                    <SelectTrigger id={`${uid}-${p.id}-type`} className="h-9"><SelectValue /></SelectTrigger>
                    <SelectContent>{TYPES.map((t) => <SelectItem key={t.v} value={t.v}>{t.l}</SelectItem>)}</SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor={`${uid}-${p.id}-series`} className="c-label">Серии по колонке</Label>
                  <Input id={`${uid}-${p.id}-series`} value={p.series ?? ""} maxLength={64} onChange={(e) => upd(i, { series: e.target.value || undefined })} placeholder="source_class" className="h-9 px-3" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor={`${uid}-${p.id}-w`} className="c-label">Ширина (4–24)</Label>
                  <Input id={`${uid}-${p.id}-w`} type="number" min={4} max={24} value={p.w} onChange={(e) => upd(i, { w: Number(e.target.value) })} className="h-9 px-3" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor={`${uid}-${p.id}-h`} className="c-label">Высота (строк × 40px, 3–24)</Label>
                  <Input id={`${uid}-${p.id}-h`} type="number" min={3} max={24} value={p.h} onChange={(e) => upd(i, { h: Number(e.target.value) })} className="h-9 px-3" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor={`${uid}-${p.id}-unit`} className="c-label">Единица</Label>
                  <Input id={`${uid}-${p.id}-unit`} value={p.unit ?? ""} maxLength={16} onChange={(e) => upd(i, { unit: e.target.value || undefined })} placeholder="%" className="h-9 px-3" />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor={`${uid}-${p.id}-sql`} className="c-label">SQL (только SELECT, read-only пользователь)</Label>
                <textarea id={`${uid}-${p.id}-sql`} value={p.sql} onChange={(e) => upd(i, { sql: e.target.value })} rows={8} spellCheck={false} maxLength={SPEC_LIMITS.maxSqlLen}
                  aria-describedby={`${uid}-macros`}
                  className="w-full resize-y p-3 font-mono text-[12.5px] leading-[1.6] text-foreground" />
                <PreviewButton sql={p.sql} />
              </div>
          </Win>
        ))}
        <div className="flex flex-wrap items-center gap-3">
          <Button type="button" variant="secondary" onClick={add} disabled={spec.panels.length >= SPEC_LIMITS.maxPanels}><Plus strokeWidth={1.5} />Добавить панель</Button>
          {spec.panels.length >= SPEC_LIMITS.maxPanels && <span className="font-mono text-xs text-muted-foreground">достигнут предел {SPEC_LIMITS.maxPanels} панелей</span>}
        </div>
      </form>

      <Win label="Макросы времени" meta="как в Grafana" bodyClassName="grid gap-2 sm:grid-cols-2" id={`${uid}-macros`}>
        {MACROS.map((m) => (
          <div key={m.m} className="flex items-baseline gap-3 font-mono text-xs">
            <code className="text-[var(--ring)]">{m.m}</code>
            <span className="text-muted-foreground">{m.d}</span>
          </div>
        ))}
      </Win>

      <Win label="JSON-модель" meta="экспорт / импорт" bodyClassName="space-y-2">
          <Label htmlFor={`${uid}-json`} className="sr-only">JSON спецификации</Label>
          <textarea id={`${uid}-json`} value={json || JSON.stringify(spec, null, 2)} onChange={(e) => { setJson(e.target.value); setJsonError(null); }} rows={10} spellCheck={false}
            aria-invalid={jsonError ? true : undefined} aria-describedby={jsonError ? `${uid}-json-error` : undefined}
            className="w-full resize-y p-3 font-mono text-[12px] leading-[1.5]" />
          {jsonError && <p id={`${uid}-json-error`} role="alert" className="text-xs text-destructive">{jsonError}</p>}
          <div className="flex flex-wrap items-center gap-3">
            <Button type="button" variant="secondary" size="sm" onClick={applyJson} disabled={!json}>
              Применить JSON в редактор
            </Button>
            <span className="font-mono text-xs text-muted-foreground">до {SPEC_LIMITS.maxPanels} панелей · до {Math.round(SPEC_LIMITS.maxJsonBytes / 1024)} КБ · лишние поля отбрасываются</span>
          </div>
      </Win>
    </div>
  );
}
