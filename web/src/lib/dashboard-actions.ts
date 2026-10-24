"use server";

import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import { requireRole } from "./auth";
import type { FormState } from "./actions";
import { audit } from "./argus-queries";
import { parseRange } from "./clickhouse";
import { deleteDashboard, runPanelQuery, saveDashboard, type DashboardSpec, type PanelData } from "./dashboards";
import { parseDashboardJson } from "./shared/dashboard-spec";

function slug(title: string): string {
  const map: Record<string, string> = { а:"a",б:"b",в:"v",г:"g",д:"d",е:"e",ё:"e",ж:"zh",з:"z",и:"i",й:"y",к:"k",л:"l",м:"m",н:"n",о:"o",п:"p",р:"r",с:"s",т:"t",у:"u",ф:"f",х:"h",ц:"c",ч:"ch",ш:"sh",щ:"sch",ъ:"",ы:"y",ь:"",э:"e",ю:"yu",я:"ya" };
  const s = title.toLowerCase().split("").map((c) => map[c] ?? c).join("").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return (s || "dashboard").slice(0, 60);
}

export async function createDashboardAction(_prev: FormState, formData: FormData): Promise<FormState> {
  const s = await requireRole("analyst");
  const title = String(formData.get("title") ?? "").trim().slice(0, 120);
  if (title.length < 2) return { error: "Название от двух символов" };
  const id = slug(title) + "-" + Math.random().toString(36).slice(2, 6);
  const spec: DashboardSpec = {
    id, title, refresh: "30s",
    panels: [{ id: "p1", title: "События по классам", type: "timeseries", w: 24, h: 8, series: "source_class",
      sql: "SELECT $__timeInterval(ts) AS time, source_class, count() AS events FROM events WHERE $__timeFilter(ts) GROUP BY time, source_class ORDER BY time" }],
  };
  const err = await saveDashboard(spec, s.user);
  if (err) return { error: err };
  await audit(s.user, "dashboard.create", id, title);
  redirect(`/dashboards/${id}/edit`);
}

export type SaveState = FormState;

export async function saveDashboardAction(_prev: SaveState, formData: FormData): Promise<SaveState> {
  const s = await requireRole("analyst");
  const id = String(formData.get("id") ?? "").slice(0, 64);
  const parsed = parseDashboardJson(String(formData.get("spec") ?? "{}"), id);
  if (!parsed.ok) return { error: parsed.error };
  const err = await saveDashboard(parsed.spec, s.user);
  if (err) return { error: err };
  await audit(s.user, "dashboard.save", id, `${parsed.spec.panels.length} панелей`);
  revalidatePath("/dashboards");
  revalidatePath(`/dashboards/${id}`);
  return { error: null, ok: true };
}

/** Удаление с редиректом на список: plain-form action для ConfirmActionForm. */
export async function deleteDashboardAction(formData: FormData): Promise<void> {
  const s = await requireRole("analyst");
  const id = String(formData.get("id") ?? "").slice(0, 64);
  await deleteDashboard(id, s.user);
  await audit(s.user, "dashboard.delete", id);
  revalidatePath("/dashboards");
  redirect("/dashboards");
}

export type PreviewState = { data: PanelData | null; error: string | null };

export async function previewPanelAction(_prev: PreviewState, formData: FormData): Promise<PreviewState> {
  await requireRole("analyst");
  const sql = String(formData.get("sql") ?? "").slice(0, 8001);
  const range = parseRange(String(formData.get("range") ?? "24h"));
  const data = await runPanelQuery(sql, range, 0);
  // Предпросмотр доступен только аналитику — полный текст ошибки ему можно.
  return { data: { ...data, rows: data.rows.slice(0, 20) }, error: data.error ? (data.errorDetail ? `${data.error}\n${data.errorDetail}` : data.error) : null };
}
