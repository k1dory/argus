import { apiGuard } from "@/lib/auth";
import { agreementApiForbidden, agreementMetrics } from "@/lib/blind-metrics";
import { LOW_DATA_N, parseAgreementWindow } from "@/lib/shared/blind-metrics";

// GET /api/incidents/agreement?window=7d|30d — согласие человека с вердиктом агента
// по правилам, отдельно для слепого и неслепого разбора, и доля false_positive.
// Только завершённые инциденты с ответом человека. Аналитик, администратор, токен API.
export async function GET(req: Request): Promise<Response> {
  const guard = await apiGuard(req, "default");
  if (guard.response) return guard.response;
  const forbidden = agreementApiForbidden(guard.session);
  if (forbidden) return forbidden;
  const window = parseAgreementWindow(new URL(req.url).searchParams.get("window"));
  if (!window) return Response.json({ error: "window — 7d или 30d" }, { status: 400 });
  try {
    const m = await agreementMetrics(window);
    return Response.json({ window: m.window, from: m.from, to: m.to, low_data_n: LOW_DATA_N, rules: m.rules, total: m.total });
  } catch (err) {
    console.error("api/incidents/agreement:", err instanceof Error ? err.message : err);
    return Response.json({ error: "хранилище недоступно" }, { status: 503 });
  }
}
