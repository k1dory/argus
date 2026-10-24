import { actorApi } from "@/lib/actors-api";
import { actorMarkdown } from "@/lib/shared/actors";

// GET /api/v1/actors/{id}/report?range= — паспорт в Markdown (text/markdown,
// вложение actor-<id>.md): шапка, алиасы с интервалами, источники и их период,
// разделы, инциденты, таймлайн, «чего нет в данных». Все значения экранированы.
// Доступ — как у /api/v1/actors/{id}, но токену сессии разбора экспорт закрыт
// (выгрузка ПДн, kind "export"); в журнале — actor.export.
export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await ctx.params;
  const r = await actorApi(req, id, "actor.export");
  if (!r.ok) return r.response;
  return new Response(actorMarkdown(r.report), {
    headers: {
      "Content-Type": "text/markdown; charset=utf-8",
      "Content-Disposition": `attachment; filename="actor-${id}.md"`,
      "Cache-Control": "private, no-store",
    },
  });
}
