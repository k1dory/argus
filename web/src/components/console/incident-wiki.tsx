import { NotebookPen } from "lucide-react";
import { MarkdownBody } from "@/components/console/markdown-body";
import { CommentForm } from "@/components/console/incident-status-form";
import { ReanalyzeButton } from "@/components/console/reanalyze-button";
import { Empty, Panel } from "@/components/console/panel";

/**
 * Досье в карточке: поле записи сверху (как комментарии в заявке), ниже —
 * выводы модели, заметка автоматики и записи команды (markdown — вид console
 * из incidentMarkdown: без шапки документа и пустых разделов). Экспорт —
 * в меню шапки карточки. Переразбор моделью в слепом разборе не предлагается:
 * его результат всё равно скрыт до завершения.
 */
export function IncidentWiki({ id, markdown, canEdit, blind = false }: { id: string; markdown: string; canEdit: boolean; blind?: boolean }) {
  const empty = markdown.trim() === "";
  return <Panel label="Досье" meta="выводы модели и записи команды">
    {canEdit && <div className="mb-5"><CommentForm incidentId={id} /></div>}
    {empty
      ? <Empty icon={NotebookPen} title="Записей пока нет" hint="Здесь появятся выводы модели и записи команды по этому инциденту." />
      : <MarkdownBody className="c-well max-h-[75vh] space-y-3 overflow-auto p-4 text-sm leading-relaxed break-words" label="Досье в Markdown">{markdown}</MarkdownBody>}
    {canEdit && !blind && <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-border pt-4"><ReanalyzeButton incidentId={id} /></div>}
  </Panel>;
}
