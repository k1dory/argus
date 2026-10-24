import { MarkdownBody } from "@/components/console/markdown-body";
import { CommentForm } from "@/components/console/incident-status-form";
import { DownloadButton } from "@/components/console/download-button";
import { ReanalyzeButton } from "@/components/console/reanalyze-button";
import { Panel } from "@/components/console/panel";

/** Markdown строится из вердикта модели и неизменяемого журнала команды. */
export function IncidentWiki({ id, markdown, canEdit }: { id: string; markdown: string; canEdit: boolean }) {
  return <Panel label="Досье инцидента" meta="Markdown · модель и команда">
    <div className="mb-4 flex flex-wrap items-center gap-2">
      <DownloadButton href={`/api/incidents/${id}/markdown`} filename={`${id}.md`}>Скачать .md</DownloadButton>
      {canEdit && <ReanalyzeButton incidentId={id} />}
    </div>
    <MarkdownBody className="c-well max-h-[75vh] space-y-3 overflow-auto p-4 text-sm leading-relaxed break-words" label="Досье в Markdown">{markdown}</MarkdownBody>
    {canEdit && <div className="mt-5 border-t border-border pt-4"><CommentForm incidentId={id} /></div>}
  </Panel>;
}
