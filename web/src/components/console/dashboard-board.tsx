// Одна плашка «доска не может читать данные» вместо одинаковой ошибки в
// каждой панели. Всем — человеческая фраза; администратору — что настроить
// и сырой текст ошибки под раскрытием.
import { Panel } from "@/components/console/panel";
import { RetryButton } from "@/components/console/retry-button";
import { humanPanelError } from "@/lib/shared/dashboard-view";

export function BoardErrorBanner({ error, detail, admin }: { error: string; detail?: string; admin: boolean }) {
  const h = humanPanelError(error);
  return (
    <Panel label="Данные доски недоступны" tone="err">
      <div className="space-y-2 text-sm">
        <p className="text-foreground">{h.text}</p>
        <p className="text-muted-foreground">Панели появятся, как только доступ к данным восстановится.</p>
        {admin ? (
          <details className="group text-[13px]">
            <summary className="inline-flex cursor-pointer items-center gap-1 text-muted-foreground hover:text-foreground">
              <span aria-hidden className="inline-block transition-transform group-open:rotate-90">›</span>
              Подробности для администратора
            </summary>
            <div className="mt-2 space-y-2 border-l border-[var(--border-strong)] pl-3 text-muted-foreground">
              {h.admin && <p>{h.admin}</p>}
              <p className="font-mono text-[12px] break-words text-[var(--fg-2)]">{error}</p>
              {detail && <pre className="max-h-48 overflow-auto whitespace-pre-wrap bg-[var(--surface-deep)] p-2 font-mono text-xs text-muted-foreground">{detail}</pre>}
            </div>
          </details>
        ) : (
          <p className="text-[13px] text-muted-foreground">Если это продолжается дольше нескольких минут, сообщите администратору.</p>
        )}
        <div className="pt-1"><RetryButton /></div>
      </div>
    </Panel>
  );
}
