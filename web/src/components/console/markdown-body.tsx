import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";

/** Markdown из хранилища (досье, комментарии, вердикты агента): HTML не
 *  рендерится, картинки не грузятся, ссылки — в новой вкладке без referrer. */
export function MarkdownBody({ children, className, label }: { children: string; className?: string; label?: string }) {
  return (
    <article className={className} aria-label={label}>
      <Markdown remarkPlugins={[remarkGfm]} skipHtml components={{
        h1: ({ children }) => <h2 className="text-xl font-semibold text-foreground">{children}</h2>,
        h2: ({ children }) => <h3 className="mt-5 border-t border-border pt-3 text-base font-semibold text-foreground">{children}</h3>,
        h3: ({ children }) => <h4 className="mt-3 font-semibold text-foreground">{children}</h4>,
        p: ({ children }) => <p className="my-2 whitespace-pre-wrap">{children}</p>,
        ul: ({ children }) => <ul className="my-2 list-disc space-y-1 pl-5">{children}</ul>,
        ol: ({ children }) => <ol className="my-2 list-decimal space-y-1 pl-5">{children}</ol>,
        li: ({ children }) => <li>{children}</li>,
        a: ({ href, children }) => <a href={href} target="_blank" rel="noopener noreferrer" className="text-[var(--ring)] underline underline-offset-2">{children}</a>,
        code: ({ children }) => <code className="font-mono text-xs">{children}</code>,
        pre: ({ children }) => <pre className="my-2 overflow-x-auto border border-border p-2">{children}</pre>,
        img: () => null,
      }}>{children}</Markdown>
    </article>
  );
}
