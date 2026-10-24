import { cn } from "@/lib/utils";
import Link from "next/link";

/** Квадратный индикатор состояния; смысл всегда дублируется текстом. */
export function Led({ color = "var(--status-ok)", title }: { color?: string; title?: string }) {
  return (
    <span
      aria-hidden={title ? undefined : true}
      role={title ? "img" : undefined}
      aria-label={title}
      title={title}
      className="c-led inline-block shrink-0"
      style={{ "--led-color": color } as React.CSSProperties}
    />
  );
}

/**
 * Панель: поверхность surface с волосяной границей и строкой заголовка
 * «Заголовок ··· meta». Глубина — слоями, без теней.
 */
export function Panel({
  label,
  meta,
  children,
  className,
  bodyClassName,
  style,
  id,
}: {
  label?: string;
  meta?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  bodyClassName?: string;
  style?: React.CSSProperties;
  id?: string;
}) {
  return (
    <section className={cn("win min-w-0", className)} style={style} id={id} aria-label={label}>
      {label && (
        <div className="win__bar">
          <span className="win__title">{label}</span>
          <span className="win__rule" aria-hidden />
          {meta && <span className="win__meta">{meta}</span>}
        </div>
      )}
      <div className={cn("win__body", bodyClassName)}>{children}</div>
    </section>
  );
}

/** Стат-плитка: mono-цифра, метка капсом, индикатор. */
export function StatTile({
  label,
  value,
  unit,
  led,
  hint,
  href,
}: {
  label: string;
  value: string;
  unit?: string;
  led?: string;
  /** Подсказка при наведении (например, полная дата) */
  hint?: string;
  /** Если метрика ведёт к списку, вся плитка становится доступной ссылкой. */
  href?: string;
}) {
  const content = (
    <>
      <div className="flex items-center gap-2">
        {led && <Led color={led} />}
        <span className="c-label">{label}</span>
        {href && <span className="ml-auto text-sm text-[var(--ring)]" aria-hidden>→</span>}
      </div>
      <div className="mt-3 text-3xl font-semibold tracking-[-0.02em] text-foreground tabular-nums">
        {value}
        {unit && <span className="ml-1 text-sm font-normal text-[var(--text-tertiary)]">{unit}</span>}
      </div>
    </>
  );
  const className = cn("win p-5", href && "block transition-colors hover:border-[var(--border-strong)] hover:bg-[var(--surface-elevated)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--ring)]");
  return href ? <Link href={href} className={className} title={hint}>{content}</Link> : <div className={className} title={hint}>{content}</div>;
}

/** Пустое состояние витрины: один стиль на всю консоль. */
export function Empty({ children, className }: { children: React.ReactNode; className?: string }) {
  return <p className={cn("text-sm text-muted-foreground", className)}>{children}</p>;
}

/** Шапка страницы: h1 совпадает с подписью в навигации; справа — фильтры или мета. */
export function PageHeader({ title, children, subtitle }: { title: React.ReactNode; children?: React.ReactNode; subtitle?: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-[26px] leading-[1.15] break-words sm:text-[32px]">{title}</h1>
        {subtitle && <p className="mt-2 max-w-[70ch] text-[15px] leading-[1.6] text-muted-foreground">{subtitle}</p>}
      </div>
      {children}
    </div>
  );
}
