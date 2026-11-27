// Вкладки-фильтры ссылками (сегмент): текущая — aria-current="page" и
// заливка; счётчики справа от подписи; вкладка с нулём — неактивна.
// Отдельная «флаг»-вкладка слева (например, «Отмеченные») — с рамкой
// и тоном ошибки, когда выбрана. Серверный компонент, без состояния.
import Link from "next/link";
import { Flag, type LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { fmtNum } from "@/lib/shared/time";

export type FilterTab = {
  key: string;
  label: string;
  href: string;
  /** Счётчик; 0 делает вкладку неактивной (кроме выбранной). Без счётчика — всегда активна. */
  count?: number;
  icon?: LucideIcon;
};

function Count({ n, className }: { n: number; className?: string }) {
  return <span className={cn("font-mono text-[12px] tabular-nums", className)}>{fmtNum(n)}</span>;
}

export function FilterTabs({
  label,
  items,
  current,
  flag,
  className,
}: {
  /** Подпись группы для скринридера: «Фильтр ленты». */
  label: string;
  items: FilterTab[];
  /** key выбранной вкладки (может совпадать с flag.key). */
  current: string;
  /** Отдельная вкладка-флаг слева: «Отмеченные», «Требуют внимания». */
  flag?: FilterTab;
  className?: string;
}) {
  return (
    <nav aria-label={label} className={cn("flex flex-wrap items-center gap-2", className)}>
      {flag && <FlagTab tab={flag} active={current === flag.key} />}
      <ul className="flex flex-wrap items-center gap-0.5 rounded-lg border border-border bg-[var(--surface-deep)] p-0.5">
        {items.map((t) => {
          const active = current === t.key;
          const disabled = !active && t.count === 0;
          const Icon = t.icon;
          const inner = (
            <>
              {Icon && <Icon className="size-3.5" strokeWidth={1.5} aria-hidden />}
              {t.label}
              {t.count !== undefined && <Count n={t.count} className={active ? "text-muted-foreground" : "text-[var(--text-tertiary)]"} />}
            </>
          );
          const base = "flex min-h-8 items-center gap-1.5 rounded-md px-3 text-[13px] transition-colors";
          return (
            <li key={t.key}>
              {disabled ? (
                <span aria-disabled="true" className={cn(base, "cursor-default text-[var(--text-disabled)]")}>{inner}</span>
              ) : (
                <Link
                  href={t.href}
                  aria-current={active ? "page" : undefined}
                  className={cn(
                    base,
                    active
                      ? "bg-[var(--surface-elevated)] font-medium text-foreground shadow-[inset_0_0_0_1px_var(--border-strong)]"
                      : "text-muted-foreground hover:bg-[var(--surface-elevated)]/60 hover:text-foreground",
                  )}
                >
                  {inner}
                </Link>
              )}
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

function FlagTab({ tab, active }: { tab: FilterTab; active: boolean }) {
  const Icon = tab.icon ?? Flag;
  const disabled = !active && tab.count === 0;
  const base = "flex min-h-9 items-center gap-1.5 rounded-lg border px-3 text-[13px] transition-colors";
  const inner = (
    <>
      <Icon className="size-3.5" strokeWidth={1.5} aria-hidden />
      {tab.label}
      {tab.count !== undefined && tab.count > 0 && <Count n={tab.count} className="text-[var(--status-err)]" />}
    </>
  );
  if (disabled) return <span aria-disabled="true" className={cn(base, "cursor-default border-border text-[var(--text-disabled)]")}>{inner}</span>;
  return (
    <Link
      href={tab.href}
      aria-current={active ? "page" : undefined}
      className={cn(
        base,
        active
          ? "border-[var(--status-err)]/60 bg-[var(--status-err)]/10 font-medium text-[var(--status-err)]"
          : "border-[var(--border-strong)] text-muted-foreground hover:bg-[var(--surface-elevated)] hover:text-foreground",
      )}
    >
      {inner}
    </Link>
  );
}
