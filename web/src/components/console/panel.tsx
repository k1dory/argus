import { cn } from "@/lib/utils";
import Link from "next/link";
import { ArrowLeft, Info, OctagonAlert, TriangleAlert, type LucideIcon } from "lucide-react";
import { TONE_COLOR, type Tone } from "./tone";

/** Тон окна/плитки: ошибка, деградация, «новое». Остальное — без тона. */
export type PanelTone = "err" | "warn" | "info";

const TONE_ICON: Record<PanelTone, LucideIcon> = { err: OctagonAlert, warn: TriangleAlert, info: Info };

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
 * «Заголовок ··· meta [действия]». Глубина — слоями, без теней.
 *
 * - label — заголовок h2 (секция подписана им через aria-labelledby);
 *   длинный обрезается многоточием, полный текст — в title;
 * - meta — короткий факт человеческим языком (время, счётчик, период), не
 *   имена таблиц и служб; строковая meta при нехватке места переносится под
 *   заголовок и обрезается с подсказкой;
 * - tone — err/warn/info: рамка, подкрашенная полоса и иконка в заголовке;
 * - actions — кнопки справа в полосе заголовка («Обновить», «Экспорт»).
 */
export function Panel({
  label,
  meta,
  tone,
  actions,
  headingLevel = 2,
  children,
  className,
  bodyClassName,
  style,
  id,
}: {
  label?: string;
  meta?: React.ReactNode;
  tone?: PanelTone;
  actions?: React.ReactNode;
  /** Уровень заголовка: 2 (по умолчанию) или 3 — для панели внутри секции с h2. */
  headingLevel?: 2 | 3;
  children: React.ReactNode;
  className?: string;
  bodyClassName?: string;
  style?: React.CSSProperties;
  id?: string;
}) {
  // Уникальный id заголовка без хуков есть только у панели с id; без него секция
  // подписана aria-label — иначе одинаковые подписи дали бы одинаковые id.
  const hid = label && id ? `${id}-title` : undefined;
  const Heading = headingLevel === 3 ? "h3" : "h2";
  const ToneIcon = tone ? TONE_ICON[tone] : null;
  return (
    <section className={cn("win min-w-0", className)} style={style} id={id} aria-labelledby={hid} aria-label={label && !hid ? label : undefined} data-tone={tone}>
      {label && (
        <div className="win__bar">
          <div className="win__head">
            {ToneIcon && <ToneIcon className="win__tone-icon" strokeWidth={1.75} aria-hidden />}
            <Heading id={hid} className="win__title" title={label}>{label}</Heading>
          </div>
          <span className="win__rule" aria-hidden />
          {meta && <span className="win__meta" title={typeof meta === "string" ? meta : undefined}>{meta}</span>}
          {actions && <div className="win__actions">{actions}</div>}
        </div>
      )}
      <div className={cn("win__body", bodyClassName)}>{children}</div>
    </section>
  );
}

/** Стат-плитка: метка, крупное значение, видимая вторая строка, индикатор. */
export function StatTile({
  label,
  value,
  unit,
  led,
  hint,
  note,
  noteTone = "warn",
  sub,
  tone,
  size = "lg",
  href,
}: {
  label: string;
  value: string;
  unit?: string;
  /** Цвет Led (CSS). Без него при заданном tone Led берёт цвет тона. */
  led?: string;
  /** Подсказка при наведении (например, полная дата). Важное — в sub, не сюда. */
  hint?: string;
  /** Видимая пометка под значением (например, «мало данных»), цвет — noteTone. */
  note?: string;
  noteTone?: Tone;
  /** Видимая вторая строка приглушённым текстом («2 из 3», «последний — 5 мин назад»). */
  sub?: React.ReactNode;
  /** Тон значения и Led: err — горит, warn — внимание, ok — в порядке. */
  tone?: Tone;
  /** lg — крупная цифра; sm — для длинных значений (даты, версии). */
  size?: "lg" | "sm";
  /** Если метрика ведёт к списку, вся плитка становится доступной ссылкой. */
  href?: string;
}) {
  const ledColor = led ?? (tone && tone !== "neutral" && tone !== "plain" && tone !== "muted" ? TONE_COLOR[tone] : undefined);
  const valueColor = tone === "err" || tone === "warn" || tone === "info" ? TONE_COLOR[tone] : undefined;
  const content = (
    <>
      <div className="flex items-center gap-2">
        {ledColor && <Led color={ledColor} />}
        <span className="c-label">{label}</span>
        {href && <span className="ml-auto text-sm text-[var(--ring)]" aria-hidden>→</span>}
      </div>
      <div
        className={cn("mt-3 font-semibold tracking-[-0.02em] text-foreground tabular-nums", size === "sm" ? "text-xl break-words" : "text-3xl")}
        style={valueColor ? { color: valueColor } : undefined}
      >
        {value}
        {unit && <span className="ml-1 text-sm font-normal text-[var(--text-tertiary)]">{unit}</span>}
      </div>
      {sub && <div className="mt-1 text-[12px] leading-snug text-muted-foreground">{sub}</div>}
      {note && <div className="mt-1 text-xs" style={{ color: TONE_COLOR[noteTone] }}>{note}</div>}
    </>
  );
  const className = cn("win p-5", href && "block transition-colors hover:border-[var(--border-strong)] hover:bg-[var(--surface-elevated)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--ring)]");
  return href ? <Link href={href} className={className} title={hint}>{content}</Link> : <div className={className} title={hint}>{content}</div>;
}

/**
 * Пустое состояние: один стиль на всю консоль.
 *
 * Короткая форма — `<Empty>Текст</Empty>` (строка приглушённым текстом).
 * Полная — `<Empty icon={Inbox} title="Исключений нет" hint="Появятся, когда…" action={<Link…/>} />`:
 * по центру, заголовок, подсказка, действие. Не начинайте текст со слова
 * «Пусто»: пишите, что будет и когда.
 */
export function Empty({
  children,
  className,
  icon: Icon,
  title,
  hint,
  action,
}: {
  children?: React.ReactNode;
  className?: string;
  icon?: LucideIcon;
  title?: React.ReactNode;
  hint?: React.ReactNode;
  action?: React.ReactNode;
}) {
  if (!title && !Icon && !hint && !action) {
    return <p className={cn("text-sm text-muted-foreground", className)}>{children}</p>;
  }
  return (
    <div className={cn("flex flex-col items-center gap-2 py-8 text-center", className)}>
      {Icon && <Icon className="size-5 text-[var(--text-tertiary)]" strokeWidth={1.5} aria-hidden />}
      {title && <p className="text-sm text-foreground">{title}</p>}
      {hint && <p className="max-w-[60ch] text-[13px] leading-relaxed text-muted-foreground">{hint}</p>}
      {children && <div className="text-[13px] text-muted-foreground">{children}</div>}
      {action && <div className="mt-1">{action}</div>}
    </div>
  );
}

/**
 * Шапка страницы: h1 совпадает с подписью в навигации; справа — действия.
 *
 * - back — ссылка «назад» над заголовком (`{ href: "/incidents", label: "Инциденты" }`);
 * - status — пилюля состояния страницы рядом с заголовком (деградация, «устарело»);
 * - actions (или children, по-старому) — действия и фильтры справа, по верхнему краю.
 */
export function PageHeader({
  title,
  children,
  subtitle,
  back,
  status,
  actions,
}: {
  title: React.ReactNode;
  children?: React.ReactNode;
  subtitle?: React.ReactNode;
  back?: { href: string; label: string };
  status?: React.ReactNode;
  actions?: React.ReactNode;
}) {
  const right = actions ?? children;
  return (
    <div className="flex flex-wrap items-start justify-between gap-4">
      <div className="min-w-0">
        {back && (
          <Link href={back.href} className="mb-2 inline-flex items-center gap-1.5 text-[13px] text-muted-foreground transition-colors hover:text-foreground">
            <ArrowLeft className="size-3.5" strokeWidth={1.5} aria-hidden />
            {back.label}
          </Link>
        )}
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          <h1 className="min-w-0 text-[26px] leading-[1.15] break-words sm:text-[32px]">{title}</h1>
          {status}
        </div>
        {subtitle && <p className="mt-2 max-w-[70ch] text-[15px] leading-[1.6] text-muted-foreground">{subtitle}</p>}
      </div>
      {right && (actions && children ? <div className="flex flex-wrap items-center gap-2">{actions}{children}</div> : right)}
    </div>
  );
}
