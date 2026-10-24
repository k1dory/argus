import Link from "next/link";
import { Button } from "@/components/ui/button";
import { fmtNum } from "@/lib/shared/time";

/** Пагинация списков: «← →», «страница N из M», диапазон строк при известном total.
 *  Крайние стрелки — не ссылки, а span с aria-disabled: недоступная ссылка в DOM не нужна. */
export function Pager({
  page,
  pages,
  total,
  pageSize,
  href,
  capped,
}: {
  page: number;
  pages: number;
  total?: number;
  pageSize?: number;
  href: (page: number) => string;
  /** Показан потолок страниц — дальше только через уточнение фильтров */
  capped?: boolean;
}) {
  if (pages <= 1 && !total) return null;
  const from = pageSize ? (page - 1) * pageSize + 1 : null;
  const to = pageSize && total != null ? Math.min(total, page * pageSize) : null;
  return (
    <nav className="mt-4 flex flex-wrap items-center gap-2 font-mono text-xs" aria-label="Страницы">
      {page <= 1 ? (
        <Button asChild variant="secondary" size="sm" className="opacity-40">
          <span aria-disabled="true" aria-label="Предыдущая страница">←</span>
        </Button>
      ) : (
        <Button asChild variant="secondary" size="sm">
          <Link href={href(page - 1)} rel="prev" aria-label="Предыдущая страница">←</Link>
        </Button>
      )}
      <span className="text-muted-foreground">
        страница {fmtNum(page)} из {fmtNum(pages)}
        {total != null && from != null && to != null && total > 0 && <> · строки {fmtNum(from)}–{fmtNum(to)} из {fmtNum(total)}</>}
        {capped && page >= pages && <> · дальше — уточните фильтры</>}
      </span>
      {page >= pages ? (
        <Button asChild variant="secondary" size="sm" className="opacity-40">
          <span aria-disabled="true" aria-label="Следующая страница">→</span>
        </Button>
      ) : (
        <Button asChild variant="secondary" size="sm">
          <Link href={href(page + 1)} rel="next" aria-label="Следующая страница">→</Link>
        </Button>
      )}
    </nav>
  );
}

/** Заголовок колонки с сортировкой через URL `sort=`/`dir=`. */
export function SortLink({
  label,
  field,
  sort,
  dir,
  href,
}: {
  label: string;
  field: string;
  sort: string;
  dir: "asc" | "desc";
  href: (sort: string, dir: "asc" | "desc") => string;
}) {
  const active = sort === field;
  const nextDir: "asc" | "desc" = active && dir === "desc" ? "asc" : "desc";
  return (
    <Link
      href={href(field, nextDir)}
      className={active ? "text-foreground underline decoration-[var(--ring)] underline-offset-4" : "hover:text-foreground"}
      aria-label={`Сортировать по «${label}» ${nextDir === "asc" ? "по возрастанию" : "по убыванию"}`}
    >
      {label}
      <span aria-hidden className="ml-1">{active ? (dir === "asc" ? "↑" : "↓") : "↕"}</span>
    </Link>
  );
}
