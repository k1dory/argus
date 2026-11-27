import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { StorageUnavailable } from "@/components/console/storage-error";
import { PageHeader } from "@/components/console/panel";
import { lookupHref, passportHref } from "@/components/console/actors-section";
import { safeQuery } from "@/lib/clickhouse";
import { resolveAlias } from "@/lib/actors";
import { ALIAS_VALUE_MAX, parseActorRange } from "@/lib/shared/actors";
import { requireActorAccess } from "@/lib/actors-access";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Субъект по алиасу · Субъекты" };

/**
 * /actors/by-alias?v=<actor_name | IP | хост>&range=: точка входа из журнала.
 * Одна персона — переход в паспорт с тем же периодом; ничьё или несколько
 * владельцев — «Кому принадлежит» (там вывод, история, где встречалось и
 * форма привязки). Без значения — пустой поиск «Кому принадлежит».
 */
export default async function ByAliasPage({ searchParams }: PageProps<"/actors/by-alias">) {
  await requireActorAccess();
  const sp = await searchParams;
  const raw = typeof sp.v === "string" ? sp.v.trim().slice(0, ALIAS_VALUE_MAX) : "";
  const range = parseActorRange(typeof sp.range === "string" ? sp.range : undefined);
  if (!raw) redirect(`/actors/lookup?range=${range}`);
  const rr = await safeQuery(() => resolveAlias(raw));
  if (!rr.ok) {
    return (
      <>
        <PageHeader title="Субъекты" back={{ href: `/actors?range=${range}`, label: "К списку" }} />
        <StorageUnavailable reason={rr.error} />
      </>
    );
  }
  if (rr.data.status === "resolved") redirect(passportHref(rr.data.matches[0].person_id, range));
  redirect(lookupHref(raw, range));
}
