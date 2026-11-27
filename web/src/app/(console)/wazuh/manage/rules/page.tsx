import Link from "next/link";
import { Empty, PageHeader, Panel } from "@/components/console/panel";
import { ServiceUnavailable } from "@/components/console/service-unavailable";
import { StatusBadge } from "../../_shared/status-badge";
import { fmtNum } from "@/lib/shared/time";
import { NewRuleFileForm } from "@/components/console/manage-forms";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { listRuleFiles, type WzRuleFile } from "@/lib/wazuh-api";
import { requirePageSession } from "@/lib/auth";

export const dynamic = "force-dynamic";
export const metadata = { title: "Правила Wazuh" };

export default async function RulesPage() {
  const session = await requirePageSession();
  const isAdmin = session.role === "admin";
  let files: WzRuleFile[] = [];
  let error: string | null = null;
  try {
    files = await listRuleFiles();
  } catch (err) {
    error = err instanceof Error ? err.message : String(err);
    console.error("manage/rules:", error);
  }

  return (
    <>
      <PageHeader
        title="Правила Wazuh"
        back={{ href: "/wazuh/manage", label: "Управление Wazuh" }}
        subtitle={<>Собственные правила из каталога <span className="font-mono">etc/rules</span>. Встроенные правила Wazuh здесь не редактируются.</>}
      />

      {error ? (
        <ServiceUnavailable service="wazuh" what="список файлов правил" reason={error} />
      ) : (
        <Panel label={`Файлы правил · ${fmtNum(files.length)}`} meta={isAdmin ? "вступают в силу после перезапуска менеджера" : "только чтение — редактирует администратор"}>
          {isAdmin && (
            <div className="mb-6">
              <NewRuleFileForm />
            </div>
          )}
          {files.length === 0 ? (
            <Empty
              title="Собственных файлов правил пока нет"
              hint={isAdmin ? "Создайте первый, например local_rules_custom.xml." : "Файлы правил создаёт администратор."}
            />
          ) : (
            <div className="c-well overflow-x-auto p-2">
              <Table>
                <TableHeader>
                  <TableRow className="border-border/60">
                    <TableHead className="c-label">Файл</TableHead>
                    <TableHead className="c-label">Статус</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {files.map((f) => (
                    <TableRow key={f.filename} className="border-border/40">
                      <TableCell>
                        <Link
                          href={`/wazuh/manage/rules/${encodeURIComponent(f.filename)}`}
                          className="font-mono text-sm text-[var(--ring)] hover:underline"
                        >
                          {f.filename}
                        </Link>
                      </TableCell>
                      <TableCell>
                        {f.status === "enabled" ? (
                          <StatusBadge label="включён" tone="ok" />
                        ) : f.status === "disabled" ? (
                          <StatusBadge label="выключен" tone="muted" />
                        ) : (
                          <span className="text-xs text-muted-foreground">{f.status ?? "—"}</span>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </Panel>
      )}
    </>
  );
}
