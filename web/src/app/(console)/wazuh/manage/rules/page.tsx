import Link from "next/link";
import { Panel } from "@/components/console/panel";
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
  let offline: string | null = null;
  try {
    files = await listRuleFiles();
  } catch (err) {
    console.error("manage/rules:", err instanceof Error ? err.message : err);
    offline = "Wazuh API недоступен — подробности в логе консоли";
  }

  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="text-3xl tracking-tight">Правила</h1>
        <span className="c-label">etc/rules — кастомные, ruleset Wazuh не трогаем</span>
      </div>

      {offline ? (
        <Panel label="Wazuh manager API · недоступен">
          <p className="text-sm text-destructive">{offline}</p>
        </Panel>
      ) : (
        <Panel label={`Файлы правил · ${files.length} шт.`} meta={isAdmin ? "применяются рестартом менеджера" : "только чтение — редактирует администратор"}>
          {isAdmin && (
            <div className="mb-6">
              <NewRuleFileForm />
            </div>
          )}
          {files.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              Кастомных файлов пока нет{isAdmin ? " — создайте первый, например local_rules_custom.xml" : ""}
            </p>
          ) : (
            <div className="c-well overflow-x-auto p-2">
              <Table>
                <TableHeader>
                  <TableRow className="border-border/60">
                    <TableHead className="c-label">Файл</TableHead>
                    <TableHead className="c-label">Каталог</TableHead>
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
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {f.relative_dirname}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{f.status ?? "—"}</TableCell>
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
