import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, RotateCw } from "lucide-react";
import { Panel } from "@/components/console/panel";
import { RuleFileEditor } from "@/components/console/manage-forms";
import { ConfirmActionForm } from "@/components/console/action-form";
import { Button } from "@/components/ui/button";
import { restartManagerAction } from "@/lib/manage-actions";
import { getRuleFile, WazuhApiError } from "@/lib/wazuh-api";
import { requirePageSession } from "@/lib/auth";
import { RULE_FILE_RE } from "@/lib/shared/wazuh-names";

export const dynamic = "force-dynamic";
export const metadata = { title: "Файл правил" };

const RULE_TEMPLATE = `<group name="local,">
  <!-- Свои правила: id 100000–120000 зарезервированы под кастомные -->
  <rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <description>Пример: переопределение уровня для sshd</description>
  </rule>
</group>
`;

export default async function RuleFilePage({
  params,
  searchParams,
}: PageProps<"/wazuh/manage/rules/[file]">) {
  const session = await requirePageSession();
  const isAdmin = session.role === "admin";
  const { file } = await params;
  const isNew = (await searchParams).new === "1";
  const filename = decodeURIComponent(file);
  // Та же регулярка, что при сохранении: путь к файлу менеджера не собирается из произвольной строки.
  if (!RULE_FILE_RE.test(filename)) notFound();

  let xml = RULE_TEMPLATE;
  let offline: string | null = null;
  let existedAlready = false;
  try {
    // И для «нового» файла проверяем существование: сохранение идёт с
    // overwrite=true, и совпадение имени с существующим файлом молча
    // затёрло бы его — вместо шаблона открываем реальное содержимое.
    xml = await getRuleFile(filename);
    existedAlready = isNew;
  } catch (err) {
    if (err instanceof WazuhApiError && err.status === 404) {
      // Новый файл может открыть только администратор; остальным — 404.
      if (!isAdmin) notFound();
      xml = RULE_TEMPLATE;
    } else {
      console.error("manage/rules/[file]:", err instanceof Error ? err.message : err);
      offline = "Wazuh API недоступен — подробности в логе консоли";
    }
  }

  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="text-3xl tracking-tight">
          <span className="font-mono">{filename}</span>
        </h1>
        <div className="flex flex-wrap gap-2">
          {isAdmin && (
            <ConfirmActionForm
              action={restartManagerAction}
              title="Перезапустить менеджер Wazuh?"
              description="Обработка событий прервётся на время рестарта. Перед этим убедитесь, что проверка конфигурации после сохранения прошла."
              confirmLabel="Перезапустить"
              successText="Менеджер перезапускается"
            >
              <Button type="submit" variant="secondary" size="sm">
                <RotateCw strokeWidth={1.5} />
                Перезапустить менеджер
              </Button>
            </ConfirmActionForm>
          )}
          <Button asChild variant="ghost" size="sm">
            <Link href="/wazuh/manage/rules">
              <ArrowLeft strokeWidth={1.5} />
              Ко всем файлам
            </Link>
          </Button>
        </div>
      </div>

      {offline ? (
        <Panel label="Wazuh manager API · недоступен">
          <p className="text-sm text-destructive">{offline}</p>
        </Panel>
      ) : (
        <Panel
          label={`Редактор · etc/rules/${filename}`}
          meta={isAdmin ? "сохранить → проверка менеджером → рестарт" : "только чтение — редактирует администратор"}
        >
          {existedAlready && (
            <p className="mb-4 text-sm text-[var(--status-warn)]">
              Файл с таким именем уже существует — открыто его текущее содержимое.
            </p>
          )}
          <RuleFileEditor filename={filename} initialXml={xml} readOnly={!isAdmin} />
        </Panel>
      )}
    </>
  );
}
