"use client";

import { useActionState, useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { AlertTriangle, CheckCircle2, FilePlus2, FolderPlus, Plus, Save } from "lucide-react";
import { toast } from "sonner";
import type { FormState } from "@/lib/actions";
import { ActionForm } from "@/components/console/action-form";
import {
  agentGroupAction,
  createGroupAction,
  saveGroupConfAction,
  saveRuleFileAction,
  type SaveRuleState,
} from "@/lib/manage-actions";
import { RULE_FILE_RE } from "@/lib/shared/wazuh-names";
import { formatXmlError, validateXml, wrapXmlRoots } from "@/lib/shared/xml";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const initial: FormState = { error: null };

/** Результат действия → toast. Реагирует только на новое состояние. */
function useActionToast(state: FormState, okText: string) {
  const seen = useRef<FormState>(state);
  useEffect(() => {
    if (seen.current === state) return;
    seen.current = state;
    if (state.error) toast.error(state.error);
    else if (state.ok) toast.success(okText);
  }, [state, okText]);
}

/** Добавление агента в группу: селект групп + submit в server action. */
export function AgentGroupAdd({
  agentId,
  groups,
}: {
  agentId: string;
  groups: string[];
}) {
  const [group, setGroup] = useState<string>("");
  if (groups.length === 0) return null;
  return (
    <ActionForm action={agentGroupAction} successText="Агент добавлен в группу" className="flex items-center gap-2" onDone={() => setGroup("")}>
      <input type="hidden" name="agent_id" value={agentId} />
      <input type="hidden" name="group_id" value={group} />
      <input type="hidden" name="op" value="add" />
      <Select value={group} onValueChange={setGroup}>
        <SelectTrigger className="h-8 w-36" aria-label={`Группа для агента ${agentId}`}>
          <SelectValue placeholder="в группу…" />
        </SelectTrigger>
        <SelectContent>
          {groups.map((g) => (
            <SelectItem key={g} value={g}>
              {g}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Button type="submit" variant="ghost" size="icon" disabled={!group} title="Добавить в группу">
        <Plus strokeWidth={1.5} />
        <span className="sr-only">Добавить в группу</span>
      </Button>
    </ActionForm>
  );
}

export function GroupCreateForm() {
  const [state, action, pending] = useActionState(createGroupAction, initial);
  const [touchedFor, setTouchedFor] = useState<FormState | null>(null);
  const touched = touchedFor === state; // новый ввод после ответа прячет ok/ошибку
  useActionToast(state, "Группа создана");
  return (
    <form action={action} className="flex flex-wrap items-end gap-3" aria-busy={pending || undefined}>
      <div className="space-y-2">
        <Label htmlFor="group-name" className="c-label">
          Новая группа
        </Label>
        <Input id="group-name" name="name" placeholder="webservers" required className="h-10 w-56 px-3" onChange={() => setTouchedFor(state)} />
      </div>
      <Button type="submit" variant="secondary" disabled={pending} className="min-h-10">
        <FolderPlus strokeWidth={1.5} />
        {pending ? "Создание…" : "Создать"}
      </Button>
      {state.error && !touched && (
        <p role="alert" className="w-full text-sm text-destructive">
          {state.error}
        </p>
      )}
      {state.ok && !touched && (
        <p role="status" className="w-full text-sm text-[var(--status-ok)]">
          Группа создана
        </p>
      )}
    </form>
  );
}

/** Ошибка XML: свой стековый валидатор (тот же, что на сервере — строка и
 *  причина одинаковые), затем DOMParser браузера как вторая проверка.
 *  Wazuh допускает несколько корневых элементов, DOMParser — нет: документ
 *  оборачивается в синтетический корень. */
function clientXmlError(xml: string): string | null {
  const own = validateXml(xml);
  if (own) return formatXmlError(own);
  if (typeof DOMParser === "undefined") return null;
  const doc = new DOMParser().parseFromString(wrapXmlRoots(xml), "application/xml");
  const pe = doc.getElementsByTagName("parsererror")[0];
  if (!pe) return null;
  const text = (pe.textContent ?? "ошибка разбора").replace(/\s+/g, " ");
  // Firefox: «… Line Number 5, Column 3»; Chromium: «error on line 5 at column 3: …»
  const m = /[Ll]ine(?: Number)?\s+(\d+)/.exec(text);
  return m ? `строка ${m[1]}: ${text.slice(0, 160)}` : text.slice(0, 200);
}

/** Редактор XML (agent.conf группы или файла правил): проверка well-formed
 *  на клиенте до отправки, Ctrl/Cmd+S — сохранить, предупреждение при уходе
 *  с несохранёнными правками; readOnly — для ролей без права редактировать. */
function XmlEditor({
  action,
  hidden,
  initialXml,
  saveLabel,
  okText,
  readOnly,
  renderExtra,
}: {
  action: (prev: SaveRuleState, formData: FormData) => Promise<SaveRuleState>;
  hidden: Record<string, string>;
  initialXml: string;
  saveLabel: string;
  okText: string;
  readOnly?: boolean;
  renderExtra?: (state: SaveRuleState) => React.ReactNode;
}) {
  const [state, formAction, pending] = useActionState(action, { error: null } as SaveRuleState);
  const [xml, setXml] = useState(initialXml);
  const [savedXml, setSavedXml] = useState(initialXml);
  const [xmlError, setXmlError] = useState<string | null>(null);
  const formRef = useRef<HTMLFormElement>(null);
  const dirty = xml !== savedXml;
  useActionToast(state, okText);

  // Успешное сохранение фиксирует «чистую» версию — beforeunload больше не
  // ругается. Производное состояние считаем при рендере, а не в эффекте.
  const [ackState, setAckState] = useState<SaveRuleState>(state);
  if (ackState !== state) {
    setAckState(state);
    if (state.ok && !state.error) setSavedXml(xml);
  }

  useEffect(() => {
    if (!dirty || readOnly) return;
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [dirty, readOnly]);

  const check = useCallback((value: string): boolean => {
    const err = clientXmlError(value);
    setXmlError(err);
    return !err;
  }, []);

  return (
    <form
      ref={formRef}
      action={formAction}
      className="space-y-4"
      aria-busy={pending || undefined}
      onSubmit={(e) => {
        if (readOnly || !check(xml)) e.preventDefault();
      }}
      onKeyDown={(e) => {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") {
          e.preventDefault();
          if (!readOnly && !pending) formRef.current?.requestSubmit();
        }
      }}
    >
      {Object.entries(hidden).map(([k, v]) => (
        <input key={k} type="hidden" name={k} value={v} />
      ))}
      <textarea
        name="xml"
        value={xml}
        onChange={(e) => {
          setXml(e.target.value);
          if (xmlError) check(e.target.value);
        }}
        onBlur={() => check(xml)}
        rows={22}
        spellCheck={false}
        readOnly={readOnly}
        aria-invalid={xmlError ? true : undefined}
        aria-describedby={xmlError ? "xml-error" : undefined}
        className="w-full resize-y border border-border bg-[var(--surface-deep)] p-4 font-mono text-[13px] leading-[1.6] read-only:opacity-70 focus-visible:border-[var(--border-strong)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]/40 aria-invalid:border-destructive"
      />
      <div className="flex flex-wrap items-center gap-3">
        {readOnly ? (
          <span className="c-label">только чтение — редактирует администратор</span>
        ) : (
          <Button type="submit" disabled={pending || !!xmlError} className="min-h-10" title="Ctrl+S">
            <Save strokeWidth={1.5} />
            {pending ? "Сохранение…" : saveLabel}
          </Button>
        )}
        {dirty && !readOnly && !pending && <span className="c-label text-[var(--status-warn)]">не сохранено</span>}
        {xmlError && (
          <p id="xml-error" role="alert" className="text-sm text-destructive">
            XML: {xmlError}
          </p>
        )}
        {!xmlError && state.error && (
          <p role="alert" className="text-sm text-destructive">
            {state.error}
          </p>
        )}
        {!xmlError && state.ok && !dirty && (
          <p role="status" className="text-sm text-[var(--status-ok)]">
            {okText}
          </p>
        )}
      </div>
      {renderExtra?.(state)}
    </form>
  );
}

export function GroupConfEditor({ group, initialXml, readOnly }: { group: string; initialXml: string; readOnly?: boolean }) {
  return (
    <XmlEditor
      action={saveGroupConfAction}
      hidden={{ group }}
      initialXml={initialXml}
      saveLabel="Сохранить agent.conf"
      okText="Сохранено — группа разъедется на агентов при следующем keepalive"
      readOnly={readOnly}
    />
  );
}

export function RuleFileEditor({
  filename,
  initialXml,
  readOnly,
}: {
  filename: string;
  initialXml: string;
  readOnly?: boolean;
}) {
  return (
    <XmlEditor
      action={saveRuleFileAction}
      hidden={{ filename }}
      initialXml={initialXml}
      saveLabel="Сохранить файл правил"
      okText="Файл сохранён"
      readOnly={readOnly}
      renderExtra={(state) =>
        state.validation ? (
          <div
            role="status"
            className={`flex items-start gap-2 border px-3 py-2 font-mono text-xs ${state.validation.ok ? "border-[var(--status-ok)]/40" : "border-destructive/60"}`}
          >
            {state.validation.ok ? (
              <CheckCircle2 strokeWidth={1.5} className="mt-0.5 size-4 shrink-0 text-[var(--status-ok)]" />
            ) : (
              <AlertTriangle strokeWidth={1.5} className="mt-0.5 size-4 shrink-0 text-destructive" />
            )}
            <span>
              <span className="c-label block">проверка конфигурации менеджера</span>
              {state.validation.ok
                ? "OK — можно применять перезапуском менеджера (кнопка сверху)"
                : `менеджер отклонил конфигурацию — НЕ перезапускайте до исправления: ${state.validation.detail}`}
            </span>
          </div>
        ) : null
      }
    />
  );
}

/** Создание нового файла правил: переход в редактор с шаблоном. */
export function NewRuleFileForm() {
  const router = useRouter();
  const [name, setName] = useState("");
  const valid = RULE_FILE_RE.test(name);
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (valid) router.push(`/wazuh/manage/rules/${encodeURIComponent(name)}?new=1`);
      }}
      className="flex flex-wrap items-end gap-3"
    >
      <div className="space-y-2">
        <Label htmlFor="rule-file" className="c-label">
          Новый файл правил
        </Label>
        <Input
          id="rule-file"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="local_rules_custom.xml"
          className="h-10 w-64 px-3"
        />
      </div>
      <Button type="submit" variant="secondary" disabled={!valid} className="min-h-10">
        <FilePlus2 strokeWidth={1.5} />
        Открыть в редакторе
      </Button>
    </form>
  );
}
