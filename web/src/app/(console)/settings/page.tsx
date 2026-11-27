import Link from "next/link";
import { Bell, ShieldAlert, ShieldMinus, ShieldOff, Undo2, XCircle } from "lucide-react";
import { PasswordForm } from "@/components/console/password-form";
import { TotpControls } from "@/components/console/totp-form";
import { Empty, PageHeader, Panel } from "@/components/console/panel";
import { FilterTabs } from "@/components/console/filter-tabs";
import { ServiceUnavailable } from "@/components/console/service-unavailable";
import { StorageUnavailable } from "@/components/console/storage-error";
import { TONE_CLASS, type Tone } from "@/components/console/tone";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { isTotpEnabled, listUsers, requirePageSession, ROLE_LABELS, ROLE_RANK } from "@/lib/auth";
import { editionFor } from "@/lib/shared/incidents";
import { formatTs, fmtNum } from "@/lib/shared/time";
import { RespondModeForm } from "@/components/console/respond-mode-form";
import { muteRuleAction } from "@/lib/actions";
import { mutedRulesList } from "@/lib/queries";
import { APP_VERSION } from "@/lib/version";
import { auditTail, incidentGet, licenseStats, listExceptions, respondStatus, responseLog, RESPOND_MODES, type RespondStatus } from "@/lib/argus-queries";
import { removeExceptionAction, unblockIpFormAction } from "@/lib/incident-actions";
import { excludeIpAction, revokeExclusionAction } from "@/lib/respond-actions";
import { CreateUserForm, DeleteUserButton, ResetPasswordButton } from "@/components/console/users-form";
import { ActionForm, ConfirmActionForm } from "@/components/console/action-form";
import { safeQuery } from "@/lib/clickhouse";
import { wazuhEnabled } from "@/lib/integrations";
import { blindAuditTail } from "@/lib/blind";
import { parseSettingsTab, SETTINGS_TABS, type SettingsTab } from "@/lib/shared/settings-view";
import { cn } from "@/lib/utils";
import { AuditTable, ResponseFeed } from "./_components/journals";
import { TtlSelect } from "./_components/ttl-select";

export const dynamic = "force-dynamic";
export const metadata = { title: "Настройки" };

const PASSWORD_RULES = <>8–64 символа: заглавная и строчная буква, цифра и один из символов <span className="font-mono">.*+?-</span>.</>;
const MODE_TONE: Record<string, Tone> = { ips: "err", simulate: "neutral", ids: "muted" };
const DT = "text-[13px] text-muted-foreground";
const FIELD_LABEL = "text-[13px] text-muted-foreground";

type Session = Awaited<ReturnType<typeof requirePageSession>>;

export default async function SettingsPage(props?: PageProps<"/settings">) {
  // Единственная страница, доступная admin со стартовым паролем.
  const session = await requirePageSession({ allowPasswordChange: true });

  // Принудительная смена — только по сессии; ?force=1 в URL лишь адрес редиректа, режим он не включает.
  if (session.mustChangePassword) {
    return (
      <>
        <PageHeader title="Настройки" />
        <div className="max-w-xl">
          <Panel label={`Смена пароля · ${session.user}`} meta="обязательна" tone="warn">
            <p className="mb-5 text-sm leading-relaxed text-muted-foreground">
              Стартовый пароль лежит в файле рядом с auth.json (admin-password.txt) и будет удалён после смены. {PASSWORD_RULES}
            </p>
            <PasswordForm force />
          </Panel>
        </div>
      </>
    );
  }

  const sp = (await props?.searchParams) ?? {};
  const tab = parseSettingsTab(sp.tab);
  const isAdmin = session.role === "admin";
  const totpEnabled = session.sso ? false : await isTotpEnabled(session.user);
  const totpMissing = isAdmin && !session.sso && !totpEnabled;

  return (
    <>
      <PageHeader title="Настройки" />
      {totpMissing && (
        <div role="alert" className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-md border border-[var(--status-warn)]/40 bg-[var(--status-warn)]/10 px-4 py-3 text-sm text-foreground">
          <ShieldAlert className="size-5 shrink-0 text-[var(--status-warn)]" strokeWidth={1.5} aria-hidden />
          <span className="min-w-0 flex-1">
            <span className="font-medium">Второй фактор выключен.</span> Включите его: у администратора есть доступ к блокировкам адресов и пользователям.
          </span>
          {tab !== "account" && (
            <Button asChild size="sm"><Link href="/settings?tab=account#totp">Включить 2FA</Link></Button>
          )}
        </div>
      )}
      <FilterTabs label="Разделы настроек" items={SETTINGS_TABS.map((t) => ({ key: t.key, label: t.label, href: `/settings?tab=${t.key}` }))} current={tab} />
      <TabBody tab={tab} session={session} totpEnabled={totpEnabled} />
    </>
  );
}

function TabBody({ tab, session, totpEnabled }: { tab: SettingsTab; session: Session; totpEnabled: boolean }) {
  switch (tab) {
    case "account": return <AccountTab session={session} totpEnabled={totpEnabled} />;
    case "users": return <UsersTab session={session} />;
    case "respond": return <RespondTab session={session} />;
    case "exceptions": return <ExceptionsTab session={session} />;
    case "audit": return <AuditTab />;
    case "system": return <SystemTab session={session} />;
  }
}

/* ===== Учётная запись ===== */

function AccountTab({ session, totpEnabled }: { session: Session; totpEnabled: boolean }) {
  if (session.sso) {
    return (
      <div className="max-w-3xl space-y-6">
        <Panel label={`Учётная запись · ${session.user}`} meta={`корпоративный вход · ${ROLE_LABELS[session.role]}`}>
          <p className="text-sm leading-relaxed text-muted-foreground">
            Вы вошли через корпоративную учётную запись: пароль и второй фактор управляются там, а роль берётся из ваших групп при каждом входе.
            Сеанс живёт 1 час.
          </p>
        </Panel>
      </div>
    );
  }
  const warn = session.role === "admin" && !totpEnabled;
  return (
    <div className="max-w-3xl space-y-6">
      <Panel label={`Смена пароля · ${session.user}`} meta={ROLE_LABELS[session.role]}>
        <p className="mb-5 text-sm leading-relaxed text-muted-foreground">
          {PASSWORD_RULES} Смена пароля завершает ваши сеансы на других устройствах.
        </p>
        <PasswordForm />
      </Panel>
      <Panel id="totp" label="Двухфакторная аутентификация" meta={totpEnabled ? "включена" : "выключена"} tone={warn ? "warn" : undefined}>
        {!totpEnabled && (
          <p className="mb-4 text-sm leading-relaxed text-muted-foreground">
            При входе, кроме пароля, понадобится шестизначный код из приложения-аутентификатора (Google Authenticator, Aegis, 1Password и т. п.).
          </p>
        )}
        <TotpControls enabled={totpEnabled} user={session.user} />
      </Panel>
    </div>
  );
}

/* ===== Пользователи ===== */

async function UsersTab({ session }: { session: Session }) {
  const isAdmin = session.role === "admin";
  const users = await listUsers();
  return (
    <div className="max-w-3xl space-y-6">
      <Panel label="Пользователи и роли" meta={isAdmin ? `${fmtNum(users.length)} · управляет администратор` : ROLE_LABELS[session.role]}>
        <ul className="mb-5 space-y-2">
          {users.map((u) => (
            <li key={u.name} className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-border bg-[var(--surface-deep)] px-3 py-2.5">
              <span className="min-w-0">
                <span className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-sm text-foreground">{u.name}</span>
                  <span className={cn("rounded-sm border px-1.5 text-[12px] leading-5", TONE_CLASS.neutral)}>{ROLE_LABELS[u.role]}</span>
                  {u.name === session.user && <span className={cn("rounded-sm border px-1.5 text-[12px] leading-5", TONE_CLASS.info)}>это вы</span>}
                  {u.role === "admin" && !u.totp && !u.sso && <span className={cn("rounded-sm border px-1.5 text-[12px] leading-5", TONE_CLASS.warn)}>без 2FA</span>}
                </span>
                <span className="mt-0.5 block text-[12px] text-muted-foreground">
                  {[`с ${formatTs(u.createdAt, "date")}`, u.totp ? "2FA включена" : null, u.builtin ? "встроенная учётная запись" : null, u.sso ? "корпоративный вход" : null].filter(Boolean).join(" · ")}
                </span>
              </span>
              {isAdmin && u.name !== session.user && !u.builtin && !u.sso && (
                <span className="flex items-center gap-1">
                  <ResetPasswordButton name={u.name} />
                  <DeleteUserButton name={u.name} />
                </span>
              )}
            </li>
          ))}
        </ul>
        {isAdmin ? <CreateUserForm /> : (
          <ul className="space-y-1 text-[13px] text-muted-foreground">
            <li><span className="text-foreground">Наблюдатель</span> — только чтение.</li>
            <li><span className="text-foreground">Аналитик</span> — отработка инцидентов, заглушение правил, агенты и группы Wazuh.</li>
            <li><span className="text-foreground">Администратор</span> — пользователи, правила, конфигурация агентов, перезапуск менеджера.</li>
          </ul>
        )}
        <p className="mt-4 text-[13px] text-muted-foreground">Пользователи корпоративного входа (sso:…) здесь не хранятся: роль приходит из их групп при входе.</p>
      </Panel>
    </div>
  );
}

/* ===== Реагирование ===== */

async function RespondTab({ session }: { session: Session }) {
  const isAdmin = session.role === "admin";
  const canEdit = ROLE_RANK[session.role] >= ROLE_RANK.analyst;
  const [respond, log] = await Promise.all([respondStatus(), safeQuery(() => responseLog({ limit: 60 }))]);
  const modeLabel = RESPOND_MODES[respond.mode]?.label ?? respond.mode;
  const engineDown = Boolean(respond.error);
  const now = new Date();
  return (
    <div className="space-y-6">
      {engineDown && (
        <ServiceUnavailable
          service="engine"
          reason={respond.error}
          what="состояние реагирования"
          consequence="Текущий режим, активные блокировки и исключения неизвестны; менять режим сейчас нельзя — движок не подтвердит смену."
        />
      )}
      <div className={cn("grid gap-6", engineDown ? "max-w-3xl" : "xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]")}>
        <div className="min-w-0 space-y-6">
          <Panel
            label="Режим реагирования"
            tone={engineDown ? "err" : undefined}
            meta={engineDown ? "движок не ответил" : respond.enabled ? `TTL ${respond.ttl} · активных блокировок ${respond.active.length}${respond.pending ? ` · в очереди повторов ${respond.pending}` : ""}` : "исполнители не настроены"}
            actions={!engineDown ? <span className={cn("rounded-sm border px-2 py-0.5 text-[13px] font-medium", TONE_CLASS[MODE_TONE[respond.mode] ?? "muted"])}>{modeLabel}</span> : undefined}
          >
            {respond.config_errors.length > 0 && (
              <p className="mb-4 rounded-md border border-[var(--status-err)]/40 bg-[var(--status-err)]/10 px-3 py-2 text-sm text-foreground">
                Ошибки в конфигурации исполнителей: {respond.config_errors.join("; ")}
              </p>
            )}
            {isAdmin ? (
              <RespondModeForm
                current={respond.mode}
                from={respond.mode_from}
                requested={respond.requested}
                disabled={engineDown}
                disabledReason="Режим можно сменить, когда движок корреляции ответит: сейчас неизвестно, какой режим действует."
              />
            ) : (
              <p className="text-sm text-muted-foreground">
                {engineDown ? "Режим неизвестен: движок не ответил." : <>Сейчас: <span className="text-foreground">{modeLabel}</span> ({respond.mode_from === "console" ? "задан в консоли" : "из файла конфигурации"}).</>} Режим переключает администратор.
              </p>
            )}
          </Panel>
        </div>
        {!engineDown && <div className="min-w-0 space-y-6"><BlocksPanel respond={respond} canEdit={canEdit} isAdmin={isAdmin} /></div>}
      </div>

      <Panel label="Журнал реагирования" meta={log.ok ? `последние ${fmtNum(log.data.length)}` : undefined}>
        {log.ok ? <ResponseFeed rows={log.data} now={now} /> : <StorageUnavailable reason={log.error} label="Журнал реагирования недоступен" what="журнал реагирования" />}
      </Panel>
    </div>
  );
}

function BlocksPanel({ respond, canEdit, isAdmin }: { respond: RespondStatus; canEdit: boolean; isAdmin: boolean }) {
  const excluded = respond.excluded ?? [];
  return (
    <Panel label="Блокировки и исключения">
      <div className="space-y-5">
        <section>
          <h3 className={cn(DT, "mb-2")}>Активные блокировки</h3>
          {respond.active.length === 0 ? <p className="text-sm text-muted-foreground">Нет</p> : (
            <ul className="space-y-2">
              {respond.active.map((b) => (
                <li key={b.ip} className="space-y-2 rounded-md border border-border bg-[var(--surface-deep)] px-3 py-2">
                  <div className="text-sm">
                    <span className="font-mono text-foreground">{b.ip}</span> <span className="text-muted-foreground">(<span className="font-mono">{b.incident}</span>) {b.manual || b.until.startsWith("0001") ? "постоянно" : "до " + formatTs(b.until, "datetime")}</span>
                  </div>
                  {canEdit && (
                    <ConfirmActionForm
                      action={unblockIpFormAction}
                      title={`Снять блокировку ${b.ip}?`}
                      description="Адрес будет разблокирован на NGFW и агентах; причина попадёт в журнал реагирования."
                      confirmLabel="Снять блокировку"
                      successText={`${b.ip} разблокирован`}
                      className="flex items-center gap-2"
                    >
                      <input type="hidden" name="ip" value={b.ip} />
                      <Input name="reason" required maxLength={500} placeholder="Причина снятия" aria-label={`Причина снятия блокировки ${b.ip}`} className="h-9 flex-1" />
                      <Button type="submit" variant="secondary"><ShieldOff strokeWidth={1.5} />Снять</Button>
                    </ConfirmActionForm>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>

        <section>
          <h3 className={cn(DT, "mb-2")}>Исключены из автоблокировки</h3>
          {excluded.length === 0 ? <p className="text-sm text-muted-foreground">Нет</p> : (
            <ul className="space-y-2">
              {excluded.map((x) => (
                <li key={x.ip} className="space-y-2 rounded-md border border-border bg-[var(--surface-deep)] px-3 py-2">
                  <div className="text-sm">
                    <span className="font-mono text-foreground">{x.ip}</span> <span className="text-muted-foreground">до {formatTs(x.until, "datetime")}</span>
                    <span className="block text-[13px] text-muted-foreground"><span className="font-mono">{x.actor}</span>: {x.reason}</span>
                  </div>
                  {isAdmin && (
                    <ConfirmActionForm
                      action={revokeExclusionAction}
                      title={`Отозвать исключение ${x.ip}?`}
                      description="Автоблокировка адреса снова работает: свежие события его инцидентов блокируют адрес. Причина попадёт в журнал реагирования."
                      confirmLabel="Отозвать исключение"
                      successText={`исключение ${x.ip} отозвано`}
                      className="flex items-center gap-2"
                    >
                      <input type="hidden" name="ip" value={x.ip} />
                      <Input name="reason" required minLength={3} maxLength={500} placeholder="Причина отзыва" aria-label={`Причина отзыва исключения ${x.ip}`} className="h-9 flex-1" />
                      <Button type="submit" variant="secondary"><Undo2 strokeWidth={1.5} />Отозвать</Button>
                    </ConfirmActionForm>
                  )}
                </li>
              ))}
            </ul>
          )}
          {isAdmin ? (
            <ConfirmActionForm
              action={excludeIpAction}
              title="Исключить адрес из автоблокировки?"
              description="До конца срока автоответ не блокирует адрес ни по одному инциденту, в том числе по будущим и по критическим. Активный блок это не снимает. Причина попадёт в журнал реагирования и аудит."
              confirmLabel="Исключить"
              successText="адрес исключён из автоблокировки"
              className="mt-3 grid grid-cols-2 items-end gap-2 sm:grid-cols-[minmax(8rem,1fr)_8rem]"
            >
              <div className="space-y-1">
                <Label htmlFor="exclude-ip" className={FIELD_LABEL}>Адрес</Label>
                <Input id="exclude-ip" name="ip" required maxLength={64} placeholder="203.0.113.7" className="h-9 font-mono" />
              </div>
              <div className="space-y-1">
                <Label htmlFor="exclude-ttl" className={FIELD_LABEL}>Срок</Label>
                <TtlSelect id="exclude-ttl" />
              </div>
              <div className="col-span-2 space-y-1 sm:col-span-1">
                <Label htmlFor="exclude-reason" className={FIELD_LABEL}>Причина</Label>
                <Input id="exclude-reason" name="reason" required minLength={3} maxLength={500} placeholder="сканер партнёра" className="h-9" />
              </div>
              <Button type="submit" variant="secondary" className="col-span-2 sm:col-span-1"><ShieldMinus strokeWidth={1.5} />Исключить</Button>
            </ConfirmActionForm>
          ) : (
            <p className="mt-2 text-[13px] text-muted-foreground">Исключает и отзывает администратор.</p>
          )}
        </section>

        <section>
          <h3 className={cn(DT, "mb-2")}>Никогда не блокируются</h3>
          <p className="text-sm">
            {respond.allowlist.length ? <span className="font-mono">{respond.allowlist.join(", ")}</span> : <span className="text-muted-foreground">список пуст</span>}
            <span className="text-muted-foreground"> — и всегда частные сети и loopback</span>
          </p>
        </section>
      </div>
    </Panel>
  );
}

/* ===== Исключения из правил и заглушённые правила ===== */

async function ExceptionsTab({ session }: { session: Session }) {
  const canEdit = ROLE_RANK[session.role] >= ROLE_RANK.analyst;
  const wazuh = wazuhEnabled();
  // Мьюты правил Wazuh — только с модулем Wazuh (таблицы алертов без него может не быть).
  const [exceptions, muted] = await Promise.all([safeQuery(() => listExceptions()), wazuh ? safeQuery(() => mutedRulesList()) : Promise.resolve(null)]);
  return (
    <div className="max-w-3xl space-y-6">
      <Panel label="Исключения из правил" meta={exceptions.ok && exceptions.data.length ? `${fmtNum(exceptions.data.length)} шт.` : undefined}>
        {!exceptions.ok ? <StorageUnavailable reason={exceptions.error} label="Исключения недоступны" what="исключения из правил" /> : exceptions.data.length === 0 ? (
          <Empty title="Исключений нет" hint="Появляются, когда инцидент закрывают как ложный с отметкой «добавить исключение»." />
        ) : (
          <ul className="space-y-2">
            {exceptions.data.map((x) => (
              <li key={`${x.rule_id}|${x.field}|${x.value}`} className="flex items-center justify-between gap-3 rounded-md border border-border bg-[var(--surface-deep)] px-3 py-2">
                <span className="min-w-0 text-sm">
                  <span className="font-mono text-[13px]"><span className="text-muted-foreground">{x.rule_id}</span> · {x.field} = <span className="text-foreground">{x.value}</span></span>
                  <span className="block text-[13px] text-muted-foreground">{x.reason} · <span className="font-mono">{x.created_by}</span> · <span className="font-mono">{x.incident_id}</span></span>
                </span>
                {canEdit && (
                  <ConfirmActionForm action={removeExceptionAction} title="Снять исключение?" description={`${x.field} = ${x.value} для правила ${x.rule_id} снова будет порождать инциденты.`} confirmLabel="Снять" successText="Исключение снято">
                    <input type="hidden" name="rule_id" value={x.rule_id} />
                    <input type="hidden" name="field" value={x.field} />
                    <input type="hidden" name="value" value={x.value} />
                    <Button type="submit" variant="ghost"><XCircle strokeWidth={1.5} />Снять</Button>
                  </ConfirmActionForm>
                )}
              </li>
            ))}
          </ul>
        )}
      </Panel>

      {muted && (
        <Panel label="Заглушённые правила Wazuh" meta={muted.ok && muted.data.length > 0 ? `${fmtNum(muted.data.length)} шт.` : undefined}>
          {!muted.ok ? <StorageUnavailable reason={muted.error} label="Заглушённые правила недоступны" what="заглушённые правила" /> : muted.data.length === 0 ? (
            <Empty title="Заглушённых правил нет" hint="Заглушить шумное правило можно кнопкой в журнале алертов: оно пропадёт из витрин, но продолжит записываться в хранилище." />
          ) : (
            <ul className="space-y-2">
              {muted.data.map((r) => (
                <li key={r.rule_id} className="flex items-center justify-between gap-3 rounded-md border border-border bg-[var(--surface-deep)] px-3 py-2">
                  <span className="text-sm">
                    <span className="font-mono text-[13px] text-muted-foreground">#{r.rule_id}</span>{" "}
                    {r.description || "—"}
                  </span>
                  {canEdit && (
                    <ActionForm action={muteRuleAction} successText={`Правило ${r.rule_id} снова в витринах`}>
                      <input type="hidden" name="rule_id" value={r.rule_id} />
                      <input type="hidden" name="muted" value="0" />
                      <Button type="submit" variant="ghost"><Bell strokeWidth={1.5} />Вернуть</Button>
                    </ActionForm>
                  )}
                </li>
              ))}
            </ul>
          )}
        </Panel>
      )}
    </div>
  );
}

/* ===== Журнал действий ===== */

async function AuditTab() {
  const res = await safeQuery(async () => blindAuditTail(await auditTail(100), incidentGet));
  return (
    <Panel label="Журнал действий" meta={res.ok ? `последние ${fmtNum(res.data.length)}` : undefined}>
      {res.ok ? <AuditTable rows={res.data} /> : <StorageUnavailable reason={res.error} label="Журнал действий недоступен" what="журнал действий" />}
    </Panel>
  );
}

/* ===== Система ===== */

async function SystemTab({ session }: { session: Session }) {
  const license = await safeQuery(() => licenseStats());
  return (
    <div className="max-w-3xl space-y-6">
      <Panel label="Объём данных (лицензия)" meta="за 30 дней">
        {!license.ok ? <StorageUnavailable reason={license.error} label="Объём данных недоступен" what="статистику объёма данных" /> : (
          <>
            <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-sm">
              <dt className={DT}>Пиковый поток, событий/с</dt><dd className="font-mono tabular-nums">{fmtNum(license.data.peak_eps_30d)}</dd>
              <dt className={DT}>Средний поток за 7 дней, событий/с</dt><dd className="font-mono tabular-nums">{fmtNum(license.data.avg_eps_7d, 2)}</dd>
              <dt className={DT}>Событий за 30 дней</dt><dd className="font-mono tabular-nums">{fmtNum(license.data.events_30d)}</dd>
              <dt className={DT}>Источников</dt><dd className="font-mono tabular-nums">{license.data.sources}</dd>
              <dt className={DT}>Хранение</dt><dd>события — {license.data.retention_days} сут., NetFlow — {license.data.netflow_retention_days} сут.</dd>
              <dt className={DT}>Редакция</dt><dd>{editionFor(license.data.peak_eps_30d)}</dd>
            </dl>
            <p className="mt-4 text-[13px] text-muted-foreground">Лицензия считается по потоку событий, а не по числу хостов.</p>
          </>
        )}
      </Panel>

      <Panel label="О системе">
        <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-sm">
          <dt className={DT}>Версия консоли</dt>
          <dd className="font-mono">{APP_VERSION}</dd>
        </dl>
        {session.role === "admin" && (
          <details className="group mt-4 text-[13px] text-muted-foreground">
            <summary className="inline-flex cursor-pointer items-center gap-1.5 hover:text-foreground">
              <span aria-hidden className="inline-block transition-transform group-open:rotate-90">›</span>
              Для администратора
            </summary>
            <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-6 gap-y-2">
              <dt>Хранилище</dt>
              <dd className="font-mono">ClickHouse · argus.events, incidents, wazuh_alerts, policy_verdicts</dd>
              <dt>Миграции схемы</dt>
              <dd className="font-mono">clickhouse/migrations + argus.schema_migrations</dd>
            </dl>
          </details>
        )}
      </Panel>
    </div>
  );
}
