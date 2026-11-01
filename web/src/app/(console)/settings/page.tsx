import { Bell, ShieldMinus, ShieldOff, Undo2, XCircle } from "lucide-react";
import { PasswordForm } from "@/components/console/password-form";
import { TotpControls } from "@/components/console/totp-form";
import { Led, Panel } from "@/components/console/panel";
import { Button } from "@/components/ui/button";
import { isTotpEnabled, listUsers, requirePageSession, ROLE_LABELS, ROLE_RANK } from "@/lib/auth";
import { editionFor } from "@/lib/shared/incidents";
import { formatTs, fmtNum } from "@/lib/shared/time";
import { RespondModeForm } from "@/components/console/respond-mode-form";
import { ResponseLog } from "@/components/console/response-log";
import { muteRuleAction } from "@/lib/actions";
import { mutedRulesList } from "@/lib/queries";
import { APP_VERSION } from "@/lib/version";
import { auditTail, incidentGet, licenseStats, listExceptions, respondStatus, responseLog, RESPOND_MODES } from "@/lib/argus-queries";
import { removeExceptionAction, unblockIpFormAction } from "@/lib/incident-actions";
import { excludeIpAction, revokeExclusionAction } from "@/lib/respond-actions";
import { EXCLUDE_TTLS } from "@/lib/shared/respond";
import { CreateUserForm, DeleteUserButton, ResetPasswordButton } from "@/components/console/users-form";
import { ActionForm, ConfirmActionForm } from "@/components/console/action-form";
import { StorageUnavailable } from "@/components/console/storage-error";
import { safeQuery } from "@/lib/clickhouse";
import { wazuhEnabled } from "@/lib/integrations";
import { blindAuditTail } from "@/lib/blind";

export const dynamic = "force-dynamic";
export const metadata = { title: "Настройки" };

export default async function SettingsPage() {
  // Единственная страница, доступная admin со стартовым паролем.
  const session = await requirePageSession({ allowPasswordChange: true });
  const isAdmin = session.role === "admin";
  const canEdit = ROLE_RANK[session.role] >= ROLE_RANK.analyst;
  const wazuh = wazuhEnabled();

  // Принудительная смена — только по сессии; ?force=1 в URL лишь адрес редиректа, режим он не включает.
  if (session.mustChangePassword) {
    return (
      <>
        <h1 className="text-3xl tracking-tight">Настройки</h1>
        <div className="max-w-xl">
          <Panel label={`Смена пароля · ${session.user}`} meta="обязательна">
            <p className="mb-5 text-sm leading-relaxed text-muted-foreground">
              Стартовый пароль лежит в файле рядом с auth.json (admin-password.txt) и будет удалён после смены.
              Политика как в Wazuh: 8–64 символа, минимум одна заглавная и одна строчная буква,
              цифра и один из символов <span className="font-mono">.*+?-</span>.
            </p>
            <PasswordForm force />
          </Panel>
        </div>
      </>
    );
  }

  // Учётная запись, пользователи и 2FA — из auth.json, показываются всегда.
  // Всё, что читается из ClickHouse, — через safeQuery: при недоступном
  // хранилище падает только правая колонка, а не вся страница.
  const [totpEnabled, users, respond, ch] = await Promise.all([
    session.sso ? Promise.resolve(false) : isTotpEnabled(session.user),
    listUsers(),
    respondStatus(),
    safeQuery(async () => {
      // Мьюты правил Wazuh — только с модулем Wazuh (таблицы алертов без него может не быть).
      const [mutedRules, exceptions, audit, license, responses] = await Promise.all([
        wazuh ? mutedRulesList() : Promise.resolve([]), listExceptions(), auditTail(60), licenseStats(), responseLog({ limit: 40 }),
      ]);
      // Вердикт агента по слепому незавершённому инциденту не читается и через общий журнал.
      return { mutedRules, exceptions, audit: await blindAuditTail(audit, incidentGet), license, responses };
    }),
  ]);

  return (
    <>
      <h1 className="text-3xl tracking-tight">Настройки</h1>
      <div className="grid gap-6 lg:grid-cols-2">
        <div className="space-y-6">
          {session.sso ? (
            <Panel label={`Учётная запись · ${session.user}`} meta={`SSO · ${ROLE_LABELS[session.role]}`}>
              <p className="text-sm leading-relaxed text-muted-foreground">
                Вход через IdP: пароль и второй фактор управляются в IdP, а роль берётся из групп при каждом входе.
                Сессия SSO живёт 1 час.
              </p>
            </Panel>
          ) : (
            <>
              <Panel label={`Смена пароля · ${session.user}`} meta={ROLE_LABELS[session.role]}>
                <p className="mb-5 text-sm leading-relaxed text-muted-foreground">
                  Политика как в Wazuh: 8–64 символа, минимум одна заглавная и одна строчная буква,
                  цифра и один из символов <span className="font-mono">.*+?-</span>.
                  Смена пароля отзывает все ваши сессии на других устройствах.
                </p>
                <PasswordForm />
              </Panel>

              <Panel
                label={`Двухфакторная аутентификация · TOTP · ${session.user}`}
                meta={totpEnabled ? "включена" : "выключена"}
              >
                <div className="mb-4 flex items-center gap-2">
                  <Led color={totpEnabled ? "var(--status-ok)" : "var(--status-warn)"} />
                  <span className="c-label">
                    {totpEnabled ? "2FA активна" : "2FA не настроена"}
                  </span>
                </div>
                <TotpControls enabled={totpEnabled} user={session.user} />
              </Panel>
            </>
          )}

          <Panel label="Пользователи и роли" meta={isAdmin ? "управляет администратор" : ROLE_LABELS[session.role]}>
            <ul className="mb-4 space-y-2">
              {users.map((u) => (
                <li key={u.name} className="flex flex-wrap items-center justify-between gap-3 border border-border bg-[var(--surface-deep)] px-3 py-2 font-mono text-xs">
                  <span>
                    {u.name}
                    {u.name === session.user && <span className="text-[var(--ring)]"> · это вы</span>}
                    <span className="text-muted-foreground"> · {ROLE_LABELS[u.role]} · с {formatTs(u.createdAt, "date")}{u.totp ? " · 2FA" : ""}{u.builtin ? " · встроенный" : ""}{u.sso ? " · SSO" : ""}</span>
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
              <p className="text-xs text-muted-foreground">наблюдатель — только чтение; аналитик — отработка инцидентов, мьюты, агенты и группы Wazuh; администратор — пользователи, правила, agent.conf, рестарт менеджера</p>
            )}
            <p className="mt-3 text-xs text-muted-foreground">SSO-пользователи (sso:…) в списке не хранятся: их роль приходит из групп IdP при входе.</p>
          </Panel>
        </div>

        <div className="space-y-6">
          {!ch.ok ? (
            <StorageUnavailable reason={ch.error} label="Мьюты, исключения, реагирование, лицензия и аудит недоступны" />
          ) : (
          <>
          {wazuh && <Panel
            label="Заглушённые правила · шумоподавление"
            meta={ch.data.mutedRules.length > 0 ? `${ch.data.mutedRules.length} шт.` : undefined}
          >
            {ch.data.mutedRules.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                Пусто. Заглушить шумное правило можно кнопкой в журнале алертов —
                оно исчезнет из всех витрин, но продолжит писаться в ClickHouse.
              </p>
            ) : (
              <ul className="space-y-2">
                {ch.data.mutedRules.map((r) => (
                  <li
                    key={r.rule_id}
                    className="flex items-center justify-between gap-3 border border-border bg-[var(--surface-deep)] px-3 py-2"
                  >
                    <span className="text-sm">
                      <span className="font-mono text-xs text-muted-foreground">#{r.rule_id}</span>{" "}
                      {r.description || "—"}
                    </span>
                    {canEdit && (
                      <ActionForm action={muteRuleAction} successText={`Правило ${r.rule_id} снова в витринах`}>
                        <input type="hidden" name="rule_id" value={r.rule_id} />
                        <input type="hidden" name="muted" value="0" />
                        <Button type="submit" variant="ghost" size="sm">
                          <Bell strokeWidth={1.5} />
                          Вернуть
                        </Button>
                      </ActionForm>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </Panel>}

          <Panel label="Исключения из правил · обратная связь «ложное»" meta={ch.data.exceptions.length ? `${ch.data.exceptions.length} шт.` : undefined}>
            {ch.data.exceptions.length === 0 ? (
              <p className="text-sm text-muted-foreground">Пусто. Появляются, когда инцидент закрывают как ложный с отметкой «добавить исключение».</p>
            ) : (
              <ul className="space-y-2">
                {ch.data.exceptions.map((x) => (
                  <li key={`${x.rule_id}|${x.field}|${x.value}`} className="flex items-center justify-between gap-3 border border-border bg-[var(--surface-deep)] px-3 py-2 font-mono text-xs">
                    <span>
                      <span className="text-muted-foreground">{x.rule_id}</span> · {x.field} = <span className="text-foreground">{x.value}</span>
                      <span className="block text-muted-foreground">{x.reason} · {x.created_by} · {x.incident_id}</span>
                    </span>
                    {canEdit && (
                      <ConfirmActionForm action={removeExceptionAction} title="Снять исключение?" description={`${x.field} = ${x.value} для правила ${x.rule_id} снова будет порождать инциденты.`} confirmLabel="Снять" successText="Исключение снято">
                        <input type="hidden" name="rule_id" value={x.rule_id} />
                        <input type="hidden" name="field" value={x.field} />
                        <input type="hidden" name="value" value={x.value} />
                        <Button type="submit" variant="ghost" size="sm"><XCircle strokeWidth={1.5} />Снять</Button>
                      </ConfirmActionForm>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel label={`Реагирование · ${RESPOND_MODES[respond.mode]?.label ?? respond.mode}`} meta={respond.error ? "движок недоступен" : respond.enabled ? `TTL ${respond.ttl} · активных блокировок ${respond.active.length}${respond.pending ? ` · в очереди повторов ${respond.pending}` : ""}` : "исполнители не настроены"}>
            {respond.error && <p className="mb-3 text-xs text-destructive">{respond.error}</p>}
            {respond.config_errors.length > 0 && <p className="mb-3 text-xs text-destructive">конфиг: {respond.config_errors.join("; ")}</p>}
            {isAdmin ? <RespondModeForm current={respond.mode} from={respond.mode_from} requested={respond.requested} /> : (
              <p className="text-xs text-muted-foreground">режим: {RESPOND_MODES[respond.mode]?.label ?? respond.mode} ({respond.mode_from === "console" ? "из консоли" : "из конфига"}) — переключает администратор</p>
            )}
            <dl className="mt-4 grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 font-mono text-xs">
              <dt className="text-muted-foreground">allowlist</dt><dd>{respond.allowlist.length ? respond.allowlist.join(", ") : "—"} <span className="text-muted-foreground">+ приватные сети и loopback всегда</span></dd>
              <dt className="text-muted-foreground">активные блокировки</dt>
              <dd>
                {respond.active.length === 0 ? "—" : (
                  <ul className="space-y-2">
                    {respond.active.map((b) => (
                      <li key={b.ip} className="flex flex-wrap items-center gap-2">
                        <span>{b.ip} ({b.incident}) {b.manual || b.until.startsWith("0001") ? "постоянно" : "до " + formatTs(b.until)}</span>
                        {canEdit && (
                          <ConfirmActionForm
                            action={unblockIpFormAction}
                            title={`Снять блокировку ${b.ip}?`}
                            description="Адрес будет разблокирован на NGFW и агентах; причина попадёт в журнал реагирования."
                            confirmLabel="Снять блокировку"
                            successText={`${b.ip} разблокирован`}
                            className="flex flex-wrap items-center gap-2"
                          >
                            <input type="hidden" name="ip" value={b.ip} />
                            <input name="reason" required maxLength={500} placeholder="причина" aria-label={`Причина снятия блокировки ${b.ip}`} className="h-8 w-48 border border-border bg-[var(--surface-deep)] px-2 font-mono text-xs" />
                            <Button type="submit" variant="ghost" size="sm"><ShieldOff strokeWidth={1.5} />Снять</Button>
                          </ConfirmActionForm>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </dd>
              <dt className="text-muted-foreground">исключены из автоблокировки</dt>
              <dd className="space-y-3">
                {(respond.excluded ?? []).length === 0 ? <span>—</span> : (
                  <ul className="space-y-2">
                    {(respond.excluded ?? []).map((x) => (
                      <li key={x.ip} className="flex flex-wrap items-center gap-2">
                        <span>{x.ip} до {formatTs(x.until)} · {x.actor}: {x.reason}</span>
                        {isAdmin && (
                          <ConfirmActionForm
                            action={revokeExclusionAction}
                            title={`Отозвать исключение ${x.ip}?`}
                            description="Автоблокировка адреса снова работает: свежие события его инцидентов блокируют адрес. Причина попадёт в журнал реагирования."
                            confirmLabel="Отозвать исключение"
                            successText={`исключение ${x.ip} отозвано`}
                            className="flex flex-wrap items-center gap-2"
                          >
                            <input type="hidden" name="ip" value={x.ip} />
                            <input name="reason" required minLength={3} maxLength={500} placeholder="причина" aria-label={`Причина отзыва исключения ${x.ip}`} className="h-8 w-48 border border-border bg-[var(--surface-deep)] px-2 font-mono text-xs" />
                            <Button type="submit" variant="ghost" size="sm"><Undo2 strokeWidth={1.5} />Отозвать</Button>
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
                    className="flex flex-wrap items-center gap-2"
                  >
                    <input name="ip" required maxLength={64} placeholder="адрес" aria-label="Адрес для исключения из автоблокировки" className="h-8 w-40 border border-border bg-[var(--surface-deep)] px-2 font-mono text-xs" />
                    <select name="ttl" required defaultValue="24h" aria-label="Срок исключения" className="h-8 border border-border bg-[var(--surface-deep)] px-2 font-mono text-xs">
                      {EXCLUDE_TTLS.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
                    </select>
                    <input name="reason" required minLength={3} maxLength={500} placeholder="причина" aria-label="Причина исключения" className="h-8 w-48 border border-border bg-[var(--surface-deep)] px-2 font-mono text-xs" />
                    <Button type="submit" variant="ghost" size="sm"><ShieldMinus strokeWidth={1.5} />Исключить</Button>
                  </ConfirmActionForm>
                ) : (
                  <p className="text-muted-foreground">исключает и отзывает администратор</p>
                )}
              </dd>
            </dl>
            <div className="c-label mt-4 mb-2">журнал реагирования · последние {ch.data.responses.length}</div>
            <ResponseLog rows={ch.data.responses} />
          </Panel>

          <Panel label="Лицензионный учёт · по потоку, не по хостам" meta="collector_health_log, 30 дней">
            <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 font-mono text-xs">
              <dt className="text-muted-foreground">пиковый EPS, 30 д</dt><dd>{fmtNum(ch.data.license.peak_eps_30d)}</dd>
              <dt className="text-muted-foreground">средний EPS, 7 д</dt><dd>{fmtNum(ch.data.license.avg_eps_7d, 2)}</dd>
              <dt className="text-muted-foreground">событий за 30 д</dt><dd>{fmtNum(ch.data.license.events_30d)}</dd>
              <dt className="text-muted-foreground">источников</dt><dd>{ch.data.license.sources}</dd>
              <dt className="text-muted-foreground">хранение событий</dt><dd>{ch.data.license.retention_days} сут. (TTL argus.events)</dd>
              <dt className="text-muted-foreground">редакция</dt>
              <dd>{editionFor(ch.data.license.peak_eps_30d)}</dd>
            </dl>
          </Panel>

          <Panel label="Журнал действий · кто, что, когда" meta={`последние ${ch.data.audit.length}`}>
            <div className="c-well max-h-80 overflow-auto p-2 font-mono text-xs">
              {ch.data.audit.length === 0 ? <p className="p-2 text-muted-foreground">пусто</p> : (
                <table className="w-full">
                  <tbody>
                    {ch.data.audit.map((a, i) => (
                      <tr key={i} className="border-b border-border/40">
                        <td className="whitespace-nowrap py-1 pr-3 text-muted-foreground">{formatTs(a.ts)}</td>
                        <td className="py-1 pr-3">{a.user}</td>
                        <td className="py-1 pr-3">{a.action}</td>
                        <td className="py-1 pr-3">{a.target}</td>
                        <td className="py-1 text-muted-foreground">{a.detail}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </Panel>
          </>
          )}

          <Panel label="О системе">
            <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 font-mono text-xs">
              <dt className="text-muted-foreground">версия консоли</dt>
              <dd>{APP_VERSION}</dd>
              <dt className="text-muted-foreground">хранилище</dt>
              <dd>ClickHouse · argus.events, incidents, wazuh_alerts, policy_verdicts</dd>
              <dt className="text-muted-foreground">миграции схемы</dt>
              <dd>clickhouse/migrations + argus.schema_migrations</dd>
            </dl>
          </Panel>
        </div>
      </div>
    </>
  );
}
