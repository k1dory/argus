// Единое состояние «служба не отвечает» для хранилища, движка и Wazuh:
// панель в тоне ошибки, человеческая фраза и последствия; технические
// подробности (текст ошибки, что проверить) — под раскрытием и только
// администратору. Остальным — «сообщите администратору».
import { getSession } from "@/lib/auth";
import { Panel } from "@/components/console/panel";
import { RetryButton } from "@/components/console/retry-button";

export type UnavailableService = "clickhouse" | "engine" | "wazuh";

type ServiceText = { name: string; consequence: string; check: React.ReactNode };

export const SERVICE_TEXT: Record<UnavailableService, ServiceText> = {
  clickhouse: {
    name: "хранилище событий не отвечает",
    consequence: "Данные на этой странице появятся, как только хранилище снова ответит.",
    check: <>Проверьте контейнер <code className="font-mono">clickhouse</code> и переменные <code className="font-mono">CLICKHOUSE_*</code> консоли; полный текст ошибки — в журнале контейнера <code className="font-mono">web</code>.</>,
  },
  engine: {
    name: "движок корреляции не отвечает",
    consequence: "Новые инциденты сейчас не создаются, а список правил и счётчики могут быть устаревшими.",
    check: <>Проверьте контейнер <code className="font-mono">engine</code> и переменную <code className="font-mono">ENGINE_URL</code> консоли.</>,
  },
  wazuh: {
    name: "менеджер Wazuh не отвечает",
    consequence: "Агенты, группы и правила Wazuh временно недоступны; алерты, уже попавшие в журнал, видны как обычно.",
    check: <>Проверьте адрес <code className="font-mono">WAZUH_API_URL</code> и учётные данные <code className="font-mono">WAZUH_API_USER</code> / <code className="font-mono">WAZUH_API_PASSWORD</code> в .env; подробности — в журнале контейнера <code className="font-mono">web</code>.</>,
  },
};

export type ServiceUnavailableProps = {
  service: UnavailableService;
  /** Сырой текст ошибки — виден только администратору, под «Подробностями». */
  reason?: string;
  /** Что не загрузилось, в винительном падеже: «список инцидентов». Без него — «данные». */
  what?: string;
  /** Заголовок панели; по умолчанию — по службе. */
  label?: string;
  /** Своя строка последствий вместо стандартной. */
  consequence?: React.ReactNode;
  /** Короткий факт справа в заголовке: «с 09:10», «последний ответ 5 мин назад». */
  since?: string;
};

const DEFAULT_LABEL: Record<UnavailableService, string> = {
  clickhouse: "Хранилище недоступно",
  engine: "Движок корреляции недоступен",
  wazuh: "Wazuh недоступен",
};

/** Презентационная часть: роль передаётся явно (admin видит подробности). */
export function ServiceUnavailableView({ service, reason, what, label, consequence, since, admin = false }: ServiceUnavailableProps & { admin?: boolean }) {
  const t = SERVICE_TEXT[service];
  return (
    <Panel label={label ?? DEFAULT_LABEL[service]} meta={since} tone="err">
      <div className="space-y-2 text-sm">
        <p className="text-foreground">Не удалось загрузить {what ?? "данные"}: {t.name}.</p>
        <p className="text-muted-foreground">{consequence ?? t.consequence}</p>
        {admin ? (
          <details className="group text-[13px]">
            <summary className="inline-flex items-center gap-1 text-muted-foreground hover:text-foreground">
              <span aria-hidden className="inline-block transition-transform group-open:rotate-90">›</span>
              Подробности для администратора
            </summary>
            <div className="mt-2 space-y-2 border-l border-[var(--border-strong)] pl-3 text-muted-foreground">
              {reason && <p className="font-mono text-[12px] break-words text-[var(--fg-2)]">{reason}</p>}
              <p>{t.check}</p>
            </div>
          </details>
        ) : (
          <p className="text-[13px] text-muted-foreground">Если это продолжается дольше нескольких минут, сообщите администратору.</p>
        )}
        <div className="pt-1"><RetryButton /></div>
      </div>
    </Panel>
  );
}

/** Роль текущей сессии; вне запроса (тесты, сборка) — не администратор. */
async function sessionIsAdmin(): Promise<boolean> {
  try {
    return (await getSession())?.role === "admin";
  } catch {
    return false;
  }
}

/**
 * Служба недоступна (серверный компонент): роль берёт из сессии сам, если
 * `admin` не передан. В клиентских компонентах — ServiceUnavailableView.
 */
export async function ServiceUnavailable(props: ServiceUnavailableProps & { admin?: boolean }) {
  const admin = props.admin ?? (await sessionIsAdmin());
  return <ServiceUnavailableView {...props} admin={admin} />;
}
