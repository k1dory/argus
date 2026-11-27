// Служба недоступна (серверный компонент): роль берёт из сессии сам.
// Презентационная часть — service-unavailable-view.tsx (её и импортируйте из "use client").
import { getSession } from "@/lib/auth";
import { ServiceUnavailableView, type ServiceUnavailableProps } from "@/components/console/service-unavailable-view";

export { SERVICE_TEXT, ServiceUnavailableView, type ServiceUnavailableProps, type UnavailableService } from "@/components/console/service-unavailable-view";

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
 * `admin` не передан. В клиентских компонентах — ServiceUnavailableView из service-unavailable-view.
 */
export async function ServiceUnavailable(props: ServiceUnavailableProps & { admin?: boolean }) {
  const admin = props.admin ?? (await sessionIsAdmin());
  return <ServiceUnavailableView {...props} admin={admin} />;
}
