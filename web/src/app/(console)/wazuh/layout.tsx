import { notFound } from "next/navigation";
import { wazuhEnabled } from "@/lib/integrations";

/** Модуль Wazuh: страницы алертов, уязвимостей, MITRE, политик, агентов и
 *  управления менеджером существуют только при ARGUS_INTEGRATION_WAZUH=1.
 *  Выключен — 404, как будто раздела нет (редиректы со старых путей в
 *  next.config.ts ведут сюда же). */
export default function WazuhLayout({ children }: { children: React.ReactNode }) {
  if (!wazuhEnabled()) notFound();
  return children;
}
