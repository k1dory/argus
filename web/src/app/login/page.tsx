import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { isAuthenticated } from "@/lib/auth";
import { LoginForm } from "@/components/console/login-form";
import { oidcConfig } from "@/lib/oidc";
import { safeNextPath } from "@/lib/shared/next-path";
import { Button } from "@/components/ui/button";
import { KeyRound } from "lucide-react";
import { Panel } from "@/components/console/panel";

export const metadata: Metadata = { title: "Вход" };

export default async function LoginPage({ searchParams }: PageProps<"/login">) {
  const sp = await searchParams;
  // Куда вернуть после входа: только относительный путь консоли (не «//», не схема).
  const next = safeNextPath(sp.next);
  if (await isAuthenticated()) redirect(next);
  const sso = oidcConfig() !== null;
  const ssoError = sp.sso;
  return (
    <main className="flex min-h-screen items-center justify-center p-6">
      <div className="w-full max-w-md space-y-6">
        <div className="text-center">
          <div className="text-[15px] font-semibold tracking-[-0.01em] text-foreground">
            argus<span className="text-[var(--text-tertiary)]">/siem</span>
          </div>
          <h1 className="mt-3 text-[24px] leading-[1.2]">
            Вход в консоль. <span className="text-muted-foreground">Инциденты, журнал и правила в одном месте.</span>
          </h1>
        </div>
        <Panel label="Вход">
          <LoginForm next={next} />
          {sso && (
            <div className="mt-5 border-t border-border pt-5">
              <Button asChild variant="secondary" className="min-h-12 w-full">
                <a href="/api/auth/oidc/login"><KeyRound strokeWidth={1.5} />Войти через SSO (IdP)</a>
              </Button>
              {ssoError && (
                <p role="alert" className="mt-3 text-sm text-destructive">
                  {ssoError === "denied" ? "IdP не подтвердил вход или группа не сопоставлена роли ARGUS" : `SSO: состояние входа не найдено. Начните вход с адреса ${new URL(oidcConfig()!.redirectUrl).origin} и завершите его за 15 минут`}
                </p>
              )}
            </div>
          )}
        </Panel>
        <p className="text-center text-[13px] leading-[1.6] text-[var(--text-tertiary)]">
          Стартовый пароль admin создан при установке — см. файл рядом с auth.json в томе консоли. Остальным пользователям пароль выдаёт администратор в настройках.
        </p>
      </div>
    </main>
  );
}
