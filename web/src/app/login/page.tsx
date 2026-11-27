import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { getAuthState, isAuthenticated } from "@/lib/auth";
import { LoginForm } from "@/components/console/login-form";
import { oidcConfig } from "@/lib/oidc";
import { safeNextPath } from "@/lib/shared/next-path";
import { Button } from "@/components/ui/button";
import { KeyRound } from "lucide-react";
import { Panel } from "@/components/console/panel";
import { ssoErrorText } from "@/lib/shared/login";

export const metadata: Metadata = { title: "Вход" };

/** Стартовый пароль admin ещё не сменён: подсказку про файл показываем только тогда. */
async function firstRun(): Promise<boolean> {
  try {
    return !(await getAuthState()).passwordChanged;
  } catch {
    return false;
  }
}

export default async function LoginPage({ searchParams }: PageProps<"/login">) {
  const sp = await searchParams;
  // Куда вернуть после входа: только относительный путь консоли (не «//», не схема).
  const next = safeNextPath(sp.next);
  if (await isAuthenticated()) redirect(next);
  const oidc = oidcConfig();
  const sso = oidc !== null;
  const ssoError = typeof sp.sso === "string" ? sp.sso : null;
  const initial = await firstRun();
  return (
    <main className="flex min-h-screen items-center justify-center p-6">
      <div className="w-full max-w-md space-y-6">
        <div className="text-center">
          <div className="text-[15px] font-semibold tracking-[-0.01em] text-foreground" aria-hidden>
            argus<span className="text-[var(--text-tertiary)]">/siem</span>
          </div>
          <h1 className="mt-3 text-[24px] leading-[1.2]">Вход в ARGUS</h1>
        </div>
        {ssoError && sso && (
          <p role="alert" className="border border-[var(--status-err)]/40 bg-[var(--status-err)]/10 px-3 py-2 text-sm leading-relaxed text-foreground">
            {ssoErrorText(ssoError, oidc ? new URL(oidc.redirectUrl).origin : null)}
          </p>
        )}
        <Panel>
          {sso ? (
            <>
              <Button asChild className="min-h-12 w-full">
                <a href="/api/auth/oidc/login"><KeyRound strokeWidth={1.5} />Войти через корпоративную учётную запись</a>
              </Button>
              <div className="my-5 flex items-center gap-3 text-[13px] text-muted-foreground" aria-hidden>
                <span className="h-px flex-1 bg-border" />или<span className="h-px flex-1 bg-border" />
              </div>
              <details className="group" open={initial}>
                <summary className="flex cursor-pointer items-center justify-center gap-1.5 text-sm text-muted-foreground hover:text-foreground">
                  <span aria-hidden className="inline-block transition-transform group-open:rotate-90">›</span>
                  Войти по паролю ARGUS
                </summary>
                <div className="mt-5"><LoginForm next={next} /></div>
              </details>
            </>
          ) : (
            <LoginForm next={next} />
          )}
        </Panel>
        <p className="text-center text-[13px] leading-[1.6] text-[var(--text-tertiary)]">
          {initial
            ? "Первый запуск: стартовый пароль admin создан при установке и лежит в файле рядом с auth.json в томе консоли. После входа его нужно сменить."
            : "Нет доступа? Обратитесь к администратору ARGUS."}
        </p>
      </div>
    </main>
  );
}
