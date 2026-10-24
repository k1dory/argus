import Link from "next/link";
import { Suspense } from "react";
import { redirect } from "next/navigation";
import { headers } from "next/headers";
import { LogOut, UserRound } from "lucide-react";
import { getSession, loginUrlWithNext, ROLE_LABELS } from "@/lib/auth";
import { logoutAction } from "@/lib/actions";
import { APP_VERSION } from "@/lib/version";
import { ConsoleNav } from "@/components/console/nav";
import { wazuhEnabled } from "@/lib/integrations";
import { ServiceLeds } from "@/components/console/service-leds";
import { Button } from "@/components/ui/button";
import { Toaster } from "@/components/ui/sonner";

export default async function ConsoleLayout({ children }: { children: React.ReactNode }) {
  const session = await getSession();
  if (!session) redirect(loginUrlWithNext((await headers()).get("x-argus-path") ?? "/"));
  const who = `${session.user} · ${ROLE_LABELS[session.role]}`;
  return (
    <div className="mx-auto w-full max-w-[1800px] px-3 pb-16 sm:px-6 lg:px-10">
      <a href="#main" className="skip-link">К содержимому</a>
      <header className="mb-6 flex flex-wrap items-center justify-between gap-x-4 gap-y-3 border-b border-border py-3 lg:mb-8">
        <div className="flex min-w-0 flex-wrap items-center gap-3">
          <Link href="/" className="text-[15px] font-semibold tracking-[-0.01em] text-foreground" aria-label="ARGUS SIEM — на обзор">
            argus<span className="text-[var(--text-tertiary)]">/siem</span>
          </Link>
          <span className="hidden font-mono text-[12px] text-[var(--text-tertiary)] lg:inline">v{APP_VERSION}</span>
          <Suspense fallback={<span className="c-label" aria-hidden>··</span>}>
            <ServiceLeds />
          </Suspense>
        </div>
        {!session.mustChangePassword && <ConsoleNav wazuh={wazuhEnabled()} />}
        <div className="flex items-center gap-2">
          <span className="c-label hidden md:inline">{who}</span>
          <span className="c-label md:hidden" title={who} aria-label={who} role="img">
            <UserRound strokeWidth={1.5} className="h-4 w-4" aria-hidden />
          </span>
          <form action={logoutAction}>
            <Button variant="ghost" size="lg" type="submit" className="min-h-12 md:min-h-9">
              <LogOut strokeWidth={1.5} />
              Выход
            </Button>
          </form>
        </div>
      </header>
      <main id="main" className="flex min-w-0 flex-col gap-6 lg:gap-8" tabIndex={-1}>{children}</main>
      <Toaster />
    </div>
  );
}
