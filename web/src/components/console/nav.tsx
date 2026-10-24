"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  Bell,
  Bug,
  ChevronDown,
  Crosshair,
  LayoutDashboard,
  Menu,
  Radio,
  ScrollText,
  Siren,
  ShieldCheck,
  Server,
  Settings,
  Wrench,
  Search,
  ListTree,
  Users,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuGroup,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

/** Подписи навигации = заголовки h1 страниц; metadata страниц берут их отсюда.
 *  wazuh — пункты необязательного модуля Wazuh: показываются, только когда
 *  модуль включён (флаг передаёт серверный layout). */
export const NAV_ITEMS = [
  { href: "/", label: "Обзор", icon: Activity },
  { href: "/incidents", label: "Инциденты", icon: Siren },
  { href: "/events", label: "Журнал", icon: ListTree },
  { href: "/actors", label: "Субъекты", icon: Users },
  { href: "/search", label: "Поиск", icon: Search },
  { href: "/dashboards", label: "Дашборды", icon: LayoutDashboard },
  { href: "/wazuh/alerts", label: "Алерты Wazuh", icon: Bell, wazuh: true },
  { href: "/wazuh/vulnerabilities", label: "Уязвимости", icon: Bug, wazuh: true },
  { href: "/wazuh/mitre", label: "MITRE ATT&CK", icon: Crosshair, wazuh: true },
  { href: "/sources", label: "Источники", icon: Radio },
  { href: "/rules", label: "Правила корреляции", icon: ScrollText },
  { href: "/wazuh/policies", label: "Политики", icon: ShieldCheck, wazuh: true },
  { href: "/wazuh/agents", label: "Агенты Wazuh", icon: Server, wazuh: true },
  { href: "/wazuh/manage", label: "Управление Wazuh", icon: Wrench, wazuh: true },
  { href: "/settings", label: "Настройки", icon: Settings },
] as const;

export type NavHref = (typeof NAV_ITEMS)[number]["href"];
type NavItem = (typeof NAV_ITEMS)[number];

export function navLabel(href: NavHref): string {
  return NAV_ITEMS.find((i) => i.href === href)?.label ?? "";
}

/** Пункты навигации для установки: без модуля Wazuh его разделов нет. */
export function navItems(wazuh: boolean): readonly NavItem[] {
  return wazuh ? NAV_ITEMS : NAV_ITEMS.filter((i) => !("wazuh" in i && i.wazuh));
}

function isActive(href: string, pathname: string): boolean {
  return href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(href + "/");
}

export function ConsoleNav({ wazuh = false }: { wazuh?: boolean }) {
  const pathname = usePathname();
  const items = navItems(wazuh);
  const current = items.find((i) => isActive(i.href, pathname));
  return (
    <>
      {/* Широкий экран: полная линейка разделов */}
      <nav className="hidden w-full flex-wrap items-center gap-x-4 gap-y-2 lg:order-last lg:flex" aria-label="Разделы консоли">
        {items.map(({ href, label }) => {
          const active = isActive(href, pathname);
          return (
            <Link
              key={href}
              href={href}
              aria-current={active ? "page" : undefined}
              className={cn(
                "flex min-h-9 items-center gap-1.5 border-b text-[13px] transition-colors",
                active
                  ? "border-[var(--ring)] text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              )}
            >
              {label}
            </Link>
          );
        })}
      </nav>

      {/* Узкий экран: компактное меню с текущим разделом в кнопке */}
      <nav className="order-last w-full lg:hidden" aria-label="Разделы консоли">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="secondary" size="lg" className="min-h-12 w-full justify-between gap-2" aria-label="Открыть меню разделов">
              <Menu data-icon="inline-start" strokeWidth={1.5} aria-hidden />
              {current?.label ?? "Разделы"}
              <ChevronDown data-icon="inline-end" strokeWidth={1.5} aria-hidden />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-[var(--radix-dropdown-menu-trigger-width)]">
            <DropdownMenuGroup>
            {items.map(({ href, label, icon: Icon }) => {
              const active = isActive(href, pathname);
              return (
                <DropdownMenuItem key={href} asChild className={active ? "text-[var(--ring)]" : undefined}>
                  <Link href={href} aria-current={active ? "page" : undefined} className="flex min-h-10 items-center gap-2 text-[13px]">
                    <Icon strokeWidth={1.5} className="h-3.5 w-3.5" aria-hidden />
                    {label}
                  </Link>
                </DropdownMenuItem>
              );
            })}
            </DropdownMenuGroup>
          </DropdownMenuContent>
        </DropdownMenu>
      </nav>
    </>
  );
}
