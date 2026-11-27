"use client";

// Кнопка входа через IdP: после клика сразу показывает, что идёт переход
// (discovery и редирект на IdP занимают секунды), и не даёт нажать дважды.
import { useState } from "react";
import { KeyRound, LoaderCircle } from "lucide-react";
import { Button } from "@/components/ui/button";

export function SsoButton({ href = "/api/auth/oidc/login" }: { href?: string }) {
  const [pending, setPending] = useState(false);
  return (
    <Button asChild className="min-h-12 w-full">
      <a
        href={href}
        aria-busy={pending || undefined}
        aria-disabled={pending || undefined}
        onClick={(e) => {
          if (pending) e.preventDefault();
          else setPending(true);
        }}
      >
        {pending ? <LoaderCircle className="animate-spin" strokeWidth={1.5} aria-hidden /> : <KeyRound strokeWidth={1.5} aria-hidden />}
        {pending ? "Переходим к входу…" : "Войти через корпоративную учётную запись"}
      </a>
    </Button>
  );
}
