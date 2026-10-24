import { randomBytes } from "node:crypto";
import { NextResponse, type NextRequest } from "next/server";

// Прокидывает путь запроса серверным компонентам (requirePageSession
// строит из него ?next= при редиректе на /login) и выдаёт CSP с nonce на
// каждый запрос. Оба заголовка задаются здесь и не могут прийти от
// клиента — входящие значения затираются.
//
// CSP: инлайн-скрипты Next (гидрация RSC через self.__next_f) получают
// nonce — Next читает его из request-заголовка Content-Security-Policy
// (шаблон 'nonce-…') и сам проставляет на свои <script>; 'strict-dynamic'
// доверяет скриптам, которые загружены доверенными. Инлайн-стили нужны
// Recharts и next/font. В dev добавляются 'unsafe-eval' (React Refresh,
// стеки ошибок) и ws: (HMR).
const dev = process.env.NODE_ENV === "development";

export function cspHeader(nonce: string): string {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    `connect-src 'self'${dev ? " ws: wss:" : ""}`,
    "frame-ancestors 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join("; ");
}

export function proxy(req: NextRequest) {
  const nonce = randomBytes(16).toString("base64");
  const csp = cspHeader(nonce);
  const headers = new Headers(req.headers);
  const { pathname, search } = req.nextUrl;
  headers.set("x-argus-path", pathname + search);
  headers.set("x-nonce", nonce);
  headers.set("content-security-policy", csp);
  const res = NextResponse.next({ request: { headers } });
  res.headers.set("Content-Security-Policy", csp);
  return res;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|icon.svg|robots.txt).*)"],
};
