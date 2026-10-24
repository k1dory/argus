import type { NextConfig } from "next";

// Caddy перед консолью ставит HSTS, X-Frame-Options, Referrer-Policy и
// X-Content-Type-Options сам (header — «set», перезаписывает). Здесь — те же
// значения плюс Permissions-Policy, чтобы прямой доступ к :3000 был не хуже.
// CSP — в src/proxy.ts: она с nonce на каждый запрос, статической быть не может.
const securityHeaders = [
  { key: "Referrer-Policy", value: "same-origin" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()" },
];

const WAZUH_PAGES = ["alerts", "vulnerabilities", "mitre", "policies", "agents", "manage"] as const;

const nextConfig: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  // next/image не используется — оптимизатор картинок лишняя поверхность.
  images: { unoptimized: true },
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
  // Страницы Wazuh переехали под /wazuh (необязательный модуль): закладки на
  // старые адреса ведут туда же. Выключенный модуль отвечает там 404.
  async redirects() {
    return WAZUH_PAGES.map((p) => ({ source: `/${p}/:path*`, destination: `/wazuh/${p}/:path*`, permanent: true }));
  },
};

export default nextConfig;
