/* eslint-disable @typescript-eslint/no-require-imports -- React грузится после моков next/* из _next-mock */
// Рендер страниц консоли в тестах без Next: серверные компоненты (в том числе
// async внутри <Suspense>) раскрываются вызовом, клиентские — через
// react-dom/server с контекстом app router, чтобы useRouter/usePathname работали.
import type React from "react";

const ReactLib = require("react") as typeof import("react");
const { renderToStaticMarkup } = require("react-dom/server") as typeof import("react-dom/server");
const { AppRouterContext } = require("next/dist/shared/lib/app-router-context.shared-runtime") as {
  AppRouterContext: React.Context<unknown>;
};
const { PathnameContext, SearchParamsContext } = require("next/dist/shared/lib/hooks-client-context.shared-runtime") as {
  PathnameContext: React.Context<string | null>;
  SearchParamsContext: React.Context<URLSearchParams | null>;
};

/** Вызовы router.push/replace/refresh из клиентских компонентов — в этот журнал. */
export const routerCalls: string[] = [];

const router = {
  back: () => routerCalls.push("back"),
  forward: () => routerCalls.push("forward"),
  refresh: () => routerCalls.push("refresh"),
  hmrRefresh: () => undefined,
  push: (href: string) => routerCalls.push(`push ${href}`),
  replace: (href: string) => routerCalls.push(`replace ${href}`),
  prefetch: () => undefined,
};

/** Оборачивает элемент в контекст app router (pathname и search по умолчанию — «/»). */
export function withRouter(node: React.ReactNode, pathname = "/", search = ""): React.ReactElement {
  return ReactLib.createElement(
    AppRouterContext.Provider,
    { value: router },
    ReactLib.createElement(
      PathnameContext.Provider,
      { value: pathname },
      ReactLib.createElement(SearchParamsContext.Provider, { value: new URLSearchParams(search) }, node),
    ),
  );
}

/** HTML клиентского/презентационного компонента (SSR, без эффектов). */
export function html(node: React.ReactNode, pathname = "/", search = ""): string {
  return renderToStaticMarkup(withRouter(node, pathname, search));
}

/** Текст из HTML: теги убраны, сущности раскрыты, пробелы схлопнуты. */
export function stripTags(markup: string): string {
  return markup
    .replace(/<(script|style)[\s\S]*?<\/\1>/g, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, "\"").replace(/&#x27;/g, "'").replace(/&nbsp;/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

const TEXT_PROPS = ["children", "label", "title", "reason", "subtitle", "hint", "meta", "description", "successText", "placeholder", "aria-label", "value", "markdown", "initialXml", "defaultValue"];

type AnyElement = React.ReactElement<Record<string, unknown>> & { type: unknown };

function isElement(x: unknown): x is AnyElement {
  return typeof x === "object" && x !== null && "props" in x && "type" in x;
}

function propsText(props: Record<string, unknown>, expand: (n: unknown) => Promise<string>): Promise<string> {
  return Promise.all(TEXT_PROPS.map((k) => (k in props ? expand(props[k]) : Promise.resolve("")))).then((parts) => parts.filter(Boolean).join(" "));
}

/**
 * Текст дерева страницы: функции-компоненты вызываются (async — ожидаются),
 * клиентские с хуками рендерятся через SSR; что не получилось — текст из props.
 * Возвращает один пробелами разделённый текст, как видит его читатель.
 */
export async function pageText(node: unknown): Promise<string> {
  const seenErrors: string[] = [];
  const expand = async (n: unknown): Promise<string> => {
    if (n === null || n === undefined || typeof n === "boolean") return "";
    if (typeof n === "string" || typeof n === "number") return String(n);
    if (n instanceof Promise) return expand(await n);
    if (Array.isArray(n)) return (await Promise.all(n.map(expand))).filter(Boolean).join(" ");
    if (!isElement(n)) return "";
    const { type, props } = n;
    if (typeof type === "string") return propsText(props, expand);
    if (typeof type === "symbol") return propsText(props, expand); // Fragment, Suspense, StrictMode
    // Компонент: прямой вызов (серверные, в т. ч. async); с хуками — SSR целиком
    // (если внутри нет async-серверных); иначе — текст из props.
    const attempt = async (produce: () => unknown, name: string): Promise<string> => {
      try {
        return await expand(produce());
      } catch (e) {
        try {
          return stripTags(renderToStaticMarkup(withRouter(n)));
        } catch (e2) {
          seenErrors.push(`${name}: ${(e as Error).message} / ${(e2 as Error).message}`);
          return propsText(props, expand);
        }
      }
    };
    if (typeof type === "object" && type !== null) {
      const t = type as { render?: (p: unknown) => unknown; type?: unknown; displayName?: string };
      if (typeof t.render === "function") return attempt(() => t.render!(props), t.displayName ?? "forwardRef");
      if (t.type) return attempt(() => ReactLib.createElement(t.type as React.ElementType, props), "memo");
      return propsText(props, expand); // Provider / Consumer / lazy
    }
    if (typeof type === "function") {
      const fn = type as ((p: unknown) => unknown) & { prototype?: { isReactComponent?: unknown } };
      if (fn.prototype && fn.prototype.isReactComponent) return propsText(props, expand);
      return attempt(() => fn(props), fn.name || "anon");
    }
    return "";
  };
  const text = (await expand(node)).replace(/\s+/g, " ").trim();
  return text;
}
