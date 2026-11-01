// Скачивание файла из API с состоянием: получить blob (ошибка сервера — текстом
// из JSON {error}, иначе HTTP-статус) и отдать его браузеру через a.download.
// Разделено на две чистые функции, чтобы проверять без DOM и без сети.

export async function fetchDownload(href: string, fetchFn: typeof fetch = fetch): Promise<Blob> {
  const resp = await fetchFn(href, { credentials: "same-origin" });
  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`;
    try {
      const j = (await resp.json()) as { error?: string };
      if (j.error) msg = j.error;
    } catch {}
    throw new Error(msg);
  }
  return resp.blob();
}

/** Минимум DOM для сохранения blob: подменяется в тестах. */
export type DownloadDom = {
  createObjectURL: (b: Blob) => string;
  revokeObjectURL: (u: string) => void;
  createElement: (tag: "a") => { href: string; download: string; click: () => void; remove: () => void };
  append: (node: { href: string }) => void;
  schedule?: (fn: () => void, ms: number) => void;
};

export const REVOKE_AFTER_MS = 10_000;

function browserDom(): DownloadDom {
  return {
    createObjectURL: (b) => URL.createObjectURL(b),
    revokeObjectURL: (u) => URL.revokeObjectURL(u),
    createElement: (tag) => document.createElement(tag),
    append: (node) => document.body.appendChild(node as unknown as Node),
  };
}

/** Сохраняет blob под именем filename; объектный URL отзывается через REVOKE_AFTER_MS. */
export function saveBlob(blob: Blob, filename: string, dom: DownloadDom = browserDom()): string {
  const url = dom.createObjectURL(blob);
  const a = dom.createElement("a");
  a.href = url;
  a.download = filename;
  dom.append(a);
  a.click();
  a.remove();
  (dom.schedule ?? setTimeout)(() => dom.revokeObjectURL(url), REVOKE_AFTER_MS);
  return url;
}
