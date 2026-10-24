// Серверный клиент Wazuh manager API (4.x): JWT через
// POST /security/user/authenticate?raw=true (живёт ~900 с), повторная
// аутентификация на 401. Управляющий контур консоли — группы, агенты,
// правила — работает через эти вызовы; путь тот же, что у policyd.
import http from "http";
import https from "https";

const API_URL = process.env.WAZUH_API_URL ?? "https://wazuh-manager:55000";
const API_USER = process.env.WAZUH_API_USER ?? "wazuh";
const API_PASSWORD = process.env.WAZUH_API_PASSWORD ?? "wazuh";
const INSECURE_TLS = process.env.WAZUH_INSECURE_TLS === "true";

export class WazuhApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}

type RawResponse = { status: number; body: string };

function rawRequest(
  method: string,
  path: string,
  opts: { token?: string; body?: string; contentType?: string; basicAuth?: boolean } = {},
): Promise<RawResponse> {
  const url = new URL(API_URL.replace(/\/$/, "") + path);
  const mod = url.protocol === "https:" ? https : http;
  const headers: Record<string, string> = {};
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
  if (opts.basicAuth) {
    headers.Authorization =
      "Basic " + Buffer.from(`${API_USER}:${API_PASSWORD}`).toString("base64");
  }
  if (opts.body !== undefined) {
    headers["Content-Type"] = opts.contentType ?? "application/json";
    headers["Content-Length"] = String(Buffer.byteLength(opts.body));
  }
  return new Promise((resolve, reject) => {
    const req = mod.request(
      url,
      { method, headers, rejectUnauthorized: url.protocol === "https:" ? !INSECURE_TLS : undefined },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => {
          clearTimeout(deadline);
          resolve({ status: res.statusCode ?? 0, body });
        });
      },
    );
    // Два таймаута: неактивность сокета И общий wall-clock — капающий
    // по байту ответ не должен держать server action вечно.
    req.setTimeout(15_000, () => req.destroy(new Error("Wazuh API: таймаут запроса")));
    const deadline = setTimeout(
      () => req.destroy(new Error("Wazuh API: превышен общий таймаут (30 с)")),
      30_000,
    );
    req.on("error", (err) => {
      clearTimeout(deadline);
      reject(err);
    });
    if (opts.body !== undefined) req.write(opts.body);
    req.end();
  });
}

const TOKEN_TTL_MS = 800_000; // токен живёт ~900 c, обновляем заранее

async function fetchToken(): Promise<string> {
  const resp = await rawRequest("POST", "/security/user/authenticate?raw=true", {
    basicAuth: true,
  });
  if (resp.status !== 200) {
    throw new WazuhApiError(`аутентификация не прошла (${resp.status})`, resp.status);
  }
  return resp.body.trim();
}

// Кэшируем promise, а не значение: N параллельных запросов на холодном
// старте делят одну аутентификацию вместо гонки из N штук.
let tokenState: { promise: Promise<string>; obtainedAt: number } | null = null;

function getToken(force = false): Promise<string> {
  if (!force && tokenState && Date.now() - tokenState.obtainedAt < TOKEN_TTL_MS) {
    return tokenState.promise;
  }
  const promise = fetchToken();
  const entry = { promise, obtainedAt: Date.now() };
  tokenState = entry;
  promise.catch(() => {
    if (tokenState === entry) tokenState = null;
  });
  return promise;
}

/** Вызов API; body-объект сериализуется в JSON, строка уходит как есть.
 *  raw: true — вернуть тело ответа как текст без разбора (XML-файлы). */
export async function wzRequest<T = unknown>(
  method: string,
  path: string,
  opts: { body?: unknown; contentType?: string; raw?: boolean } = {},
): Promise<T> {
  const body =
    opts.body === undefined
      ? undefined
      : typeof opts.body === "string"
        ? opts.body
        : JSON.stringify(opts.body);
  let token = await getToken();
  let resp = await rawRequest(method, path, { token, body, contentType: opts.contentType });
  if (resp.status === 401) {
    token = await getToken(true);
    resp = await rawRequest(method, path, { token, body, contentType: opts.contentType });
  }
  if (resp.status < 200 || resp.status >= 300) {
    let detail = resp.body.slice(0, 300);
    try {
      const parsed = JSON.parse(resp.body);
      detail = parsed.detail ?? parsed.title ?? parsed.message ?? detail;
    } catch {
      /* не JSON — оставляем как есть */
    }
    throw new WazuhApiError(`${method} ${path}: ${resp.status} ${detail}`, resp.status);
  }
  if (opts.raw) return resp.body as T;
  let parsed: unknown;
  try {
    parsed = JSON.parse(resp.body);
  } catch {
    return resp.body as T; // неожиданно не-JSON — отдаём как есть
  }
  // Wazuh отвечает 200 и на частично/полностью проваленные операции,
  // складывая ошибки в data.failed_items — не даём им сойти за успех.
  const failed = (parsed as { data?: { failed_items?: { error?: { message?: string } }[] } })
    ?.data?.failed_items;
  if (Array.isArray(failed) && failed.length > 0) {
    const msg = failed[0]?.error?.message ?? JSON.stringify(failed[0]).slice(0, 200);
    throw new WazuhApiError(`${method} ${path}: операция не выполнена — ${msg}`, resp.status);
  }
  return parsed as T;
}

type ItemsResponse<T> = {
  data: { affected_items: T[]; total_affected_items: number; failed_items?: unknown[] };
  message?: string;
};

function items<T>(resp: ItemsResponse<T>): T[] {
  return resp.data?.affected_items ?? [];
}

/** Wazuh отдаёт страницы по 500 объектов. Сверяем total, чтобы частичный
 *  ответ API не выглядел полным списком управляемых агентов. */
export async function fetchAllItems<T>(path: string, fetchPage: (path: string) => Promise<ItemsResponse<T>>): Promise<T[]> {
  const out: T[] = [];
  const separator = path.includes("?") ? "&" : "?";
  for (let offset = 0; offset < 100_000; offset += 500) {
    const resp = await fetchPage(`${path}${separator}limit=500&offset=${offset}`);
    const page = items(resp);
    const total = Number(resp.data?.total_affected_items);
    if (!Number.isSafeInteger(total) || total < 0 || page.length === 0 && out.length < total) {
      throw new WazuhApiError("Wazuh API вернул неполную страницу списка", 502);
    }
    out.push(...page);
    if (out.length >= total) return out;
  }
  throw new WazuhApiError("Список Wazuh превысил допустимый объём", 502);
}

const allItems = <T,>(path: string): Promise<T[]> => fetchAllItems<T>(path, (p) => wzRequest<ItemsResponse<T>>("GET", p));

/* ===== Менеджер ===== */

export type ManagerInfo = { version: string; type?: string; name?: string };

export async function managerInfo(): Promise<ManagerInfo | null> {
  const resp = await wzRequest<ItemsResponse<ManagerInfo>>("GET", "/manager/info");
  return items(resp)[0] ?? null;
}

export async function managerConfigValid(): Promise<boolean> {
  return (await managerConfigValidation()).ok;
}

/** GET /manager/configuration/validation — менеджер прогоняет конфигурацию и
 *  правила целиком; ошибки приходят в failed_items (wzRequest бросает их как
 *  WazuhApiError). Вызывается после сохранения правил — до предложения рестарта. */
export async function managerConfigValidation(): Promise<{ ok: boolean; detail: string }> {
  try {
    const resp = await wzRequest<ItemsResponse<{ name?: string; status: string }>>(
      "GET",
      "/manager/configuration/validation",
    );
    const bad = items(resp).filter((i) => i.status !== "OK");
    if (bad.length > 0) return { ok: false, detail: bad.map((i) => `${i.name ?? "manager"}: ${i.status}`).join("; ") };
    return { ok: true, detail: items(resp).map((i) => `${i.name ?? "manager"}: OK`).join("; ") || "OK" };
  } catch (err) {
    return { ok: false, detail: err instanceof Error ? err.message : String(err) };
  }
}

export async function restartManager(): Promise<void> {
  await wzRequest("PUT", "/manager/restart");
}

/* ===== Агенты ===== */

export type WzAgent = {
  id: string;
  name: string;
  ip?: string;
  status: string;
  version?: string;
  group?: string[];
  lastKeepAlive?: string;
  os?: { name?: string };
};

export async function listAgents(): Promise<WzAgent[]> {
  return allItems<WzAgent>("/agents?sort=%2Bid&select=id,name,ip,status,version,group,lastKeepAlive,os.name");
}

export async function restartAgent(id: string): Promise<void> {
  await wzRequest("PUT", `/agents/${encodeURIComponent(id)}/restart`);
}

export async function addAgentToGroup(id: string, group: string): Promise<void> {
  await wzRequest("PUT", `/agents/${encodeURIComponent(id)}/group/${encodeURIComponent(group)}`);
}

export async function removeAgentFromGroup(id: string, group: string): Promise<void> {
  await wzRequest(
    "DELETE",
    `/agents/${encodeURIComponent(id)}/group/${encodeURIComponent(group)}`,
  );
}

/* ===== Группы ===== */

export type WzGroup = { name: string; count?: number; configSum?: string };

export async function listGroups(): Promise<WzGroup[]> {
  const resp = await wzRequest<ItemsResponse<WzGroup>>("GET", "/groups?limit=500");
  return items(resp);
}

export async function createGroup(groupId: string): Promise<void> {
  await wzRequest("POST", "/groups", { body: { group_id: groupId } });
}

export async function deleteGroup(groupId: string): Promise<void> {
  await wzRequest("DELETE", `/groups?groups_list=${encodeURIComponent(groupId)}`);
}

export async function groupAgents(groupId: string): Promise<WzAgent[]> {
  return allItems<WzAgent>(`/groups/${encodeURIComponent(groupId)}/agents?select=id,name,ip,status,version`);
}

export async function getGroupConf(groupId: string): Promise<string> {
  // raw=true отдаёт agent.conf как XML-текст.
  return wzRequest<string>(
    "GET",
    `/groups/${encodeURIComponent(groupId)}/files/agent.conf?raw=true`,
    { raw: true },
  );
}

export async function putGroupConf(groupId: string, xml: string): Promise<void> {
  await wzRequest("PUT", `/groups/${encodeURIComponent(groupId)}/configuration`, {
    body: xml,
    contentType: "application/xml",
  });
}

/* ===== Правила (etc/rules — кастомные) ===== */

export type WzRuleFile = { filename: string; relative_dirname: string; status?: string };

export async function listRuleFiles(): Promise<WzRuleFile[]> {
  const resp = await wzRequest<ItemsResponse<WzRuleFile>>(
    "GET",
    "/rules/files?relative_dirname=etc%2Frules&limit=500",
  );
  return items(resp);
}

export async function getRuleFile(filename: string): Promise<string> {
  return wzRequest<string>(
    "GET",
    `/rules/files/${encodeURIComponent(filename)}?raw=true&relative_dirname=etc%2Frules`,
    { raw: true },
  );
}

export async function putRuleFile(filename: string, xml: string): Promise<void> {
  await wzRequest("PUT", `/rules/files/${encodeURIComponent(filename)}?overwrite=true`, {
    body: xml,
    contentType: "application/octet-stream",
  });
}
