/* eslint-disable @typescript-eslint/no-require-imports -- моки кладутся в кэш CJS до загрузки модулей, статический import не подходит */
// Минимальные подмены next/headers, next/cache и журнала аудита для тестов
// auth/actions в обычном Node (тесты грузятся tsx как CJS — см. probe в
// _server-only-hook.cjs). Модули кладутся в require.cache ДО require auth.ts,
// поэтому импорты в тестах — динамические (loadAuth), а не статические.
import Module from "node:module";
import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { blockCandidates, RESPOND_MODES } from "../src/lib/shared/respond";
import { ResponseCookies } from "next/dist/compiled/@edge-runtime/cookies";

export type AuditEntry = { user: string; action: string; target: string; detail: string };

/** Заглушки argus-queries: тест может подменить любую (mocks.queries.incidentGet = …). */
export type QueryMocks = {
  audit: (user: string, action: string, target: string, detail?: string, opts?: { strict?: boolean }) => Promise<void>;
  incidentGet: (id: string) => Promise<Record<string, unknown> | null>;
  requestBlockIp: (...args: unknown[]) => Promise<{ error?: string; results?: { executor: string; ok: boolean; detail: string }[] }>;
  blockCandidatesFor: (inc: { actor_name: string; chain: string[]; tags?: string[] }) => string[];
  requestUnblockIp: (...args: unknown[]) => Promise<{ error?: string; results?: { executor: string; ok: boolean; detail: string }[] }>;
  requestReanalyze: (id: string) => Promise<string | null>;
  addException: (...args: unknown[]) => Promise<void>;
  addIncidentComment: (...args: unknown[]) => Promise<void>;
  incidentCommentExists: (id: string, commentId: string) => Promise<boolean>;
  deactivateException: (...args: unknown[]) => Promise<void>;
  incidentTransition: (...args: unknown[]) => Promise<void>;
  setRespondMode: (...args: unknown[]) => Promise<void>;
  /** Запросы маршрутов API к ClickHouse (сессии разбора): по умолчанию — пусто. */
  chQuery: (sql: string, params?: Record<string, string | number>) => Promise<Record<string, unknown>[]>;
  incidentComments: (id: string, limit?: number) => Promise<unknown[]>;
  incidentFirstResponse: (id: string) => Promise<string | null>;
  incidentStateHistory: (id: string, limit?: number) => Promise<unknown[]>;
  verdictGet: (id: string) => Promise<unknown>;
  sourcesHealth: () => Promise<unknown[]>;
  /** По умолчанию — sourcesHealth без пропущенных, чтобы тесты, подменяющие sourcesHealth, работали и для маршрута. */
  sourcesHealthReport: () => Promise<{ sources: unknown[]; omitted: number }>;
  incidentsList: (...args: unknown[]) => Promise<unknown>;
  saveTriageRevocation: (sessionId: string, incidentId: string, expiresAt: string) => Promise<void>;
  triageRevocations: () => Promise<Map<string, number>>;
  saveTriageVerdict: (input: { incidentId: string; state: string; sessionId: string; actor: string }) => Promise<void>;
  triageVerdictClaim: (incidentId: string) => Promise<{ incident_id: string; session_id: string; claimed_at: string } | null>;
  triageVerdictWinner: (incidentId: string) => Promise<string | null>;
  claimTriageVerdict: (input: { incidentId: string; sessionId: string; actor: string }) => Promise<string>;
  saveAgentVerdict: (row: Record<string, unknown>) => Promise<void>;
  agentVerdictsFor: (incidentId: string, limit?: number) => Promise<Record<string, unknown>[]>;
  agentVerdictBySession: (incidentId: string, sessionId: string) => Promise<Record<string, unknown> | null>;
  /** Запросы страниц консоли (обзор, лента, источники, правила, настройки): по умолчанию — пусто. */
  incidentStats: () => Promise<{ total: number; open: number; escalated: number; pii: number }>;
  eventsByClass: (hours: number) => Promise<{ source_class: string; count: number; sources: number }[]>;
  eventsRecent: (source?: string, limit?: number) => Promise<Record<string, unknown>[]>;
  engineRules: () => Promise<{ rules: Record<string, unknown>[]; health: Record<string, unknown> | null; error: string | null }>;
  rulesFalsePositives: () => Promise<Record<string, { rule_id: string; total: number; false_positive: number; closed: number }>>;
  listExceptions: () => Promise<Record<string, unknown>[]>;
  auditTail: (limit?: number) => Promise<Record<string, unknown>[]>;
  licenseStats: () => Promise<{ peak_eps_30d: number; avg_eps_7d: number; events_30d: number; retention_days: number; sources: number }>;
  respondStatus: () => Promise<Record<string, unknown>>;
  responseLog: (opts?: { incidentId?: string; limit?: number }) => Promise<Record<string, unknown>[]>;
  verdictsFor: (ids: string[]) => Promise<Record<string, Record<string, unknown>>>;
  incidentClosuresFor: (ids: string[]) => Promise<Record<string, Record<string, unknown>>>;
  scanGroups: (...args: unknown[]) => Promise<Record<string, unknown>[]>;
  scanGroupIncidents: (...args: unknown[]) => Promise<Record<string, unknown>[]>;
  incidentBlockStates: (...args: unknown[]) => Promise<Record<string, string>>;
  incidentLabels: (since: string, limit: number, after?: import("../src/lib/label-cursor").LabelCursor) => Promise<unknown[]>;
};

type WazuhApi = typeof import("../src/lib/wazuh-api");

type Mocks = {
  jar: Map<string, string>;
  headers: Map<string, string>;
  responseHeaders: Headers;
  audit: AuditEntry[];
  authFile: string;
  queries: QueryMocks;
  /** Подмены функций wazuh-api на время теста; без подмены — настоящий модуль (сеть недоступна → ECONNREFUSED). */
  wazuh: Partial<WazuhApi>;
};

let installed: Mocks | null = null;

function inject(filename: string, exports: Record<string, unknown>): void {
  const m = new Module(filename);
  m.filename = filename;
  m.loaded = true;
  m.exports = exports;
  // В тест-раннере require — «специальный», без .cache; кэш модулей — Module._cache.
  (Module as unknown as { _cache: Record<string, Module> })._cache[filename] = m;
}

/** Ставит моки и временный AUTH_FILE; идемпотентно в пределах процесса. */
export function installNextMocks(): Mocks {
  if (installed) return installed;
  const jar = new Map<string, string>();
  const headers = new Map<string, string>();
  const responseHeaders = new Headers();
  const responseCookies = new ResponseCookies(responseHeaders);
  const audit: AuditEntry[] = [];
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "argus-auth-"));
  const authFile = path.join(dir, "auth.json");
  process.env.AUTH_FILE = authFile;
  // Сеть в тестах не нужна: всё, что ходит наружу, должно падать быстро.
  process.env.CLICKHOUSE_URL = "http://127.0.0.1:9";
  process.env.WAZUH_API_URL = "http://127.0.0.1:9";
  process.env.ENGINE_URL = "http://127.0.0.1:9";

  const cookieApi = {
    get: (name: string) => (jar.has(name) ? { name, value: jar.get(name)! } : undefined),
    set: (name: string, value: string) => void jar.set(name, value),
    delete: (arg: string | { name: string; path?: string }) => {
      if (typeof arg === "string") responseCookies.delete(arg);
      else responseCookies.delete(arg);
      jar.delete(typeof arg === "string" ? arg : arg.name);
    },
  };
  const headerApi = { get: (name: string) => headers.get(name.toLowerCase()) ?? null };
  inject(require.resolve("next/headers"), {
    cookies: async () => cookieApi,
    headers: async () => headerApi,
  });
  inject(require.resolve("next/cache"), {
    revalidatePath: () => undefined,
    revalidateTag: () => undefined,
  });
  // Журнал действий — в память: тесты проверяют, что действия пишут аудит.
  // Статусы/поля — настоящие (из shared/incidents), а не пустышки: иначе
  // проверка статуса в действиях отвергала бы всё подряд.
  const shared = require("../src/lib/shared/incidents") as typeof import("../src/lib/shared/incidents");
  const queries: QueryMocks = {
    audit: async (user, action, target, detail = "") => {
      audit.push({ user, action, target, detail });
    },
    incidentGet: async () => null,
    requestBlockIp: async () => ({ error: "движок недоступен" }),
    blockCandidatesFor: (inc) => blockCandidates(inc.actor_name, inc.chain),
    requestUnblockIp: async () => ({ error: "движок недоступен" }),
    requestReanalyze: async () => "движок недоступен",
    addException: async () => undefined,
    addIncidentComment: async () => undefined,
    incidentCommentExists: async () => false,
    deactivateException: async () => undefined,
    incidentTransition: async () => undefined,
    setRespondMode: async () => undefined,
    chQuery: async () => [],
    incidentComments: async () => [],
    incidentFirstResponse: async () => null,
    incidentStateHistory: async () => [],
    verdictGet: async () => null,
    sourcesHealth: async () => [],
    sourcesHealthReport: async () => ({ sources: await queries.sourcesHealth(), omitted: 0 }),
    incidentsList: async () => ({ rows: [], total: 0, page: 1, pageSize: 50 }),
    saveTriageRevocation: async () => undefined,
    triageRevocations: async () => new Map(),
    saveTriageVerdict: async () => undefined,
    triageVerdictClaim: async () => null,
    triageVerdictWinner: async () => null,
    claimTriageVerdict: async (m) => m.sessionId,
    saveAgentVerdict: async () => undefined,
    agentVerdictsFor: async () => [],
    agentVerdictBySession: async () => null,
    incidentStats: async () => ({ total: 0, open: 0, escalated: 0, pii: 0 }),
    eventsByClass: async () => [],
    eventsRecent: async () => [],
    engineRules: async () => ({ rules: [], health: null, error: null }),
    rulesFalsePositives: async () => ({}),
    listExceptions: async () => [],
    auditTail: async () => [],
    licenseStats: async () => ({ peak_eps_30d: 0, avg_eps_7d: 0, events_30d: 0, retention_days: 180, sources: 0 }),
    respondStatus: async () => ({ mode: "simulate", mode_from: "config", enabled: false, ttl: "", allowlist: [], active: [], config_errors: [], pending: 0, requested: null }),
    responseLog: async () => [],
    verdictsFor: async () => ({}),
    incidentClosuresFor: async () => ({}),
    scanGroups: async () => [],
    scanGroupIncidents: async () => [],
    incidentBlockStates: async () => ({}),
    incidentLabels: async () => [],
  };
  const argusQueries = require.resolve(path.resolve(__dirname, "../src/lib/argus-queries"));
  const delegate = Object.fromEntries(
    (Object.keys(queries) as (keyof QueryMocks)[]).map((k) => [k, (...args: unknown[]) => (queries[k] as (...a: unknown[]) => unknown)(...args)]),
  );
  inject(argusQueries, {
    ...delegate,
    IncidentWorkflowError: class IncidentWorkflowError extends Error {},
    INCIDENT_STATUSES: shared.INCIDENT_STATUSES,
    EXCEPTION_FIELDS: shared.EXCEPTION_FIELDS,
    isIncidentStatus: shared.isIncidentStatus,
    RESPOND_MODES,
    STALE_SOURCES_LIMIT: 2000,
  });
  // wazuh-api: настоящий модуль за делегатом (tests/_wazuh-delegate.ts), чтобы
  // тест мог подменить одну функцию. Резолв «./wazuh-api» перенаправляется на
  // делегат для всех, кроме самого делегата.
  const wazuhFile = require.resolve(path.resolve(__dirname, "../src/lib/wazuh-api"));
  const delegateFile = require.resolve(path.resolve(__dirname, "./_wazuh-delegate"));
  type Resolver = (this: unknown, request: string, parent: { filename?: string } | undefined, ...rest: unknown[]) => string;
  const M = Module as unknown as { _resolveFilename: Resolver };
  const origResolve = M._resolveFilename;
  M._resolveFilename = function (request, parent, ...rest) {
    const resolved = origResolve.call(this, request, parent, ...rest);
    return resolved === wazuhFile && parent?.filename !== delegateFile ? delegateFile : resolved;
  };
  const wazuh = (require(delegateFile) as { overrides: Partial<WazuhApi> }).overrides;
  installed = { jar, headers, responseHeaders, audit, authFile, queries, wazuh };
  return installed;
}

export type AuthModule = typeof import("../src/lib/auth");
export function loadAuth(): AuthModule {
  installNextMocks();
  return require("../src/lib/auth") as AuthModule;
}

/** Ошибка redirect() Next: digest NEXT_REDIRECT. */
export function isRedirect(err: unknown): boolean {
  return err instanceof Error && String((err as { digest?: string }).digest ?? err.message).startsWith("NEXT_REDIRECT");
}

export function formData(fields: Record<string, string>): FormData {
  const fd = new FormData();
  for (const [k, v] of Object.entries(fields)) fd.set(k, v);
  return fd;
}
