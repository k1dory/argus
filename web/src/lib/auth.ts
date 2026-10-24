// Аутентификация по модели из документации Wazuh (installation assistant):
// при первой установке пароль администратора генерируется и кладётся в файл
// рядом с auth.json (не в лог), затем меняется в самой консоли — до смены
// все остальные действия заблокированы.
// Парольная политика — та же, что у wazuh-passwords-tool: 8–64 символа,
// минимум одна заглавная, одна строчная, цифра и один из символов .*+?-
// Дополнительно: TOTP (RFC 6238) как второй фактор — у каждого локального
// пользователя свой секрет; отзыв сессий — через tokenVersion пользователя.
import { promises as fs } from "fs";
import path from "path";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import { SignJWT, jwtVerify } from "jose";
import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { generateTotpSecret, verifyTotp } from "./totp";
import { safeNextPath } from "./shared/next-path";
import { audit, saveTriageRevocation, triageRevocations } from "./argus-queries";
import { isEntityKind, TRIAGE_ENTITIES_MAX, TRIAGE_ENTITY_MAX_LEN, TRIAGE_RELATIONS, TRIAGE_SESSION_REQUESTS, TRIAGE_TTL_MAX_SEC, type TriageBinding, type TriageEntity, type TriageRelation, type TriageScope } from "./shared/triage";

const AUTH_FILE = path.resolve(/*turbopackIgnore: true*/ process.env.AUTH_FILE ?? "./.auth.json");
/** Стартовый пароль admin: файл 0600 рядом с auth.json, удаляется при первой смене. */
export const ADMIN_PASSWORD_FILE = path.join(path.dirname(AUTH_FILE), "admin-password.txt");
const SESSION_COOKIE = "wazuh_console_session";
const LOGIN_TOTP_COOKIE = "wazuh_console_login_totp";
const SESSION_TTL_SEC = 12 * 60 * 60;
const LOGIN_TOTP_TTL_SEC = 5 * 60;
/** SSO-сессия короче: роль приходит из групп IdP и должна пересматриваться чаще. */
const SSO_SESSION_TTL_SEC = 60 * 60;
// Имена SSO-пользователей живут в своём пространстве: `sso:i.petrov`
// никогда не совпадёт с локальным `i.petrov` или встроенным admin.
import { SSO_PREFIX } from "./oidc";
export { SSO_PREFIX };

export const ADMIN_USER = "admin";

import "server-only";
import { ROLE_RANK, ROLE_LABELS, isRole, type Role } from "./shared/incidents";
export { ROLE_RANK, ROLE_LABELS, isRole, type Role };

/** Отказ по роли. digest читает error.tsx (в проде текст ошибки вырезается),
 *  чтобы показать «недостаточно прав», а не общий сбой. */
export class ForbiddenError extends Error {
  digest = "FORBIDDEN";
  constructor(message = "Недостаточно прав") {
    super(message);
    this.name = "ForbiddenError";
  }
}

export type ConsoleUser = {
  name: string;
  passwordHash: string;
  role: Role;
  createdAt: string;
  totpSecret?: string | null;
  totpPendingSecret?: string | null;
  /** Версия сессий: инкремент отзывает все выданные JWT этого пользователя. */
  tokenVersion?: number;
};

type AuthState = {
  user: string;
  passwordHash: string;
  sessionSecret: string;
  generatedAt: string;
  passwordChanged: boolean;
  // TOTP встроенного admin — поля на корне ради совместимости со старым auth.json.
  totpSecret?: string | null;
  totpPendingSecret?: string | null;
  tokenVersion?: number;
  // Дополнительные пользователи с ролями (admin — встроенный, всегда есть).
  users?: ConsoleUser[];
};

const PASSWORD_SYMBOLS = ".*+?-";

export function validatePasswordPolicy(password: string): string | null {
  if (password.length < 8 || password.length > 64) {
    return "Пароль должен быть длиной от 8 до 64 символов";
  }
  if (!/[A-Z]/.test(password)) return "Нужна хотя бы одна заглавная буква";
  if (!/[a-z]/.test(password)) return "Нужна хотя бы одна строчная буква";
  if (!/[0-9]/.test(password)) return "Нужна хотя бы одна цифра";
  if (![...PASSWORD_SYMBOLS].some((s) => password.includes(s))) {
    return `Нужен хотя бы один символ из: ${PASSWORD_SYMBOLS}`;
  }
  return null;
}

function generatePassword(): string {
  // Гарантируем все классы символов из документированной политики.
  const upper = "ABCDEFGHJKMNPQRSTUVWXYZ";
  const lower = "abcdefghjkmnpqrstuvwxyz";
  const digits = "23456789";
  const all = upper + lower + digits + PASSWORD_SYMBOLS;
  const pick = (set: string) => set[crypto.randomInt(set.length)];
  const chars = [
    pick(upper),
    pick(lower),
    pick(digits),
    pick(PASSWORD_SYMBOLS),
    ...Array.from({ length: 12 }, () => pick(all)),
  ];
  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}

let statePromise: Promise<AuthState> | null = null;

async function loadOrInit(): Promise<AuthState> {
  try {
    const raw = await fs.readFile(AUTH_FILE, "utf8");
    return JSON.parse(raw) as AuthState;
  } catch (err) {
    // Пересоздаём состояние ТОЛЬКО если файла нет. Битый JSON или ошибка
    // тома — повод упасть громко, а не молча сбросить пароль администратора.
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    const password = generatePassword();
    const state: AuthState = {
      user: ADMIN_USER,
      passwordHash: await bcrypt.hash(password, 12),
      sessionSecret: crypto.randomBytes(32).toString("hex"),
      generatedAt: new Date().toISOString(),
      passwordChanged: false,
      totpSecret: null,
      totpPendingSecret: null,
      tokenVersion: 0,
      users: [],
    };
    await fs.mkdir(path.dirname(AUTH_FILE), { recursive: true });
    await fs.writeFile(AUTH_FILE, JSON.stringify(state, null, 2), { mode: 0o600 });
    // Пароль — в файл с правами 0600, в лог только его путь: логи контейнера
    // читают все, у кого есть docker, и они уезжают в сборщики логов.
    await fs.writeFile(ADMIN_PASSWORD_FILE, password + "\n", { mode: 0o600 });
    console.log("INFO: --- Summary ---");
    console.log(`INFO:    User: ${ADMIN_USER}`);
    console.log(`INFO:    Пароль admin — в файле ${ADMIN_PASSWORD_FILE} (удалится после первой смены пароля)`);
    return state;
  }
}

export function getAuthState(): Promise<AuthState> {
  statePromise ??= loadOrInit();
  return statePromise;
}

// Все изменения auth.json идут через одну очередь: параллельные server
// actions (создать юзера + включить TOTP) иначе читали бы одно состояние
// и последний записавший стирал бы чужие правки.
let writeQueue: Promise<unknown> = Promise.resolve();

async function writeAtomic(updated: AuthState): Promise<void> {
  const tmp = `${AUTH_FILE}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(updated, null, 2), { mode: 0o600 });
  await fs.rename(tmp, AUTH_FILE); // rename атомарен: либо старый файл, либо новый
  statePromise = Promise.resolve(updated);
}

/** Прочитать состояние, применить изменение, записать — атомарно относительно
 *  других вызовов mutateState. fn возвращает новое состояние или null (без записи). */
async function mutateState<T>(fn: (state: AuthState) => Promise<{ next: AuthState | null; result: T }>): Promise<T> {
  const run = async () => {
    const state = await getAuthState();
    const { next, result } = await fn(state);
    if (next) await writeAtomic(next);
    return result;
  };
  const job = writeQueue.then(run, run);
  writeQueue = job.catch(() => undefined);
  return job;
}

/* ===== Единая модель пользователя: встроенный admin (поля на корне auth.json)
   и именованные пользователи из users[] читаются/пишутся одними функциями. ===== */

type UserRecord = {
  name: string;
  role: Role;
  passwordHash: string;
  totpSecret: string | null;
  totpPendingSecret: string | null;
  tokenVersion: number;
  builtin: boolean;
};

function findUser(state: AuthState, name: string): UserRecord | null {
  if (name === state.user) {
    return {
      name, role: "admin", passwordHash: state.passwordHash, builtin: true,
      totpSecret: state.totpSecret ?? null, totpPendingSecret: state.totpPendingSecret ?? null,
      tokenVersion: state.tokenVersion ?? 0,
    };
  }
  const u = (state.users ?? []).find((x) => x.name === name);
  if (!u) return null;
  return {
    name, role: u.role, passwordHash: u.passwordHash, builtin: false,
    totpSecret: u.totpSecret ?? null, totpPendingSecret: u.totpPendingSecret ?? null,
    tokenVersion: u.tokenVersion ?? 0,
  };
}

type UserPatch = Partial<Pick<UserRecord, "passwordHash" | "totpSecret" | "totpPendingSecret" | "tokenVersion">>;

function patchUser(state: AuthState, name: string, patch: UserPatch): AuthState {
  if (name === state.user) return { ...state, ...patch };
  return { ...state, users: (state.users ?? []).map((u) => (u.name === name ? { ...u, ...patch } : u)) };
}

/* ===== Rate limiting логина: скользящее окно в памяти процесса,
   отдельно на пару «адрес клиента + имя пользователя» и отдельно на адрес.
   Глобальный счётчик позволял одному боту заблокировать вход всем. ===== */
const LOGIN_WINDOW_MS = 5 * 60 * 1000;
const LOGIN_MAX_FAILURES = 10;
const LOGIN_MAX_PER_IP = 30;
/** Потолок ключей: перебор имён с одного адреса плодит ключ на каждое имя. */
const LOGIN_MAX_KEYS = 50_000;
const LOGIN_SWEEP_EVERY = 100;
const loginFailures = new Map<string, number[]>();
let loginFailureWrites = 0;

/** Убрать ключи, у которых все метки старше окна; при переполнении — самые старые записи. */
function sweepLoginFailures(now: number): void {
  const cutoff = now - LOGIN_WINDOW_MS;
  for (const [key, marks] of loginFailures) {
    if (!marks.some((t) => t > cutoff)) loginFailures.delete(key);
  }
  for (const key of loginFailures.keys()) {
    if (loginFailures.size < LOGIN_MAX_KEYS) break;
    loginFailures.delete(key); // Map хранит порядок вставки: первые — самые старые
  }
}

/** Число ключей лимитера (для тестов и диагностики). */
export function loginFailureKeyCount(): number {
  return loginFailures.size;
}

/** Адрес клиента. X-Forwarded-For подставляет любой клиент, поэтому ему
 *  верим только за доверенным прокси: compose ставит консоль за Caddy и
 *  выставляет TRUSTED_PROXY=1. Без него берём x-real-ip (его выставляет
 *  только прокси) либо «unknown» — тогда лимит общий на всех прямых клиентов. */
async function clientIp(): Promise<string> {
  const h = await headers();
  if (process.env.TRUSTED_PROXY === "1") {
    const fwd = h.get("x-forwarded-for")?.split(",")[0]?.trim();
    if (fwd) return fwd;
  }
  return h.get("x-real-ip") || "unknown";
}

function recentFailures(key: string, now: number): number[] {
  const cutoff = now - LOGIN_WINDOW_MS;
  const kept = (loginFailures.get(key) ?? []).filter((t) => t > cutoff);
  if (kept.length) loginFailures.set(key, kept);
  else loginFailures.delete(key);
  return kept;
}

export async function loginThrottled(user: string, now = Date.now()): Promise<boolean> {
  const ip = await clientIp();
  return (
    recentFailures(`${ip}|${user}`, now).length >= LOGIN_MAX_FAILURES ||
    recentFailures(ip, now).length >= LOGIN_MAX_PER_IP
  );
}

export async function recordLoginFailure(user: string, now = Date.now()): Promise<void> {
  const ip = await clientIp();
  // Чистка — раз в LOGIN_SWEEP_EVERY записей, не на каждую: полный обход
  // карты на каждом неудачном входе под перебором стоил бы дороже самой проверки.
  if (++loginFailureWrites % LOGIN_SWEEP_EVERY === 0) sweepLoginFailures(now);
  for (const key of [`${ip}|${user}`, ip]) {
    if (!loginFailures.has(key) && loginFailures.size >= LOGIN_MAX_KEYS) sweepLoginFailures(now);
    loginFailures.set(key, [...recentFailures(key, now), now]);
  }
}

/* ===== Лимит неудачных TOTP — по имени пользователя, не по адресу: код
   подбирается против конкретного секрета, и смена IP не должна помогать.
   5 подряд → блок 15 минут, каждый следующий блок вдвое длиннее. Счётчик
   блоков затухает: если с конца последнего блока прошло больше двух его
   длин, история забывается — иначе легитимный пользователь, раз ошибившийся
   месяц назад, получал бы сразу длинный блок. ===== */
const TOTP_MAX_FAILURES = 5;
const TOTP_LOCK_BASE_MS = 15 * 60 * 1000;
const TOTP_LOCK_MAX_MS = 24 * 60 * 60 * 1000;
type TotpLock = { fails: number; lockedUntil: number; locks: number; lockMs: number };
const totpFailures = new Map<string, TotpLock>();

/** Сколько мс до снятия блокировки TOTP; 0 — не заблокирован. */
export function totpLockRemainingMs(user: string, now = Date.now()): number {
  const e = totpFailures.get(user);
  return e && e.lockedUntil > now ? e.lockedUntil - now : 0;
}

/** Результат: locked — эта неудача включила блок; locks — его порядковый номер; lockMs — длина. */
export function recordTotpFailure(user: string, now = Date.now()): { locked: boolean; locks: number; lockMs: number } {
  let e = totpFailures.get(user) ?? { fails: 0, lockedUntil: 0, locks: 0, lockMs: 0 };
  if (e.locks > 0 && now - e.lockedUntil > 2 * e.lockMs) e = { fails: 0, lockedUntil: 0, locks: 0, lockMs: 0 };
  e.fails += 1;
  let locked = false;
  if (e.fails >= TOTP_MAX_FAILURES) {
    e.lockMs = Math.min(TOTP_LOCK_MAX_MS, TOTP_LOCK_BASE_MS * 2 ** e.locks);
    e.lockedUntil = now + e.lockMs;
    e.locks += 1;
    e.fails = 0;
    locked = true;
  }
  totpFailures.set(user, e);
  return { locked, locks: e.locks, lockMs: e.lockMs };
}

export function clearTotpFailures(user: string): void {
  totpFailures.delete(user);
}

/* ===== Лимит запросов к /api/*: token bucket в памяти на ключ
   (пользователь сессии или bearer-токен). ===== */
const buckets = new Map<string, { tokens: number; updatedAt: number }>();

/** true — запрос пропускаем; retryAfterSec — сколько ждать при отказе. */
export function rateLimit(key: string, limitPerWindow: number, windowMs = 60_000, now = Date.now()): { ok: boolean; retryAfterSec: number } {
  const b = buckets.get(key) ?? { tokens: limitPerWindow, updatedAt: now };
  const refill = ((now - b.updatedAt) / windowMs) * limitPerWindow;
  b.tokens = Math.min(limitPerWindow, b.tokens + Math.max(0, refill));
  b.updatedAt = now;
  if (b.tokens >= 1) {
    b.tokens -= 1;
    buckets.set(key, b);
    return { ok: true, retryAfterSec: 0 };
  }
  buckets.set(key, b);
  const perToken = windowMs / limitPerWindow;
  return { ok: false, retryAfterSec: Math.max(1, Math.ceil(((1 - b.tokens) * perToken) / 1000)) };
}

// Фиксированная стоимость проверки: bcrypt всегда выполняется, даже если
// имя пользователя не совпало (иначе тайминг выдаёт валидные имена).
const DUMMY_HASH = bcrypt.hashSync("dummy-timing-equalizer", 12);

/** Проверка пароля; возвращает роль пользователя или null. */
export async function verifyCredentials(user: string, password: string): Promise<Role | null> {
  const state = await getAuthState();
  const u = findUser(state, user);
  const ok = await bcrypt.compare(password, u?.passwordHash ?? DUMMY_HASH); // bcrypt всегда выполняется
  return ok && u ? u.role : null;
}

/* ===== Пользователи и роли (управляет admin) ===== */

export type UserInfo = { name: string; role: Role; createdAt: string; totp: boolean; builtin: boolean };

export async function listUsers(): Promise<UserInfo[]> {
  const state = await getAuthState();
  return [
    { name: state.user, role: "admin", createdAt: state.generatedAt, totp: Boolean(state.totpSecret), builtin: true },
    ...(state.users ?? []).map((u) => ({ name: u.name, role: u.role, createdAt: u.createdAt, totp: Boolean(u.totpSecret), builtin: false })),
  ];
}

const USER_NAME_RE = /^[a-z0-9._-]{2,32}$/;

/** Создаёт пользователя, возвращает сгенерированный пароль (показывается один раз). */
export async function createUser(name: string, role: Role): Promise<{ password: string } | { error: string }> {
  if (!USER_NAME_RE.test(name)) {
    return { error: "Имя: 2–32 символа, латиница, цифры, . _ -" };
  }
  if (!isRole(role)) return { error: "Неизвестная роль" };
  type Result = { password: string } | { error: string };
  return mutateState<Result>(async (state) => {
    if (findUser(state, name)) {
      return { next: null, result: { error: "Пользователь с таким именем уже есть" } };
    }
    const password = generatePassword();
    const users = [...(state.users ?? []), {
      name, role, createdAt: new Date().toISOString(), passwordHash: await bcrypt.hash(password, 12),
      totpSecret: null, totpPendingSecret: null, tokenVersion: 0,
    }];
    return { next: { ...state, users }, result: { password } };
  });
}

/** Удаление пользователя. Нельзя: себя, встроенного admin и последнего
 *  именованного администратора. Встроенный admin в счёт не идёт: это
 *  break-glass-учётка со стартовым паролем в файле, а не рабочий администратор. */
export async function deleteUser(name: string, by: string): Promise<string | null> {
  return mutateState(async (state) => {
    if (name === by) return { next: null, result: "Нельзя удалить самого себя" };
    if (name === state.user) return { next: null, result: "Встроенного администратора удалить нельзя" };
    const all = state.users ?? [];
    const victim = all.find((u) => u.name === name);
    if (!victim) return { next: null, result: "Пользователь не найден" };
    if (victim.role === "admin" && all.filter((u) => u.role === "admin").length <= 1) {
      return { next: null, result: "Это последний администратор — сначала назначьте другого" };
    }
    return { next: { ...state, users: all.filter((u) => u.name !== name) }, result: null };
  });
}

/** Смена своего пароля по текущему. Инкремент tokenVersion отзывает все
 *  сессии этого пользователя (украденный JWT перестаёт действовать), чужие
 *  сессии не трогаются. Для admin снимает принудительную смену и удаляет файл
 *  со стартовым паролем. */
export async function changePassword(user: string, current: string, next: string): Promise<string | null> {
  const policyError = validatePasswordPolicy(next);
  if (policyError) return policyError;
  return mutateState(async (state) => {
    const u = findUser(state, user);
    if (!u || !(await bcrypt.compare(current, u.passwordHash))) {
      return { next: null, result: "Текущий пароль неверен" };
    }
    let updated = patchUser(state, user, { passwordHash: await bcrypt.hash(next, 12), tokenVersion: u.tokenVersion + 1 });
    if (u.builtin) {
      updated = { ...updated, passwordChanged: true };
      await fs.rm(ADMIN_PASSWORD_FILE, { force: true }).catch(() => undefined);
    }
    return { next: updated, result: null };
  });
}

/** Сброс пароля другому пользователю администратором: новый пароль
 *  показывается один раз, старые сессии пользователя отзываются. */
export async function resetUserPassword(name: string, by: string): Promise<{ password: string } | { error: string }> {
  type Result = { password: string } | { error: string };
  return mutateState<Result>(async (state) => {
    if (name === by) return { next: null, result: { error: "Свой пароль меняется через «Смена пароля»" } };
    const u = findUser(state, name);
    if (!u) return { next: null, result: { error: "Пользователь не найден" } };
    if (u.builtin) return { next: null, result: { error: "Пароль встроенного admin меняет только он сам" } };
    const password = generatePassword();
    const next = patchUser(state, name, { passwordHash: await bcrypt.hash(password, 12), tokenVersion: u.tokenVersion + 1 });
    return { next, result: { password } };
  });
}

/* ===== TOTP — per-user ===== */

export async function isTotpEnabled(user: string): Promise<boolean> {
  const state = await getAuthState();
  return Boolean(findUser(state, user)?.totpSecret);
}

export async function verifyLoginTotp(user: string, code: string): Promise<"ok" | "required" | "invalid" | "locked"> {
  const state = await getAuthState();
  const secret = findUser(state, user)?.totpSecret;
  if (!secret) return "ok";
  if (totpLockRemainingMs(user) > 0) return "locked";
  if (!code) return "required";
  if (verifyTotp(secret, code)) {
    clearTotpFailures(user);
    return "ok";
  }
  const r = recordTotpFailure(user);
  // Первый блок — в журнал: пять неверных кодов подряд — это либо подбор,
  // либо рассинхрон часов у пользователя; обе причины стоит увидеть.
  if (r.locked && r.locks === 1) {
    await audit(user, "session.totp.lock", user, `${TOTP_MAX_FAILURES} неверных кодов подряд · блок ${Math.round(r.lockMs / 60000)} мин`);
  }
  return "invalid";
}

export async function beginTotpEnrollment(user: string): Promise<{ secret: string } | { error: string }> {
  type Result = { secret: string } | { error: string };
  return mutateState<Result>(async (state) => {
    if (!findUser(state, user)) return { next: null, result: { error: "Пользователь не найден" } };
    const secret = generateTotpSecret();
    return { next: patchUser(state, user, { totpPendingSecret: secret }), result: { secret } };
  });
}

export async function confirmTotpEnrollment(user: string, code: string): Promise<string | null> {
  return mutateState(async (state) => {
    const u = findUser(state, user);
    if (!u) return { next: null, result: "Пользователь не найден" };
    if (!u.totpPendingSecret) return { next: null, result: "Сначала сгенерируйте секрет" };
    if (!verifyTotp(u.totpPendingSecret, code)) return { next: null, result: "Код не подошёл — проверьте приложение" };
    return { next: patchUser(state, user, { totpSecret: u.totpPendingSecret, totpPendingSecret: null }), result: null };
  });
}

/** Отключение 2FA требует и текущий пароль, и код: украденной сессии этого мало. */
export async function disableTotp(user: string, password: string, code: string): Promise<string | null> {
  return mutateState(async (state) => {
    const u = findUser(state, user);
    if (!u) return { next: null, result: "Пользователь не найден" };
    if (!u.totpSecret) return { next: null, result: "TOTP не включён" };
    if (!(await bcrypt.compare(password, u.passwordHash))) return { next: null, result: "Текущий пароль неверен" };
    if (!verifyTotp(u.totpSecret, code)) return { next: null, result: "Неверный код TOTP" };
    return { next: patchUser(state, user, { totpSecret: null, totpPendingSecret: null }), result: null };
  });
}

/* ===== Сессии ===== */

async function secretKey(): Promise<Uint8Array> {
  const state = await getAuthState();
  return new TextEncoder().encode(state.sessionSecret);
}

/** Отдельный ключ: challenge второго шага нельзя принять за JWT сессии. */
async function totpChallengeKey(): Promise<Uint8Array> {
  const state = await getAuthState();
  return crypto.createHmac("sha256", state.sessionSecret).update("login-totp-challenge").digest();
}

/** Отдельный ключ: токен triage-session нельзя принять за JWT сессии консоли и наоборот. */
async function triageKey(): Promise<Uint8Array> {
  const state = await getAuthState();
  return crypto.createHmac("sha256", state.sessionSecret).update("triage-session").digest();
}

const TRIAGE_TYP = "triage-session";
const TRIAGE_AUD = "argus-triage";

/** Выпуск токена triage-session. Область считает вызывающий (lib/triage-queries),
 *  здесь — только подпись и потолки. */
export async function signTriageToken(input: {
  incidentId: string; related: Record<string, TriageRelation>; entities: TriageEntity[]; bind: TriageBinding; searchFrom: string; ttlSec: number;
}): Promise<{ token: string; scope: TriageScope }> {
  const ttl = Math.min(TRIAGE_TTL_MAX_SEC, Math.max(60, Math.floor(input.ttlSec) || TRIAGE_TTL_MAX_SEC));
  const sessionId = crypto.randomUUID();
  const exp = Math.floor(Date.now() / 1000) + ttl;
  const seen = new Set<string>();
  const entities: TriageEntity[] = [];
  for (const e of input.entities) {
    const value = e.value.trim();
    const key = `${e.kind}\u0000${value}`; // регистр значим, как в SQL
    if (!isEntityKind(e.kind) || !value || value.length > TRIAGE_ENTITY_MAX_LEN || seen.has(key)) continue;
    seen.add(key);
    entities.push({ kind: e.kind, value, ...(e.weak && { weak: true }) });
    if (entities.length >= TRIAGE_ENTITIES_MAX) break;
  }
  // Сущность в токене — [вид, значение] или [вид, значение, 1] (частая, только
  // в паре): якорем она служит только в полях своего вида (fieldEntityKind).
  // bd — привязка строк поиска (обязательный предикат, search.ts).
  const bind: TriageBinding = { actors: input.bind.actors.filter(Boolean), nodes: input.bind.nodes.filter(Boolean) };
  const token = await new SignJWT({ typ: TRIAGE_TYP, rel: input.related, ent: entities.map((e) => (e.weak ? [e.kind, e.value, 1] : [e.kind, e.value])), bd: bind, sf: input.searchFrom })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(input.incidentId)
    .setAudience(TRIAGE_AUD)
    .setJti(sessionId)
    .setIssuedAt()
    .setExpirationTime(exp)
    .sign(await triageKey());
  return { token, scope: { sessionId, incidentId: input.incidentId, related: input.related, entities, bind, searchFrom: input.searchFrom, expiresAt: new Date(exp * 1000).toISOString() } };
}

/** Отозванные сессии разбора (jti → срок токена, мс). Источник правды —
 *  argus.triage_session_revocations: список читается один раз на процесс и
 *  дальше ведётся в памяти, отзыв пишется в базу до того, как вступить в
 *  силу. Пока список не прочитан (ClickHouse недоступен), токены разбора не
 *  принимаются: отказ безопаснее, чем пропустить отозванный. */
let revokedTriage: Map<string, number> | null = null;
let revokedLoading: Promise<Map<string, number> | null> | null = null;

async function revokedSessions(): Promise<Map<string, number> | null> {
  if (revokedTriage) return revokedTriage;
  revokedLoading ??= triageRevocations()
    .then((m) => (revokedTriage = m))
    .catch((err) => {
      console.error("triage revocations:", err instanceof Error ? err.message : err);
      return null;
    })
    .finally(() => (revokedLoading = null));
  return revokedLoading;
}

/** Сбросить состояние сессий разбора в памяти — как после рестарта процесса (тесты). */
export function forgetTriageMemory(): void {
  revokedTriage = null;
  revokedLoading = null;
  triageUsage.clear();
}

export async function revokeTriageSession(scope: TriageScope): Promise<void> {
  await saveTriageRevocation(scope.sessionId, scope.incidentId, scope.expiresAt);
  (await revokedSessions())?.set(scope.sessionId, Date.parse(scope.expiresAt));
  triageUsage.delete(scope.sessionId);
}

export async function verifyTriageToken(token: string, now = Date.now()): Promise<TriageScope | null> {
  try {
    const { payload } = await jwtVerify(token, await triageKey(), { audience: TRIAGE_AUD, algorithms: ["HS256"] });
    const incidentId = String(payload.sub ?? "");
    const sessionId = String(payload.jti ?? "");
    if (payload.typ !== TRIAGE_TYP || !/^INC-\d{1,9}$/.test(incidentId) || !sessionId || !payload.exp) return null;
    // Срок — не больше часа от выпуска, даже если ключ подписал больший.
    if (!payload.iat || payload.exp - payload.iat > TRIAGE_TTL_MAX_SEC) return null;
    const revoked = await revokedSessions();
    if (!revoked) return null;
    for (const [id, until] of revoked) if (until < now) revoked.delete(id);
    if (revoked.has(sessionId)) return null;
    const rel = payload.rel && typeof payload.rel === "object" ? (payload.rel as Record<string, unknown>) : {};
    const related: Record<string, TriageRelation> = {};
    for (const [id, r] of Object.entries(rel)) {
      if (/^INC-\d{1,9}$/.test(id) && id !== incidentId && TRIAGE_RELATIONS.includes(r as TriageRelation)) related[id] = r as TriageRelation;
    }
    const entities: TriageEntity[] = Array.isArray(payload.ent)
      ? payload.ent.flatMap((e): TriageEntity[] => {
        if (!Array.isArray(e) || (e.length !== 2 && !(e.length === 3 && e[2] === 1)) || !isEntityKind(e[0]) || typeof e[1] !== "string") return [];
        return [{ kind: e[0], value: e[1], ...(e.length === 3 && { weak: true }) }];
      })
      : [];
    const searchFrom = typeof payload.sf === "string" && Number.isFinite(Date.parse(payload.sf)) ? payload.sf : new Date(now).toISOString();
    // Без привязки (bd) поиск не вернёт ни строки: предикат «0».
    const bd = payload.bd && typeof payload.bd === "object" ? (payload.bd as Record<string, unknown>) : {};
    const strings = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x !== "") : []);
    const bind: TriageBinding = { actors: strings(bd.actors), nodes: strings(bd.nodes) };
    return { sessionId, incidentId, related, entities, bind, searchFrom, expiresAt: new Date(payload.exp * 1000).toISOString() };
  } catch {
    return null;
  }
}

/** Вызывается только после успешной проверки пароля. */
export async function beginLoginTotp(user: string): Promise<void> {
  const state = await getAuthState();
  const u = findUser(state, user);
  if (!u?.totpSecret) throw new Error("TOTP не включён");
  const token = await new SignJWT({ purpose: "login-totp", tv: u.tokenVersion })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(user)
    .setIssuedAt()
    .setExpirationTime(`${LOGIN_TOTP_TTL_SEC}s`)
    .sign(await totpChallengeKey());
  (await cookies()).set(LOGIN_TOTP_COOKIE, token, {
    httpOnly: true, sameSite: "strict", secure: cookieSecure(),
    path: "/login", maxAge: LOGIN_TOTP_TTL_SEC,
  });
}

export async function pendingLoginTotp(): Promise<{ user: string; role: Role } | null> {
  const token = (await cookies()).get(LOGIN_TOTP_COOKIE)?.value;
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, await totpChallengeKey());
    if (payload.purpose !== "login-totp" || typeof payload.sub !== "string") return null;
    const state = await getAuthState();
    const u = findUser(state, payload.sub);
    if (!u?.totpSecret || Number(payload.tv) !== u.tokenVersion) return null;
    return { user: u.name, role: u.role };
  } catch {
    return null;
  }
}

export async function clearLoginTotp(): Promise<void> {
  (await cookies()).delete({ name: LOGIN_TOTP_COOKIE, path: "/login" });
}

/** Единое правило Secure для всех кук консоли (сессия, OIDC state):
 *  в проде — только по TLS; SESSION_SECURE=false — осознанный plain HTTP. */
export function cookieSecure(): boolean {
  if (process.env.SESSION_SECURE !== undefined) return process.env.SESSION_SECURE === "true";
  return process.env.NODE_ENV === "production";
}

/** Как аутентифицирован запрос: сессия консоли (кука), служебный bearer
 *  ARGUS_API_TOKEN, учётка triage-issuer или токен triage-session. Проверки
 *  прав опираются на kind, а не на имя пользователя: локальный viewer с
 *  логином api-token остаётся наблюдателем консоли. */
export type SessionKind = "console" | "api-token" | "issuer" | "triage-session";

export type Session = {
  kind: SessionKind;
  user: string;
  role: Role;
  sso: boolean;
  /** Встроенный admin со стартовым паролем: до смены разрешены только смена пароля и выход. */
  mustChangePassword: boolean;
  /** Токен triage-session: область чтения агента разбора (только API). */
  triage?: TriageScope;
  /** Служебная учётка triage-issuer: только выпуск triage-session. */
  issuer?: true;
};

/** JWT сессии. Локальный пользователь получает tv = его tokenVersion;
 *  SSO-пользователь — только с префиксом sso: и коротким TTL. */
export async function signSessionToken(user: string, role: Role, sso: boolean): Promise<string> {
  const state = await getAuthState();
  let tv = 0;
  if (sso) {
    if (!user.startsWith(SSO_PREFIX)) throw new Error("SSO-пользователь должен иметь префикс sso:");
  } else {
    const u = findUser(state, user);
    if (!u) throw new Error("Пользователь не найден");
    tv = u.tokenVersion;
  }
  return new SignJWT({ sub: user, role, sso, tv })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(`${sso ? SSO_SESSION_TTL_SEC : SESSION_TTL_SEC}s`)
    .sign(await secretKey());
}

/** Сессия из токена или null. Роль и существование локального пользователя
 *  берутся из текущего состояния, а не из JWT: удалённый или пониженный в
 *  правах пользователь теряет доступ сразу; tv сверяется с tokenVersion —
 *  смена пароля отзывает выданные токены. SSO-ветка — только для payload.sso
 *  с именем в пространстве sso:, роль — из групп IdP, зафиксированных в токене. */
export async function verifySessionToken(token: string): Promise<Session | null> {
  try {
    const { payload } = await jwtVerify(token, await secretKey());
    const user = String(payload.sub ?? "");
    if (!user) return null;
    if (payload.sso === true) {
      if (!user.startsWith(SSO_PREFIX) || !isRole(payload.role)) return null;
      return { kind: "console", user, role: payload.role, sso: true, mustChangePassword: false };
    }
    if (user.startsWith(SSO_PREFIX)) return null;
    const state = await getAuthState();
    const u = findUser(state, user);
    if (!u) return null;
    if (Number(payload.tv ?? 0) !== u.tokenVersion) return null;
    return { kind: "console", user, role: u.role, sso: false, mustChangePassword: u.builtin && !state.passwordChanged };
  } catch {
    return null;
  }
}

export async function createSession(user: string = ADMIN_USER, role: Role = "admin", sso = false): Promise<void> {
  const token = await signSessionToken(user, role, sso);
  const jar = await cookies();
  jar.set(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: "strict",
    secure: cookieSecure(),
    path: "/",
    maxAge: sso ? SSO_SESSION_TTL_SEC : SESSION_TTL_SEC,
  });
}

export async function destroySession(): Promise<void> {
  const jar = await cookies();
  jar.delete(SESSION_COOKIE);
}

/** Текущая сессия или null. */
export async function getSession(): Promise<Session | null> {
  const jar = await cookies();
  const token = jar.get(SESSION_COOKIE)?.value;
  if (!token) return null;
  return verifySessionToken(token);
}

/** Гард для каждой страницы консоли: layout Next.js обходится крафтовым
 *  RSC-запросом к сегменту, поэтому проверка в layout — не защита.
 *  Пока admin не сменил стартовый пароль, любая страница ведёт на смену —
 *  кроме самой страницы настроек (allowPasswordChange). */
/** Текущий путь запроса для возврата после входа: берём из заголовка,
 *  который выставляет proxy.ts (x-argus-path); без него — "/". */
async function currentPath(): Promise<string> {
  try {
    const h = await headers();
    return h.get("x-argus-path") ?? "/";
  } catch {
    return "/";
  }
}

export function loginUrlWithNext(path: string): string {
  const next = safeNextPath(path);
  return next === "/" ? "/login" : `/login?next=${encodeURIComponent(next)}`;
}

export async function requirePageSession(opts: { allowPasswordChange?: boolean } = {}): Promise<Session> {
  const s = await getSession();
  if (!s) redirect(loginUrlWithNext(await currentPath()));
  if (s.mustChangePassword && !opts.allowPasswordChange) redirect("/settings?force=1");
  return s;
}

export const MUST_CHANGE_PASSWORD_MSG = "Сначала смените стартовый пароль администратора (Настройки)";

/** Сессия для API-маршрутов: кука консоли ИЛИ bearer-токен ARGUS_API_TOKEN
 *  (для MCP-сервера и скриптов). Токен даёт только чтение — роль наблюдателя.
 *  Токен короче 32 символов не принимается вовсе — короткий секрет перебираем. */
export const API_TOKEN_MIN_LENGTH = 32;

export function bearerTokenValid(given: string, configured: string | undefined, minLength = API_TOKEN_MIN_LENGTH): boolean {
  const token = configured ?? "";
  if (given.length < minLength || token.length < minLength) return false;
  // Сравниваем хэши: длина одинаковая всегда, тайминг не выдаёт длину токена.
  const a = crypto.createHash("sha256").update(given).digest();
  const b = crypto.createHash("sha256").update(token).digest();
  return crypto.timingSafeEqual(a, b);
}

/** Похоже на JWT (три части base64url): такие bearer проверяются как triage-session. */
const JWT_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

/** Токен учётки triage-issuer: задан, достаточно длинный и не совпадает с
 *  ARGUS_API_TOKEN (иначе любой держатель API-токена выпускал бы сессии). */
function issuerTokenValid(given: string): boolean {
  const issuer = process.env.ARGUS_TRIAGE_ISSUER_TOKEN;
  if (!issuer || issuer === process.env.ARGUS_API_TOKEN) return false;
  return bearerTokenValid(given, issuer);
}

export async function apiSession(req: Request): Promise<Session | null> {
  const auth = req.headers.get("authorization") ?? "";
  if (auth.startsWith("Bearer ")) {
    const given = auth.slice(7).trim();
    const triage = JWT_RE.test(given) ? await verifyTriageToken(given) : null;
    if (triage) return { kind: "triage-session", user: `triage:${triage.sessionId}`, role: "viewer", sso: false, mustChangePassword: false, triage };
    if (issuerTokenValid(given)) {
      return { kind: "issuer", user: "triage-issuer", role: "viewer", sso: false, mustChangePassword: false, issuer: true };
    }
    if (bearerTokenValid(given, process.env.ARGUS_API_TOKEN)) {
      return { kind: "api-token", user: "api-token", role: "viewer", sso: false, mustChangePassword: false };
    }
    return null;
  }
  const s = await getSession();
  return s && !s.mustChangePassword ? s : null;
}

/** Лимиты /api/*: 60 запросов в минуту на сессию/токен, экспорт — 5. */
export const API_RATE = { default: 60, export: 5, tail: 120 } as const;

/** Запросов за сессию разбора: ARGUS_TRIAGE_SESSION_REQUESTS или 100. */
export function triageSessionBudget(): number {
  const n = Number(process.env.ARGUS_TRIAGE_SESSION_REQUESTS);
  return Number.isInteger(n) && n > 0 ? n : TRIAGE_SESSION_REQUESTS;
}

/** Счётчик запросов сессий разбора: jti → { сколько, до какого срока }. */
const triageUsage = new Map<string, { used: number; until: number }>();

/** Сколько запросов осталось у сессии разбора (без учёта текущего). */
export function triageRequestsLeft(scope: TriageScope): number {
  return Math.max(0, triageSessionBudget() - (triageUsage.get(scope.sessionId)?.used ?? 0));
}

function chargeTriage(scope: TriageScope, now: number): boolean {
  for (const [id, u] of triageUsage) if (u.until < now) triageUsage.delete(id);
  const u = triageUsage.get(scope.sessionId) ?? { used: 0, until: Date.parse(scope.expiresAt) };
  if (u.used >= triageSessionBudget()) return false;
  u.used++;
  triageUsage.set(scope.sessionId, u);
  return true;
}

/** Отказ вне области сессии разбора — один формат во всех маршрутах. */
export function outOfScope(detail = "вне области сессии разбора"): Response {
  return Response.json({ error: "out_of_scope", detail }, { status: 403 });
}

export type ApiGuardOptions = {
  /** Маршрут сам проверяет область triage-session (иначе такой токен — 403). */
  triage?: boolean;
  /** Не тратить бюджет сессии разбора: закрытие сессии должно пройти и
   *  после исчерпания лимита. Лимит в минуту действует. */
  uncharged?: boolean;
  /** Маршрут только для triage-issuer (выпуск сессий). */
  issuer?: boolean;
};

/** Общий вход API-маршрутов: 401 без сессии, 429 при превышении лимита.
 *  Токены triage-session и triage-issuer пускаются только туда, где это
 *  явно разрешено: новый маршрут по умолчанию им закрыт. */
export async function apiGuard(req: Request, kind: keyof typeof API_RATE = "default", opts: ApiGuardOptions = {}): Promise<{ session: Session; response?: undefined } | { session?: undefined; response: Response }> {
  const session = await apiSession(req);
  if (!session) return { response: Response.json({ error: "нужна сессия или bearer-токен" }, { status: 401 }) };
  if (!!opts.issuer !== !!session.issuer) return { response: outOfScope(session.issuer ? "учётка выпускает только сессии разбора" : "только для triage-issuer") };
  if (session.triage) {
    if (!opts.triage || kind === "export") return { response: outOfScope() };
    // Свой бакет у каждой сессии: агенты не делят лимит общего ARGUS_API_TOKEN.
    if (!opts.uncharged && !chargeTriage(session.triage, Date.now())) {
      return { response: Response.json({ error: "budget_exhausted", detail: "лимит запросов сессии разбора исчерпан" }, { status: 429 }) };
    }
  }
  const rl = rateLimit(`${kind}|${session.triage ? "triage" : session.sso ? "sso" : "local"}|${session.user}`, API_RATE[kind]);
  if (!rl.ok) {
    return { response: Response.json({ error: "слишком много запросов" }, { status: 429, headers: { "Retry-After": String(rl.retryAfterSec) } }) };
  }
  return { session };
}

export async function isAuthenticated(): Promise<boolean> {
  return (await getSession()) !== null;
}

/** Гард роли для server actions без FormState: бросает ForbiddenError
 *  (digest FORBIDDEN — error.tsx покажет «недостаточно прав»). */
export async function requireRole(min: Role): Promise<Session> {
  const s = await getSession();
  if (!s) redirect("/login");
  if (s.mustChangePassword) throw new ForbiddenError(MUST_CHANGE_PASSWORD_MSG);
  if (ROLE_RANK[s.role] < ROLE_RANK[min]) {
    throw new ForbiddenError(`Недостаточно прав: нужна роль «${ROLE_LABELS[min]}»`);
  }
  return s;
}

/** То же для actions с FormState: отказ возвращается как { error }, а не
 *  бросается — в проде error.tsx текст исключений вырезает. */
export type Authorized = { ok: true; session: Session } | { ok: false; error: string };

export async function authorize(min: Role): Promise<Authorized> {
  const s = await getSession();
  if (!s) redirect("/login");
  if (s.mustChangePassword) return { ok: false, error: MUST_CHANGE_PASSWORD_MSG };
  if (ROLE_RANK[s.role] < ROLE_RANK[min]) return { ok: false, error: `Недостаточно прав: нужна роль «${ROLE_LABELS[min]}»` };
  return { ok: true, session: s };
}
