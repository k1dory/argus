// Человеческие подписи событий единой схемы: действие → фраза, исход → слово,
// вид события (для иконки строки). Сырые значения остаются второй строкой и
// в детали — словарь только помогает прочитать ленту, а не прячет данные.
// Чистые функции — общие для журнала, поиска и тестов.

import { SEVERITY, type SeverityThresholds } from "./severity";

type Phrase = string | { ok?: string; fail?: string; any: string };

/** Частые действия коллекторов и движка. Нет в словаре — показывается action как есть. */
export const ACTION_LABELS: Record<string, Phrase> = {
  "auth.login": { ok: "Вход в систему", fail: "Неудачный вход", any: "Вход в систему" },
  "auth.ssh": { ok: "Вход по SSH", fail: "Неудачный вход по SSH", any: "Вход по SSH" },
  "auth.otp": { ok: "Подтверждён одноразовый код", fail: "Неверный одноразовый код", any: "Проверка одноразового кода" },
  login: { ok: "Вход в систему", fail: "Неудачный вход", any: "Вход в систему" },
  "auth.logout": "Выход из системы",
  "login.fail": "Неудачный вход",
  "app.authorize": { ok: "Вход в приложение через IdP", fail: "Отказ во входе в приложение", any: "Вход в приложение через IdP" },
  "priv.sudo": { ok: "Команда через sudo", fail: "Отказ в sudo", any: "Команда через sudo" },
  "user.change": "Изменена учётная запись",
  flow: { ok: "Сетевое соединение", fail: "Соединение заблокировано", any: "Сетевое соединение" },
  "net.firewall": { ok: "Соединение через межсетевой экран", fail: "Соединение заблокировано экраном", any: "Срабатывание межсетевого экрана" },
  "session.allow": "Сеанс разрешён",
  "proxy.access": { ok: "Запрос через прокси", fail: "Запрос через прокси заблокирован", any: "Запрос через прокси" },
  "event.dns": "DNS-запрос",
  "file.read": "Чтение файла",
  "file.delete": "Удаление файла",
  "file.rename": "Переименование файла",
  "http.attack": "Атака на веб-приложение",
  "threat.detect": "Обнаружена угроза",
  "threat.incident": "Инцидент у внешнего детектора",
  "disk.usage": "Заполнение диска",
  "sandbox.egress": "Исходящее соединение из песочницы",
  "sandbox.api": "Обращение к API песочницы",
  "identity.alias": "Привязан псевдоним учётной записи",
  "identity.alias.revoke": "Отвязан псевдоним учётной записи",
  "identity.policy.violation": "Нарушение политики учётных записей",
  "config.update": "Изменена конфигурация",
  "engine.started": "Движок запущен",
  "engine.stopped": "Движок остановлен",
  "engine.restarted": "Движок перезапущен",
  "collector.sink_recovered": "Доставка событий восстановлена",
  "collector.sink_stalled": "Доставка событий остановилась",
  "collector.clock_skew": "Часы источника расходятся",
  "rules.rejected": "Правила корреляции отклонены",
  "vm.start": "Запуск виртуальной машины",
  "vm.delete": "Удаление виртуальной машины",
  "pve.api.write": "Изменение через API Proxmox",
  "iam.key.create": "Создан ключ доступа",
  "repo.push": "Отправка в репозиторий",
  "gitlab.project_access_token_created": "Создан токен проекта GitLab",
  "gitlab.project_access_token_rotated": "Перевыпущен токен проекта GitLab",
  "gitlab.project_access_token_revoked": "Отозван токен проекта GitLab",
};

const FAIL = new Set(["failure", "deny", "denied", "blocked", "block", "drop", "reject", "detected"]);
const OK = new Set(["success", "allow", "allowed", "accept", "pass"]);

export const OUTCOME_WORDS: Record<string, string> = {
  success: "успех",
  failure: "неудача",
  allow: "разрешено",
  deny: "запрещено",
  detected: "обнаружено",
  blocked: "заблокировано",
};

/** Исход «плохой» (отказ, блок, обнаружение) — для красного бейджа. */
export const isBadOutcome = (outcome: string): boolean => FAIL.has(outcome.toLowerCase());

/** Слово исхода по-русски или как пришло; unknown и пусто — пустая строка. */
export function outcomeWord(outcome: string): string {
  const o = outcome.toLowerCase();
  if (!o || o === "unknown") return "";
  return OUTCOME_WORDS[o] ?? outcome;
}

/**
 * Заголовок строки ленты: фраза из словаря с учётом исхода; rule.<N> —
 * «Правило Wazuh N»; k8s.<глагол>.<ресурс> — «Kubernetes: …». Без фразы —
 * сам action (known=false), а пустой action — «Событие без действия».
 */
export function actionTitle(action: string, outcome = ""): { title: string; known: boolean } {
  const a = action.trim();
  if (!a || a === "x") return { title: "Событие без действия", known: true };
  const p = ACTION_LABELS[a] ?? ACTION_LABELS[a.toLowerCase()];
  if (p) {
    if (typeof p === "string") return { title: p, known: true };
    const o = outcome.toLowerCase();
    return { title: (FAIL.has(o) ? p.fail : OK.has(o) ? p.ok : undefined) ?? p.any, known: true };
  }
  const rule = /^rule\.(\d+)$/.exec(a);
  if (rule) return { title: `Правило Wazuh ${rule[1]}`, known: true };
  if (a.startsWith("k8s.")) return { title: `Kubernetes: ${a.slice(4).replace(/\./g, " ")}`, known: true };
  return { title: a, known: false };
}

export type EventKind = "auth" | "priv" | "net" | "file" | "k8s" | "threat" | "identity" | "infra" | "system" | "other";

/** Вид события для иконки строки: по префиксу action, затем по классу источника. */
export function eventKind(action: string, sourceClass = ""): EventKind {
  const a = action.toLowerCase();
  const c = sourceClass.toLowerCase();
  if (/^(auth|login|app\.authorize)/.test(a)) return "auth";
  if (a.startsWith("priv.")) return "priv";
  if (/^(flow|net\.|proxy\.|session\.|event\.dns|sandbox\.egress)/.test(a)) return "net";
  if (a.startsWith("file.")) return "file";
  if (a.startsWith("k8s.") || c === "k8s") return "k8s";
  if (/^(rule\.|threat\.|http\.attack)/.test(a) || c === "wazuh" || c === "ids") return "threat";
  if (/^(user\.|identity\.|iam\.)/.test(a) || c === "idp") return "identity";
  if (/^(vm\.|pve\.|disk\.|config\.|repo\.|gitlab\.)/.test(a) || c === "hypervisor" || c === "cicd") return "infra";
  if (/^(engine\.|collector\.|rules\.)/.test(a) || c === "system") return "system";
  if (c === "netflow") return "net";
  return "other";
}

/**
 * Важность строки ленты по шкале событий (SEVERITY.events): критичная —
 * «err», высокая — «warn», остальное — без подсветки. Вкладка «Только важное»
 * фильтрует по тому же порогу (severity ≥ high).
 */
export function eventImportance(severity: number, t: SeverityThresholds = SEVERITY.events): "err" | "warn" | null {
  if (severity >= t.critical) return "err";
  if (severity >= t.high) return "warn";
  return null;
}
