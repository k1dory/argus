// Компоненты консоли: презентационные и клиентские рендерятся через
// react-dom/server с контекстом app router (_render.ts). Проверяется разметка:
// подписи, состояния «пусто», тона, ссылки и доступность (aria), а не поведение
// обработчиков — его в SSR нет.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks } from "./_next-mock";
import { html, stripTags, pageText, routerCalls } from "./_render";

installNextMocks();

/* eslint-disable @typescript-eslint/no-require-imports -- компоненты грузятся после моков next/* */
const React = require("react") as typeof import("react");
const C = <T,>(p: string): T => require(`../src/components/console/${p}`) as T;
const panel = C<typeof import("../src/components/console/panel")>("panel");
const storage = C<typeof import("../src/components/console/storage-error")>("storage-error");
const badges = C<typeof import("../src/components/console/incident-badges")>("incident-badges");
const sev = C<typeof import("../src/components/console/severity-badge")>("severity-badge");
const tone = C<typeof import("../src/components/console/tone")>("tone");
const pager = C<typeof import("../src/components/console/pager")>("pager");
const chain = C<typeof import("../src/components/console/chain-table")>("chain-table");
const respLog = C<typeof import("../src/components/console/response-log")>("response-log");
const hit = C<typeof import("../src/components/console/search-hit")>("search-hit");
const leds = C<typeof import("../src/components/console/service-leds")>("service-leds");
const skel = C<typeof import("../src/components/console/skeletons")>("skeletons");
const md = C<typeof import("../src/components/console/markdown-body")>("markdown-body");
const wiki = C<typeof import("../src/components/console/incident-wiki")>("incident-wiki");
const dash = C<typeof import("../src/components/console/dash-panels")>("dash-panels");
const charts = C<typeof import("../src/components/console/charts")>("charts");
const nav = C<typeof import("../src/components/console/nav")>("nav");
const loginForm = C<typeof import("../src/components/console/login-form")>("login-form");
const range = C<typeof import("../src/components/console/range-picker")>("range-picker");
const autoRefresh = C<typeof import("../src/components/console/auto-refresh")>("auto-refresh");
const download = C<typeof import("../src/components/console/download-button")>("download-button");
const refresh = C<typeof import("../src/components/console/refresh-data-button")>("refresh-data-button");
const copyable = C<typeof import("../src/components/console/copyable")>("copyable");
const histogram = C<typeof import("../src/components/console/journal/histogram")>("journal/histogram");
const raw = C<typeof import("../src/components/console/journal/raw-block")>("journal/raw-block");
const feed = C<typeof import("../src/components/console/journal/event-feed")>("journal/event-feed");
const filterBar = C<typeof import("../src/components/console/journal/filter-bar")>("journal/filter-bar");
const alertsFilters = C<typeof import("../src/components/console/alerts-filters")>("alerts-filters");
const actionForm = C<typeof import("../src/components/console/action-form")>("action-form");
const statusForm = C<typeof import("../src/components/console/incident-status-form")>("incident-status-form");
const usersForm = C<typeof import("../src/components/console/users-form")>("users-form");
const respondForm = C<typeof import("../src/components/console/respond-mode-form")>("respond-mode-form");
const blockBtn = C<typeof import("../src/components/console/block-ip-button")>("block-ip-button");
const unblockBtn = C<typeof import("../src/components/console/unblock-ip-button")>("unblock-ip-button");
const reopenBtn = C<typeof import("../src/components/console/triage-reopen-button")>("triage-reopen-button");
const reanalyzeBtn = C<typeof import("../src/components/console/reanalyze-button")>("reanalyze-button");
const boundary = C<typeof import("../src/components/console/incident-action-boundary")>("incident-action-boundary");
const passwordForm = C<typeof import("../src/components/console/password-form")>("password-form");
const totpForm = C<typeof import("../src/components/console/totp-form")>("totp-form");
const manageForms = C<typeof import("../src/components/console/manage-forms")>("manage-forms");
const wizard = C<typeof import("../src/components/console/agent-wizard")>("agent-wizard");
const dashEditor = C<typeof import("../src/components/console/dashboard-editor")>("dashboard-editor");
const dashCreate = C<typeof import("../src/components/console/dashboard-create")>("dashboard-create");
const actorForms = C<typeof import("../src/components/console/actor-forms")>("actor-forms");
/* eslint-enable @typescript-eslint/no-require-imports */

// Свободная типизация createElement: тесты передают children третьим аргументом, а не в props.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const h = React.createElement as (type: any, props?: any, ...children: any[]) => React.ReactElement;
const NOW = "2026-10-29 10:00:00";
/** Текст компонента (без тегов и скриптов). */
const text = (el: React.ReactElement, pathname = "/", search = "") => stripTags(html(el, pathname, search));

before(() => {
  console.error = () => undefined;
});

/* ===== Панели, бейджи, тона ===== */

test("panel: Led с подписью доступен, без неё — декоративный; StatTile со ссылкой — <a>; PageHeader с подзаголовком", () => {
  assert.match(html(h(panel.Led, { title: "живой" })), /role="img"[^>]*aria-label="живой"/);
  assert.match(html(h(panel.Led, {})), /aria-hidden="true"/);
  const tile = html(h(panel.StatTile, { label: "Открытых", value: "3", unit: "%", led: "var(--status-err)", hint: "все", href: "/incidents" }));
  assert.match(tile, /<a [^>]*href="\/incidents"/);
  assert.match(tile, /title="все"/);
  assert.match(stripTags(tile), /Открытых → 3 %/);
  assert.doesNotMatch(html(h(panel.StatTile, { label: "x", value: "1" })), /<a /);
  const p = html(h(panel.Panel, { label: "Окно", meta: "мета", id: "w1" }, "тело"));
  assert.match(p, /aria-label="Окно"/);
  assert.match(p, /win__meta/);
  assert.doesNotMatch(html(h(panel.Panel, {}, "тело")), /win__bar/, "без label шапки нет");
  assert.match(text(h(panel.PageHeader, { title: "Заголовок", subtitle: "подзаголовок" }, "справа")), /Заголовок подзаголовок справа/);
  assert.match(text(h(panel.Empty, { className: "x" }, "пусто")), /пусто/);
});

test("storage-error и бейджи: причина и подсказка; уровни и статусы по тонам и подписям", () => {
  const s = text(h(storage.StorageUnavailable, { reason: "нет соединения", label: "Своя подпись" }));
  assert.match(s, /Своя подпись clickhouse/);
  assert.match(s, /нет соединения/);
  assert.match(s, /CLICKHOUSE_\*/);
  assert.match(html(h(badges.LevelBadge, { level: "critical" })), /status-err/);
  assert.match(text(h(badges.LevelBadge, { level: "critical" })), /критический|critical/i);
  assert.match(html(h(badges.StatusBadge, { status: "closed" })), /status-ok/);
  assert.match(text(h(badges.StatusBadge, { status: "closed" })), /закрыт/);
  assert.match(text(h(badges.StatusBadge, { status: "weird" })), /weird/, "неизвестный статус показывается как есть");
  assert.match(html(h(sev.SeverityBadge, { level: 12 })), /status-err/);
  assert.match(html(h(sev.SeverityBadge, { level: 7 })), /status-warn/);
  assert.match(html(h(sev.SeverityBadge, { level: 3 })), /text-muted-foreground/);
  assert.equal(tone.toneFor(tone.LEVEL_TONE, "HIGH"), "warn");
  assert.equal(tone.toneFor(tone.STATUS_TONE, "nope"), "muted");
  assert.equal(tone.toneFor(tone.VULN_TONE, "Critical"), "err");
  assert.equal(tone.toneFor(tone.AGENT_STATUS_TONE, "active"), "ok");
  assert.deepEqual([tone.ruleLevelTone(12), tone.ruleLevelTone(7), tone.ruleLevelTone(6)], ["err", "warn", "muted"]);
});

/* ===== Пагинация и сортировка ===== */

test("pager: одна страница без total — ничего; крайние стрелки не ссылки; диапазон строк; потолок", () => {
  assert.equal(html(h(pager.Pager, { page: 1, pages: 1, href: () => "/x" })), "");
  const first = html(h(pager.Pager, { page: 1, pages: 3, total: 250, pageSize: 100, href: (p: number) => `/x?page=${p}` }));
  assert.match(first, /<span aria-disabled="true" aria-label="Предыдущая страница"[^>]*>←<\/span>/);
  assert.match(first, /href="\/x\?page=2"[^>]*rel="next"|rel="next"[^>]*href="\/x\?page=2"/);
  assert.match(stripTags(first), /страница 1 из 3 · строки 1–100 из 250/);
  const last = stripTags(html(h(pager.Pager, { page: 3, pages: 3, total: 250, pageSize: 100, capped: true, href: (p: number) => `/x?page=${p}` })));
  assert.match(last, /строки 201–250 из 250 · дальше — уточните фильтры/);
  assert.match(html(h(pager.Pager, { page: 3, pages: 3, total: 250, pageSize: 100, href: (p: number) => `/x?page=${p}` })), /aria-label="Следующая страница"[^>]*>→<\/span>/);
  assert.match(stripTags(html(h(pager.Pager, { page: 1, pages: 1, total: 7, pageSize: 50, href: () => "/x" }))), /строки 1–7 из 7/);

  const active = html(h(pager.SortLink, { label: "Уровень", field: "level", sort: "level", dir: "desc", href: (s: string, d: string) => `/a?sort=${s}&dir=${d}` }));
  assert.match(active, /href="\/a\?sort=level&amp;dir=asc"/, "активная desc → следующая asc");
  assert.match(active, /↓/);
  const idle = html(h(pager.SortLink, { label: "Время", field: "ts", sort: "level", dir: "desc", href: (s: string, d: string) => `/a?sort=${s}&dir=${d}` }));
  assert.match(idle, /dir=desc"/);
  assert.match(idle, /↕/);
  assert.match(idle, /по убыванию/);
});

/* ===== Цепочка, журнал реагирования, выдача поиска ===== */

test("chain-table: строки движка по колонкам, примечание «→», свободный текст; пустая цепочка", () => {
  assert.match(text(h(chain.ChainTable, { chain: [] })), /цепочка пуста/);
  const t = html(h(chain.ChainTable, { chain: [
    "10:00:00  linux.auth        bastion        login.failed             user=root from 203.0.113.5",
    "→ порог достигнут",
    "просто текст",
  ], date: "2026-10-29" }));
  const s = stripTags(t);
  assert.match(s, /время \(2026-10-29\)/);
  assert.match(s, /10:00:00 linux\.auth bastion login\.failed user=root from 203\.0\.113\.5/);
  assert.match(s, /→ порог достигнут/);
  assert.match(s, /просто текст/);
  assert.match(t, /href="[^"]*source[^"]*linux\.auth|linux\.auth[^<]*<\/a>/, "источник — ссылка в поиск");
  assert.equal((t.match(/colspan="5"/gi) ?? []).length, 2, "примечание и свободный текст — на всю ширину");
});

test("response-log: пусто; симуляция и ручной режим; compact скрывает инцидент и причину", () => {
  assert.match(text(h(respLog.ResponseLog, { rows: [] })), /ни одной автоблокировки/);
  const rows = [
    { ts: NOW, incident_id: "INC-7", rule_id: "r", ip: "203.0.113.5", mode: "ips", executor: "wazuh", dry_run: 1, ok: 1, detail: "ok", reason: "TTL", actor: "argus-engine" },
    { ts: NOW, incident_id: "INC-8", rule_id: "r", ip: "203.0.113.6", mode: "manual", executor: "ngfw", dry_run: 0, ok: 0, detail: "timeout", reason: "оператор", actor: "admin" },
    { ts: NOW, incident_id: "INC-9", rule_id: "r", ip: "203.0.113.7", mode: "odd", executor: "x", dry_run: 0, ok: 1, detail: "", reason: "", actor: "" },
  ];
  const full = stripTags(html(h(respLog.ResponseLog, { rows })));
  assert.match(full, /симуляция INC-7 203\.0\.113\.5 wazuh выполнено ok · TTL/);
  assert.match(full, /оператор INC-8 203\.0\.113\.6 ngfw ошибка timeout · оператор/);
  assert.match(full, /odd INC-9/, "неизвестный режим показывается как есть");
  const compact = stripTags(html(h(respLog.ResponseLog, { rows, compact: true })));
  assert.doesNotMatch(compact, /INC-7/);
  assert.doesNotMatch(compact, /· TTL/);
});

test("search-hit: индекс alerts и events — ссылки по полям, тон серьёзности, время, подробности с JSON", () => {
  const cols = [{ key: "time", label: "Время" }, { key: "rule_level", label: "Ур." }, { key: "rule_id", label: "Правило" }, { key: "agent_name", label: "Агент" }, { key: "srcip", label: "srcip" }];
  const row = { time: NOW, rule_level: 12, rule_id: 5763, agent_name: "web-01", srcip: "203.0.113.5", raw: "{\"a\":1}" };
  const a = html(h("table", null, h("tbody", null, h(hit.SearchHit, { row, columns: cols, index: "alerts" }))));
  assert.match(a, /status-err/, "уровень 12 — критичный тон");
  assert.match(a, /href="\/wazuh\/agents"/);
  assert.match(a, /srcip/);
  assert.match(a, /&quot;a&quot;: 1/, "raw JSON переформатирован");
  assert.match(a, /<dt[^>]*>rule_id<\/dt>/);
  const ecols = [{ key: "time", label: "Время" }, { key: "severity", label: "Ур." }, { key: "source", label: "Источник" }, { key: "actor_name", label: "Субъект" }, { key: "node", label: "Узел" }, { key: "src_ip", label: "IP" }, { key: "object", label: "Объект" }];
  const e = html(h("table", null, h("tbody", null, h(hit.SearchHit, { row: { time: NOW, severity: 3, source: "linux.auth", actor_name: "root", node: "bastion", src_ip: "0", object: "", raw: "not json" }, columns: ecols, index: "events" }))));
  assert.match(e, /linux\.auth/);
  assert.match(e, /bastion/);
  assert.match(stripTags(e), /not json/);
  assert.match(e, /—/, "пустое значение в подробностях — тире");
});

/* ===== Скелеты, LED служб, Markdown ===== */

test("skeletons: все варианты с aria-hidden, PageSkeleton объявляет загрузку", () => {
  for (const [name, props] of [["StatRowSkeleton", { count: 2 }], ["TableSkeleton", { rows: 3, label: "лента" }], ["ChartSkeleton", { label: "график" }], ["PanelSkeleton", { lines: 2 }]] as const) {
    const out = html(h(skel[name] as React.FC<Record<string, unknown>>, props as Record<string, unknown>));
    assert.match(out, /aria-hidden/, name);
  }
  const page = html(h(skel.PageSkeleton, {}));
  assert.match(page, /role="status"/);
  assert.match(stripTags(page), /Загрузка…/);
  assert.match(html(h(skel.TableSkeleton, { label: "лента" })), /лента/);
});

test("service-leds: зелёный/красный по SELECT 1 и /healthz, детали в sr-only", async (t) => {
  t.mock.method(globalThis, "fetch", async (input: URL | string) => (String(input).includes("/healthz") ? new Response("x", { status: 503 }) : new Response("1\n")));
  const out = await pageText(h(leds.ServiceLeds, {}));
  assert.match(out, /clickhouse ClickHouse отвечает/);
  assert.match(out, /движок движок: HTTP 503/);
});

test("markdown-body: заголовки понижены, HTML вырезан, ссылки в новой вкладке, картинок нет; incident-wiki", () => {
  const out = html(h(md.MarkdownBody, { label: "Досье", className: "c" }, "# Заголовок\n\n<b>жирно</b> и [ссылка](https://example.org)\n\n![img](x.png)\n\n- a\n\n1. b\n\n`код`\n\n```\nблок\n```"));
  assert.match(out, /<article class="c" aria-label="Досье">/);
  assert.match(out, /<h2[^>]*>Заголовок<\/h2>/);
  assert.doesNotMatch(out, /<b>/);
  assert.match(out, /<a href="https:\/\/example\.org" target="_blank" rel="noopener noreferrer"/);
  assert.doesNotMatch(out, /<img/);
  assert.match(out, /<code class="font-mono text-xs">код<\/code>/);
  assert.match(out, /<pre[^>]*><code[^>]*>блок/);
  const w = text(h(wiki.IncidentWiki, { id: "INC-7", markdown: "## Разбор\n\nтекст", canEdit: true }));
  assert.match(w, /Досье инцидента/);
  assert.match(w, /Скачать \.md/);
  assert.match(w, /Переразобрать|Повторить разбор|разбор/i);
  assert.match(w, /Разбор текст/);
  assert.doesNotMatch(text(h(wiki.IncidentWiki, { id: "INC-7", markdown: "x", canEdit: false })), /Отправить|Добавить запись/);
});

/* ===== Панели дашбордов и графики ===== */

test("dash-panels: pivot по series-колонке и по числовым колонкам, лимит серий; stat/table/bar/ошибка; сетка", () => {
  const p = { id: "p1", title: "Ряд", type: "timeseries" as const, sql: "SELECT 1", w: 12, h: 6, series: "src" };
  const d = { columns: ["t", "src", "n"], rows: [{ t: NOW, src: "a", n: "5" }, { t: NOW, src: "b", n: 7 }, { t: "2026-10-29 11:00:00", src: "a", n: 1 }], ms: 3 };
  const piv = dash.pivotTimeseries(p, d);
  assert.deepEqual(piv.series, [{ key: "s0", label: "a" }, { key: "s1", label: "b" }]);
  assert.deepEqual(piv.data, [{ time: NOW, s0: 5, s1: 7 }, { time: "2026-10-29 11:00:00", s0: 1 }]);
  const many = dash.pivotTimeseries(p, { columns: ["t", "src", "n"], rows: Array.from({ length: 15 }, (_, i) => ({ t: NOW, src: `s${i}`, n: 1 })), ms: 0 });
  assert.equal(many.series.length, 12, "не больше MAX_SERIES серий");
  const plain = dash.pivotTimeseries({ ...p, series: undefined }, { columns: ["t", "n", "m", "label"], rows: [{ t: NOW, n: 1, m: "2", label: "x" }], ms: 0 });
  assert.deepEqual(plain.series, [{ key: "s0", label: "n" }, { key: "s1", label: "m" }]);
  assert.deepEqual(dash.pivotTimeseries(p, { columns: [], rows: [], ms: 0 }), { data: [], series: [] });

  assert.match(text(h(dash.TimeSeriesPanel, { panel: p, data: { columns: [], rows: [], ms: 0 }, longRange: false })), /нет данных за период/);
  assert.match(html(h(dash.TimeSeriesPanel, { panel: p, data: d, longRange: true })), /role="img" aria-label="Ряд"/);
  const stat = text(h(dash.StatPanel, { panel: { ...p, type: "stat", unit: "шт" }, data: { columns: ["total", "avg", "name"], rows: [{ total: 12, avg: 1.25, name: "x" }], ms: 0 } }));
  assert.match(stat, /total 12 шт avg 1,3 шт name x шт|total 12 шт avg 1\.3 шт name x шт/);
  const table = html(h(dash.TablePanel, { data: { columns: ["ts", "source", "n"], rows: [{ ts: NOW, source: "a", n: 3.14159 }], ms: 0 } }));
  assert.match(stripTags(table), /ts source n 2026-10-29 10:00:00 UTC a 3,14|3\.14/);
  assert.match(html(h(dash.BarPanel, { panel: { ...p, type: "bar", title: "" }, data: { columns: ["name", "n"], rows: [{ name: "a", n: 2 }], ms: 0 } })), /aria-label="столбцы"/);
  const err = html(h(dash.PanelBody, { panel: p, data: { columns: [], rows: [], ms: 0, error: "код 60: нет таблицы", errorDetail: "Code: 60. DB::Exception: …" }, longRange: false }));
  assert.match(err, /role="alert"/);
  assert.match(stripTags(err), /код 60: нет таблицы полный ответ ClickHouse Code: 60/);
  assert.match(text(h(dash.PanelBody, { panel: { ...p, type: "table" }, data: { columns: [], rows: [], ms: 0 }, longRange: false })), /нет данных/);
  const grid = html(h(dash.DashboardGrid, { panels: [p, { ...p, id: "p2", type: "stat", title: "" }], data: { p1: { ...d, cached: true, truncated: true } }, longRange: false }));
  assert.match(stripTags(grid), /Ряд ряд · 3 мс · кэш · обрезано/);
  assert.match(stripTags(grid), /p2 число · 0 мс нет данных за период/, "панель без данных и без title — по id");
  assert.match(grid, /--dash-h:240px/);
});

test("charts: серии по серьёзности, топ правил и тактик — SVG с aria-label", () => {
  const series = html(h(charts.AlertsSeriesChart, { data: [{ bucket: NOW, low: 1, high: 2, critical: 3 }], longRange: false }));
  assert.match(series, /role="img" aria-label="Алерты по времени и серьёзности"/);
  assert.match(series, /--color-critical/);
  assert.match(html(h(charts.TopRulesChart, { rules: [{ ruleId: 5763, description: "sshd", level: 10, count: 9 }] })), /aria-label="Топ правил по числу алертов"/);
  assert.match(html(h(charts.TacticsChart, { tactics: Array.from({ length: 8 }, (_, i) => ({ tactic: `t${i}`, count: i })) })), /height:272px/, "высота растёт с числом строк");
});

/* ===== Навигация и клиентские элементы управления ===== */

test("nav: пункты Wazuh только с модулем; активный раздел — aria-current; меню узкого экрана", () => {
  assert.ok(nav.navItems(false).every((i) => !("wazuh" in i)));
  assert.ok(nav.navItems(true).some((i) => i.href === "/wazuh/alerts"));
  assert.equal(nav.navLabel("/incidents"), "Инциденты");
  const wide = html(h(nav.ConsoleNav, { wazuh: true }), "/incidents/INC-7");
  assert.match(wide, /aria-current="page"[^>]*href="\/incidents"/);
  assert.match(wide, /Алерты Wazuh/);
  assert.match(stripTags(wide), /Инциденты/, "текущий раздел в кнопке меню");
  const root = html(h(nav.ConsoleNav, {}), "/");
  assert.match(root, /aria-current="page"[^>]*href="\/"/);
  assert.doesNotMatch(root, /Алерты Wazuh/);
  assert.match(html(h(nav.ConsoleNav, {}), "/unknown"), /Разделы/, "вне разделов — подпись по умолчанию");
});

test("range-picker, auto-refresh, download, refresh, copyable: SSR-разметка и состояния", () => {
  const rp = html(h(range.RangePicker, { value: "7d" }), "/incidents", "page=3");
  assert.match(rp, /aria-label="Диапазон времени"/);
  assert.match(rp, /aria-pressed="true"[^>]*>7 дней|7 дней/);
  assert.equal((rp.match(/aria-pressed="true"/g) ?? []).length, 1);
  assert.equal(html(h(autoRefresh.AutoRefresh, { seconds: 2 })), "", "интервал меньше 5 с — компонент не рисуется");
  assert.match(text(h(autoRefresh.AutoRefresh, { seconds: 30, label: "обновление" })), /обновление 30 с · через 30 с/);
  assert.match(html(h(autoRefresh.AutoRefresh, { seconds: 30 })), /aria-label="Приостановить автообновление"/);
  const dl = html(h(download.DownloadButton, { href: "/api/x", filename: "x.csv", variant: "ghost" }, "CSV"));
  assert.match(dl, /aria-busy="false"/);
  assert.match(stripTags(dl), /CSV/);
  assert.match(text(h(refresh.RefreshDataButton, {})), /Обновить/);
  const link = html(h(copyable.Copyable, { value: "203.0.113.5", href: "/search?q=x", label: "IP" }));
  assert.match(link, /<a [^>]*title="203\.0\.113\.5"[^>]*href="\/search\?q=x"/);
  assert.match(link, /aria-label="Скопировать ip 203\.0\.113\.5"/);
  const btn = html(h(copyable.Copyable, { value: "v" }, "подпись"));
  assert.match(btn, /<button type="button"[^>]*title="Скопировать v"/);
  assert.match(stripTags(btn), /подпись/);
  assert.equal(routerCalls.length, 0, "SSR не вызывает навигацию");
});

/* ===== Журнал событий ===== */

test("journal: гистограмма с подписями и ссылками корзин, raw-блок JSON/текст/пусто, лента с инцидентами и фильтры", () => {
  const bar = (startMs: number, total: number, critical = 0, high = 0) => ({ bucket: NOW, low: total - critical - high, high, critical, total, startMs, endMs: startMs + 60_000, from: "2026-10-29T10:00", to: "2026-10-29T10:01" });
  const hg = html(h(histogram.JournalHistogram, { bars: [bar(0, 10, 2, 3), bar(60_000, 0), bar(120_000, 5)], longRange: false, hrefFor: (b: { from: string }) => `/events?from=${b.from}`, bucketMinutes: 1 }));
  assert.match(hg, /aria-label="События по времени"/);
  assert.match(hg, /href="\/events\?from=2026-10-29T10:00"/);
  assert.match(stripTags(hg), /критичная 2 высокая 3 ниже высокой 10 корзина 1 мин/);
  assert.equal((hg.match(/role="listitem"/g) ?? []).length, 3);

  const json = html(h(raw.RawBlock, { raw: "{\"a\":1,\"b\":[true,null]}", source: "k8s.audit" }));
  assert.match(stripTags(json), /raw\.json k8s\.audit JSON · 7 стр\./);
  assert.match(json, /text-str|text-num|text-kw/);
  assert.match(stripTags(html(h(raw.RawBlock, { raw: "<86>sshd: Failed", source: "linux.auth" }))), /raw\.log linux\.auth text · 1 стр\./);
  assert.match(stripTags(html(h(raw.RawBlock, { raw: "  ", source: "s" }))), /не передал сырое событие/);
  assert.match(html(h(raw.CopyButton, { value: "v", label: "Скопировать" })), /aria-label="Скопировать"/);

  const ev = { time: NOW, received: NOW, id: "1", severity: 9, source: "linux.auth", source_class: "syslog", vendor: "", product: "", action: "login", outcome: "failure", actor_name: "root", actor_kind: "user", object: "/etc/passwd", node: "bastion", session_id: "", src_ip: "203.0.113.5", src_port: 0, dst_ip: "", dst_port: 0, proto: "", bytes: 0, packets: 0, value: 0, unit: "", pii: 0, attrs: { rule: "5763" }, raw: "x" };
  const filters = { q: "", range: "24h" as const, page: 1 };
  const f = html(h(feed.EventFeed, { initial: [ev, { ...ev, id: "2", severity: 2, actor_name: "", object: "", src_ip: "" }], incidents: { "1": [{ incident_id: "INC-7", rule_id: "r", rule_title: "Перебор SSH", level: "high", status: "new", node: "bastion", actor_name: "root", sources: ["linux.auth"], first_ts: NOW, last_ts: NOW }] }, filters: filters as never, cursor: "c", liveAllowed: true, showDate: true }), "/events");
  const ft = stripTags(f);
  assert.match(ft, /в ленте 2/);
  assert.match(ft, /INC-7/);
  assert.match(ft, /root/);
  assert.match(ft, /\/etc\/passwd/);
  assert.match(f, /status-err|text-err/, "серьёзность 9 — критичный тон");
  assert.match(stripTags(html(h(feed.EventFeed, { initial: [], incidents: {}, filters: filters as never, cursor: "c", liveAllowed: false, showDate: false }), "/events")), /Событий нет/);

  const fb = html(h(filterBar.JournalFilterBar, { filters: { ...filters, source: "gone.src", host: "bastion", sev: 7, rule: "5763", from: "2026-10-29T00:00" } as never, sources: ["linux.auth"], hosts: ["bastion"] }), "/events");
  assert.match(fb, /role="search"/);
  assert.match(stripTags(fb), /gone\.src/, "выбранный источник показан, даже если его нет в окне");
  assert.match(fb, /value="5763"/);
  assert.match(fb, /value="2026-10-29T00:00"/);
  assert.match(stripTags(html(h(alertsFilters.AlertsFilters, { agents: ["web-01"] }), "/wazuh/alerts", "level=10&agent=web-01&q=ssh")), /Описание правила Уровень Агент Найти/);
});

/* ===== Формы действий (SSR без обработчиков) ===== */

test("action-form: обычная форма и форма с подтверждением — диалог закрыт, кнопка на месте", () => {
  const act = async () => undefined;
  const a = html(h(actionForm.ActionForm, { action: act, successText: "ок", className: "inline" }, h("button", { type: "submit" }, "Жми")));
  assert.match(a, /<form class="inline"/);
  assert.match(stripTags(a), /Жми/);
  const c = html(h(actionForm.ConfirmActionForm, { action: act, title: "Удалить?", description: "навсегда", confirmLabel: "Да" }, h("button", { type: "submit" }, "Удалить")));
  assert.match(stripTags(c), /Удалить/);
  assert.doesNotMatch(stripTags(c), /навсегда/, "описание — только в открытом диалоге");
});

test("incident-status-form: взять/назначить без владельца; статусы и исключения — владельцу; завершённый; чужой", () => {
  const users = [{ name: "analyst1", role: "analyst" }, { name: "admin", role: "admin" }, { name: "viewer1", role: "viewer" }];
  const exceptions = [{ field: "actor.name", value: "root", label: "субъект" }];
  const out = html(h(statusForm.IncidentStatusForm, { incidentId: "INC-7", status: "new", owner: "", currentUser: "analyst1", isAdmin: true, users, exceptions }));
  const t = stripTags(out);
  assert.match(t, /Взять в работу/);
  assert.match(t, /Назначить или передать аналитику/);
  assert.match(out, /<option value="admin">admin \(администратор\)<\/option>/);
  assert.doesNotMatch(out, /value="viewer1"/, "наблюдателю не назначают");
  assert.doesNotMatch(t, /субъект/, "исключения — только в форме статуса владельца");
  const mine = stripTags(html(h(statusForm.IncidentStatusForm, { incidentId: "INC-7", status: "in_progress", owner: "analyst1", currentUser: "analyst1", isAdmin: false, users, exceptions })));
  assert.doesNotMatch(mine, /Взять в работу/);
  assert.match(mine, /Статус расследования/);
  assert.match(mine, /эскалация в работе наблюдение закрыт ложное/, "варианты статуса; исключения появляются после выбора «ложное» на клиенте");
  const noone = stripTags(html(h(statusForm.IncidentStatusForm, { incidentId: "INC-7", status: "in_progress", owner: "analyst1", currentUser: "analyst1", isAdmin: true, users: [{ name: "analyst1", role: "analyst" }], exceptions: [] })));
  assert.match(noone, /Некому назначить/);
  assert.match(stripTags(html(h(statusForm.IncidentStatusForm, { incidentId: "INC-7", status: "closed", owner: "analyst1", currentUser: "analyst1", isAdmin: false, users, exceptions }))), /Инцидент завершён/);
  assert.match(stripTags(html(h(statusForm.IncidentStatusForm, { incidentId: "INC-7", status: "in_progress", owner: "admin", currentUser: "analyst1", isAdmin: false, users, exceptions }))), /Статус меняет ответственный: admin/);
  assert.match(stripTags(html(h(statusForm.CommentForm, { incidentId: "INC-7" }))), /запис|комментар/i);
});

test("метка закрытия: вопросы плана разметки, тактика из тегов, кандидаты техники и «другое»", async () => {
  const { attackFormOptions } = await import("../src/lib/shared/attack");
  const attack = attackFormOptions(["attack.credential_access", "attack.t1110.001"]);
  const sec = html(h(statusForm.ClosureLabelFields, { ops: false, status: "closed", attack, disabled: false }));
  const t = stripTags(sec);
  assert.match(t, /Характер срабатывания/);
  assert.match(t, /Какой уровень правильный/);
  assert.match(sec, /<option value="4">критический \(critical\)<\/option>/);
  assert.match(sec, /<select[^>]*name="attack_tactic"[^>]*required/, "тактика обязательна, кроме ложного");
  assert.match(sec, /<option value="credential-access" selected="">Credential Access<\/option>/, "тактика по умолчанию — из тегов правила");
  assert.match(sec, /<option value="T1110.001">T1110.001 [^<]+<\/option>/, "техника из тегов — первой");
  const techniqueSelect = /<select[^>]*name="attack_technique"[\s\S]*?<\/select>/.exec(sec)?.[0] ?? "";
  const techniques = [...techniqueSelect.matchAll(/<option value="(T\d{4}(?:\.\d{3})?|other)">/g)].map((m) => m[1]);
  assert.equal(techniques[0], "T1110.001");
  assert.equal(techniques.at(-1), "other");
  assert.ok(techniques.length <= 21, `не больше 20 кандидатов и «другое»: ${techniques.length}`);
  assert.match(t, new RegExp(`ATT&CK Enterprise ${attack.version.replace(".", "\\.")}`));
  assert.doesNotMatch(sec, /name="severity_correct"/, "severity_correct вычисляет движок");
  const fp = html(h(statusForm.ClosureLabelFields, { ops: false, status: "false_positive", attack, disabled: false }));
  assert.doesNotMatch(fp, /<select[^>]*name="attack_tactic"[^>]*required/, "у ложного срабатывания тактика необязательна");
  const ops = html(h(statusForm.ClosureLabelFields, { ops: true, status: "closed", attack, disabled: false }));
  const o = stripTags(ops);
  assert.match(o, /Причина/);
  assert.match(o, /Действовать сейчас/);
  assert.match(o, /Срочность/);
  assert.match(o, /Что сделали/);
  assert.doesNotMatch(ops, /<select[^>]*name="ops_action"[^>]*required/, "«что сделали» — необязательно");
  assert.match(ops, /<option value="process_crash">процесс упал<\/option>/);
  assert.doesNotMatch(ops, /value="false_positive"/, "ложное — только вместе со статусом «ложное срабатывание»");
  assert.match(html(h(statusForm.ClosureLabelFields, { ops: true, status: "false_positive", attack, disabled: false })), /<option value="false_positive" selected="">ложное срабатывание<\/option>/);
});

test("прочие формы: пользователи, режим реагирования, блокировки, повторный разбор, пароль, TOTP, Wazuh, дашборды, алиасы", () => {
  assert.match(stripTags(html(h(usersForm.CreateUserForm, {}))), /Имя Роль Создать/);
  assert.match(html(h(usersForm.ResetPasswordButton, { name: "u1" })), /u1/);
  assert.match(html(h(usersForm.DeleteUserButton, { name: "u1" })), /u1/);
  const rm = stripTags(html(h(respondForm.RespondModeForm, { current: "ids", from: "console", requested: "ips" })));
  assert.match(rm, /IDS — только детект/);
  assert.match(rm, /Применить/);
  assert.match(rm, /консоль/);
  assert.match(stripTags(html(h(respondForm.RespondModeForm, { current: "simulate", from: "config", requested: null }))), /argus\.analyst\.yml/);
  const blk = html(h(blockBtn.BlockIpButton, { incidentId: "INC-7", ip: "203.0.113.5" }));
  assert.match(blk, /data-slot="alert-dialog-trigger"/, "блокировка — через подтверждение");
  assert.match(stripTags(blk), /блокир/i);
  assert.match(stripTags(html(h(unblockBtn.UnblockIpButton, { ip: "203.0.113.5", incidentId: "INC-7", action: async () => ({ error: null }) }))), /Снять|разблок/i);
  assert.match(stripTags(html(h(reopenBtn.TriageReopenButton, { incidentId: "INC-7" }))), /повторн|разбор/i);
  assert.match(stripTags(html(h(reanalyzeBtn.ReanalyzeButton, { incidentId: "INC-7" }))), /разбор|разобрать/i);
  assert.match(stripTags(html(h(boundary.IncidentActionBoundary, { id: "INC-7", revision: "r1" }, "внутри"))), /внутри/);
  const pw = html(h(passwordForm.PasswordForm, { force: true }));
  assert.match(pw, /type="password"/);
  assert.match(stripTags(pw), /Сменить пароль/);
  assert.match(stripTags(html(h(totpForm.TotpControls, { enabled: false, user: "u" }))), /Сгенерировать секрет/);
  assert.match(stripTags(html(h(totpForm.TotpControls, { enabled: true, user: "u" }))), /Отключить|выключить/i);
  assert.match(stripTags(html(h(manageForms.AgentGroupAdd, { agentId: "001", groups: ["web", "db"] }))), /web|группу|Добавить/i);
  assert.match(stripTags(html(h(manageForms.GroupCreateForm, {}))), /Создать|группа/i);
  const conf = html(h(manageForms.GroupConfEditor, { group: "web", initialXml: "<agent_config/>", readOnly: true }));
  assert.match(conf, /&lt;agent_config\/&gt;/);
  assert.match(conf, /readonly|disabled/i);
  const rf = html(h(manageForms.RuleFileEditor, { filename: "local_rules.xml", initialXml: "<group/>", readOnly: false }));
  assert.match(rf, /local_rules\.xml/);
  assert.match(stripTags(rf), /Сохранить/);
  assert.match(stripTags(html(h(manageForms.NewRuleFileForm, {}))), /\.xml|файл/i);
  const wz = stripTags(html(h(wizard.AgentWizard, { version: "4.9.0", managerHost: "wazuh.example", groups: ["web"], passwordRequired: true })));
  assert.match(wz, /wazuh\.example/);
  assert.match(wz, /4\.9\.0/);
  assert.match(wz, /WAZUH_REGISTRATION_PASSWORD|парол/i);
  const ed = html(h(dashEditor.DashboardEditor, { initial: { id: "ops", title: "Операции", panels: [{ id: "p1", title: "Ряд", type: "timeseries", sql: "SELECT 1", w: 12, h: 6 }] } }), "/dashboards/ops/edit", "range=7d");
  assert.match(stripTags(ed), /Операции/);
  assert.match(stripTags(ed), /SELECT 1/);
  assert.match(stripTags(html(h(dashCreate.CreateDashboardForm, {}))), /Создать|Новый/i);
  const bind = html(h(actorForms.BindAliasForm, { persons: [{ person_id: "i.petrov", display: "Иван Петров" }], value: "ipetrov", kind: "login" }));
  assert.match(stripTags(bind), /существующая персона новая персона Персона Вид Значение/);
  assert.match(stripTags(bind), /Привязать/);
  assert.match(bind, /value="ipetrov"/);
  assert.match(bind, /Иван Петров|i\.petrov/, "персоны — в списке выбора (Radix Select рендерит значения только после открытия)");
  assert.match(html(h(actorForms.CloseAliasButton, { personId: "i.petrov", kind: "login", value: "ipetrov" })), /ipetrov/);
  assert.match(html(h(actorForms.ConfirmAliasButton, { personId: "i.petrov", kind: "login", value: "ipetrov", policy: "подтвердить" })), /ipetrov/);
  const rl = html(h(actorForms.ActorRangeLinks, { current: "7d", base: "/actors/i.petrov" }));
  assert.match(rl, /href="\/actors\/i\.petrov\?range=24h"/);
  assert.match(rl, /aria-pressed="true"|aria-current/);
});

test("login-form: шаг пароля и скрытый next; SSR без ошибки входа", () => {
  const out = html(h(loginForm.LoginForm, { next: "/incidents" }));
  assert.match(out, /name="next" value="\/incidents"/);
  assert.match(out, /autocomplete="username"/i);
  assert.match(out, /autocomplete="current-password"/i);
  assert.doesNotMatch(out, /role="alert"/);
  assert.match(stripTags(out), /Войти/);
});
