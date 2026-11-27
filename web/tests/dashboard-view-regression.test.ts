// Регрессии доски и редактора дашборда (ревью дизайна, ветка ui-overview):
// - при точном интервале подсвечивался пресет «24 часа», хотя данные за другое окно;
// - одинаковая ошибка повторялась в каждой панели вместо одной плашки;
// - у упавшей панели в мете было «0 мс»;
// - переход по ссылке внутри приложения терял несохранённые правки;
// - удаление панели было мгновенным, без возврата.
import test from "node:test";
import assert from "node:assert/strict";
import {
  boardTime, columnLabel, commonPanelError, guardedHref, humanPanelError, intervalLabel, removeAt, restoreAt,
} from "../src/lib/shared/dashboard-view";
import { panelMeta } from "../src/components/console/dash-panels";
import { html, stripTags } from "./_render";

test("доска: при точном интервале ни один пресет не подсвечен, окно — интервал", () => {
  const bt = boardTime({ from: "2026-11-27T08:00", to: "2026-11-27T12:00" });
  assert.equal(bt.picker, undefined);
  assert.equal(bt.exact, true);
  assert.equal(typeof bt.window, "object");
  assert.deepEqual(bt.window, { range: "24h", from: "2026-11-27T08:00", to: "2026-11-27T12:00" });
  // Ссылка в редактор/обратно сохраняет интервал, а не подменяет его пресетом.
  assert.equal(new URLSearchParams(bt.query).get("from"), "2026-11-27T08:00");
  assert.equal(new URLSearchParams(bt.query).get("range"), null);
  assert.equal(intervalLabel(bt.time), "27.11 08:00 — 27.11 12:00");
});

test("доска: интервал без конца — «до сейчас», пресет тоже не горит", () => {
  const bt = boardTime({ range: "7d", from: "2026-11-27T08:00" });
  assert.equal(bt.picker, undefined);
  assert.equal(intervalLabel(bt.time), "27.11 08:00 — сейчас");
});

test("доска: без интервала — пресет из URL или 24 часа", () => {
  assert.equal(boardTime({}).picker, "24h");
  assert.equal(boardTime({ range: "7d" }).picker, "7d");
  assert.equal(boardTime({ range: "7d" }).window, "7d");
  assert.equal(boardTime({ range: "evil" }).picker, "24h");
  assert.equal(intervalLabel(boardTime({}).time), null);
});

test("доска: одна общая ошибка — когда все панели упали одинаково", () => {
  const ro = "read-only пользователь не настроен (CLICKHOUSE_RO_USER/CLICKHOUSE_RO_PASSWORD)";
  assert.deepEqual(commonPanelError([{ error: ro }, { error: ro }, { error: ro }]), { error: ro, detail: undefined });
  assert.equal(commonPanelError([{ error: ro }, {}]), null);
  assert.equal(commonPanelError([{ error: ro }, { error: "другая" }]), null);
  assert.equal(commonPanelError([{ error: ro }]), null);
  const h = humanPanelError(ro);
  assert.doesNotMatch(h.text, /CLICKHOUSE/);
  assert.match(h.admin ?? "", /CLICKHOUSE_RO_USER/);
});

test("доска: у упавшей панели мета «ошибка», а не «0 мс»; тип — только редактору", () => {
  const p = { id: "p1", title: "t", type: "table" as const, w: 12, h: 8, sql: "SELECT 1" };
  const failed = stripTags(html(panelMeta(p, { columns: [], rows: [], error: "x", ms: 0 })));
  assert.equal(failed, "ошибка");
  assert.doesNotMatch(failed, /мс/);
  const ok = String(panelMeta(p, { columns: [], rows: [], ms: 34, cached: true }));
  assert.doesNotMatch(ok, /таблица/);
  assert.match(String(panelMeta(p, { columns: [], rows: [], ms: 34 }, true)), /^таблица · /);
});

test("редактор: клик по внутренней ссылке при несохранённых правках перехватывается", () => {
  const loc = { href: "https://c.local/dashboards/x/edit?range=24h", origin: "https://c.local" };
  const left = { button: 0 };
  assert.equal(guardedHref(left, { href: "https://c.local/dashboards/x?range=24h" }, loc), "/dashboards/x?range=24h");
  assert.equal(guardedHref(left, { href: "/incidents" }, loc), "/incidents");
  // Не трогаем: новая вкладка, модификаторы, средняя кнопка, чужой сайт, якорь на той же странице, скачивание.
  assert.equal(guardedHref(left, { href: "/incidents", target: "_blank" }, loc), null);
  assert.equal(guardedHref({ button: 0, metaKey: true }, { href: "/incidents" }, loc), null);
  assert.equal(guardedHref({ button: 1 }, { href: "/incidents" }, loc), null);
  assert.equal(guardedHref(left, { href: "https://example.org/" }, loc), null);
  assert.equal(guardedHref(left, { href: "/dashboards/x/edit?range=24h#macros" }, loc), null);
  assert.equal(guardedHref(left, { href: "/export.csv", download: true }, loc), null);
  assert.equal(guardedHref(left, null, loc), null);
  assert.equal(guardedHref({ button: 0, defaultPrevented: true }, { href: "/incidents" }, loc), null);
});

test("редактор: удалённую панель можно вернуть на прежнее место", () => {
  const panels = [{ id: "a" }, { id: "b" }, { id: "c" }];
  const { list, removed } = removeAt(panels, 1);
  assert.deepEqual(list.map((p) => p.id), ["a", "c"]);
  assert.equal(removed?.id, "b");
  assert.deepEqual(restoreAt(list, removed!, 1).map((p) => p.id), ["a", "b", "c"]);
  // Повторное «Вернуть» не дублирует панель; индекс за краем — в конец.
  assert.deepEqual(restoreAt(panels, removed!, 1).map((p) => p.id), ["a", "b", "c"]);
  assert.deepEqual(restoreAt([{ id: "a" }], { id: "z" }, 9).map((p) => p.id), ["a", "z"]);
  assert.equal(removeAt(panels, 7).removed, undefined);
});

test("доска: подписи колонок без snake_case; AS \"Событий\" — как есть", () => {
  assert.equal(columnLabel("source_class"), "Source class");
  assert.equal(columnLabel("events"), "Events");
  assert.equal(columnLabel("Событий"), "Событий");
  assert.equal(columnLabel("Открыто сейчас"), "Открыто сейчас");
});
