package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/respond"
)

// Правила сканов в миниатюре: скан портов (respond, medium) и долбёжка в один
// порт (без respond, low) в общей группе склейки, порог — на адрес.
const scanPortsRule = `
title: inbound port scan
id: t-scan
level: medium
detection:
  selection: {source.class: netflow, attrs.scope: inbound}
  threshold: {kind: distinct, field: dst.port, distinct: 3, window: 10m, group_by: src.ip}
  condition: selection and threshold
auto_close: 2h
collapse: {by: src.net, group: inbound-scan, block_cap: %d, block_cap_window: 1h}
respond: {action: block_ip, target: src.ip, min_level: medium, ttl: 1h}
`

const scanHammerRule = `
title: inbound hammering
id: t-hammer
level: low
detection:
  selection: {source.class: netflow, attrs.scope: inbound, dst.port: 22}
  threshold: {kind: count, count: 3, window: 10m, group_by: src.ip}
  condition: selection and threshold
auto_close: 2h
collapse: {by: src.net, group: inbound-scan, block_cap: %d, block_cap_window: 1h}
`

func flow(ts, ip string, port uint16) *model.Event {
	return &model.Event{TS: ts, Source: "netflow.core", SourceClass: "netflow", Action: "flow", SrcIP: ip, DstIP: "192.0.2.10", DstPort: port,
		Node: "192.0.2.1", Attrs: map[string]string{"scope": "inbound", "transport": "file"}}
}

// portScan — адрес стучится в n разных портов (не 22).
func portScan(ip string, n int) []*model.Event {
	var evs []*model.Event
	for i := 0; i < n; i++ {
		evs = append(evs, flow(fmt.Sprintf("2026-11-01 10:00:%02d.000", i), ip, uint16(1000+i)))
	}
	return evs
}

// hammer — адрес n раз в порт 22.
func hammer(ip string, n int) []*model.Event {
	var evs []*model.Event
	for i := 0; i < n; i++ {
		evs = append(evs, flow(fmt.Sprintf("2026-11-01 10:01:%02d.000", i), ip, 22))
	}
	return evs
}

func scanEngine(t *testing.T, f *fakeCH, capN int, rcfg respond.Config) *engine {
	t.Helper()
	dir := rulesDirWith(t, map[string]string{
		"scan.yml":   fmt.Sprintf(scanPortsRule, capN),
		"hammer.yml": fmt.Sprintf(scanHammerRule, capN),
	})
	return testEngine(t, f, dir, rcfg, "s", "s")
}

func (e *engine) applyEvents(events []*model.Event, now time.Time) (created, updated []*incidents.Incident) {
	dets, _ := eval.Evaluate(eval.Input{Rules: e.current(), Events: events, Now: now})
	created, updated, _ = e.reg.Apply(dets, now)
	return created, updated
}

func blockedIPs(rows []string) map[string]int {
	out := map[string]int{}
	for _, r := range rows {
		var row struct {
			IP       string `json:"ip"`
			Executor string `json:"executor"`
			OK       int    `json:"ok"`
		}
		if json.Unmarshal([]byte(r), &row) == nil && row.Executor == "ngfw.test" && row.OK == 1 {
			out[row.IP]++
		}
	}
	return out
}

// Два адреса одной /24 — один инцидент на подсеть и два блока: второй адрес
// блокируется, хотя первый уже решён.
func TestScanCollapseOneIncidentTwoBlocks(t *testing.T) {
	f := newFakeCH(t)
	srv, blocks := ngfw(t)
	e := scanEngine(t, f, 32, ipsConfig(srv))
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)

	created, _ := e.applyEvents(portScan("203.0.113.10", 4), now)
	if len(created) != 1 || created[0].ActorName != "203.0.113.0/24" || created[0].GroupKey != "collapse:inbound-scan:203.0.113.0/24" {
		t.Fatalf("первый адрес: %+v", created)
	}
	e.autoRespond(context.Background(), snapshotIncidents(created), now)
	f.waitRows(t, "response_log", 1)

	evs := append(portScan("203.0.113.10", 4), portScan("203.0.113.20", 5)...)
	created2, updated := e.applyEvents(evs, now.Add(time.Minute))
	if len(created2) != 0 || len(updated) != 1 || updated[0].IncidentID != created[0].IncidentID {
		t.Fatalf("второй адрес подсети завёл новый инцидент: created=%d updated=%d", len(created2), len(updated))
	}
	inc := updated[0]
	if len(inc.Members) != 2 || inc.EventCount != 9 {
		t.Fatalf("участники: %+v events=%d", inc.Members, inc.EventCount)
	}
	e.autoRespond(context.Background(), snapshotIncidents(updated), now.Add(time.Minute))
	rows := f.waitRows(t, "response_log", 2)
	if got := blockedIPs(rows); got["203.0.113.10"] != 1 || got["203.0.113.20"] != 1 || *blocks != 2 {
		t.Fatalf("блоки: %v rows=%v", got, rows)
	}
	// Повтор цикла без нового — ни нового блока, ни записи.
	e.autoRespond(context.Background(), snapshotIncidents(updated), now.Add(2*time.Minute))
	time.Sleep(50 * time.Millisecond)
	if *blocks != 2 {
		t.Fatalf("повторная блокировка: %d", *blocks)
	}
}

// Потолок новых блоков инцидента за окно: сверх него адрес не блокируется, а в
// журнал — пометка «решение за аналитиком».
func TestScanCollapseIncidentCap(t *testing.T) {
	f := newFakeCH(t)
	srv, blocks := ngfw(t)
	e := scanEngine(t, f, 2, ipsConfig(srv))
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
	var evs []*model.Event
	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		evs = append(evs, portScan(ip, 3)...)
	}
	created, _ := e.applyEvents(evs, now)
	if len(created) != 1 || len(created[0].Members) != 3 {
		t.Fatalf("инцидент: %+v", created)
	}
	e.autoRespond(context.Background(), snapshotIncidents(created), now)
	rows := f.waitRows(t, "response_log", 3)
	if *blocks != 2 || len(blockedIPs(rows)) != 2 {
		t.Fatalf("потолок 2: блоков %d rows=%v", *blocks, rows)
	}
	capped := 0
	for _, r := range rows {
		if strings.Contains(r, "потолок блокировок инцидента") && strings.Contains(r, "решение за аналитиком") {
			capped++
		}
	}
	if capped != 1 {
		t.Fatalf("пометка потолка: %v", rows)
	}
	// Окно потолка прошло, но адрес уже решён (capped) — сам не блокируется.
	e.autoRespond(context.Background(), snapshotIncidents(created), now.Add(2*time.Hour))
	time.Sleep(50 * time.Millisecond)
	if *blocks != 2 {
		t.Fatalf("capped-адрес заблокирован позже: %d", *blocks)
	}
}

// Скан портов и долбёжка одного адреса — один инцидент. Адрес, по которому
// сработала только долбёжка (без respond), не блокируется из-за соседа.
func TestScanCollapseRulesShareIncident(t *testing.T) {
	f := newFakeCH(t)
	srv, blocks := ngfw(t)
	e := scanEngine(t, f, 32, ipsConfig(srv))
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
	evs := append(portScan("192.0.2.77", 3), hammer("192.0.2.77", 3)...)
	evs = append(evs, hammer("192.0.2.88", 3)...)
	created, _ := e.applyEvents(evs, now)
	if len(created) != 1 {
		t.Fatalf("ждали один инцидент на подсеть, получено %d", len(created))
	}
	inc := created[0]
	if inc.RuleID != "t-scan" || inc.Level != "medium" {
		t.Fatalf("инцидент представляет старшее правило: rule=%s level=%s", inc.RuleID, inc.Level)
	}
	rulesOf := map[string]string{}
	for _, m := range inc.Members {
		rulesOf[m.IP] = strings.Join(m.Rules, ",")
	}
	if rulesOf["192.0.2.77"] != "t-hammer,t-scan" || rulesOf["192.0.2.88"] != "t-hammer" {
		t.Fatalf("правила участников: %v", rulesOf)
	}
	e.autoRespond(context.Background(), snapshotIncidents(created), now)
	rows := f.waitRows(t, "response_log", 1)
	time.Sleep(50 * time.Millisecond)
	if got := blockedIPs(f.rows("response_log")); got["192.0.2.77"] != 1 || got["192.0.2.88"] != 0 || *blocks != 1 {
		t.Fatalf("блоки: %v rows=%v", got, rows)
	}
}

// IPv6 склеивается по /48, IPv4 и IPv6 не смешиваются.
func TestScanCollapseIPv6(t *testing.T) {
	f := newFakeCH(t)
	e := scanEngine(t, f, 32, respond.Config{Mode: respond.ModeIDS})
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
	var evs []*model.Event
	for _, ip := range []string{"2001:db8:1:a::1", "2001:db8:1:b::2", "2001:db8:2::3", "203.0.113.5"} {
		evs = append(evs, portScan(ip, 3)...)
	}
	created, _ := e.applyEvents(evs, now)
	got := map[string]int{}
	for _, inc := range created {
		got[inc.ActorName] = len(inc.Members)
	}
	want := map[string]int{"2001:db8:1::/48": 2, "2001:db8:2::/48": 1, "203.0.113.0/24": 1}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("подсети: %v, ждали %v", got, want)
	}
}

// Рестарт: склеенный инцидент восстанавливается по group_key и members;
// записанный адрес не блокируется заново, новый адрес подсети — блокируется
// и дописывается в тот же инцидент.
func TestScanCollapseRestart(t *testing.T) {
	f := newFakeCH(t)
	srv, blocks := ngfw(t)
	e := scanEngine(t, f, 32, ipsConfig(srv))
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
	created, _ := e.applyEvents(portScan("203.0.113.10", 4), now)
	if len(created) != 1 {
		t.Fatal("нет инцидента")
	}
	// Строка incidents так, как её записал движок, и обратно — как после рестарта.
	raw, err := json.Marshal(created[0])
	if err != nil {
		t.Fatal(err)
	}
	var restored incidents.Incident
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"members":"[{`) || len(restored.Members) != 1 || restored.GroupKey == "" {
		t.Fatalf("members не пережил запись: %s", raw)
	}
	restored.Events = nil
	e.reg = incidents.NewRegistry(100, []incidents.Incident{restored})
	e.restoreRespState([]incidents.Incident{restored}, now)

	evs := append(portScan("203.0.113.10", 4), portScan("203.0.113.30", 3)...)
	created2, updated := e.applyEvents(evs, now.Add(time.Minute))
	if len(created2) != 0 || len(updated) != 1 || updated[0].IncidentID != restored.IncidentID || len(updated[0].Members) != 2 {
		t.Fatalf("после рестарта: created=%d updated=%+v", len(created2), updated)
	}
	e.autoRespond(context.Background(), snapshotIncidents(updated), now.Add(time.Minute))
	rows := f.waitRows(t, "response_log", 1)
	time.Sleep(50 * time.Millisecond)
	if got := blockedIPs(f.rows("response_log")); got["203.0.113.10"] != 0 || got["203.0.113.30"] != 1 || *blocks != 1 {
		t.Fatalf("блоки после рестарта: %v rows=%v", got, rows)
	}
}

// Открытый инцидент адреса, заведённый до склейки, задним числом не
// склеивается: его сработка дописывается в него же.
func TestScanCollapseLegacyIncidentKeepsUpdating(t *testing.T) {
	f := newFakeCH(t)
	e := scanEngine(t, f, 32, respond.Config{Mode: respond.ModeIDS})
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
	legacy := incidents.Incident{IncidentID: "INC-7", RuleID: "t-scan", RuleTitle: "inbound port scan", Level: "medium", Status: incidents.StatusNew,
		ActorName: "203.0.113.10", Node: "192.0.2.1", EventCount: 3, FirstTS: "2026-11-01 10:00:00.000", LastTS: "2026-11-01 10:00:02.000"}
	e.reg = incidents.NewRegistry(7, []incidents.Incident{legacy})
	created, updated := e.applyEvents(append(portScan("203.0.113.10", 5), portScan("203.0.113.20", 3)...), now)
	if len(updated) != 1 || updated[0].IncidentID != "INC-7" || updated[0].GroupKey != "" {
		t.Fatalf("старый инцидент адреса: %+v", updated)
	}
	if len(created) != 1 || created[0].ActorName != "203.0.113.0/24" || len(created[0].Members) != 1 || created[0].Members[0].IP != "203.0.113.20" {
		t.Fatalf("новый адрес подсети — в склеенный инцидент: %+v", created)
	}
}
