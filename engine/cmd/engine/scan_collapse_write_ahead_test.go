package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
)

// Контракт записи вперёд (вместо TestPR49FollowupLostResponseInsertDoesNotResetCap и
// TestPR49Round3LostInsertStillReservesCapacity из ревью codex: их предпосылка —
// блок на NGFW без следа в журнале — противоречит требованию аудита). Каждый блок
// адреса склеенного инцидента предваряется записью-резервом в response_log.

// (а) Резерв не записался — блоков нет, место не занято, адрес ждёт. Когда
// ClickHouse снова принимает, следующая попытка (не раньше паузы) блокирует.
func TestWriteAheadReserveFailureBlocksNothing(t *testing.T) {
	f := newFakeCH(t)
	srv, blocks := pr49NGFW(t)
	e := scanEngine(t, f, 32, ipsConfig(srv))
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
	var events []*model.Event
	for i := 1; i <= 3; i++ {
		events = append(events, pr49Round3Scan(fmt.Sprintf("203.0.113.%d", i), 3, now.Add(-time.Second))...)
	}
	created, _ := e.applyEvents(events, now)
	if len(created) != 1 {
		t.Fatal("fixture must create one subnet incident")
	}
	id := created[0].IncidentID
	f.mu.Lock()
	f.fail["response_log"] = true
	f.mu.Unlock()
	e.autoRespond(context.Background(), snapshotIncidents(created), now)
	if blocks.Load() != 0 || len(e.respCap[id]) != 0 || len(f.rows("response_log")) != 0 {
		t.Fatalf("без записанного резерва блоков быть не должно: blocks=%d slots=%d", blocks.Load(), len(e.respCap[id]))
	}
	f.mu.Lock()
	f.fail["response_log"] = false
	f.mu.Unlock()
	// До паузы — без новой попытки.
	e.autoRespond(context.Background(), snapshotIncidents(created), now.Add(10*time.Second))
	if blocks.Load() != 0 {
		t.Fatalf("повтор раньше паузы: %d", blocks.Load())
	}
	e.autoRespond(context.Background(), snapshotIncidents(created), now.Add(time.Minute))
	if blocks.Load() != 3 || len(e.respCap[id]) != 3 {
		t.Fatalf("после восстановления ClickHouse: blocks=%d slots=%d", blocks.Load(), len(e.respCap[id]))
	}
	reserves := 0
	for _, r := range f.rows("response_log") {
		if strings.Contains(r, `"detail":"резерв:`) {
			reserves++
		}
	}
	if reserves != 3 {
		t.Fatalf("резервов в журнале %d, ждали 3", reserves)
	}
}

// (б) Резерв записан, итог после исполнителей — нет. После рестарта адрес считается
// заблокированным: место занято, повторного блока нет; потолок не сбрасывается.
func TestWriteAheadReserveWithoutOutcomeHoldsSlot(t *testing.T) {
	f := newFakeCH(t)
	srv, blocks := pr49NGFW(t)
	e := scanEngine(t, f, 32, ipsConfig(srv))
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
	var events []*model.Event
	for i := 1; i <= 32; i++ {
		events = append(events, pr49Round3Scan(fmt.Sprintf("203.0.113.%d", i), 3, now.Add(-time.Second))...)
	}
	created, _ := e.applyEvents(events, now)
	if len(created) != 1 {
		t.Fatal("fixture must create one subnet incident")
	}
	old := pr49PersistedIncident(t, created[0])
	f.mu.Lock()
	f.failIf = func(table, body string) bool {
		return table == "response_log" && !strings.Contains(body, `"detail":"резерв:`)
	}
	f.mu.Unlock()
	e.autoRespond(context.Background(), snapshotIncidents(created), now)
	if blocks.Load() != 32 || len(f.rows("response_log")) != 32 {
		t.Fatalf("фикстура: 32 блока, в журнале только 32 резерва: blocks=%d rows=%d", blocks.Load(), len(f.rows("response_log")))
	}
	f.mu.Lock()
	f.failIf = nil
	f.mu.Unlock()
	pr49FollowupSaveResponses(f)
	restarted := scanEngine(t, f, 32, ipsConfig(srv))
	restarted.reg = incidents.NewRegistry(100, []incidents.Incident{old})
	restarted.restoreRespState([]incidents.Incident{old}, now.Add(time.Minute))
	if st := restarted.respStatus(old.IncidentID + "|203.0.113.1"); st != "done" {
		t.Fatalf("резерв без итога — сомнительный блок, повтора нет: state=%q", st)
	}
	// Те же адреса снова сканируют, плюс новый: ни повторных блоков, ни нового сверх потолка.
	events = nil
	for i := 1; i <= 33; i++ {
		events = append(events, pr49Round3Scan(fmt.Sprintf("203.0.113.%d", i), 4, now.Add(2*time.Minute))...)
	}
	_, updated := restarted.applyEvents(events, now.Add(2*time.Minute+time.Second))
	if len(updated) != 1 || updated[0].IncidentID != old.IncidentID {
		t.Fatal("сканы должны дописаться в восстановленный инцидент")
	}
	restarted.autoRespond(context.Background(), snapshotIncidents(updated), now.Add(2*time.Minute+time.Second))
	if got := blocks.Load(); got != 32 || len(restarted.respCap[old.IncidentID]) != 32 {
		t.Fatalf("резервы без итога должны держать потолок: blocks=%d slots=%d", got, len(restarted.respCap[old.IncidentID]))
	}
}
