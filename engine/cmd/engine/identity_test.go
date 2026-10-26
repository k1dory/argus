package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/respond"
)

// Алиасы из сырого потока событий попадают в identity_aliases, персона
// заводится, невалидные события не ломают проход; счётчик виден в /metrics.
func TestObserveIdentitiesFromEvents(t *testing.T) {
	f := newFakeCH(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), respond.Config{}, "tok", "tok")
	events := []*model.Event{
		{TS: "2026-10-13 08:00:00.000", Source: "idp.example", SourceClass: "identity", Action: "identity.alias", ActorName: "i.petrov",
			Attrs: map[string]string{"alias_kind": "email", "alias_value": "I.Petrov@Example.org"}},
		{TS: "2026-10-13 08:00:01.000", Source: "vpn.example", SourceClass: "identity", Action: "identity.alias", ActorName: "i.petrov",
			Attrs: map[string]string{"alias_kind": "ip", "alias_value": "10.77.0.11"}},
		{TS: "2026-10-13 08:00:02.000", Source: "vpn.example", SourceClass: "identity", Action: "identity.alias", ActorName: "Bad Actor",
			Attrs: map[string]string{"alias_kind": "ip", "alias_value": "10.77.0.12"}},
		{TS: "2026-10-13 08:00:03.000", Source: "syslog.sshd", SourceClass: "syslog", Action: "auth.ssh", ActorName: "ipetrov", SrcIP: "10.77.0.11"},
	}
	e.observeIdentities(context.Background(), events)
	persons := f.rows("identities")
	if len(persons) != 1 || !strings.Contains(persons[0], `"person_id":"i.petrov"`) || !strings.Contains(persons[0], `"display":"i.petrov"`) {
		t.Fatalf("identities: %v", persons)
	}
	aliases := f.rows("identity_aliases")
	if len(aliases) != 2 {
		t.Fatalf("identity_aliases: %v", aliases)
	}
	var row map[string]any
	if err := json.Unmarshal([]byte(aliases[0]), &row); err != nil {
		t.Fatal(err)
	}
	if row["alias_value"] != "i.petrov@example.org" || row["source"] != "event:idp.example" || row["valid_from"] != "2026-10-13 08:00:00.000" || row["valid_to"] != nil || row["deleted"] != float64(0) {
		t.Errorf("строка алиаса: %v", row)
	}
	code, body := do(t, e.handler(), http.MethodGet, "/metrics", "tok", "")
	if code != 200 || !strings.Contains(body, `argus_engine_identity_alias_total{result="ok"} 2`) || !strings.Contains(body, `argus_engine_identity_alias_total{result="invalid"} 1`) {
		t.Errorf("/metrics %d:\n%s", code, body)
	}
}

// IDENTITIES_FILE синхронизируется по отпечатку: первый проход пишет персоны и
// алиасы, неизменённый файл второй раз не пишется, POST /reload — принудительно.
func TestMaybeSyncIdentitiesFile(t *testing.T) {
	f := newFakeCH(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), respond.Config{}, "tok", "tok")
	path := filepath.Join(t.TempDir(), "identities.yml")
	if err := os.WriteFile(path, []byte("persons:\n  i.petrov:\n    display: Иван Петров\n    team: platform\n    aliases:\n      - {kind: login, value: IPetrov}\n      - {kind: ip, value: 10.77.0.42, from: 2026-10-15}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.identFile = path
	ctx := context.Background()
	e.maybeSyncIdentities(ctx, false)
	if rows := f.rows("identities"); len(rows) != 1 || !strings.Contains(rows[0], `"display":"Иван Петров"`) {
		t.Fatalf("identities: %v", rows)
	}
	aliases := f.rows("identity_aliases")
	if len(aliases) != 2 || !strings.Contains(aliases[0], `"source":"yaml"`) || !strings.Contains(aliases[0], `"alias_value":"ipetrov"`) || !strings.Contains(aliases[1], `"valid_from":"2026-10-15 00:00:00.000"`) {
		t.Fatalf("identity_aliases: %v", aliases)
	}
	e.maybeSyncIdentities(ctx, false)
	if len(f.rows("identity_aliases")) != 2 {
		t.Error("неизменённый файл не должен перезаписываться")
	}
	if code, _ := do(t, e.handler(), http.MethodPost, "/reload", "tok", ""); code != http.StatusAccepted {
		t.Fatalf("/reload: %d", code)
	}
	if len(f.rows("identity_aliases")) != 4 {
		t.Error("/reload должен перечитать файл принудительно")
	}
	// Битый файл — прежние алиасы остаются, записи нет.
	if err := os.WriteFile(path, []byte("persons:\n  i.petrov:\n    colour: red\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.maybeSyncIdentities(ctx, true)
	if len(f.rows("identity_aliases")) != 4 {
		t.Error("ошибка разбора не должна ничего записывать")
	}
	// Без IDENTITIES_FILE — no-op.
	e.identFile = ""
	e.maybeSyncIdentities(ctx, true)
}

// Сбой записи алиасов не теряет события: они повторяются на следующем цикле,
// очередь повтора ограничена.
func TestObserveIdentitiesRetriesOnStoreError(t *testing.T) {
	f := newFakeCH(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), respond.Config{}, "tok", "tok")
	ev := &model.Event{TS: "2026-10-13 08:00:00.000", Source: "idp.example", SourceClass: "identity", Action: "identity.alias", ActorName: "i.petrov",
		Attrs: map[string]string{"alias_kind": "login", "alias_value": "ipetrov"}}
	f.mu.Lock()
	f.fail["identity_aliases"] = true
	f.mu.Unlock()
	e.observeIdentities(context.Background(), []*model.Event{ev})
	if len(e.identRetry) != 1 || len(f.rows("identity_aliases")) != 0 {
		t.Fatalf("событие должно ждать повтора: retry=%d rows=%d", len(e.identRetry), len(f.rows("identity_aliases")))
	}
	f.mu.Lock()
	f.fail["identity_aliases"] = false
	f.mu.Unlock()
	e.observeIdentities(context.Background(), nil) // следующий цикл без новых событий
	if len(e.identRetry) != 0 || len(f.rows("identity_aliases")) != 1 {
		t.Fatalf("повтор не применился: retry=%d rows=%v", len(e.identRetry), f.rows("identity_aliases"))
	}
	// Переполнение очереди: остаются последние identRetryMax.
	f.mu.Lock()
	f.fail["identity_aliases"] = true
	f.mu.Unlock()
	many := make([]*model.Event, identRetryMax+5)
	for i := range many {
		many[i] = &model.Event{TS: "2026-10-13 08:00:00.000", Source: "idp.example", Action: "identity.alias", ActorName: "i.petrov",
			Attrs: map[string]string{"alias_kind": "uid", "alias_value": strconv.Itoa(i)}}
	}
	e.observeIdentities(context.Background(), many)
	if len(e.identRetry) != identRetryMax || e.identRetry[0].Attrs["alias_value"] != "5" {
		t.Fatalf("очередь повтора: %d, первое %s", len(e.identRetry), e.identRetry[0].Attrs["alias_value"])
	}
}

// Политики из IDENTITIES_FILE действуют на алиасы из событий: нарушение
// пишется событием argus.identity / identity.policy.violation в журнал
// (откуда его читают правила), алиас при reject не записывается, счётчик — в /metrics.
func TestIdentityPoliciesEmitViolationEvents(t *testing.T) {
	f := newFakeCH(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), respond.Config{}, "tok", "tok")
	path := filepath.Join(t.TempDir(), "identities.yml")
	yml := "persons:\n  i.petrov:\n    aliases:\n      - {kind: email, value: i.petrov@example.org}\n" +
		"policies:\n  email: { sources: [], on_violation: reject }\n  ip: { sources: [\"event:vpn.*\"], on_violation: flag }\n"
	if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	e.identFile = path
	ctx := context.Background()
	e.maybeSyncIdentities(ctx, false)
	if len(f.rows("identity_aliases")) != 1 || len(f.rows("events")) != 0 {
		t.Fatalf("файл проходит без политик: aliases %v events %v", f.rows("identity_aliases"), f.rows("events"))
	}
	e.observeIdentities(ctx, []*model.Event{
		{TS: "2026-10-20 10:00:00.000", Source: "idp.example", SourceClass: "identity", Action: "identity.alias", ActorName: "i.petrov",
			Attrs: map[string]string{"alias_kind": "email", "alias_value": "other@example.org"}},
		{TS: "2026-10-20 10:00:01.000", Source: "idp.example", SourceClass: "identity", Action: "identity.alias", ActorName: "i.petrov",
			Attrs: map[string]string{"alias_kind": "ip", "alias_value": "10.77.0.77"}},
	})
	aliases := f.rows("identity_aliases")
	if len(aliases) != 2 || !strings.Contains(aliases[1], `"alias_value":"10.77.0.77"`) || !strings.Contains(aliases[1], `"note":"policy:sources"`) {
		t.Fatalf("reject не пишется, flag пишется с пометкой: %v", aliases)
	}
	events := f.rows("events")
	if len(events) != 2 {
		t.Fatalf("события нарушений: %v", events)
	}
	var row map[string]any
	if err := json.Unmarshal([]byte(events[0]), &row); err != nil {
		t.Fatal(err)
	}
	attrs, _ := row["attrs"].(map[string]any)
	if row["source"] != "argus.identity" || row["action"] != "identity.policy.violation" || row["outcome"] != "failure" || row["severity"] != float64(6) ||
		row["actor_name"] != "i.petrov" || row["object"] != "email:other@example.org" || row["value"] != float64(1) || row["unit"] != "count" ||
		attrs["policy"] != "email" || attrs["rule"] != "sources" || attrs["source"] != "idp.example" || attrs["action_taken"] != "reject" {
		t.Errorf("событие нарушения: %v", row)
	}
	code, body := do(t, e.handler(), http.MethodGet, "/metrics", "tok", "")
	if code != 200 || !strings.Contains(body, `argus_engine_identity_policy_total{rule="sources",action="reject"} 1`) ||
		!strings.Contains(body, `argus_engine_identity_policy_total{rule="sources",action="flag"} 1`) {
		t.Errorf("/metrics %d:\n%s", code, body)
	}
}
