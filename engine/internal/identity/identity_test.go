package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
)

// fakeStore — хранилище в памяти: версии строк по ключу, как ReplacingMergeTree.
type fakeStore struct {
	persons map[string]Person
	aliases map[string]Alias // Key() → последняя версия
	deleted map[string]bool
	events  []*model.Event // InsertEvents: события нарушений политик
	calls   []string
	fail    string // имя метода, который должен вернуть ошибку
}

func newFakeStore() *fakeStore {
	return &fakeStore{persons: map[string]Person{}, aliases: map[string]Alias{}, deleted: map[string]bool{}}
}

func (f *fakeStore) UpsertIdentities(_ context.Context, ps []Person) error {
	f.calls = append(f.calls, "UpsertIdentities")
	if f.fail == "UpsertIdentities" {
		return errors.New("boom")
	}
	for _, p := range ps {
		f.persons[p.ID] = p
	}
	return nil
}

func (f *fakeStore) UpsertAliases(_ context.Context, as []Alias) error {
	f.calls = append(f.calls, "UpsertAliases")
	if f.fail == "UpsertAliases" {
		return errors.New("boom")
	}
	for _, a := range as {
		f.aliases[a.Key()] = a
		delete(f.deleted, a.Key())
	}
	return nil
}

func (f *fakeStore) DeleteAliases(_ context.Context, as []Alias) error {
	f.calls = append(f.calls, "DeleteAliases")
	for _, a := range as {
		f.deleted[a.Key()] = true
	}
	return nil
}

func (f *fakeStore) OpenAliases(_ context.Context, kind, value, person string) ([]Alias, error) {
	f.calls = append(f.calls, "OpenAliases")
	var out []Alias
	for k, a := range f.aliases {
		if f.deleted[k] || a.Kind != kind || a.Value != value || (person != "" && a.PersonID != person) || a.ValidTo != nil {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

func (f *fakeStore) AliasesBySource(_ context.Context, source string) ([]Alias, error) {
	f.calls = append(f.calls, "AliasesBySource")
	var out []Alias
	for k, a := range f.aliases {
		if !f.deleted[k] && a.Source == source {
			out = append(out, a)
		}
	}
	return out, nil
}

func (f *fakeStore) KnownPersons(_ context.Context, ids []string) (map[string]bool, error) {
	f.calls = append(f.calls, "KnownPersons")
	if f.fail == "KnownPersons" {
		return nil, errors.New("boom")
	}
	out := map[string]bool{}
	for _, id := range ids {
		if _, ok := f.persons[id]; ok {
			out[id] = true
		}
	}
	return out, nil
}

func (f *fakeStore) AliasesByPerson(_ context.Context, person, kind string) ([]Alias, error) {
	f.calls = append(f.calls, "AliasesByPerson")
	if f.fail == "AliasesByPerson" {
		return nil, errors.New("boom")
	}
	var out []Alias
	for k, a := range f.aliases {
		if !f.deleted[k] && a.PersonID == person && a.Kind == kind {
			out = append(out, a)
		}
	}
	return out, nil
}

func (f *fakeStore) InsertEvents(_ context.Context, events []*model.Event) error {
	f.calls = append(f.calls, "InsertEvents")
	if f.fail == "InsertEvents" {
		return errors.New("boom")
	}
	f.events = append(f.events, events...)
	return nil
}

func (f *fakeStore) alias(kind, value, person string) (Alias, bool) {
	for k, a := range f.aliases {
		if !f.deleted[k] && a.Kind == kind && a.Value == value && a.PersonID == person {
			return a, true
		}
	}
	return Alias{}, false
}

func TestNormalize(t *testing.T) {
	cases := []struct{ kind, in, want string }{
		{KindEmail, " I.Petrov@Example.ORG ", "i.petrov@example.org"},
		{KindLogin, "IPetrov", "ipetrov"},
		{KindHost, "WEB-01.Corp", "web-01.corp"},
		{KindIP, "010.077.000.011", ""}, // ведущие нули — не адрес
		{KindIP, "10.77.0.11", "10.77.0.11"},
		{KindIP, "2001:DB8:0:0:0:0:0:1", "2001:db8::1"},
		{KindIP, "::ffff:10.77.0.11", "10.77.0.11"},
		{KindIP, "fe80::1%eth0", "fe80::1"},
		{KindUID, " 4711 ", "4711"},
		{KindSID, "S-1-5-21-1", "S-1-5-21-1"},
		{KindPhone, "+7 (999) 123-45-67", "+79991234567"},
		{KindPhone, " +1-202-555-0143 ", "+12025550143"},
		{KindPhone, "+7", ""},                     // мало цифр
		{KindPhone, "79991234567", ""},            // без «+»
		{KindPhone, "+0999123456", ""},            // ведущий ноль
		{KindPhone, "+7999123456789012", ""},      // 16 цифр
		{KindPhone, "+7 999 123 45 67 доб 1", ""}, // буквы
		{"passport", "4510 123456", ""},           // неизвестный вид
		{KindEmail, "petrov", ""},
		{KindLogin, "", ""},
		{KindLogin, "two words", ""},
	}
	for _, c := range cases {
		got, err := Normalize(c.kind, c.in)
		if c.want == "" {
			if err == nil {
				t.Errorf("%s %q: ожидалась ошибка, получено %q", c.kind, c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s %q: %q, %v; ожидалось %q", c.kind, c.in, got, err, c.want)
		}
	}
	for _, id := range []string{"i.petrov", "svc-backup", "a_b", "0abc", strings.Repeat("a", 64)} {
		if !ValidPersonID(id) {
			t.Errorf("person_id %q должен быть допустим", id)
		}
	}
	for _, id := range []string{"", "I.Petrov", ".petrov", "иван", "a b", strings.Repeat("a", 65)} {
		if ValidPersonID(id) {
			t.Errorf("person_id %q должен быть отклонён", id)
		}
	}
}

const sampleYAML = `
persons:
  i.petrov:
    display: "Иван Петров"
    team: platform
    aliases:
      - {kind: email, value: I.Petrov@Example.org}
      - {kind: login, value: ipetrov}
      - {kind: ip, value: 10.77.0.11, from: 2026-10-01, to: 2026-10-20, confidence: 0.9, note: "ноутбук"}
      - {kind: ip, value: 10.77.0.42, from: 2026-10-15T09:00:00Z}
  svc-backup:
    kind: service
    aliases:
      - {kind: login, value: svc-backup}
`

func TestParseFile(t *testing.T) {
	set, err := Parse([]byte(sampleYAML))
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Persons) != 2 || set.Persons[0].ID != "i.petrov" || set.Persons[1].ID != "svc-backup" {
		t.Fatalf("персоны: %+v", set.Persons)
	}
	if set.Persons[0].Kind != PersonKind || set.Persons[0].Display != "Иван Петров" || set.Persons[0].Team != "platform" {
		t.Errorf("i.petrov: %+v", set.Persons[0])
	}
	if set.Persons[1].Kind != ServiceKind || set.Persons[1].Display != "svc-backup" {
		t.Errorf("svc-backup: display по умолчанию = id, kind service: %+v", set.Persons[1])
	}
	if len(set.Aliases) != 5 {
		t.Fatalf("алиасов %d: %+v", len(set.Aliases), set.Aliases)
	}
	a := set.Aliases
	if a[0].Value != "i.petrov@example.org" || !a[0].ValidFrom.Equal(Epoch) || a[0].ValidTo != nil || a[0].Confidence != 1 || a[0].Source != SourceYAML {
		t.Errorf("email: %+v", a[0])
	}
	if a[2].ValidFrom != time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) || a[2].ValidTo == nil || *a[2].ValidTo != time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC) {
		t.Errorf("интервал ip: %+v", a[2])
	}
	if a[2].Confidence != 0.9 || a[2].Note != "ноутбук" {
		t.Errorf("confidence/note: %+v", a[2])
	}
	if a[3].ValidFrom != time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC) || a[3].ValidTo != nil {
		t.Errorf("RFC3339 from: %+v", a[3])
	}
	if _, err := Parse(nil); err != nil {
		t.Errorf("пустой файл: %v", err)
	}
}

func TestParseFileErrors(t *testing.T) {
	cases := map[string]string{
		"persons:\n  I.Petrov:\n    aliases: []\n":                                                   "persons.I.Petrov",
		"persons:\n  a:\n    kind: robot\n":                                                          "persons.a.kind",
		"persons:\n  a:\n    aliases: [{kind: passport, value: 1}]\n":                                "aliases[0]",
		"persons:\n  a:\n    aliases: [{kind: phone, value: 89991234567}]\n":                         "aliases[0]",
		"persons:\n  a:\n    aliases: [{kind: ip, value: 10.0.0.300}]\n":                             "aliases[0]",
		"persons:\n  a:\n    aliases: [{kind: login, value: x, from: вчера}]\n":                      "aliases[0].from",
		"persons:\n  a:\n    aliases: [{kind: login, value: x, from: 2026-10-02, to: 2026-10-01}]\n": "aliases[0].to",
		"persons:\n  a:\n    aliases: [{kind: login, value: x, confidence: 1.5}]\n":                  "confidence",
		"persons:\n  a:\n    aliases: [{kind: login, value: x, colour: red}]\n":                      "colour",
		"persons:\n  a:\n    nickname: x\n":                                                          "nickname",
		"persons:\n  a:\n    aliases: [{kind: login, value: X}, {kind: login, value: x}]\n":          "уже объявлен",
	}
	for yml, want := range cases {
		_, err := Parse([]byte(yml))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: ожидалась ошибка с %q, получено %v", yml, want, err)
		}
	}
}

func ev(ts, action, actor, source string, attrs map[string]string) *model.Event {
	return &model.Event{TS: ts, Source: source, SourceClass: "identity", Action: action, ActorName: actor, Attrs: attrs}
}

func TestObserveAlias(t *testing.T) {
	st := newFakeStore()
	o := New(st)
	events := []*model.Event{
		ev("2026-10-13 08:00:00.000", "auth.login", "ipetrov", "idp.example", nil), // не алиас — мимо
		ev("2026-10-13 08:00:00.000", ActionAlias, "i.petrov", "idp.example", map[string]string{"alias_kind": "email", "alias_value": "I.Petrov@Example.org"}),
		ev("2026-10-13 08:00:01.000", ActionAlias, "i.petrov", "vpn.example", map[string]string{"alias_kind": "ip", "alias_value": "10.77.0.11", "valid_from": "2026-10-01", "confidence": "0.9", "note": "ноутбук"}),
		ev("2026-10-13 08:00:02.000", ActionAlias, "a.sidorov", "vpn.example", map[string]string{"alias_kind": "ip", "alias_value": "10.77.0.42", "valid_to": "2026-10-15 09:00:00"}),
	}
	s := o.Observe(context.Background(), events)
	if s.OK != 3 || s.Invalid != 0 || s.Errors != 0 {
		t.Fatalf("stats %+v", s)
	}
	if len(st.persons) != 2 || st.persons["i.petrov"].Display != "i.petrov" || st.persons["a.sidorov"].Kind != PersonKind {
		t.Errorf("персоны заведены из событий: %+v", st.persons)
	}
	a, ok := st.alias(KindEmail, "i.petrov@example.org", "i.petrov")
	if !ok || a.Source != "event:idp.example" || !a.ValidFrom.Equal(time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)) || a.ValidTo != nil || a.Confidence != 1 {
		t.Errorf("email: %+v ok=%v", a, ok)
	}
	a, ok = st.alias(KindIP, "10.77.0.11", "i.petrov")
	if !ok || !a.ValidFrom.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) || a.Confidence != 0.9 || a.Note != "ноутбук" {
		t.Errorf("ip с valid_from: %+v", a)
	}
	a, ok = st.alias(KindIP, "10.77.0.42", "a.sidorov")
	if !ok || a.ValidTo == nil || !a.ValidTo.Equal(time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("ip с valid_to: %+v", a)
	}
	// Повтор снимка: персона уже известна — KnownPersons не вызывается второй раз.
	calls := len(st.calls)
	o.Observe(context.Background(), events[1:2])
	for _, c := range st.calls[calls:] {
		if c == "KnownPersons" || c == "UpsertIdentities" {
			t.Errorf("повторный снимок не должен перепроверять персону: %v", st.calls[calls:])
		}
	}
	// Персону, заведённую файлом, событие не перезаписывает.
	st.persons["s.ivanova"] = Person{ID: "s.ivanova", Display: "Светлана Иванова", Kind: PersonKind}
	o.Observe(context.Background(), []*model.Event{ev("2026-10-13 08:00:03.000", ActionAlias, "s.ivanova", "idp.example", map[string]string{"alias_kind": "login", "alias_value": "sivanova"})})
	if st.persons["s.ivanova"].Display != "Светлана Иванова" {
		t.Errorf("display затёрт: %+v", st.persons["s.ivanova"])
	}
}

func TestObserveRevoke(t *testing.T) {
	st := newFakeStore()
	o := New(st)
	ctx := context.Background()
	o.Observe(ctx, []*model.Event{
		ev("2026-10-13 08:00:00.000", ActionAlias, "a.sidorov", "vpn.example", map[string]string{"alias_kind": "ip", "alias_value": "10.77.0.42"}),
	})
	// Отзыв без действующего алиаса — предупреждение, invalid.
	s := o.Observe(ctx, []*model.Event{
		ev("2026-10-15 09:00:00.000", ActionRevoke, "i.petrov", "vpn.example", map[string]string{"alias_kind": "ip", "alias_value": "10.77.0.42"}),
	})
	if s.OK != 0 || s.Invalid != 1 {
		t.Fatalf("отзыв чужого алиаса: %+v", s)
	}
	s = o.Observe(ctx, []*model.Event{
		ev("2026-10-15 09:00:00.000", ActionRevoke, "a.sidorov", "vpn.example", map[string]string{"alias_kind": "ip", "alias_value": "10.77.0.42"}),
		ev("2026-10-15 09:05:00.000", ActionAlias, "i.petrov", "vpn.example", map[string]string{"alias_kind": "ip", "alias_value": "10.77.0.42"}),
	})
	if s.OK != 2 || s.Invalid != 0 {
		t.Fatalf("передача адреса: %+v", s)
	}
	a, _ := st.alias(KindIP, "10.77.0.42", "a.sidorov")
	if a.ValidTo == nil || !a.ValidTo.Equal(time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)) || !a.ValidFrom.Equal(time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)) {
		t.Errorf("закрытый алиас: %+v", a)
	}
	b, _ := st.alias(KindIP, "10.77.0.42", "i.petrov")
	if b.ValidTo != nil || !b.ValidFrom.Equal(time.Date(2026, 10, 15, 9, 5, 0, 0, time.UTC)) {
		t.Errorf("новый алиас: %+v", b)
	}
	mid := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	late := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	if !a.ActiveAt(mid) || a.ActiveAt(late) || b.ActiveAt(mid) || !b.ActiveAt(late) || a.ActiveAt(*a.ValidTo) {
		t.Error("интервалы: valid_from <= ts < valid_to")
	}
	// Повторный отзыв — алиас уже закрыт.
	s = o.Observe(ctx, []*model.Event{
		ev("2026-10-15 09:10:00.000", ActionRevoke, "a.sidorov", "vpn.example", map[string]string{"alias_kind": "ip", "alias_value": "10.77.0.42"}),
	})
	if s.Invalid != 1 {
		t.Errorf("повторный отзыв: %+v", s)
	}
}

func TestObserveInvalid(t *testing.T) {
	st := newFakeStore()
	o := New(st)
	bad := []*model.Event{
		ev("2026-10-13 08:00:00.000", ActionAlias, "I.Petrov", "idp.example", map[string]string{"alias_kind": "login", "alias_value": "x"}),
		ev("2026-10-13 08:00:00.000", ActionAlias, "i.petrov", "idp.example", nil),
		ev("2026-10-13 08:00:00.000", ActionAlias, "i.petrov", "idp.example", map[string]string{"alias_kind": "ip", "alias_value": "not-an-ip"}),
		ev("2026-10-13 08:00:00.000", ActionAlias, "i.petrov", "idp.example", map[string]string{"alias_kind": "login"}),
		ev("2026-10-13 08:00:00.000", ActionAlias, "i.petrov", "idp.example", map[string]string{"alias_kind": "login", "alias_value": "x", "valid_from": "позавчера"}),
		ev("2026-10-13 08:00:00.000", ActionAlias, "i.petrov", "idp.example", map[string]string{"alias_kind": "login", "alias_value": "x", "confidence": "2"}),
		ev("2026-10-13 08:00:00.000", ActionAlias, "i.petrov", "idp.example", map[string]string{"alias_kind": "login", "alias_value": "x", "valid_to": "2026-10-01"}),
		ev("garbage", ActionAlias, "i.petrov", "idp.example", map[string]string{"alias_kind": "login", "alias_value": "x"}),
		ev("2026-10-13 08:00:00.000", ActionRevoke, "i.petrov", "idp.example", map[string]string{"alias_kind": "ip", "alias_value": "nope"}),
	}
	s := o.Observe(context.Background(), bad)
	if s.Invalid != len(bad) || s.OK != 0 || len(st.aliases) != 0 || len(st.persons) != 0 {
		t.Fatalf("stats %+v, aliases %d, persons %d", s, len(st.aliases), len(st.persons))
	}
	var b strings.Builder
	o.WriteMetrics(&b)
	if !strings.Contains(b.String(), `argus_engine_identity_alias_total{result="invalid"} 9`) {
		t.Errorf("метрика: %s", b.String())
	}
	// Ошибка хранилища — error, не паника.
	st.fail = "UpsertAliases"
	s = o.Observe(context.Background(), []*model.Event{ev("2026-10-13 08:00:00.000", ActionAlias, "i.petrov", "idp.example", map[string]string{"alias_kind": "login", "alias_value": "x"})})
	if s.Errors != 1 || s.OK != 0 {
		t.Errorf("ошибка хранилища: %+v", s)
	}
	if New(nil).Observe(context.Background(), bad).Invalid != 0 {
		t.Error("без хранилища — no-op")
	}
}

func TestSyncFileMarksDeleted(t *testing.T) {
	st := newFakeStore()
	o := New(st)
	ctx := context.Background()
	set, err := Parse([]byte(sampleYAML))
	if err != nil {
		t.Fatal(err)
	}
	if err := o.SyncFile(ctx, set); err != nil {
		t.Fatal(err)
	}
	if len(st.persons) != 2 || len(st.aliases) != 5 || len(st.deleted) != 0 {
		t.Fatalf("первая синхронизация: persons %d aliases %d deleted %d", len(st.persons), len(st.aliases), len(st.deleted))
	}
	// Алиас из события того же человека файл не трогает.
	o.Observe(ctx, []*model.Event{ev("2026-10-13 08:00:00.000", ActionAlias, "i.petrov", "vpn.example", map[string]string{"alias_kind": "ip", "alias_value": "10.77.0.77"})})
	// Из файла пропал ip 10.77.0.11 и весь svc-backup; у email сменился from.
	set2, err := Parse([]byte(`
persons:
  i.petrov:
    display: "Иван Петров"
    aliases:
      - {kind: email, value: i.petrov@example.org, from: 2026-01-01}
      - {kind: login, value: ipetrov}
      - {kind: ip, value: 10.77.0.42, from: 2026-10-15T09:00:00Z}
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := o.SyncFile(ctx, set2); err != nil {
		t.Fatal(err)
	}
	wantDeleted := []Alias{
		{Kind: KindIP, Value: "10.77.0.11", ValidFrom: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), PersonID: "i.petrov"},
		{Kind: KindLogin, Value: "svc-backup", ValidFrom: Epoch, PersonID: "svc-backup"},
		{Kind: KindEmail, Value: "i.petrov@example.org", ValidFrom: Epoch, PersonID: "i.petrov"},
	}
	for _, a := range wantDeleted {
		if !st.deleted[a.Key()] {
			t.Errorf("должен быть помечен удалённым: %s %s", a.Kind, a.Value)
		}
	}
	if len(st.deleted) != len(wantDeleted) {
		t.Errorf("удалено %d, ожидалось %d", len(st.deleted), len(wantDeleted))
	}
	if _, ok := st.alias(KindIP, "10.77.0.77", "i.petrov"); !ok {
		t.Error("алиас из события не должен удаляться синхронизацией файла")
	}
	if _, ok := st.persons["svc-backup"]; !ok {
		t.Error("персоны файлом не удаляются")
	}
	if Signature("") != "" || Signature("/nonexistent/identities.yml") != "" {
		t.Error("подпись отсутствующего файла — пустая")
	}
}

// Операции применяются по времени события: выдача 08:00 → отзыв 09:00 →
// выдача 10:00 в одном батче оставляет второй интервал открытым; отзыв не
// трогает интервалы, начатые после него.
func TestObserveOrderedWithinBatch(t *testing.T) {
	st := newFakeStore()
	o := New(st)
	batch := []*model.Event{ // нарочно не по порядку
		ev("2026-10-15 10:00:00.000", ActionAlias, "i.petrov", "vpn.example", map[string]string{"alias_kind": "ip", "alias_value": "10.77.0.42"}),
		ev("2026-10-15 09:00:00.000", ActionRevoke, "i.petrov", "vpn.example", map[string]string{"alias_kind": "ip", "alias_value": "10.77.0.42"}),
		ev("2026-10-15 08:00:00.000", ActionAlias, "i.petrov", "vpn.example", map[string]string{"alias_kind": "ip", "alias_value": "10.77.0.42"}),
	}
	s := o.Observe(context.Background(), batch)
	if s.OK != 3 || s.Invalid != 0 || s.Errors != 0 || len(s.Retry) != 0 {
		t.Fatalf("stats %+v", s)
	}
	var open, closed []Alias
	for k, a := range st.aliases {
		if st.deleted[k] {
			continue
		}
		if a.ValidTo == nil {
			open = append(open, a)
		} else {
			closed = append(closed, a)
		}
	}
	if len(open) != 1 || !open[0].ValidFrom.Equal(time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("открытым должен остаться интервал с 10:00: %+v", open)
	}
	if len(closed) != 1 || !closed[0].ValidFrom.Equal(time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)) || !closed[0].ValidTo.Equal(time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("интервал 08:00 закрыт в 09:00: %+v", closed)
	}
}

// Сбой хранилища: события возвращаются в Retry и применяются повторным вызовом.
func TestObserveRetryAfterStoreError(t *testing.T) {
	st := newFakeStore()
	o := New(st)
	ctx := context.Background()
	events := []*model.Event{
		ev("2026-10-13 08:00:00.000", ActionAlias, "i.petrov", "idp.example", map[string]string{"alias_kind": "login", "alias_value": "ipetrov"}),
		ev("2026-10-13 08:00:01.000", ActionAlias, "a.sidorov", "idp.example", map[string]string{"alias_kind": "login", "alias_value": "asidorov"}),
		ev("2026-10-13 08:00:02.000", ActionAlias, "i.petrov", "idp.example", map[string]string{"alias_kind": "login"}), // невалидное — не повторяется
	}
	st.fail = "UpsertAliases"
	s := o.Observe(ctx, events)
	if s.Errors != 2 || s.Invalid != 1 || len(s.Retry) != 2 || len(st.aliases) != 0 {
		t.Fatalf("stats %+v, aliases %d", s, len(st.aliases))
	}
	st.fail = ""
	s = o.Observe(ctx, s.Retry)
	if s.OK != 2 || len(s.Retry) != 0 || len(st.aliases) != 2 {
		t.Fatalf("повтор: %+v, aliases %d", s, len(st.aliases))
	}
}

// Ошибка записи выдачи останавливает батч: отзыв после неё не выполняется
// (иначе он не нашёл бы алиас и был бы отброшен как invalid, а повтор выдачи
// оставил бы алиас открытым); весь остаток уходит в Retry в порядке обработки
// и применяется повтором целиком.
func TestObserveAbortsBatchOnFlushError(t *testing.T) {
	st := newFakeStore()
	o := New(st)
	ctx := context.Background()
	batch := []*model.Event{
		ev("2026-10-15 08:00:00.000", ActionAlias, "a.sidorov", "vpn.example", map[string]string{"alias_kind": "ip", "alias_value": "10.77.0.42"}),
		ev("2026-10-15 09:00:00.000", ActionRevoke, "a.sidorov", "vpn.example", map[string]string{"alias_kind": "ip", "alias_value": "10.77.0.42"}),
		ev("2026-10-15 09:05:00.000", ActionAlias, "i.petrov", "vpn.example", map[string]string{"alias_kind": "ip", "alias_value": "10.77.0.42"}),
	}
	st.fail = "UpsertAliases"
	s := o.Observe(ctx, batch)
	if s.Invalid != 0 || s.OK != 0 || len(s.Retry) != 3 || len(st.aliases) != 0 {
		t.Fatalf("после ошибки записи отзыв не должен выполняться: %+v", s)
	}
	for i, e := range s.Retry {
		if e != batch[i] {
			t.Fatalf("Retry в порядке обработки: %d → %s %s", i, e.TS, e.Action)
		}
	}
	calls := strings.Join(st.calls, ",")
	if strings.Contains(calls, "OpenAliases") {
		t.Fatalf("отзыв после ошибки flush не должен ходить в хранилище: %s", calls)
	}
	st.fail = ""
	s = o.Observe(ctx, s.Retry)
	if s.OK != 3 || s.Invalid != 0 || len(s.Retry) != 0 {
		t.Fatalf("повтор остатка: %+v", s)
	}
	a, _ := st.alias(KindIP, "10.77.0.42", "a.sidorov")
	b, _ := st.alias(KindIP, "10.77.0.42", "i.petrov")
	if a.ValidTo == nil || !a.ValidTo.Equal(time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)) || b.ValidTo != nil {
		t.Fatalf("после повтора: a=%+v b=%+v", a, b)
	}
	// Ошибка на отзыве: он и всё после него — в Retry, записанные выдачи — нет.
	st2 := newFakeStore()
	o2 := New(st2)
	o2.Observe(ctx, batch[:1])
	st2.fail = "UpsertAliases" // отзыв переписывает строку тем же UpsertAliases
	s = o2.Observe(ctx, batch[1:])
	if len(s.Retry) != 2 || s.Retry[0] != batch[1] || s.Retry[1] != batch[2] || s.Errors != 1 {
		t.Fatalf("ошибка отзыва: %+v", s)
	}
}
