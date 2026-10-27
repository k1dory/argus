package identity

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/model"
)

// Поставляемый identities.yml разбирается, телефон i.petrov приведён к E.164,
// а демонстрационная фикстура identity.ndjson под его политиками не даёт ни
// нарушений, ни отклонённых событий: иначе `make demo` заводил бы инциденты
// по rules/ops/identity-*.yml на чистых данных.
func TestRepoIdentitiesFileAndFixture(t *testing.T) {
	set, err := LoadFile("../../../identities.yml")
	if err != nil {
		t.Fatal(err)
	}
	var phone *Alias
	for i := range set.Aliases {
		if set.Aliases[i].Kind == KindPhone && set.Aliases[i].PersonID == "i.petrov" {
			phone = &set.Aliases[i]
		}
	}
	if phone == nil || phone.Value != "+79991234567" {
		t.Fatalf("телефон i.petrov: %+v", phone)
	}
	for _, kind := range []string{KindIP, KindHost, KindEmail, KindPhone} {
		if _, ok := set.Policies[kind]; !ok {
			t.Errorf("нет политики для %s", kind)
		}
	}
	f, err := os.Open("../../../fixtures/events/identity.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var events []*model.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var e model.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		e.Ensure()
		events = append(events, &e)
	}
	st := newFakeStore()
	o := New(st)
	ctx := context.Background()
	if err := o.SyncFile(ctx, set); err != nil {
		t.Fatal(err)
	}
	s := o.Observe(ctx, events)
	if s.Invalid != 0 || s.Errors != 0 || s.Policy != 0 || len(st.events) != 0 {
		t.Fatalf("фикстура под политиками файла: %+v, нарушений %d", s, len(st.events))
	}
	// Телефон уже выдан файлом и действует: снимок из otp.example без valid_from —
	// повтор, а не второй интервал. Алиас в карте один, источник — файл.
	var phones int
	for k, a := range st.aliases {
		if !st.deleted[k] && a.Kind == KindPhone && a.Value == "+79991234567" && a.PersonID == "i.petrov" {
			phones++
			if a.Source != SourceYAML {
				t.Errorf("телефон должен остаться алиасом файла, получил source %q", a.Source)
			}
		}
	}
	if phones != 1 || s.Repeated == 0 {
		t.Errorf("телефон: строк %d (ожидалась одна), повторов снимков %d (ожидался хотя бы один)", phones, s.Repeated)
	}
	// Событие OTP: actor_name — сам номер, как login у ssh.
	var otp bool
	for _, e := range events {
		if e.Action == "auth.otp" && e.ActorName == "+79991234567" && e.Source == "otp.example" {
			otp = true
		}
	}
	if !otp {
		t.Error("в фикстуре нет события auth.otp с номером телефона в actor_name")
	}
}
