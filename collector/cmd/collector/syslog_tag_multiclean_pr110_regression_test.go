package main

import (
	"testing"

	"github.com/devitex-soft/argus/collector/internal/listen"
	"github.com/devitex-soft/argus/collector/internal/model"
	"github.com/devitex-soft/argus/collector/internal/normalize"
	"github.com/devitex-soft/argus/collector/internal/parse"
)

// Syslog принимает произвольные байты. При удалении C0 из "ta\xc2\x00\x80g"
// возникает C1 U+0080, удаляемый следующим проходом Clean. Поэтому ключ SD
// может превратиться в tag уже ПОСЛЕ восстановления APP-NAME. Дополнительные
// вложенные C1 проверяют также восстановление перед последним Sanitize.
func TestPR110RejectedTagSurvivesRepeatedSDKeyCleaning(t *testing.T) {
	const app = "daemon/path"
	const origin = `[origin@32473 ip="192.0.2.30"]`
	for _, tc := range []struct{ name, key string }{
		{"literal", "tag"},
		{"del", "ta\x7fg"},
		{"c1", "ta\xc2\x80g"},
		{"c1_after_c0_removal", "ta\xc2\x00\x80g"},
		{"nested_c1", "ta\xc2\xc2\x00\x80\x80g"},
		{"twice_nested_c1", "ta\xc2\xc2\xc2\x00\x80\x80\x80g"},
	} {
		line := "<30>1 2026-11-01T12:00:00Z host-01 " + app + " 12 event-1 [" + tc.key + "]" + origin + " hello"
		sl, err := parse.ParseSyslog(line)
		if err != nil || sl.AppName != app {
			t.Fatalf("syslog fixture: err=%v app=%q", err, sl.AppName)
		}
		if _, ok := sl.Structured[tc.key]; !ok {
			t.Fatalf("fixture SD key %q was not accepted", tc.key)
		}
		for _, stage := range []struct {
			name string
			run  func(*testing.T) model.Event
		}{
			{"normalizer", func(*testing.T) model.Event { return (&normalize.Normalizer{}).FromSyslog(sl, line) }},
			{"dispatcher", func(t *testing.T) model.Event {
				t.Helper()
				e, ok := parseSyslogLine(&normalize.Normalizer{}, nil, line, listen.Peer{
					Addr: "192.0.2.40", Transport: "udp",
				})
				if !ok {
					t.Fatal("dispatcher rejected the syslog fixture")
				}
				return e
			}},
		} {
			t.Run(tc.name+"/"+stage.name, func(t *testing.T) {
				// Sanitize переименовывает ключи во время range по map: проверяем
				// несколько порядков обхода, требуя инвариант в каждом из них.
				for attempt := 0; attempt < 128; attempt++ {
					e := stage.run(t)
					if e.Source != "syslog.generic" {
						t.Fatalf("source=%q, want syslog.generic", e.Source)
					}
					if e.Attrs["tag"] != app {
						t.Fatalf("attempt %d: SD key %q overwrote APP-NAME: tag=%q, want %q; attrs=%q",
							attempt, tc.key, e.Attrs["tag"], app, e.Attrs)
					}
					if e.Raw != line || e.Attrs["origin@32473.ip"] != "192.0.2.30" {
						t.Fatal("raw evidence or unrelated structured data changed")
					}
				}
			})
		}
	}
}
