package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/listen"
	"github.com/devitex-soft/argus/collector/internal/model"
	"github.com/devitex-soft/argus/collector/internal/normalize"
	"github.com/devitex-soft/argus/collector/internal/parse"
)

func pr110Round2NestedC1(depth int) string {
	return strings.Repeat("\xc2", depth) + "\x00" + strings.Repeat("\x80", depth)
}

// LEEF принимает произвольные ключи. Ключ с восемью вложенными C1 после
// Ensure нормализатора ещё не равен peer/peer_cn/scope, поэтому присваивание
// или удаление служебного атрибута его не затрагивает. Финальный Sanitize
// не должен превращать этот остаток в поддельное происхождение события.
// attrs.peer используется engine/respond.TrustedEvent для trusted_sources.
func TestPR110Round2NestedAttrsCannotOverwriteProvenance(t *testing.T) {
	peer := listen.Peer{Addr: "192.0.2.40", Transport: "tcp", Format: parse.FormatLEEF}
	for _, depth := range []int{8, 15} {
		for _, tc := range []struct {
			name, prefix, suffix, forged, want string
		}{
			{"peer", "pe", "er", "192.0.2.77", peer.Addr},
			{"peer_cn", "peer_", "cn", "trusted-agent", ""},
			{"scope", "sc", "ope", "internal", ""},
		} {
			t.Run(fmt.Sprintf("%s/depth_%d", tc.name, depth), func(t *testing.T) {
				key := tc.prefix + pr110Round2NestedC1(depth) + tc.suffix
				line := "LEEF:1.0|UserGate|NGFW|7|deny|src=198.51.100.55\tdst=192.0.2.10\t" + key + "=" + tc.forged
				l, ok := parse.ParseLEEF(line)
				if !ok || l.Ext[key] != tc.forged {
					t.Fatalf("fixture did not retain the untrusted LEEF key: ok=%v ext=%q", ok, l.Ext)
				}
				for attempt := 0; attempt < 32; attempt++ {
					e, ok := parseSyslogLine(&normalize.Normalizer{}, nil, line, peer)
					if !ok || e.Source != "ngfw.usergate" || e.SrcIP != "198.51.100.55" || e.Raw != line {
						t.Fatalf("fixture dispatch changed: ok=%v event=%+v", ok, e)
					}
					if got := e.Attrs[tc.name]; got != tc.want {
						t.Fatalf("attempt %d: untrusted LEEF key replaced attrs.%s: got %q, want %q; attrs=%q",
							attempt, tc.name, got, tc.want, e.Attrs)
					}
				}
			})
		}
	}
}

// Продолжение тестов 8fedf75: их максимальная глубина равна трём, а дефект
// возвращается на границе восьми проходов и снова затирает отвергнутый TAG.
func TestPR110Round2DeepSDKeyPreservesRejectedTag(t *testing.T) {
	const app = "daemon/path"
	for _, depth := range []int{8, 15} {
		key := "ta" + pr110Round2NestedC1(depth) + "g"
		line := "<30>1 2026-11-01T12:00:00Z host-01 " + app + " 12 event-1 [" + key + "] hello"
		sl, err := parse.ParseSyslog(line)
		if err != nil || sl.AppName != app {
			t.Fatalf("syslog fixture: err=%v app=%q", err, sl.AppName)
		}
		if _, ok := sl.Structured[key]; !ok {
			t.Fatalf("fixture SD key %q was not accepted", key)
		}
		for _, stage := range []struct {
			name string
			run  func(*testing.T) model.Event
		}{
			{"normalizer", func(*testing.T) model.Event {
				return (&normalize.Normalizer{}).FromSyslog(sl, line)
			}},
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
			t.Run(fmt.Sprintf("%s/depth_%d", stage.name, depth), func(t *testing.T) {
				for attempt := 0; attempt < 32; attempt++ {
					e := stage.run(t)
					if e.Source != "syslog.generic" || e.Raw != line {
						t.Fatalf("fixture source or evidence changed: event=%+v", e)
					}
					if got := e.Attrs["tag"]; got != app {
						t.Fatalf("attempt %d: nested SD key overwrote APP-NAME: tag=%q, want %q; attrs=%q",
							attempt, got, app, e.Attrs)
					}
				}
			})
		}
	}
}
