package main

import (
	"testing"

	"github.com/devitex-soft/argus/collector/internal/listen"
	"github.com/devitex-soft/argus/collector/internal/normalize"
	"github.com/devitex-soft/argus/collector/internal/parse"
)

// Присваивание attrs.tag после Structured Data защищает от буквального [tag],
// но Ensure/Sanitize затем очищает ключи SD. Принятый разборщиком ключ с DEL,
// C0 или ANSI превращается в tag и снова затирает исходный APP-NAME.
// Проверяем весь путь приёма: после FromSyslog есть ещё один Sanitize.
func TestPR101Round2RejectedTagSurvivesSDKeyCleaning(t *testing.T) {
	const app = "daemon/path"
	const origin = `[origin@32473 ip="192.0.2.30"]`
	for _, tc := range []struct{ name, sd string }{
		{"no_collision", origin},
		{"literal_tag", "[tag]" + origin},
		{"del_in_key", "[ta\x7fg]" + origin},
		{"c0_in_key", "[t\x01ag]" + origin},
		{"ansi_in_key", "[ta\x1b[0mg]" + origin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := "<30>1 2026-11-01T12:00:00Z host-01 " + app + " 12 event-1 " + tc.sd + " hello"
			sl, err := parse.ParseSyslog(line)
			if err != nil || sl.AppName != app {
				t.Fatalf("syslog fixture: err=%v app=%q", err, sl.AppName)
			}
			e, ok := parseSyslogLine(&normalize.Normalizer{}, nil, line, listen.Peer{
				Addr: "192.0.2.40", Transport: "udp",
			})
			if !ok || e.Source != "syslog.generic" {
				t.Fatalf("fallback event: ok=%v source=%q", ok, e.Source)
			}
			if e.Attrs["tag"] != app {
				t.Errorf("attrs.tag=%q, want original APP-NAME %q after SD key cleaning", e.Attrs["tag"], app)
			}
			if e.Attrs["origin@32473.ip"] != "192.0.2.30" || e.Attrs["peer"] != "192.0.2.40" {
				t.Errorf("unrelated metadata changed: %v", e.Attrs)
			}
			if e.Raw != line {
				t.Error("raw syslog evidence was changed")
			}
		})
	}
}
