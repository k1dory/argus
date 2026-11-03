package normalize

import (
	"fmt"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/parse"
)

// SD-элемент без параметров [tag] разбирается как Structured["tag"] = "".
// Он не должен стирать исходный APP-NAME, сохранённый нормализатором при
// переносе события в syslog.generic: это ключ для поиска прежнего источника.
func TestPR101RejectedSyslogTagSurvivesStructuredData(t *testing.T) {
	norm := &Normalizer{}
	for _, tag := range []string{"my(app)", "daemon/path", strings.Repeat("a", 33)} {
		for _, sd := range []string{"-", "[tag]", `[tag][origin@32473 ip="192.0.2.30"]`} {
			t.Run(tag+"/"+sd, func(t *testing.T) {
				line := fmt.Sprintf("<30>1 2026-11-01T12:00:00Z host-01 %s 12 event-1 %s hello", tag, sd)
				sl, err := parse.ParseSyslog(line)
				if err != nil {
					t.Fatal(err)
				}
				if sl.AppName != tag {
					t.Fatalf("fixture app=%q, want %q", sl.AppName, tag)
				}
				e := norm.FromSyslog(sl, line)
				if e.Source != "syslog.generic" {
					t.Fatalf("source=%q, want syslog.generic", e.Source)
				}
				if e.Attrs["tag"] != tag {
					t.Errorf("attrs.tag=%q, want original APP-NAME %q", e.Attrs["tag"], tag)
				}
				if strings.Contains(sd, "origin@32473") && e.Attrs["origin@32473.ip"] != "192.0.2.30" {
					t.Error("unrelated structured data was lost")
				}
			})
		}
	}
}
