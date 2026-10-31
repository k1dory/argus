package normalize

import (
	"strings"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/parse"
)

func TestDNSVendorNameNormalization(t *testing.T) {
	n := &Normalizer{}
	for _, key := range []string{"query", "qname", "query_name", "domain", "destinationDnsDomain", "dns.question.name"} {
		for _, action := range []string{"DNS", "allow"} {
			t.Run("CEF/"+key+"/"+action, func(t *testing.T) {
				line := `CEF:0|Check Point|FireWall-1|R81|dns|DNS|3|src=10.30.1.8 dst=203.0.113.53 dpt=53 proto=UDP in=300 act=` + action + ` ` + key + `=encoded.example.test`
				c, ok := parse.ParseCEF(line)
				if !ok {
					t.Fatal("CEF fixture not parsed")
				}
				e := n.FromCEF(c, parse.Syslog{}, line)
				wantQuery, wantAction := "encoded.example.test", "event.dns"
				if action == "allow" {
					wantQuery, wantAction = "", "session.allow"
				}
				if e.Action != wantAction || e.Attrs["dns_query"] != wantQuery || e.Attrs[key] != "encoded.example.test" || e.DstPort != 53 || e.Bytes != 300 {
					t.Fatalf("CEF DNS contract lost: %+v", e)
				}
			})
			t.Run("LEEF/"+key+"/"+action, func(t *testing.T) {
				line := "LEEF:1.0|Check Point|FireWall-1|R81|DNS|" + strings.Join([]string{"src=10.30.1.8", "dst=203.0.113.53", "dstPort=53", "proto=UDP", "totalBytes=300", "action=" + action, key + "=encoded.example.test"}, "\t")
				l, ok := parse.ParseLEEF(line)
				if !ok {
					t.Fatal("LEEF fixture not parsed")
				}
				e := n.FromLEEF(l, parse.Syslog{}, line)
				wantQuery, wantAction := "encoded.example.test", "event.dns"
				if action == "allow" {
					wantQuery, wantAction = "", "session.allow"
				}
				if e.Action != wantAction || e.Attrs["dns_query"] != wantQuery || e.Attrs[key] != "encoded.example.test" || e.DstPort != 53 || e.Bytes != 300 {
					t.Fatalf("LEEF DNS contract lost: %+v", e)
				}
			})
		}
	}
}
