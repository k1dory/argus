package main

import (
	"os"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/listen"
	"github.com/devitex-soft/argus/collector/internal/normalize"
)

// Все строки VRP — один источник net.vrp, а не по источнику на мнемонику.
func TestVRPMixedCaseLinesShareOneSource(t *testing.T) {
	raw, err := os.ReadFile("../../internal/parse/testdata/vrp_mixed_case.syslog")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		e, ok := parseSyslogLine(&normalize.Normalizer{}, nil, line, listen.Peer{Addr: "192.0.2.40", Transport: "udp"})
		if !ok || e.Source != "net.vrp" || e.Attrs["module"] == "" || e.Attrs["mnemonic"] == "" {
			t.Fatalf("%s\n → source=%q attrs=%v", line, e.Source, e.Attrs)
		}
	}
}

// Тег, который не похож на имя программы, — не источник: syslog.generic и attrs.tag.
func TestSyslogTagIsSourceOnlyForProgramNames(t *testing.T) {
	for _, tc := range []struct{ line, source, tag string }{
		{"<30>Nov  1 12:00:00 host-1 sshd[12]: Accepted publickey for root", "syslog.sshd", ""},
		{"<30>Nov  1 12:00:00 host-1 nginx: GET /", "syslog.nginx", ""},
		// VRP-подобный тег, который разборщик VRP не принял (не та форма)
		{"<188>Nov  1 2026 12:00:00 sw9 %%01FOO/x/bar(l):text", "syslog.generic", "%%01FOO/x/bar(l)"},
		{"<30>Nov  1 12:00:00 host-1 my(app): hello", "syslog.generic", "my(app)"},
	} {
		e, ok := parseSyslogLine(&normalize.Normalizer{}, nil, tc.line, listen.Peer{Addr: "192.0.2.30", Transport: "udp"})
		if !ok || e.Source != tc.source || e.Attrs["tag"] != tc.tag {
			t.Errorf("%s\n → source=%q tag=%q", tc.line, e.Source, e.Attrs["tag"])
		}
	}
}
