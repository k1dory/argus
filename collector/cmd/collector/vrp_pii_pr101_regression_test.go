package main

import (
	"fmt"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/listen"
	"github.com/devitex-soft/argus/collector/internal/normalize"
	"github.com/devitex-soft/argus/collector/internal/parse"
)

// До PR #101 эти варианты регистра попадали в FromSyslog, который отмечал
// email и телефон как ПДн. Выбор нового разборщика не должен снимать этот флаг:
// engine/internal/analyst.Route использует его для запрета облачного маршрута.
// Все адреса и учётные записи синтетические; тест не обращается к сети.
func TestPR101VRPRecognitionPreservesPII(t *testing.T) {
	norm := &normalize.Normalizer{}
	peer := listen.Peer{Addr: "192.0.2.40", Transport: "udp"}
	for _, envelope := range []struct{ name, prefix string }{
		{"rfc3164", "<189>Nov  1 2026 12:00:00 switch-01 "},
		{"rfc5424", "<189>1 2026-11-01T12:00:00Z switch-01 vrp - - - "},
		{"raw", ""},
	} {
		for _, tc := range []struct {
			name, module, mnemonic, fields string
			pii                            uint8
		}{
			{"lower_module_email", "cli", "LOGIN", "UserName=alice@example.test, Ip=192.0.2.10", 1},
			{"mixed_mnemonic_email", "CLI", "Login", "UserName=alice@example.test, Ip=192.0.2.10", 1},
			{"mixed_module_phone", "cLi", "Login", "UserName=qa-user, Contact=+1 202 555 0100, Ip=192.0.2.10", 1},
			{"without_pii", "CLI", "Login", "UserName=qa-user, Ip=192.0.2.10", 0},
		} {
			t.Run(envelope.name+"/"+tc.name, func(t *testing.T) {
				line := envelope.prefix + fmt.Sprintf("%%%%01%s/5/%s(s):CID=0x80ca2713;The user logged in. (%s)", tc.module, tc.mnemonic, tc.fields)
				sl, err := parse.ParseSyslog(line)
				if err != nil {
					t.Fatal(err)
				}
				// Контроль прежнего fallback на той же строке, без копирования
				// реализации детектора ПДн в тест.
				if fallback := norm.FromSyslog(sl, line); fallback.PII != tc.pii {
					t.Fatalf("fixture: syslog fallback pii=%d, want %d", fallback.PII, tc.pii)
				}
				e, ok := parseSyslogLine(norm, nil, line, peer)
				if !ok {
					t.Fatal("event was dropped")
				}
				if e.PII != tc.pii {
					t.Errorf("source=%q action=%q: pii=%d, want %d; recognizing VRP must preserve the PII policy", e.Source, e.Action, e.PII, tc.pii)
				}
			})
		}
	}
}
