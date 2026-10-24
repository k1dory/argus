package normalize

import (
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
	"github.com/devitex-soft/argus/collector/internal/parse"
)

func fixNow(t *testing.T) time.Time {
	t.Helper()
	fixed := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	model.Now = func() time.Time { return fixed }
	t.Cleanup(func() { model.Now = time.Now })
	return fixed
}

func TestPickTimeBounds(t *testing.T) {
	fixNow(t)
	cases := map[string]struct {
		year int
		raw  bool // ts_raw ожидается
	}{
		"1757066138":                {2025, false}, // секунды
		"1757066138000":             {2025, false}, // миллисекунды
		"9223372036854775807":       {2026, true},  // MaxInt64 — не год 292278994
		"99999999999999999":         {2026, true},
		"-5":                        {2026, true},
		"2999-01-01T00:00:00Z":      {2026, true}, // в будущем
		"2001-01-01 00:00:00":       {2026, true}, // старше 10 лет
		"Sep 13 2026 10:00:00":      {2026, false},
		strings.Repeat("1", 300):    {2026, true},
		"not a time at all":         {2026, true},  // не разобрано → now, значение в ts_raw
		"2026-09-15T11:00:00Z":      {2026, false}, // +23h — ок
		"2026-09-15T13:00:00Z":      {2026, true},  // +25h — выброс
		"2026-09-14T14:59:00+03:00": {2026, false},
	}
	n := &Normalizer{}
	for in, want := range cases {
		c := parse.CEF{Vendor: "X", Product: "Y", Ext: map[string]string{"rt": in}}
		e := n.FromCEF(c, parse.Syslog{}, "raw")
		ts, ok := model.ParseTS(e.TS)
		if !ok || ts.Year() != want.year {
			t.Errorf("%q → ts=%q (год %d), want %d", in, e.TS, ts.Year(), want.year)
		}
		if _, has := e.Attrs["ts_raw"]; has != want.raw {
			t.Errorf("%q → ts_raw=%q, want present=%v", in, e.Attrs["ts_raw"], want.raw)
		}
		if want.raw && len(in) <= 64 && e.Attrs["ts_raw"] != in {
			t.Errorf("%q → ts_raw должен быть исходной строкой, got %q", in, e.Attrs["ts_raw"])
		}
	}
	// syslog без времени и с временем из будущего
	e := n.FromSyslog(parse.Syslog{Timestamp: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Message: "m"}, "raw")
	if !strings.HasPrefix(e.Attrs["ts_raw"], "2030-01-01") || !strings.HasPrefix(e.TS, "2026-09-14 12:00") {
		t.Errorf("syslog future: ts=%q raw=%q", e.TS, e.Attrs["ts_raw"])
	}
	// NetFlow с переполненным End
	f := n.FromFlow(parse.Flow{End: time.UnixMilli(1 << 62)}, "netflow.core", "10.0.0.1")
	if _, ok := f.Attrs["ts_raw"]; !ok || !strings.HasPrefix(f.TS, "2026-09-14 12:00") {
		t.Errorf("flow overflow: %q %v", f.TS, f.Attrs)
	}
}

func TestPIIHeuristicsExtended(t *testing.T) {
	yes := []string{
		"ivanov@corp.ru", "user@localhost", "a.b@example.museum", "IVANOV@EXAMPLE.COM",
		"ivanov [at] example.com", "ivanov[at]example[dot]com", "ivanov (at) corp.ru",
		"+7 (921) 123-45-67", "8-921-123-45-67", "+1 415 555 2671", "+441632960961", "+49 30 901820",
		"call +7 921 1234567 now",
	}
	no := []string{
		"", "robot$", "system:serviceaccount:kube-system:x", "10.0.0.1:443", "GET /index.html",
		"+1", "+12345", "v1.2.3+build.42", "1757066138", "svc-account", "user at example",
		"ivanov@corp", "DOMAIN\\ivanov@WS01", "root@srv", "ivanov [at] corp",
	}
	for _, s := range yes {
		if !HasPII(s) {
			t.Errorf("%q должен считаться ПДн", s)
		}
	}
	for _, s := range no {
		if HasPII(s) {
			t.Errorf("%q не должен считаться ПДн", s)
		}
	}
	n := &Normalizer{}
	for _, k := range []string{"user.email", "email", "phone", "msisdn", "suser", "duser"} {
		c := parse.CEF{Vendor: "X", Ext: map[string]string{k: "ivanov@corp.ru"}}
		if e := n.FromCEF(c, parse.Syslog{}, ""); e.PII != 1 {
			t.Errorf("поле %s с e-mail не помечено PII", k)
		}
	}
	c := parse.CEF{Vendor: "X", Ext: map[string]string{"unrelated": "ivanov@corp.ru"}}
	if e := n.FromCEF(c, parse.Syslog{}, ""); e.PII != 0 {
		t.Error("e-mail в не-ПДн поле не должен ставить флаг")
	}
	// конфиг дополняет, а не заменяет список по умолчанию
	n2 := &Normalizer{PIIFields: []string{"custom"}}
	for _, k := range []string{"custom", "suser"} {
		c := parse.CEF{Vendor: "X", Ext: map[string]string{k: "+7 921 123-45-67"}}
		if e := n2.FromCEF(c, parse.Syslog{}, ""); e.PII != 1 {
			t.Errorf("поле %s не помечено PII", k)
		}
	}
}

func TestNormalizeSanitizes(t *testing.T) {
	n := &Normalizer{}
	line := "<34>1 2026-09-14T11:00:00Z host\x1b[31m app - - - CEF:0|V|P|1|1|Name\x07|5|suser=adm\x1b[0min request=/x\r\nEvil: 1 msg=" + strings.Repeat("A", 10000)
	sl, _ := parse.ParseSyslog(line)
	c, _ := parse.ParseCEF(line)
	e := n.FromCEF(c, sl, line)
	if e.ActorName != "admin" || e.Object != "/x  Evil: 1" || e.Node != "host" || e.Attrs["name"] != "Name" {
		t.Errorf("не санитизировано: actor=%q object=%q node=%q name=%q", e.ActorName, e.Object, e.Node, e.Attrs["name"])
	}
	if len(e.Attrs["msg"]) != model.MaxFieldLen || e.Attrs["truncated"] != "1" {
		t.Errorf("msg не обрезан: %d truncated=%q", len(e.Attrs["msg"]), e.Attrs["truncated"])
	}
	if e.Raw != line {
		t.Error("Raw изменён")
	}
}

// FuzzNormalize — полный путь строки syslog/CEF/LEEF/WAF через разбор и
// нормализацию: ни паник, ни невалидного ts.
func FuzzNormalize(f *testing.F) {
	for _, s := range []string{
		"<134>1 2026-09-05T10:12:18Z fw-01 CheckPoint - - - CEF:0|Check Point|FW|R81|Accept|Firewall|0|src=10.0.0.1 dst=1.1.1.1 spt=1 dpt=443 rt=1757066138000 suser=a@b.c",
		"<14>Sep 14 12:00:00 ug LEEF:2.0|UserGate|NGFW|7|deny|x5e|src=10.1.1.1^dst=8.8.8.8^devTime=9223372036854775807^usrName=u",
		"<34>1 - - - - - - plain message +7 921 123 45 67",
		"2026/09/14 12:00:00 [error] ModSecurity: Access denied with code 403 (phase 2). [file \"x\"] [id \"949110\"] [msg \"m\"] [severity \"2\"] [hostname \"h\"] [uri \"/\"]",
		"CEF:0|a|b|c|d|e|f|rt=-1 end=99999999999999999999 start=2999-01-01T00:00:00Z",
		"", "<", "\x1b[31mred\x1b[0m",
	} {
		f.Add(s)
	}
	n := &Normalizer{}
	f.Fuzz(func(t *testing.T, line string) {
		sl, _ := parse.ParseSyslog(line)
		var e model.Event
		switch {
		case strings.Contains(line, "CEF:"):
			c, _ := parse.ParseCEF(line)
			e = n.FromCEF(c, sl, line)
		case strings.Contains(line, "LEEF:"):
			l, _ := parse.ParseLEEF(line)
			e = n.FromLEEF(l, sl, line)
		case parse.IsWAFErrorLine(line):
			if wf, ok := parse.ParseWAFErrorLine(line); ok {
				e = n.FromWAF(wf, line)
			} else {
				e = n.FromSyslog(sl, line)
			}
		default:
			e = n.FromSyslog(sl, line)
		}
		if ts, ok := model.ParseTS(e.TS); !ok || ts.Year() < 2000 || ts.Year() > 2100 {
			t.Fatalf("ts %q невалиден", e.TS)
		}
		if e.Attrs == nil || e.Raw != line {
			t.Fatal("Ensure/Raw")
		}
	})
}
