package asn

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixture = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n" +
	"1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n" +
	"45.33.0.0\t45.33.127.255\t63949\tUS\tAKAMAI-LINODE-AP Akamai Connected Cloud\n" +
	"2600:3c00::\t2600:3c0f:ffff:ffff:ffff:ffff:ffff:ffff\t63949\tUS\tAKAMAI-LINODE-AP\n"

func mustParse(t *testing.T, s string) *Table {
	t.Helper()
	tb, err := Parse(strings.NewReader(s), 1)
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

func TestLookupBoundariesAndUnrouted(t *testing.T) {
	tb := mustParse(t, fixture)
	if tb.Rows() != 4 {
		t.Fatalf("rows %d", tb.Rows())
	}
	for _, c := range []struct {
		ip  string
		asn uint32
		ok  bool
	}{
		{"1.0.0.0", 13335, true}, {"1.0.0.255", 13335, true}, {"0.255.255.255", 0, false},
		{"1.0.2.1", 0, false}, // AS 0 — Not routed
		{"45.33.127.255", 63949, true}, {"45.33.128.0", 0, false},
		{"::ffff:45.33.32.156", 63949, true},
		{"2600:3c00::1", 63949, true}, {"2600:3c10::", 0, false}, {"2001:4860::1", 0, false},
	} {
		n, _, ok := tb.Lookup(netip.MustParseAddr(c.ip))
		if ok != c.ok || n != c.asn {
			t.Errorf("%s: %d %v, ожидалось %d %v", c.ip, n, ok, c.asn, c.ok)
		}
	}
}

func TestParseGzip(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(fixture))
	zw.Close()
	tb, err := Parse(&buf, 4)
	if err != nil || tb.Rows() != 4 {
		t.Fatalf("gzip: %v", err)
	}
}

func TestParseRejectsBrokenTables(t *testing.T) {
	for name, s := range map[string]string{
		"мало полей":        "1.0.0.0\t1.0.0.255\t13335\tUS\n",
		"не адрес":          "1.0.0.x\t1.0.0.255\t13335\tUS\tX\n",
		"ASN не число":      "1.0.0.0\t1.0.0.255\tAS13335\tUS\tX\n",
		"конец раньше":      "1.0.0.255\t1.0.0.0\t13335\tUS\tX\n",
		"разные семейства":  "1.0.0.0\t2600::\t13335\tUS\tX\n",
		"не по возрастанию": "45.33.0.0\t45.33.127.255\t1\tUS\tX\n1.0.0.0\t1.0.0.255\t2\tUS\tY\n",
		"пересечение":       "1.0.0.0\t1.0.0.255\t1\tUS\tX\n1.0.0.128\t1.0.1.255\t2\tUS\tY\n",
		"пересечение IPv6":  "2600::\t2600::ff\t1\tUS\tX\n2600::80\t2600::1ff\t2\tUS\tY\n",
		"зона в адресе":     "fe80::1%eth0\tfe80::2\t1\tUS\tX\n",
		"битый gzip":        "\x1f\x8b\x08garbage",
	} {
		if _, err := Parse(strings.NewReader(s), 1); err == nil {
			t.Errorf("%s: таблица принята", name)
		}
	}
	if _, err := Parse(strings.NewReader(fixture), 5); err == nil {
		t.Error("меньше minRows — таблица принята")
	}
}

func TestCleanOrg(t *testing.T) {
	if got := cleanOrg(" A\x00B\x1b[31mC\t "); got != "AB[31mC" {
		t.Errorf("управляющие символы: %q", got)
	}
	long := strings.Repeat("я", MaxOrgLen) // 2 байта на руну
	got := cleanOrg(long)
	if len(got) > MaxOrgLen || !strings.HasPrefix(long, got) || strings.ContainsRune(got, 0xfffd) {
		t.Errorf("обрезка: %d байт", len(got))
	}
}

func TestPublic(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8": true, "45.33.32.156": true, "2600:3c00::1": true,
		"10.1.2.3": false, "192.168.0.170": false, "172.20.0.1": false, "100.72.4.11": false,
		"127.0.0.1": false, "169.254.1.1": false, "203.0.113.5": false, "224.0.0.1": false,
		"255.255.255.255": false, "::1": false, "fd00::1": false, "fe80::1": false, "2001:db8::7": false,
		"::ffff:10.0.0.1": false, "::ffff:8.8.8.8": true,
	} {
		if got := Public(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s: %v", ip, got)
		}
	}
}

func TestEnrichNeverTrustsEventValues(t *testing.T) {
	tb := mustParse(t, fixture)
	attrs := map[string]string{SrcASN: "1", SrcASOrg: "spoof", DstASN: "2", DstASOrg: "spoof", "keep": "x"}
	Enrich(attrs, "45.33.32.156", "10.0.0.7", tb)
	want := map[string]string{SrcASN: "63949", SrcASOrg: "AKAMAI-LINODE-AP Akamai Connected Cloud", "keep": "x"}
	if len(attrs) != len(want) {
		t.Fatalf("attrs: %v", attrs)
	}
	for k, v := range want {
		if attrs[k] != v {
			t.Errorf("%s=%q", k, attrs[k])
		}
	}
	// Без таблицы и для неизвестных адресов — только удаление.
	attrs = map[string]string{SrcASN: "1", DstASOrg: "spoof"}
	Enrich(attrs, "45.33.32.156", "1.0.0.1", nil)
	if len(attrs) != 0 {
		t.Errorf("без таблицы: %v", attrs)
	}
	attrs = map[string]string{SrcASN: "1"}
	Enrich(attrs, "not-an-ip", "1.0.2.1", tb)
	if len(attrs) != 0 {
		t.Errorf("не адрес и AS 0: %v", attrs)
	}
	attrs = map[string]string{}
	Enrich(attrs, "", "1.0.0.1", tb)
	if attrs[DstASN] != "13335" || attrs[SrcASN] != "" {
		t.Errorf("только dst: %v", attrs)
	}
}

func TestReloadKeepsOldTableOnBrokenFileAndPicksUpChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip2asn.tsv")
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	db := Open(path, 2)
	if db.Table() == nil || db.Table().Rows() != 4 {
		t.Fatal("первая загрузка")
	}
	touch := func(body string, at time.Time) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, at, at); err != nil {
			t.Fatal(err)
		}
	}
	old := db.Table()
	touch("1.0.0.0\t1.0.0.255\tbroken\tUS\tX\n", time.Now().Add(time.Hour))
	if err := db.Reload(); err == nil {
		t.Error("битый файл принят")
	}
	if db.Table() != old {
		t.Error("битый файл заменил рабочую таблицу")
	}
	touch("1.0.0.0\t1.0.0.255\t13335\tUS\tX\n", time.Now().Add(2*time.Hour))
	if err := db.Reload(); err == nil {
		t.Error("меньше minRows принято")
	}
	touch("8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n9.9.9.0\t9.9.9.255\t19281\tUS\tQUAD9\n", time.Now().Add(3*time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go db.Watch(ctx, 10*time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if n, _, ok := db.Table().Lookup(netip.MustParseAddr("8.8.8.8")); ok && n == 15169 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Watch не перечитал изменённый файл")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, _, ok := db.Table().Lookup(netip.MustParseAddr("45.33.32.156")); ok {
		t.Error("старая таблица осталась после перечитывания")
	}
}

func TestOpenMissingFileIsEmptyNotFatal(t *testing.T) {
	db := Open(filepath.Join(t.TempDir(), "absent.tsv"), 1)
	if db.Table() != nil {
		t.Error("таблица без файла")
	}
	var none *DB
	if none.Table() != nil {
		t.Error("nil DB")
	}
}
