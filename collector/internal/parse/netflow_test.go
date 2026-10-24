package parse

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

// v9-пакет только с шаблоном tid от заданного sourceID.
func v9Template(sourceID uint32, tid uint16) []byte {
	tmpl := binary.BigEndian.AppendUint16(nil, tid)
	tmpl = binary.BigEndian.AppendUint16(tmpl, 2)
	tmpl = binary.BigEndian.AppendUint16(tmpl, 8)
	tmpl = binary.BigEndian.AppendUint16(tmpl, 4)
	tmpl = binary.BigEndian.AppendUint16(tmpl, 12)
	tmpl = binary.BigEndian.AppendUint16(tmpl, 4)
	tset := binary.BigEndian.AppendUint16(nil, 0)
	tset = binary.BigEndian.AppendUint16(tset, uint16(4+len(tmpl)))
	tset = append(tset, tmpl...)
	hdr := binary.BigEndian.AppendUint16(nil, 9)
	hdr = binary.BigEndian.AppendUint16(hdr, 1)
	hdr = binary.BigEndian.AppendUint32(hdr, 10_000)
	hdr = binary.BigEndian.AppendUint32(hdr, 1757066138)
	hdr = binary.BigEndian.AppendUint32(hdr, 1)
	hdr = binary.BigEndian.AppendUint32(hdr, sourceID)
	return append(hdr, tset...)
}

func TestTemplateCacheBounded(t *testing.T) {
	d := NewDecoder()
	for i := uint32(0); i < 10_000; i++ {
		if _, err := d.Decode("10.0.0.1", v9Template(i, 256)); err != nil {
			t.Fatal(err)
		}
	}
	if n := d.Exporters(); n != MaxExporters {
		t.Fatalf("экспортёров в кэше %d, want %d", n, MaxExporters)
	}
	// свежие ключи остались, старые вытеснены
	if d.Templates("10.0.0.1/9999") != 1 || d.Templates("10.0.0.1/0") != 0 {
		t.Errorf("LRU: 9999→%d, 0→%d", d.Templates("10.0.0.1/9999"), d.Templates("10.0.0.1/0"))
	}
	// шаблонов на экспортёра — не больше потолка
	for tid := 256; tid < 256+3000; tid++ {
		d.Decode("10.0.0.2", v9Template(7, uint16(tid)))
	}
	if n := d.Templates("10.0.0.2/7"); n != MaxTemplatesPerExporter {
		t.Fatalf("шаблонов %d, want %d", n, MaxTemplatesPerExporter)
	}
	// и рабочий раунд-трип из parse_test по-прежнему проходит через кэш
	flows, err := d.Decode("10.0.0.254", buildV9())
	if err != nil || len(flows) != 1 {
		t.Fatalf("roundtrip после вытеснений: %v %d", err, len(flows))
	}
}

func TestTemplateTTL(t *testing.T) {
	d := NewDecoder()
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return now }
	d.Decode("10.0.0.1", v9Template(1, 256))
	d.Decode("10.0.0.1", v9Template(2, 256))
	now = now.Add(30 * time.Minute)
	d.Decode("10.0.0.1", v9Template(2, 257)) // второй ключ используется
	now = now.Add(45 * time.Minute)
	d.Decode("10.0.0.1", v9Template(3, 256)) // триггер sweep: ключ 1 молчит 75 мин
	if d.Templates("10.0.0.1/1") != 0 {
		t.Error("ключ без активности дольше часа должен быть выброшен")
	}
	// у активного ключа остаётся только шаблон, который использовали за последний час
	if d.Templates("10.0.0.1/2") != 1 {
		t.Errorf("активный ключ: %d шаблонов, want 1", d.Templates("10.0.0.1/2"))
	}
}

func TestExporterAllowlist(t *testing.T) {
	nets, err := ParseCIDRs(" 10.0.0.0/24, 192.168.1.7 ,2001:db8::/32")
	if err != nil || len(nets) != 3 {
		t.Fatalf("%v %d", err, len(nets))
	}
	if _, err := ParseCIDRs("nope"); err == nil {
		t.Error("мусор должен давать ошибку")
	}
	d := NewDecoder()
	d.Allow = nets
	for ex, ok := range map[string]bool{"10.0.0.254": true, "192.168.1.7": true, "192.168.1.8": false, "2001:db8::1": true, "8.8.8.8": false, "": false} {
		_, err := d.Decode(ex, buildV9())
		if (err == nil) != ok {
			t.Errorf("%q: err=%v, want allowed=%v", ex, err, ok)
		}
	}
	if d.Exporters() != 3 {
		t.Errorf("в кэш попали запрещённые экспортёры: %d", d.Exporters())
	}
}

func TestIPFIXMillisBounded(t *testing.T) {
	if !unixMilliBounded(^uint64(0)).IsZero() || !unixMilliBounded(0).IsZero() {
		t.Error("переполненные миллисекунды должны давать нулевое время")
	}
	if got := unixMilliBounded(1_757_066_138_000); got.Year() != 2025 {
		t.Errorf("%v", got)
	}
	_ = fmt.Sprint
}
