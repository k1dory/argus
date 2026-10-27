package parse

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Flow — одна запись потока после декодирования по шаблону.
type Flow struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	Proto            uint8
	TCPFlags         uint8 // tcpControlBits (поле 6): SYN=0x02, ACK=0x10 …
	Bytes, Packets   uint64
	Start, End       time.Time
	Fields           map[uint16][]byte // все поля шаблона как есть
}

type tmplField struct {
	id     uint16
	length uint16
	pen    uint32 // IPFIX enterprise number, 0 — стандартное поле
}

// Потолки кэша шаблонов: чужой UDP-пакет с новым source id не должен
// растить память бесконечно. Неиспользуемое вытесняется по LRU и по TTL.
const (
	MaxExporters            = 256
	MaxTemplatesPerExporter = 1024
	TemplateTTL             = time.Hour
	sweepEvery              = time.Minute
)

type tmplEntry struct {
	fields []tmplField
	used   time.Time
}

type exporterTemplates struct {
	tmpl map[uint16]*tmplEntry
	used time.Time
}

// Decoder держит шаблоны по экспортёру (адрес + source id / domain):
// без них записи данных нечитаемы, поэтому первые пакеты до шаблона молча
// пропускаются — это нормальное поведение NetFlow.
type Decoder struct {
	mu        sync.Mutex
	templates map[string]*exporterTemplates
	lastSweep time.Time
	now       func() time.Time

	// Allow — если непусто, пакеты от экспортёров вне этих сетей отбрасываются.
	Allow []*net.IPNet
}

func NewDecoder() *Decoder {
	return &Decoder{templates: map[string]*exporterTemplates{}, now: time.Now}
}

// ParseCIDRs разбирает список сетей через запятую (NETFLOW_EXPORTERS);
// голый IP — как /32 или /128. Пустая строка — пустой список (всем можно).
func ParseCIDRs(s string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			ip := net.ParseIP(part)
			if ip == nil {
				return nil, fmt.Errorf("netflow exporters: не IP и не CIDR: %q", part)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("netflow exporters: %w", err)
		}
		out = append(out, n)
	}
	return out, nil
}

func (d *Decoder) allowed(exporter string) bool {
	if len(d.Allow) == 0 {
		return true
	}
	ip := net.ParseIP(exporter)
	if ip == nil {
		return false
	}
	for _, n := range d.Allow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Decode разбирает один UDP-пакет NetFlow v9 (version 9) или IPFIX (10).
func (d *Decoder) Decode(exporter string, pkt []byte) ([]Flow, error) {
	if !d.allowed(exporter) {
		return nil, fmt.Errorf("netflow: экспортёр %s не в NETFLOW_EXPORTERS", exporter)
	}
	if len(pkt) < 16 {
		return nil, errors.New("netflow: пакет короче заголовка")
	}
	d.sweep()
	version := binary.BigEndian.Uint16(pkt[0:2])
	switch version {
	case 9:
		return d.decodeV9(exporter, pkt)
	case 10:
		return d.decodeIPFIX(exporter, pkt)
	}
	return nil, fmt.Errorf("netflow: версия %d не поддерживается (нужны v9 или IPFIX)", version)
}

// sweep раз в минуту выбрасывает экспортёров и шаблоны, молчавшие дольше TTL.
func (d *Decoder) sweep() {
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if now.Sub(d.lastSweep) < sweepEvery {
		return
	}
	d.lastSweep = now
	for key, ex := range d.templates {
		if now.Sub(ex.used) > TemplateTTL {
			delete(d.templates, key)
			continue
		}
		for tid, t := range ex.tmpl {
			if now.Sub(t.used) > TemplateTTL {
				delete(ex.tmpl, tid)
			}
		}
	}
}

// Exporters — сколько ключей (экспортёр/source id) в кэше; для тестов и метрик.
func (d *Decoder) Exporters() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.templates)
}

// Templates — сколько шаблонов у ключа.
func (d *Decoder) Templates(key string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	if ex := d.templates[key]; ex != nil {
		return len(ex.tmpl)
	}
	return 0
}

func (d *Decoder) decodeV9(exporter string, pkt []byte) ([]Flow, error) {
	if len(pkt) < 20 {
		return nil, errors.New("netflow v9: короткий заголовок")
	}
	sysUptime := binary.BigEndian.Uint32(pkt[4:8])
	unixSecs := binary.BigEndian.Uint32(pkt[8:12])
	sourceID := binary.BigEndian.Uint32(pkt[16:20])
	key := fmt.Sprintf("%s/%d", exporter, sourceID)
	base := time.Unix(int64(unixSecs), 0).UTC()
	var flows []Flow
	off := 20
	for off+4 <= len(pkt) {
		fsID := binary.BigEndian.Uint16(pkt[off : off+2])
		fsLen := int(binary.BigEndian.Uint16(pkt[off+2 : off+4]))
		if fsLen < 4 || off+fsLen > len(pkt) {
			break
		}
		body := pkt[off+4 : off+fsLen]
		switch {
		case fsID == 0:
			d.parseTemplates(key, body, false)
		case fsID == 1:
			// options template — не нужен для потоков
		case fsID >= 256:
			flows = append(flows, d.decodeData(key, fsID, body, func(f *Flow, fields map[uint16][]byte) {
				// v9: FIRST/LAST_SWITCHED — миллисекунды sysUptime
				if v, ok := fields[22]; ok && len(v) == 4 {
					f.Start = base.Add(-time.Duration(int64(sysUptime)-int64(binary.BigEndian.Uint32(v))) * time.Millisecond)
				}
				if v, ok := fields[21]; ok && len(v) == 4 {
					f.End = base.Add(-time.Duration(int64(sysUptime)-int64(binary.BigEndian.Uint32(v))) * time.Millisecond)
				}
			})...)
		}
		off += fsLen
	}
	return flows, nil
}

func (d *Decoder) decodeIPFIX(exporter string, pkt []byte) ([]Flow, error) {
	length := int(binary.BigEndian.Uint16(pkt[2:4]))
	if length > len(pkt) {
		length = len(pkt)
	}
	exportTime := time.Unix(int64(binary.BigEndian.Uint32(pkt[4:8])), 0).UTC()
	domain := binary.BigEndian.Uint32(pkt[12:16])
	key := fmt.Sprintf("%s/ipfix/%d", exporter, domain)
	var flows []Flow
	off := 16
	for off+4 <= length {
		setID := binary.BigEndian.Uint16(pkt[off : off+2])
		setLen := int(binary.BigEndian.Uint16(pkt[off+2 : off+4]))
		if setLen < 4 || off+setLen > length {
			break
		}
		body := pkt[off+4 : off+setLen]
		switch {
		case setID == 2:
			d.parseTemplates(key, body, true)
		case setID == 3:
			// options template
		case setID >= 256:
			flows = append(flows, d.decodeData(key, setID, body, func(f *Flow, fields map[uint16][]byte) {
				if v, ok := fields[152]; ok && len(v) == 8 { // flowStartMilliseconds
					f.Start = unixMilliBounded(binary.BigEndian.Uint64(v))
				}
				if v, ok := fields[153]; ok && len(v) == 8 {
					f.End = unixMilliBounded(binary.BigEndian.Uint64(v))
				}
				if v, ok := fields[150]; ok && len(v) == 4 { // flowStartSeconds
					f.Start = time.Unix(int64(binary.BigEndian.Uint32(v)), 0).UTC()
				}
				if v, ok := fields[151]; ok && len(v) == 4 {
					f.End = time.Unix(int64(binary.BigEndian.Uint32(v)), 0).UTC()
				}
				if f.End.IsZero() {
					f.End = exportTime
				}
			})...)
		}
		off += setLen
	}
	return flows, nil
}

// unixMilliBounded: миллисекунды из пакета могут быть любым uint64 —
// за пределами правдоподобного (до 2200 г.) считаем «нет метки».
func unixMilliBounded(ms uint64) time.Time {
	if ms == 0 || ms > 7_258_118_400_000 {
		return time.Time{}
	}
	return time.UnixMilli(int64(ms)).UTC()
}

func (d *Decoder) parseTemplates(key string, body []byte, ipfix bool) {
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	ex := d.templates[key]
	if ex == nil {
		if len(d.templates) >= MaxExporters {
			d.evictExporter()
		}
		ex = &exporterTemplates{tmpl: map[uint16]*tmplEntry{}}
		d.templates[key] = ex
	}
	ex.used = now
	off := 0
	for off+4 <= len(body) {
		tid := binary.BigEndian.Uint16(body[off : off+2])
		count := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		fields := make([]tmplField, 0, min(count, 64))
		for i := 0; i < count && off+4 <= len(body); i++ {
			id := binary.BigEndian.Uint16(body[off : off+2])
			ln := binary.BigEndian.Uint16(body[off+2 : off+4])
			off += 4
			f := tmplField{id: id, length: ln}
			if ipfix && id&0x8000 != 0 && off+4 <= len(body) {
				f.id = id & 0x7fff
				f.pen = binary.BigEndian.Uint32(body[off : off+4])
				off += 4
			}
			fields = append(fields, f)
		}
		if tid >= 256 && len(fields) > 0 {
			if _, ok := ex.tmpl[tid]; !ok && len(ex.tmpl) >= MaxTemplatesPerExporter {
				evictTemplate(ex)
			}
			ex.tmpl[tid] = &tmplEntry{fields: fields, used: now}
		}
	}
}

func (d *Decoder) evictExporter() {
	var oldKey string
	var oldest time.Time
	for k, ex := range d.templates {
		if oldKey == "" || ex.used.Before(oldest) {
			oldKey, oldest = k, ex.used
		}
	}
	delete(d.templates, oldKey)
}

func evictTemplate(ex *exporterTemplates) {
	var oldID uint16
	var oldest time.Time
	first := true
	for id, t := range ex.tmpl {
		if first || t.used.Before(oldest) {
			oldID, oldest, first = id, t.used, false
		}
	}
	delete(ex.tmpl, oldID)
}

func (d *Decoder) lookup(key string, tid uint16) []tmplField {
	d.mu.Lock()
	defer d.mu.Unlock()
	ex := d.templates[key]
	if ex == nil {
		return nil
	}
	t := ex.tmpl[tid]
	if t == nil {
		return nil
	}
	now := d.now()
	ex.used, t.used = now, now
	return t.fields
}

func (d *Decoder) decodeData(key string, tid uint16, body []byte, stamp func(*Flow, map[uint16][]byte)) []Flow {
	tmpl := d.lookup(key, tid)
	if tmpl == nil {
		return nil // шаблон ещё не пришёл
	}
	var flows []Flow
	off := 0
	for {
		fields := map[uint16][]byte{}
		start := off
		ok := true
		for _, f := range tmpl {
			ln := int(f.length)
			if ln == 65535 { // IPFIX variable length
				if off >= len(body) {
					ok = false
					break
				}
				ln = int(body[off])
				off++
				if ln == 255 {
					if off+2 > len(body) {
						ok = false
						break
					}
					ln = int(binary.BigEndian.Uint16(body[off : off+2]))
					off += 2
				}
			}
			if off+ln > len(body) {
				ok = false
				break
			}
			if f.pen == 0 {
				fields[f.id] = body[off : off+ln]
			}
			off += ln
		}
		if !ok || off == start {
			break
		}
		fl := Flow{Fields: fields}
		fl.SrcIP = ipStr(fields[8], fields[27])
		fl.DstIP = ipStr(fields[12], fields[28])
		fl.SrcPort = u16(fields[7])
		fl.DstPort = u16(fields[11])
		if v := fields[4]; len(v) == 1 {
			fl.Proto = v[0]
		}
		fl.Bytes = uN(fields[1])
		fl.Packets = uN(fields[2])
		if v := fields[6]; len(v) >= 1 {
			fl.TCPFlags = v[len(v)-1] // при двухбайтовом поле флаги в младшем байте
		}
		stamp(&fl, fields)
		flows = append(flows, fl)
		if len(body)-off < 4 { // паддинг набора
			break
		}
	}
	return flows
}

func ipStr(v4, v6 []byte) string {
	if len(v4) == 4 {
		return net.IP(v4).String()
	}
	if len(v6) == 16 {
		return net.IP(v6).String()
	}
	return ""
}

func u16(b []byte) uint16 {
	switch len(b) {
	case 2:
		return binary.BigEndian.Uint16(b)
	case 1:
		return uint16(b[0])
	}
	return 0
}

func uN(b []byte) uint64 {
	var n uint64
	for _, x := range b {
		n = n<<8 | uint64(x)
	}
	return n
}

// TCPFlagsString — флаги TCP буквами в привычном порядке tcpdump-подобных
// инструментов: "S", "SA", "FPA"… Пусто, когда флагов нет.
func TCPFlagsString(f uint8) string {
	var b []byte
	for _, x := range []struct {
		bit uint8
		c   byte
	}{{0x02, 'S'}, {0x10, 'A'}, {0x01, 'F'}, {0x04, 'R'}, {0x08, 'P'}, {0x20, 'U'}, {0x40, 'E'}, {0x80, 'C'}} {
		if f&x.bit != 0 {
			b = append(b, x.c)
		}
	}
	return string(b)
}

// ProtoName — номер протокола IP в имя для колонки proto.
func ProtoName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 47:
		return "gre"
	case 50:
		return "esp"
	case 58:
		return "icmpv6"
	}
	return fmt.Sprintf("ip-%d", p)
}
