// Package parse — разбор форматов источников: syslog (RFC 5424 / RFC 3164),
// CEF, LEEF, NetFlow v9 / IPFIX, Kubernetes audit, GitLab.
package parse

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// now подменяется в тестах (год для RFC 3164 берётся из текущего времени).
var now = time.Now

type Syslog struct {
	Facility   int
	Severity   int
	Timestamp  time.Time
	Hostname   string
	AppName    string
	ProcID     string
	MsgID      string
	Message    string
	Structured map[string]string // SD-элементы RFC 5424, ключи вида id.param
	Format     string            // rfc5424 | rfc3164 | raw
	// Zoneless — время из заголовка RFC 3164 без часового пояса: разобрано как UTC,
	// а на деле это местное время отправителя (см. InZone).
	Zoneless bool
	// yearless — в заголовке нет и года: InZone выбирает его заново по часам пояса.
	yearless bool
}

// ParseSyslog принимает строку с PRI или без; никогда не теряет сообщение.
func ParseSyslog(line string) (Syslog, error) {
	s := Syslog{Message: strings.TrimRight(line, "\r\n"), Format: "raw", Facility: -1, Severity: -1}
	if !strings.HasPrefix(s.Message, "<") {
		return s, nil
	}
	end := strings.IndexByte(s.Message, '>')
	if end < 1 || end > 4 {
		return s, errors.New("syslog: некорректный PRI")
	}
	pri, err := strconv.Atoi(s.Message[1:end])
	if err != nil {
		return s, errors.New("syslog: PRI не число")
	}
	s.Facility, s.Severity = pri/8, pri%8
	rest := s.Message[end+1:]
	if strings.HasPrefix(rest, "1 ") {
		return parse5424(s, rest[2:])
	}
	return parse3164(s, rest)
}

func parse5424(s Syslog, rest string) (Syslog, error) {
	s.Format = "rfc5424"
	// TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA [MSG]
	fields := strings.SplitN(rest, " ", 6)
	if len(fields) < 6 {
		s.Message = rest
		return s, errors.New("syslog: мало полей RFC 5424")
	}
	if fields[0] != "-" {
		if t, err := time.Parse(time.RFC3339Nano, fields[0]); err == nil {
			s.Timestamp = t
		}
	}
	s.Hostname, s.AppName, s.ProcID, s.MsgID = nilDash(fields[1]), nilDash(fields[2]), nilDash(fields[3]), nilDash(fields[4])
	sd := fields[5]
	if strings.HasPrefix(sd, "-") {
		s.Message = strings.TrimPrefix(strings.TrimPrefix(sd, "-"), " ")
		return s, nil
	}
	s.Structured = map[string]string{}
	pos := 0
	for pos < len(sd) && sd[pos] == '[' {
		close := findSDClose(sd, pos)
		if close < 0 {
			break
		}
		parseSDElement(sd[pos+1:close], s.Structured)
		pos = close + 1
	}
	s.Message = strings.TrimPrefix(sd[pos:], " ")
	return s, nil
}

func findSDClose(sd string, start int) int {
	inQuote := false
	for i := start + 1; i < len(sd); i++ {
		switch sd[i] {
		case '\\':
			i++
		case '"':
			inQuote = !inQuote
		case ']':
			if !inQuote {
				return i
			}
		}
	}
	return -1
}

func parseSDElement(body string, out map[string]string) {
	sp := strings.IndexByte(body, ' ')
	if sp < 0 {
		out[body] = ""
		return
	}
	id := body[:sp]
	rest := body[sp+1:]
	for len(rest) > 0 {
		eq := strings.IndexByte(rest, '=')
		if eq < 0 {
			break
		}
		key := strings.TrimSpace(rest[:eq])
		rest = rest[eq+1:]
		if len(rest) == 0 || rest[0] != '"' {
			break
		}
		rest = rest[1:]
		var val strings.Builder
		i := 0
		for i < len(rest) {
			if rest[i] == '\\' && i+1 < len(rest) {
				val.WriteByte(rest[i+1])
				i += 2
				continue
			}
			if rest[i] == '"' {
				break
			}
			val.WriteByte(rest[i])
			i++
		}
		out[id+"."+key] = val.String()
		if i+1 <= len(rest) {
			rest = strings.TrimLeft(rest[min(i+1, len(rest)):], " ")
		} else {
			rest = ""
		}
	}
}

// isoHeaderLayouts — ISO 8601 в заголовке BSD-формата: так шлют rsyslog
// (ForwardFormat, «2026-10-27T23:42:55.001234+03:00») и RouterOS с
// syslog-time-format=iso8601 («2026-10-27T23:42:55.0019+0300», без двоеточия в зоне).
var isoHeaderLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05.999999999-0700",
	"2006-01-02T15:04:05-0700",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05",
}

func parse3164(s Syslog, rest string) (Syslog, error) {
	s.Format = "rfc3164"
	// ISO-время вместо «Mmm dd hh:mm:ss»: <PRI>2026-10-27T23:42:55+03:00 HOST MSG
	if len(rest) > 19 && rest[4] == '-' && rest[10] == 'T' {
		if sp := strings.IndexByte(rest, ' '); sp > 0 {
			for _, layout := range isoHeaderLayouts {
				if t, err := time.Parse(layout, rest[:sp]); err == nil {
					s.Timestamp = t.UTC()
					rest = strings.TrimLeft(rest[sp+1:], " ")
					break
				}
			}
		}
	}
	// Mmm dd yyyy hh:mm:ss HOST MSG — Huawei VRP (info-center) пишет год в заголовок.
	if s.Timestamp.IsZero() && len(rest) >= 20 && rest[6] == ' ' && rest[11] == ' ' {
		if t, err := time.Parse("Jan _2 2006 15:04:05", rest[:20]); err == nil {
			s.Timestamp, s.Zoneless = t.UTC(), true
			rest = strings.TrimLeft(rest[20:], " ")
		}
	}
	// Mmm dd hh:mm:ss HOST TAG[pid]: MSG
	if s.Timestamp.IsZero() && len(rest) >= 15 {
		if t, err := time.Parse("Jan _2 15:04:05", rest[:15]); err == nil {
			// BSD-формат без года: подставляем текущий; «31 декабря» в первых
			// числах января — это прошлый год, а не событие из будущего
			s.Timestamp, s.Zoneless, s.yearless = withYear(t, time.UTC), true, true
			rest = strings.TrimLeft(rest[15:], " ")
		}
	}
	sp := strings.IndexByte(rest, ' ')
	if sp > 0 {
		s.Hostname = rest[:sp]
		rest = rest[sp+1:]
	}
	if col := strings.IndexByte(rest, ':'); col > 0 && col < 48 && !strings.ContainsAny(rest[:col], " |") {
		tag := rest[:col]
		if br := strings.IndexByte(tag, '['); br > 0 && strings.HasSuffix(tag, "]") {
			s.ProcID = tag[br+1 : len(tag)-1]
			tag = tag[:br]
		}
		s.AppName = tag
		rest = strings.TrimLeft(rest[col+1:], " ")
	}
	s.Message = rest
	return s, nil
}

func nilDash(v string) string {
	if v == "-" {
		return ""
	}
	return v
}

// InZone перечитывает время заголовка без пояса как местное время loc: QNAP,
// коммутаторы и прочие устройства с RFC 3164 пишут часы своего пояса, а в
// заголовке смещения нет. Время с поясом (RFC 5424, ISO) не трогается.
func (s Syslog) InZone(loc *time.Location) Syslog {
	if !s.Zoneless || loc == nil || s.Timestamp.IsZero() {
		return s
	}
	t := s.Timestamp
	if s.yearless {
		// Год выбирается по календарю отправителя: в Москве уже 1 января, когда в UTC
		// ещё 31 декабря, и «Jan 1» — это наступивший год, а не прошлый.
		s.Timestamp = withYear(t, loc).UTC()
		return s
	}
	s.Timestamp = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), loc).UTC()
	return s
}

// withYear ставит времени без года (месяц, день, часы) текущий год по часам loc;
// «31 декабря» в первых числах января — это прошлый год, а не событие из будущего.
func withYear(t time.Time, loc *time.Location) time.Time {
	cur := now().In(loc)
	ts := time.Date(cur.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), loc)
	if ts.After(cur.Add(24 * time.Hour)) {
		ts = ts.AddDate(-1, 0, 0)
	}
	return ts
}

// PeerZones — часовые пояса отправителей syslog без пояса в заголовке
// (SYSLOG_PEER_TZ="192.168.0.59=Europe/Moscow,10.10.10.0/24=Europe/Moscow").
type PeerZones []peerZone

type peerZone struct {
	pfx netip.Prefix
	loc *time.Location
}

// ParsePeerZones разбирает список «адрес или CIDR=пояс IANA» через запятую.
func ParsePeerZones(spec string) (PeerZones, error) {
	var z PeerZones
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		addr, zone, ok := strings.Cut(item, "=")
		if !ok {
			return nil, fmt.Errorf("syslog tz: %q — нужно адрес=пояс", item)
		}
		addr, zone = strings.TrimSpace(addr), strings.TrimSpace(zone)
		if !strings.Contains(addr, "/") {
			ip, err := netip.ParseAddr(addr)
			if err != nil {
				return nil, fmt.Errorf("syslog tz: %q: %w", addr, err)
			}
			addr = netip.PrefixFrom(ip, ip.BitLen()).String()
		}
		pfx, err := netip.ParsePrefix(addr)
		if err != nil {
			return nil, fmt.Errorf("syslog tz: %q: %w", addr, err)
		}
		loc, err := time.LoadLocation(zone)
		if err != nil {
			return nil, fmt.Errorf("syslog tz: %q: %w", zone, err)
		}
		z = append(z, peerZone{pfx: pfx.Masked(), loc: loc})
	}
	return z, nil
}

// Lookup — пояс отправителя; при пересечении побеждает самый узкий префикс.
func (z PeerZones) Lookup(addr string) *time.Location {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return nil
	}
	ip = ip.Unmap()
	var best *peerZone
	for i := range z {
		if z[i].pfx.Contains(ip) && (best == nil || z[i].pfx.Bits() > best.pfx.Bits()) {
			best = &z[i]
		}
	}
	if best == nil {
		return nil
	}
	return best.loc
}
