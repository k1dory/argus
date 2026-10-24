// Package parse — разбор форматов источников: syslog (RFC 5424 / RFC 3164),
// CEF, LEEF, NetFlow v9 / IPFIX, Kubernetes audit, GitLab.
package parse

import (
	"errors"
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

func parse3164(s Syslog, rest string) (Syslog, error) {
	s.Format = "rfc3164"
	// Mmm dd hh:mm:ss HOST TAG[pid]: MSG
	if len(rest) >= 15 {
		if t, err := time.Parse("Jan _2 15:04:05", rest[:15]); err == nil {
			// BSD-формат без года: подставляем текущий; «31 декабря» в первых
			// числах января — это прошлый год, а не событие из будущего
			cur := now()
			s.Timestamp = time.Date(cur.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
			if s.Timestamp.After(cur.Add(24 * time.Hour)) {
				s.Timestamp = s.Timestamp.AddDate(-1, 0, 0)
			}
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
