package parse

import (
	"strconv"
	"strings"
)

// LEEF — IBM Log Event Extended Format (UserGate, Ideco и др.).
// 1.0: LEEF:1.0|Vendor|Product|Version|EventID|<tab-separated ext>
// 2.0: LEEF:2.0|Vendor|Product|Version|EventID|delim|<ext>, delim — символ или xHH.
type LEEF struct {
	Version string
	Vendor  string
	Product string
	DevVer  string
	EventID string
	Ext     map[string]string
}

func ParseLEEF(line string) (LEEF, bool) {
	idx := strings.Index(line, "LEEF:")
	if idx < 0 {
		return LEEF{}, false
	}
	body := line[idx+5:]
	verEnd := strings.IndexByte(body, '|')
	if verEnd < 0 {
		return LEEF{}, false
	}
	l := LEEF{Version: body[:verEnd], Ext: map[string]string{}}
	rest := body[verEnd+1:]
	nHeader := 4
	if strings.HasPrefix(l.Version, "2") {
		nHeader = 5
	}
	parts := splitEscaped(rest, '|', nHeader+1)
	if len(parts) < nHeader+1 {
		return LEEF{}, false
	}
	l.Vendor, l.Product, l.DevVer, l.EventID = parts[0], parts[1], parts[2], parts[3]
	delim := "\t"
	ext := parts[nHeader]
	if nHeader == 5 {
		d := parts[4]
		switch {
		case d == "":
			delim = "\t"
		case strings.HasPrefix(strings.ToLower(d), "x") && len(d) == 3:
			if n, err := strconv.ParseUint(d[1:], 16, 8); err == nil {
				delim = string(rune(n))
			}
		default:
			delim = d
		}
	}
	for _, kv := range strings.Split(ext, delim) {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		l.Ext[kv[:eq]] = kv[eq+1:]
	}
	return l, true
}
