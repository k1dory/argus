package parse

import (
	"regexp"
	"strconv"
	"strings"
)

// CEF — ArcSight Common Event Format: так экспортируют Check Point, PAN-OS,
// Kaspersky, CrowdStrike и большинство NGFW/EDR.
type CEF struct {
	Version       int
	Vendor        string
	Product       string
	DeviceVersion string
	SignatureID   string
	Name          string
	Severity      int
	Ext           map[string]string
}

var cefKeyRe = regexp.MustCompile(`(?:^|\s)([A-Za-z0-9_.\-]+)=`)

// ParseCEF находит "CEF:" в строке (до неё может стоять syslog-префикс).
func ParseCEF(line string) (CEF, bool) {
	idx := strings.Index(line, "CEF:")
	if idx < 0 {
		return CEF{}, false
	}
	body := line[idx+4:]
	header := splitEscaped(body, '|', 8)
	if len(header) < 8 {
		return CEF{}, false
	}
	c := CEF{Ext: map[string]string{}}
	c.Version, _ = strconv.Atoi(strings.TrimSpace(header[0]))
	c.Vendor, c.Product, c.DeviceVersion = header[1], header[2], header[3]
	c.SignatureID, c.Name = header[4], header[5]
	c.Severity = parseCEFSeverity(header[6])
	parseExtensions(header[7], c.Ext)
	return c, true
}

func parseCEFSeverity(s string) int {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "low":
		return 3
	case "medium":
		return 5
	case "high":
		return 8
	case "very-high", "very high", "critical":
		return 10
	}
	n, _ := strconv.Atoi(s)
	if n > 10 {
		n = 10
	}
	return n
}

// splitEscaped режет по разделителю, уважая экранирование '\|' и '\\'.
func splitEscaped(s string, sep byte, max int) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\\' && i+1 < len(s) {
			cur.WriteByte(s[i+1])
			i++
			continue
		}
		if ch == sep && len(out) < max-1 {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(ch)
	}
	out = append(out, cur.String())
	return out
}

// parseExtensions: "key=value key2=value with spaces" — значение тянется до
// следующего " key=". Экранирование '\=' и '\\' снимается.
func parseExtensions(ext string, out map[string]string) {
	locs := cefKeyRe.FindAllStringSubmatchIndex(ext, -1)
	for i, loc := range locs {
		key := ext[loc[2]:loc[3]]
		valStart := loc[1]
		valEnd := len(ext)
		if i+1 < len(locs) {
			valEnd = locs[i+1][0]
		}
		val := strings.TrimSpace(ext[valStart:valEnd])
		val = strings.ReplaceAll(val, `\=`, "=")
		val = strings.ReplaceAll(val, `\\`, `\`)
		out[key] = val
	}
}
