package parse

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// Объявленные форматы строк. Разборщик выбирается по объявлению источника, а не по
// содержимому строки: «CEF:», «LEEF:», «Coraza:» в данных (имя файла, User-Agent,
// сообщение правила) не должны менять разборщик. ModSecurity объявить нельзя: его
// error-лог надёжно не разобрать (msg и uri не экранированы) — только JSON-аудит.
const (
	FormatCEF       = "cef"
	FormatLEEF      = "leef"
	FormatWAFCoraza = "waf-coraza" // JSON-лог Caddy со строкой «Coraza: …» (coraza-caddy)
)

// ValidFormat — допустимое объявление формата.
func ValidFormat(f string) bool {
	return f == FormatCEF || f == FormatLEEF || f == FormatWAFCoraza
}

// PeerFormats — форматы по адресу отправителя
// (SYSLOG_PEER_FORMAT="10.0.0.5=cef,10.1.0.0/16=leef").
type PeerFormats []peerFormat

type peerFormat struct {
	pfx    netip.Prefix
	format string
}

// ParsePeerFormats разбирает список «адрес или CIDR=формат» через запятую.
func ParsePeerFormats(spec string) (PeerFormats, error) {
	var f PeerFormats
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		addr, format, ok := strings.Cut(item, "=")
		if !ok {
			return nil, fmt.Errorf("syslog format: %q — нужно адрес=формат", item)
		}
		format = strings.TrimSpace(format)
		if !ValidFormat(format) {
			return nil, fmt.Errorf("syslog format: %q — формат cef, leef или waf-coraza", format)
		}
		pfx, err := peerPrefix("syslog format", strings.TrimSpace(addr))
		if err != nil {
			return nil, err
		}
		f = append(f, peerFormat{pfx: pfx, format: format})
	}
	return f, nil
}

// Lookup — объявленный формат отправителя; при пересечении — самый узкий префикс.
func (f PeerFormats) Lookup(addr string) string {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	ip = ip.WithZone("").Unmap()
	best := -1
	for i := range f {
		if f[i].pfx.Contains(ip) && (best < 0 || f[i].pfx.Bits() > f[best].pfx.Bits()) {
			best = i
		}
	}
	if best < 0 {
		return ""
	}
	return f[best].format
}

// ParseCorazaLine — строка объявленного формата waf-coraza: только JSON-объект лога
// Caddy с logger http.handlers.waf и строкой Coraza в msg. Голый текст, битый JSON,
// JSON-строка или массив не принимаются; строка ModSecurity — тоже: её msg и uri не
// экранированы, и запрос подделывает метаданные правила — источник ModSecurity только
// JSON-аудит.
func ParseCorazaLine(line string) (WAF, bool) {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "{") {
		return WAF{}, false
	}
	var j struct {
		Logger string `json:"logger"`
		Msg    string `json:"msg"`
	}
	if json.Unmarshal([]byte(t), &j) != nil || j.Logger != "http.handlers.waf" || j.Msg == "" {
		return WAF{}, false
	}
	w, ok := ParseWAFErrorLine(t)
	if !ok || w.Product != "coraza" {
		return WAF{}, false
	}
	return w, true
}
