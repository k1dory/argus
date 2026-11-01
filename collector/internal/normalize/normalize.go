// Package normalize приводит разобранные записи вендоров к единой схеме
// события и решает, содержит ли событие ПДн.
package normalize

import (
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
	"github.com/devitex-soft/argus/collector/internal/parse"
)

// SourceRule — переопределение классификации из collector.yml.
type SourceRule struct {
	Vendor  string `yaml:"vendor"`  // подстрока в Device Vendor, без учёта регистра
	Product string `yaml:"product"` // необязательная подстрока в Device Product
	Name    string `yaml:"name"`    // ngfw.checkpoint
	Class   string `yaml:"class"`   // ngfw | edr | cicd | k8s | netflow | syslog
	PII     bool   `yaml:"pii"`     // источник целиком содержит ПДн
}

type Normalizer struct {
	Rules     []SourceRule
	PIIFields []string // ключи CEF/LEEF, по которым ищем e-mail и т.п.
	// InternalNets — «свои» сети для направления потока (attrs.scope у NetFlow):
	// inbound — снаружи внутрь, outbound — изнутри наружу, internal — обе стороны
	// свои, external — обе чужие (транзит). Пусто — RFC 1918, 100.64/10, loopback,
	// link-local; свои белые блоки добавляются через INTERNAL_NETS.
	InternalNets []netip.Prefix
	// NATAddrs — внешние адреса NAT (FLOW_NAT_ADDRS). Поток с таким адресом — копия
	// уже учтённого потока изнутри, снятая экспортёром после трансляции:
	// attrs.post_nat=1, правила по исходящему трафику его пропускают, чтобы один
	// и тот же разговор не давал второго инцидента на адрес NAT.
	NATAddrs []netip.Prefix
}

var defaultInternalNets = func() []netip.Prefix {
	var out []netip.Prefix
	for _, c := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128"} {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}()

func (n *Normalizer) inPrefixes(nets []netip.Prefix, ip string) bool {
	if len(nets) == 0 {
		return false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range nets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// IsInternal — адрес из своих сетей (InternalNets или умолчания).
func (n *Normalizer) IsInternal(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	nets := n.InternalNets
	if len(nets) == 0 {
		nets = defaultInternalNets
	}
	for _, p := range nets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// FlowScope — направление потока относительно своих сетей.
func (n *Normalizer) FlowScope(src, dst string) string {
	si, di := n.IsInternal(src), n.IsInternal(dst)
	switch {
	case si && di:
		return "internal"
	case !si && di:
		return "inbound"
	case si && !di:
		return "outbound"
	}
	return "external"
}

// ПДн-эвристики: e-mail (с обфускацией «[at]»/«(at)»/«[dot]»), российские
// номера и международные E.164. Домен e-mail должен содержать точку либо быть
// известным локальным именем (localhost и т.п.): «ivanov@corp» — это скорее
// логин домена Windows или SSH-цель, чем адрес.
var emailRe = regexp.MustCompile(`(?i)[a-z0-9._%+\-]{1,64}(?:@|\s?\[at\]\s?|\s?\(at\)\s?)([a-z0-9\-]{1,63}(?:(?:\.|\s?\[dot\]\s?)[a-z0-9\-]{1,63})*)`)
var phoneRe = regexp.MustCompile(`(?:\+7|8)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}|\+[1-9](?:[\s\-().]?\d){7,14}(?:\D|$)`)

// localDomains — однословные домены, которые считаем адресом и без точки.
var localDomains = map[string]bool{"localhost": true, "local": true, "lan": true, "internal": true, "intranet": true, "home": true}

func hasEmail(s string) bool {
	for _, m := range emailRe.FindAllStringSubmatch(s, -1) {
		domain := strings.ToLower(m[1])
		if strings.Contains(domain, ".") || strings.Contains(domain, "[dot]") || localDomains[domain] {
			return true
		}
	}
	return false
}

// DefaultPIIFields — ключи CEF/LEEF/JSON, где ищем e-mail и телефоны.
var DefaultPIIFields = []string{"suser", "duser", "usrName", "user", "identUserName", "request", "msg",
	"user.email", "email", "phone", "msisdn", "mail", "cs1", "cs2"}

// HasPII — есть ли в строке e-mail или телефон.
func HasPII(s string) bool {
	return s != "" && (hasEmail(s) || phoneRe.MatchString(s))
}

// встроенная таблица вендоров: достаточно для старта без конфига
var builtin = []SourceRule{
	{Vendor: "check point", Name: "ngfw.checkpoint", Class: "ngfw"},
	{Vendor: "palo alto", Product: "cortex", Name: "edr.cortex", Class: "edr"},
	{Vendor: "palo alto", Name: "ngfw.panos", Class: "ngfw"},
	{Vendor: "usergate", Name: "ngfw.usergate", Class: "ngfw"},
	{Vendor: "ideco", Name: "ngfw.ideco", Class: "ngfw"},
	{Vendor: "fortinet", Name: "ngfw.fortigate", Class: "ngfw"},
	{Vendor: "squid", Name: "ngfw.squid", Class: "ngfw"},
	{Vendor: "kaspersky", Name: "edr.kaspersky", Class: "edr"},
	{Vendor: "crowdstrike", Name: "edr.crowdstrike", Class: "edr"},
	{Vendor: "microsoft", Product: "sysmon", Name: "edr.sysmon", Class: "edr"},
	{Vendor: "gitlab", Name: "gitlab.audit", Class: "cicd"},
	{Vendor: "jenkins", Name: "jenkins.audit", Class: "cicd"},
	{Vendor: "harbor", Name: "harbor.audit", Class: "cicd"},
}

// Classify возвращает имя источника, класс и флаг ПДн по вендору/продукту.
func (n *Normalizer) Classify(vendor, product string) (string, string, bool) {
	v, p := strings.ToLower(vendor), strings.ToLower(product)
	for _, set := range [][]SourceRule{n.Rules, builtin} {
		for _, r := range set {
			if r.Vendor != "" && !strings.Contains(v, strings.ToLower(r.Vendor)) {
				continue
			}
			if r.Product != "" && !strings.Contains(p, strings.ToLower(r.Product)) {
				continue
			}
			name := r.Name
			if name == "" {
				name = r.Class + "." + slug(firstNonEmpty(product, vendor))
			}
			return name, r.Class, r.PII
		}
	}
	return "syslog." + slug(firstNonEmpty(vendor, "generic")), "syslog", false
}

func (n *Normalizer) FromCEF(c parse.CEF, sl parse.Syslog, raw string) model.Event {
	name, class, pii := n.Classify(c.Vendor, c.Product)
	e := model.Event{
		Source: name, SourceClass: class, Vendor: c.Vendor, Product: c.Product,
		Severity: uint8(clamp(c.Severity, 0, 10)), Raw: raw, Attrs: map[string]string{},
	}
	ext := c.Ext
	e.SetTS(pickTime(ext["rt"], ext["end"], ext["start"], sl.Timestamp))
	e.SrcIP, e.DstIP = ext["src"], ext["dst"]
	e.SrcPort, e.DstPort = port(ext["spt"]), port(ext["dpt"])
	e.Proto = strings.ToLower(ext["proto"])
	e.Bytes = num(ext["in"]) + num(ext["out"])
	e.Node = firstNonEmpty(ext["dvchost"], ext["dhost"], ext["shost"], sl.Hostname)
	e.SessionID = firstNonEmpty(ext["externalId"], ext["cs6"], ext["eventId"])
	e.ActorName = firstNonEmpty(ext["suser"], ext["duser"], ext["sntdom"])
	e.ActorKind = actorKind(e.ActorName)
	e.Object = firstNonEmpty(ext["request"], ext["filePath"], ext["fname"], ext["dproc"], ext["sproc"], ext["destinationServiceName"])
	e.Action, e.Outcome = actionOutcome(ext["act"], ext["outcome"], ext["cat"], c.Name)
	for k, v := range ext {
		switch k {
		case "src", "dst", "spt", "dpt", "proto", "in", "out", "rt":
		default:
			e.Attrs[k] = v
		}
	}
	e.Attrs["signature"] = c.SignatureID
	e.Attrs["name"] = c.Name
	if pii || n.detectPII(ext) {
		e.PII = 1
	}
	e.Ensure()
	return e
}

func (n *Normalizer) FromLEEF(l parse.LEEF, sl parse.Syslog, raw string) model.Event {
	name, class, pii := n.Classify(l.Vendor, l.Product)
	ext := l.Ext
	e := model.Event{
		Source: name, SourceClass: class, Vendor: l.Vendor, Product: l.Product,
		Raw: raw, Attrs: map[string]string{},
	}
	e.SetTS(pickTime(ext["devTime"], "", "", sl.Timestamp))
	e.SrcIP, e.DstIP = ext["src"], ext["dst"]
	e.SrcPort, e.DstPort = port(ext["srcPort"]), port(ext["dstPort"])
	e.Proto = strings.ToLower(ext["proto"])
	e.Bytes = num(ext["totalBytes"]) + num(ext["bytesIn"]) + num(ext["bytesOut"])
	e.Node = firstNonEmpty(ext["identHostName"], ext["devName"], sl.Hostname)
	e.SessionID = ext["sessionId"]
	e.ActorName = firstNonEmpty(ext["usrName"], ext["user"], ext["identUserName"])
	e.ActorKind = actorKind(e.ActorName)
	e.Object = firstNonEmpty(ext["url"], ext["resource"], ext["fileName"])
	e.Action, e.Outcome = actionOutcome(ext["action"], ext["result"], ext["cat"], l.EventID)
	sevStr := firstNonEmpty(ext["sev"], ext["severity"])
	if sv, err := strconv.Atoi(sevStr); err == nil {
		e.Severity = uint8(clamp(sv, 0, 10))
	}
	for k, v := range ext {
		e.Attrs[k] = v
	}
	e.Attrs["event_id"] = l.EventID
	if pii || n.detectPII(ext) {
		e.PII = 1
	}
	e.Ensure()
	return e
}

// FromSyslog — обычный syslog без CEF/LEEF: всё, у чего нет агента.
func (n *Normalizer) FromSyslog(sl parse.Syslog, raw string) model.Event {
	e := model.Event{
		Source: "syslog." + slug(firstNonEmpty(sl.AppName, "generic")), SourceClass: "syslog",
		Vendor: "syslog", Product: sl.AppName, Node: sl.Hostname, Raw: raw,
		Object: sl.Message, Action: "syslog." + slug(firstNonEmpty(sl.AppName, "message")),
		Attrs: map[string]string{"format": sl.Format, "procid": sl.ProcID, "msgid": sl.MsgID},
	}
	e.SetTS(sl.Timestamp, "")
	if sl.Severity >= 0 {
		e.Severity = uint8(clamp((7-sl.Severity)*10/7, 0, 10))
	}
	for k, v := range sl.Structured {
		e.Attrs[k] = v
	}
	if HasPII(sl.Message) {
		e.PII = 1
	}
	e.Ensure()
	return e
}

func (n *Normalizer) FromFlow(f parse.Flow, source, exporter string) model.Event {
	e := model.Event{
		Source: source, SourceClass: "netflow", Vendor: "netflow", Product: "ipfix",
		Action: "flow", Outcome: "unknown", Node: exporter,
		SrcIP: f.SrcIP, DstIP: f.DstIP, SrcPort: f.SrcPort, DstPort: f.DstPort,
		Proto: parse.ProtoName(f.Proto), Bytes: f.Bytes, Packets: f.Packets,
		Attrs: map[string]string{},
	}
	end := f.End
	if end.IsZero() {
		end = time.Now()
	}
	e.SetTS(end, "")
	if !f.Start.IsZero() {
		e.Attrs["duration_ms"] = strconv.FormatInt(end.Sub(f.Start).Milliseconds(), 10)
	}
	e.Attrs["scope"] = n.FlowScope(f.SrcIP, f.DstIP)
	// Средний размер пакета: запрос DNS — до ~100 байт, пакеты по 1200+ на порт 53
	// — это уже не DNS (QUIC, VPN), что бы ни было написано в номере порта.
	if f.Packets > 0 {
		e.Attrs["avg_pkt"] = strconv.FormatUint(f.Bytes/f.Packets, 10)
	}
	if n.inPrefixes(n.NATAddrs, f.SrcIP) || n.inPrefixes(n.NATAddrs, f.DstIP) {
		e.Attrs["post_nat"] = "1"
	}
	if f.Proto == 6 {
		if fl := parse.TCPFlagsString(f.TCPFlags); fl != "" {
			e.Attrs["tcp_flags"] = fl
		}
		// Попытка соединения без ответа: SYN есть, ACK нет — так выглядят сканы и
		// стук в закрытые порты; установленные сессии несут ACK.
		if f.TCPFlags&0x02 != 0 && f.TCPFlags&0x10 == 0 {
			e.Attrs["syn_only"] = "1"
		}
	}
	e.Ensure()
	return e
}

func (n *Normalizer) detectPII(ext map[string]string) bool {
	for _, keys := range [][]string{n.PIIFields, DefaultPIIFields} {
		for _, k := range keys {
			if v, ok := ext[k]; ok && HasPII(v) {
				return true
			}
		}
	}
	return false
}

func actionOutcome(act, outcome, cat, name string) (string, string) {
	a := strings.ToLower(firstNonEmpty(act, name))
	switch {
	case containsAny(a, "accept", "allow", "permit", "pass"):
		return "session.allow", "allow"
	case containsAny(a, "drop", "deny", "block", "reject", "prevent"):
		return "session.deny", "deny"
	case containsAny(a, "detect", "threat", "malware", "virus", "exploit", "suspicious"):
		return "threat.detect", firstNonEmpty(strings.ToLower(outcome), "unknown")
	case containsAny(a, "login", "logon", "auth"):
		o := strings.ToLower(outcome)
		if containsAny(o, "fail", "deny", "invalid") || containsAny(a, "fail") {
			return "auth.failure", "failure"
		}
		return "auth.success", "success"
	case containsAny(a, "process", "exec", "create"):
		return "process.create", firstNonEmpty(strings.ToLower(outcome), "success")
	}
	return "event." + slug(firstNonEmpty(cat, a, "unknown")), firstNonEmpty(strings.ToLower(outcome), "unknown")
}

func actorKind(name string) string {
	l := strings.ToLower(name)
	switch {
	case name == "":
		return "unknown"
	case strings.HasSuffix(name, "$"), strings.HasPrefix(l, "svc"), strings.Contains(l, "service"),
		strings.HasPrefix(l, "system:"), strings.HasSuffix(l, "_bot"):
		return "service"
	case l == "system" || l == "root" || l == "nt authority\\system":
		return "system"
	}
	return "user"
}

// pickTime — первое разобранное время из кандидатов и его исходная строка
// (для attrs.ts_raw, если время окажется вне окна). Unix-значения: до 1e11 —
// секунды, до 1e16 — миллисекунды; больше (в т.ч. MaxInt64) — мусор, а не
// год 292278994. Если ни один кандидат не разобрался, возвращается нулевое
// время и первое непустое значение: SetTS поставит now и сохранит его в ts_raw.
func pickTime(vals ...any) (time.Time, string) {
	firstRaw := ""
	for _, v := range vals {
		switch x := v.(type) {
		case time.Time:
			if !x.IsZero() {
				return x, ""
			}
		case string:
			if x == "" {
				continue
			}
			if firstRaw == "" {
				firstRaw = x
			}
			if n, err := strconv.ParseInt(x, 10, 64); err == nil {
				switch {
				case n < 0 || n >= 1e16:
					continue
				case n >= 1e11:
					return time.UnixMilli(n).UTC(), x
				default:
					return time.Unix(n, 0).UTC(), x
				}
			}
			if len(x) > 64 {
				continue
			}
			for _, layout := range []string{time.RFC3339Nano, "Jan 02 2006 15:04:05", "2006-01-02 15:04:05", "Jan 02 2006 15:04:05 MST"} {
				if t, err := time.Parse(layout, x); err == nil {
					return t, x
				}
			}
		}
	}
	return time.Time{}, firstRaw
}

func port(s string) uint16 {
	n, _ := strconv.Atoi(s)
	if n < 0 || n > 65535 {
		return 0
	}
	return uint16(n)
}

func num(s string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	return n
}

func clamp(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func slug(s string) string {
	s = strings.Trim(slugRe.ReplaceAllString(strings.ToLower(s), "_"), "_")
	if s == "" {
		return "unknown"
	}
	return s
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// FromWAF — транзакция ModSecurity/Coraza в единую схему: действие http.attack
// при сработавших правилах (иначе http.request), исход deny если движок
// блокировал, allow — если только заметил (DetectionOnly или score не набран).
// Серьёзность — по худшей CRS-severity: CRITICAL→9, ERROR→7, WARNING→5, NOTICE→3.
func (n *Normalizer) FromWAF(w parse.WAF, raw string) model.Event {
	e := model.Event{
		Source: "waf." + firstNonEmpty(w.Product, "modsecurity"), SourceClass: "waf",
		Vendor: map[string]string{"coraza": "Coraza", "modsecurity": "OWASP"}[w.Product], Product: w.Product,
		Action: "http.request", Outcome: "allow", ActorName: w.ClientIP, ActorKind: "unknown",
		// Node — только server_id audit-лога: его задаёт оператор в конфиге WAF.
		// [hostname] error-лога у ModSecurity (Apache r->hostname, nginx
		// headers_in.server) — это заголовок Host запроса: его присылает клиент, и
		// он недоверенный в любом виде, даже как IP или IP:порт — только
		// attrs.http_host. У Coraza [hostname] пишет сам WAF: локальный адрес
		// сокета, на который пришёл запрос, — его IP допускается в dst_ip и
		// attrs.server_addr. Узел окончательно выбирает коллектор (cmd/collector
		// wafNode): отправитель → node: источника → server_id → адрес сервера →
		// адрес отправителя.
		Object: strings.TrimSpace(w.Method + " " + w.URI), Node: w.ServerID,
		SessionID: w.UniqueID, SrcIP: w.ClientIP, SrcPort: uint16(w.ClientPort), DstIP: w.HostIP, DstPort: uint16(w.HostPort),
		Proto: "tcp", Raw: raw, Attrs: map[string]string{},
	}
	if addr := wafServerAddr(w); addr != "" {
		e.Attrs["server_addr"] = addr
		if e.DstIP == "" {
			e.DstIP = addr
		}
	}
	if host := strings.TrimSpace(w.ServerName); host != "" {
		if _, isAddr := hostAddr(host); !isAddr || w.Product != "coraza" {
			e.Attrs["http_host"] = host // от клиента: справочно, не узел и не адрес сервера
		}
	}
	if e.Vendor == "" {
		e.Vendor = "OWASP"
	}
	// unix_timestamp Coraza однозначен; строка timestamp — локальное время хоста без зоны.
	if w.UnixNano > 0 {
		e.SetTS(time.Unix(0, w.UnixNano), w.Time)
	} else if t := parseWAFTime(w.Time); !t.IsZero() {
		e.SetTS(t, w.Time)
	}
	if len(w.Rules) > 0 {
		e.Action = "http.attack"
		switch {
		case w.MaxSeverity >= 0 && w.MaxSeverity <= 2:
			e.Severity = 9
		case w.MaxSeverity == 3:
			e.Severity = 7
		case w.MaxSeverity == 4:
			e.Severity = 5
		case w.MaxSeverity >= 5:
			e.Severity = 3
		default:
			e.Severity = 5
		}
		if w.AnomalyIn >= 20 && e.Severity < 9 {
			e.Severity = 9
		}
		ids := make([]string, 0, len(w.Rules))
		msgs := make([]string, 0, len(w.Rules))
		for _, r := range w.Rules {
			if r.ID != "" {
				ids = append(ids, r.ID)
			}
			if r.Msg != "" && len(msgs) < 5 {
				msgs = append(msgs, r.Msg)
			}
		}
		e.Attrs["rule_ids"] = strings.Join(ids, ",")
		e.Attrs["msgs"] = strings.Join(msgs, " | ")
		if len(w.Categories) > 0 {
			e.Attrs["category"] = w.Categories[0]
			e.Attrs["categories"] = strings.Join(w.Categories, ",")
		}
		if w.AnomalyIn > 0 {
			e.Attrs["anomaly_score"] = strconv.Itoa(w.AnomalyIn)
		}
	}
	// deny — только когда блокировал сам WAF (Access denied / 949110 при 403), а не приложение ответило 403
	if w.Blocked && !strings.EqualFold(w.EngineMode, "DetectionOnly") {
		e.Outcome = "deny"
	} else {
		e.Outcome = "allow"
	}
	if w.Status != 0 {
		e.Attrs["status"] = strconv.Itoa(w.Status)
	}
	if w.EngineMode != "" {
		e.Attrs["engine_mode"] = w.EngineMode
	}
	if w.Host != "" {
		e.Attrs["host"] = w.Host
	}
	if w.Method != "" {
		e.Attrs["method"] = w.Method
	}
	if w.UserAgent != "" {
		e.Attrs["user_agent"] = w.UserAgent
	}
	e.Ensure()
	return e
}

// wafServerAddr — адрес сервера WAF из доверенных данных: host_ip audit-лога или,
// только у Coraza, IP из [hostname] (локальный адрес сокета, его пишет сам WAF).
// [hostname] ModSecurity — заголовок Host клиента: адресом сервера не бывает.
func wafServerAddr(w parse.WAF) string {
	if w.HostIP != "" {
		return w.HostIP
	}
	if w.Product == "coraza" {
		if ip, ok := hostAddr(w.ServerName); ok {
			return ip
		}
	}
	return ""
}

// hostAddr — IP из «addr», «addr:port», «[v6]:port»; ok=false для имени и пустой строки.
func hostAddr(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.Trim(s, "[]")
	if ip := net.ParseIP(s); ip != nil {
		return ip.String(), true
	}
	return "", false
}

func parseWAFTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "02/Jan/2006:15:04:05 -0700", "02/Jan/2006:15:04:05.000000 -0700", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
