package parse

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// WAF — разобранная транзакция ModSecurity v3 или Coraza (Caddy/nginx):
// запрос, ответ, режим движка и сработавшие правила CRS.
type WAF struct {
	Product     string // modsecurity | coraza
	Time        string // как в логе (RFC3339 или "13/Sep/2026:12:00:00 +0000")
	ClientIP    string
	ClientPort  int
	HostIP      string
	HostPort    int
	ServerID    string // hostname из producer/server_id
	Method      string
	URI         string
	Host        string // заголовок Host
	UserAgent   string
	Status      int
	EngineMode  string // On | DetectionOnly | Off
	UniqueID    string
	Rules       []WAFRule
	AnomalyIn   int // Inbound Anomaly Score, если CRS его сообщил
	Categories  []string
	MaxSeverity int  // CRS: 0 EMERGENCY … 7 DEBUG; -1 если нет правил
	Blocked     bool // движок заблокировал запрос (Access denied / 949110 при status 403)
	Final       bool // итоговая запись транзакции (audit-лог всегда; в error-логе — Access denied или 949110/980130)
}

type WAFRule struct {
	ID       string
	Msg      string
	Severity int // -1 — не указана
	Tags     []string
	Data     string
}

// --- JSON audit log (SecAuditLogFormat JSON): ModSecurity v3 и Coraza ---

type modsecAudit struct {
	Transaction struct {
		Time       string `json:"time_stamp"` // ModSecurity
		Timestamp  string `json:"timestamp"`  // Coraza
		ClientIP   string `json:"client_ip"`
		ClientPort int    `json:"client_port"`
		HostIP     string `json:"host_ip"`
		HostPort   int    `json:"host_port"`
		ServerID   string `json:"server_id"`
		UniqueID   string `json:"unique_id"`
		ID         string `json:"id"`
		Request    struct {
			Method  string            `json:"method"`
			URI     string            `json:"uri"`
			Headers map[string]string `json:"headers"`
		} `json:"request"`
		Response struct {
			HTTPCode int `json:"http_code"` // ModSecurity
			Status   int `json:"status"`    // Coraza
		} `json:"response"`
		Producer struct {
			ModSecurity string   `json:"modsecurity"`
			Connector   string   `json:"connector"`
			Server      string   `json:"server"`
			Engine      string   `json:"secrules_engine"` // ModSecurity
			RuleEngine  string   `json:"rule_engine"`     // Coraza
			Components  []string `json:"components"`
			Rulesets    []string `json:"rulesets"`
		} `json:"producer"`
		Messages []modsecMessage `json:"messages"` // Coraza кладёт messages внутрь transaction
	} `json:"transaction"`
	Messages []modsecMessage `json:"messages"` // ModSecurity — на верхнем уровне
}

type modsecMessage struct {
	Message string        `json:"message"`
	Details modsecDetails `json:"details"` // ModSecurity
	Data    modsecDetails `json:"data"`    // Coraza
}

type modsecDetails struct {
	RuleID   string          `json:"ruleId"`
	ID       json.RawMessage `json:"id"`
	Msg      string          `json:"msg"`
	Data     string          `json:"data"`
	Severity json.RawMessage `json:"severity"`
	Tags     []string        `json:"tags"`
}

var anomalyRe = regexp.MustCompile(`(?i)inbound anomaly score exceeded.*?total(?: inbound)? score:\s*(\d+)`)

// IsWAFAudit — быстрый признак JSON audit-лога ModSecurity/Coraza.
func IsWAFAudit(b []byte) bool {
	t := strings.TrimSpace(string(b))
	return strings.HasPrefix(t, "{") && strings.Contains(t, `"transaction"`)
}

// ParseWAFAudit разбирает одну транзакцию (один JSON-объект).
func ParseWAFAudit(b []byte) (WAF, bool) {
	var a modsecAudit
	if err := json.Unmarshal(b, &a); err != nil || (a.Transaction.ClientIP == "" && a.Transaction.Request.URI == "") {
		return WAF{}, false
	}
	t := a.Transaction
	w := WAF{
		Product: "modsecurity", Time: firstNonEmpty(t.Time, t.Timestamp), ClientIP: t.ClientIP, ClientPort: t.ClientPort,
		HostIP: t.HostIP, HostPort: t.HostPort, ServerID: t.ServerID, Method: t.Request.Method, URI: t.Request.URI,
		Status: firstNonZero(t.Response.HTTPCode, t.Response.Status), UniqueID: firstNonEmpty(t.UniqueID, t.ID),
		EngineMode: firstNonEmpty(t.Producer.Engine, t.Producer.RuleEngine), MaxSeverity: -1,
	}
	if strings.Contains(strings.ToLower(t.Producer.Connector+t.Producer.Server+t.Producer.ModSecurity), "coraza") || t.Producer.RuleEngine != "" {
		w.Product = "coraza"
	}
	for k, v := range t.Request.Headers {
		switch strings.ToLower(k) {
		case "host":
			w.Host = v
		case "user-agent":
			w.UserAgent = v
		}
	}
	msgs := a.Messages
	if len(msgs) == 0 {
		msgs = t.Messages
	}
	for _, m := range msgs {
		d := m.Details
		if d.RuleID == "" && rawString(d.ID) == "" && d.Msg == "" {
			d = m.Data
		}
		r := WAFRule{ID: firstNonEmpty(d.RuleID, rawString(d.ID)), Msg: firstNonEmpty(d.Msg, m.Message), Tags: d.Tags, Data: d.Data, Severity: -1}
		if sev := rawString(d.Severity); sev != "" {
			if s, err := strconv.Atoi(sev); err == nil {
				r.Severity = s
			} else {
				r.Severity = severityWord(sev)
			}
		}
		w.addRule(r)
	}
	w.Final = true
	w.Blocked = !strings.EqualFold(w.EngineMode, "DetectionOnly") && (w.Status == 403 || w.Status == 406) && w.hasFinalRule()
	return w, true
}

// hasFinalRule — сработало правило оценки anomaly score (CRS 949110/980130) — признак решения WAF, а не приложения.
func (w *WAF) hasFinalRule() bool {
	for _, r := range w.Rules {
		if r.ID == "949110" || r.ID == "980130" || r.ID == "959100" {
			return true
		}
	}
	return false
}

// --- error-log строка: Apache/nginx "ModSecurity: Warning. …" и Caddy "Coraza: Warning. …" ---

var (
	kvRe      = regexp.MustCompile(`\[([a-z_]+) "((?:[^"\\]|\\.)*)"\]`)
	clientRe  = regexp.MustCompile(`\[client "?([0-9a-fA-F.:]+)(?::\d+)?"?\]`)
	wafMarkRe = regexp.MustCompile(`(?:ModSecurity|Coraza): (Warning|Access denied with (?:code (\d+)|redirect|connection close))`)
	// метаданные правила начинаются с [file "…"] — всё до него (в т.ч. Value: `…' атакующего) не разбираем
	fileTagRe = regexp.MustCompile(`\[file "`)
)

// IsWAFErrorLine — строка error-лога ModSecurity/Coraza (в т.ч. внутри JSON-лога Caddy).
func IsWAFErrorLine(line string) bool {
	return strings.Contains(line, "ModSecurity: ") || strings.Contains(line, "Coraza: ")
}

// ParseWAFErrorLine разбирает строку error-лога. Если строка — JSON Caddy
// ({"logger":"http.handlers.waf","msg":"…"}), текст берётся из msg.
func ParseWAFErrorLine(line string) (WAF, bool) {
	text := line
	if strings.HasPrefix(strings.TrimSpace(line), "{") {
		var j struct {
			Msg    string  `json:"msg"`
			TS     float64 `json:"ts"`
			Logger string  `json:"logger"`
		}
		if json.Unmarshal([]byte(line), &j) == nil && j.Msg != "" {
			text = j.Msg
		}
	}
	loc := wafMarkRe.FindStringSubmatchIndex(text)
	if loc == nil {
		return WAF{}, false
	}
	m := wafMarkRe.FindStringSubmatch(text)
	w := WAF{Product: "modsecurity", MaxSeverity: -1}
	if strings.HasPrefix(text[loc[0]:], "Coraza") {
		w.Product = "coraza"
	}
	// [client X] — только в префиксе до маркера: в значениях атакующего он подделывается
	if c := clientRe.FindStringSubmatch(text[:loc[0]]); c != nil {
		w.ClientIP = c[1]
	}
	denied := strings.HasPrefix(m[1], "Access denied")
	if m[2] != "" {
		w.Status, _ = strconv.Atoi(m[2])
	}
	// метаданные правила — от первого [file "…"]; до него — совпадение с данными запроса
	meta := text[loc[1]:]
	if fi := fileTagRe.FindStringIndex(meta); fi != nil {
		meta = meta[fi[0]:]
	} else {
		meta = ""
	}
	r := WAFRule{Severity: -1}
	for _, kv := range kvRe.FindAllStringSubmatch(meta, -1) {
		v := strings.ReplaceAll(kv[2], `\"`, `"`)
		switch kv[1] {
		case "id":
			r.ID = v
		case "msg":
			r.Msg = v
		case "data":
			r.Data = v
		case "severity":
			if n, err := strconv.Atoi(v); err == nil {
				r.Severity = n
			} else {
				r.Severity = severityWord(v)
			}
		case "tag":
			r.Tags = append(r.Tags, v)
		case "hostname":
			w.Host = v
		case "uri":
			w.URI = v
		case "unique_id":
			w.UniqueID = v
		}
	}
	if r.ID != "" || r.Msg != "" {
		w.addRule(r)
	}
	// «Access denied» = движок заблокировал; Warning — только детект (DetectionOnly или score ещё не набран).
	// Одна транзакция даёт N строк Warning (по правилу) и одну итоговую: событием считаем итоговую —
	// Access denied либо оценку anomaly score (949110/980130), иначе счётчики правил завышаются в N раз.
	if denied {
		w.EngineMode, w.Blocked = "On", true
	}
	w.Final = denied || w.hasFinalRule()
	return w, true
}

func (w *WAF) addRule(r WAFRule) {
	w.Rules = append(w.Rules, r)
	if r.Severity >= 0 && (w.MaxSeverity < 0 || r.Severity < w.MaxSeverity) {
		w.MaxSeverity = r.Severity // у CRS 0 — самое серьёзное
	}
	if a := anomalyRe.FindStringSubmatch(r.Msg + " " + r.Data); a != nil {
		w.AnomalyIn, _ = strconv.Atoi(a[1])
	}
	for _, t := range r.Tags {
		if c, ok := crsCategory(t); ok && !containsStr(w.Categories, c) {
			w.Categories = append(w.Categories, c)
		}
	}
}

// crsCategory: attack-sqli → sqli, attack-xss → xss, attack-rce → rce, …
func crsCategory(tag string) (string, bool) {
	t := strings.ToLower(tag)
	if !strings.HasPrefix(t, "attack-") {
		return "", false
	}
	return strings.TrimPrefix(t, "attack-"), true
}

func severityWord(s string) int {
	switch strings.ToUpper(s) {
	case "EMERGENCY":
		return 0
	case "ALERT":
		return 1
	case "CRITICAL":
		return 2
	case "ERROR":
		return 3
	case "WARNING":
		return 4
	case "NOTICE":
		return 5
	case "INFO":
		return 6
	case "DEBUG":
		return 7
	}
	return -1
}

func firstNonZero(a, b int) int {
	if a != 0 {
		return a
	}
	return b
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// rawString: значение JSON как строка — число ("id":930130) или строка ("severity":"critical").
func rawString(r json.RawMessage) string {
	s := strings.TrimSpace(string(r))
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		var out string
		if json.Unmarshal(r, &out) == nil {
			return out
		}
		return s[1 : len(s)-1]
	}
	if s == "null" {
		return ""
	}
	return s
}
