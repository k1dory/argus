package parse

import (
	"regexp"
	"strings"

	"github.com/devitex-soft/argus/collector/internal/model"
)

/* ===== QNAP QTS / QuTS hero (QuLog Center → «Отправить серверу Syslog») =====
   <30>Oct 31 00:42:55 QNAP-2 qulogd[16075]: conn log: Users: erp_read, Source IP: 192.168.0.254,
   Computer name: localhost, Connection type: FTP, Accessed resources: erp/2026/a.jpg, Action: Read
   <30>Oct 31 00:43:18 QNAP-2 qulogd[16075]: event log: Users: admin, Source IP: 192.168.0.108,
   Computer name: ---, Application: Users, Category: General, Content: [Users] Created user "bkp".
   Журнал доступа (conn log) — входы и действия с файлами по SMB/AFP/FTP/NFS/HTTP;
   журнал событий (event log) — администрирование, диски, RAID, приложения. QNAP
   пишет время своего пояса без смещения — его задаёт SYSLOG_PEER_TZ. В пути
   (Accessed resources) бывают запятые, поэтому поля режутся по известным ключам. */

var (
	qnapConnRe  = regexp.MustCompile(`^conn log: Users: (.*?), Source IP: (.*?), Computer name: (.*?), Connection type: (.*?), Accessed resources: (.*), Action: (.*)$`)
	qnapEventRe = regexp.MustCompile(`^event log: Users: (.*?), Source IP: (.*?), Computer name: (.*?), Application: (.*?), Category: (.*?), Content: (.*)$`)
)

// qnapFileActions — действия журнала доступа над файлами и каталогами.
var qnapFileActions = map[string]string{
	"read": "file.read", "write": "file.write", "delete": "file.delete", "rename": "file.rename",
	"move": "file.move", "copy": "file.copy", "add": "file.create", "mkdir": "file.create",
	"create": "file.create",
}

// ParseQNAP распознаёт журналы доступа и событий QuLog Center.
func ParseQNAP(sl Syslog) (model.Event, bool) {
	if sl.AppName != "qulogd" {
		return model.Event{}, false
	}
	msg := strings.TrimSpace(sl.Message)
	e := model.Event{
		Source: "nas.qnap", SourceClass: "storage", Vendor: "QNAP", Product: "qts",
		Node: sl.Hostname, Raw: msg, Outcome: "unknown", Attrs: map[string]string{},
	}
	if !sl.Timestamp.IsZero() {
		e.SetTS(sl.Timestamp, "")
	}
	if sl.Severity >= 0 {
		e.Severity = uint8(clampInt((7-sl.Severity)*10/7, 0, 10))
	}
	var user, ip, host string
	if m := qnapConnRe.FindStringSubmatch(msg); m != nil {
		user, ip, host = m[1], m[2], m[3]
		proto, res, act := m[4], m[5], strings.TrimSpace(m[6])
		e.Attrs["log"], e.Attrs["protocol"], e.Attrs["qnap_action"] = "access", proto, act
		if qnapSet(res) {
			e.Object = res
		}
		la := strings.ToLower(act)
		switch {
		case la == "login success":
			e.Action, e.Outcome = "auth.login", "success"
		case strings.HasPrefix(la, "login fail"):
			e.Action, e.Outcome, e.Severity = "auth.login", "failure", 5
		case la == "logout":
			e.Action, e.Outcome = "auth.logout", "success"
		case qnapFileActions[la] != "":
			e.Action, e.Outcome = qnapFileActions[la], "success"
		default:
			e.Action, e.Outcome = "file."+slugQNAP(la), "success"
		}
	} else if m := qnapEventRe.FindStringSubmatch(msg); m != nil {
		user, ip, host = m[1], m[2], m[3]
		app, cat, content := m[4], m[5], strings.TrimSpace(m[6])
		e.Attrs["log"], e.Attrs["application"], e.Attrs["category"] = "event", app, cat
		e.Object = content
		lc := strings.ToLower(content)
		switch {
		case strings.Contains(lc, "failed to log in") || strings.Contains(lc, "login failed"):
			e.Action, e.Outcome, e.Severity = "auth.login", "failure", 5
		case strings.Contains(lc, "logged in"):
			e.Action, e.Outcome = "auth.login", "success"
		case qnapStorage(app, lc):
			e.Action = "storage.event"
			// Уровень берётся из PRI: warning/error QNAP — это уже сбой, info — штатно.
			if sl.Severity >= 0 && sl.Severity <= 4 {
				e.Outcome = "failure"
			} else {
				e.Outcome = "success"
			}
		case qnapConfig(lc):
			e.Action, e.Outcome = "system.config", "success"
			if e.Severity < 4 {
				e.Severity = 4
			}
		default:
			e.Action, e.Outcome = "system.event", "success"
		}
	} else {
		return model.Event{}, false
	}
	if qnapSet(user) {
		e.ActorName, e.ActorKind = user, "user"
	}
	if qnapSet(ip) {
		e.SrcIP = ip
	}
	if qnapSet(host) {
		e.Attrs["client_host"] = host
	}
	e.Ensure()
	return e, true
}

// qnapSet — QNAP пишет «---» вместо пустого значения.
func qnapSet(v string) bool {
	v = strings.TrimSpace(v)
	return v != "" && v != "---"
}

func qnapStorage(app, content string) bool {
	if strings.Contains(strings.ToLower(app), "storage") {
		return true
	}
	for _, w := range []string{"disk", "raid", "volume", "storage pool", "s.m.a.r.t", "smart", "rebuild", "degraded", "bad block"} {
		if strings.Contains(content, w) {
			return true
		}
	}
	return false
}

func qnapConfig(content string) bool {
	for _, w := range []string{"created", "deleted", "changed", "modified", "enabled", "disabled", "removed", "added", "set "} {
		if strings.Contains(content, w) {
			return true
		}
	}
	return false
}

func slugQNAP(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case b.Len() > 0 && !strings.HasSuffix(b.String(), "_"):
			b.WriteByte('_')
		}
	}
	out := strings.TrimSuffix(b.String(), "_")
	if out == "" {
		return "other"
	}
	return out
}
