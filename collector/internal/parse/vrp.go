package parse

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/devitex-soft/argus/collector/internal/model"
)

/* ===== Huawei VRP (CloudEngine, S-серия) через info-center =====
   <189>Oct 27 2026 21:47:12 sw1 %%01CLI/5/LOGOUT(s):CID=0x80ca2713;The user succeeded in
   logging out of VTY0. (UserType=SSH, UserName=levadmin, Ip=185.25.9.57, VpnName=_public_)
   Заголовок с годом разбирает ParseSyslog; здесь — тело: модуль/уровень/мнемоника,
   текст и список Key=Value в скобках. */

var (
	vrpHeadRe = regexp.MustCompile(`^%%\d{2}([A-Z0-9_-]+)/(\d)/([A-Z0-9_-]+)\(([a-z])\)(?:\[(\d+)\])?:(?:CID=[0-9a-fx]+;)?\s*(.*)$`)
	vrpKVRe   = regexp.MustCompile(`([A-Za-z][A-Za-z0-9_-]*)=("[^"]*"|[^,()]*)`)
)

// ParseVRP распознаёт строку info-center Huawei VRP.
func ParseVRP(sl Syslog) (model.Event, bool) {
	msg := strings.TrimSpace(sl.Message)
	// RFC 3164 принимает «%%01CLI/5/LOGOUT(s)» за тег приложения — собираем обратно.
	if strings.HasPrefix(sl.AppName, "%%") {
		msg = sl.AppName + ":" + msg
	}
	m := vrpHeadRe.FindStringSubmatch(msg)
	if m == nil {
		return model.Event{}, false
	}
	module, sevStr, mnemonic, kind, text := m[1], m[2], m[3], m[4], strings.TrimSpace(m[6])
	e := model.Event{
		Source: "net.vrp", SourceClass: "network", Vendor: "Huawei", Product: "vrp",
		Node: sl.Hostname, Raw: msg, Outcome: "unknown",
		Attrs: map[string]string{"module": module, "mnemonic": mnemonic, "kind": kind},
	}
	if !sl.Timestamp.IsZero() {
		e.SetTS(sl.Timestamp, "")
	}
	// Уровень VRP 0–7 как у syslog: 0 — emergency, 7 — debug.
	if sv, err := strconv.Atoi(sevStr); err == nil {
		e.Severity = uint8(clampInt((7-sv)*10/7, 0, 10))
		e.Attrs["level"] = sevStr
	}
	// Список параметров в скобках: (UserType=SSH, UserName=levadmin, Ip=…)
	kv := map[string]string{}
	msg = text
	if open := strings.LastIndex(text, "("); open >= 0 && strings.HasSuffix(text, ")") {
		for _, x := range vrpKVRe.FindAllStringSubmatch(text[open+1:len(text)-1], -1) {
			kv[x[1]] = strings.Trim(x[2], `" `)
		}
		msg = strings.TrimSpace(text[:open])
	}
	for k, v := range kv {
		if v != "" {
			e.Attrs[strings.ToLower(k)] = v
		}
	}
	user := firstOf(kv, "UserName", "User", "user")
	ip := firstOf(kv, "Ip", "IP", "IPAddress", "SourceIp", "ip")
	e.Object = msg

	key := module + "/" + mnemonic
	lower := strings.ToLower(msg)
	switch {
	case mnemonic == "LOGIN" || mnemonic == "SSH_USER_LOGIN" || strings.Contains(mnemonic, "LOGIN"):
		e.Action, e.Outcome = "auth.login", "success"
		if strings.Contains(lower, "fail") || strings.Contains(mnemonic, "FAIL") {
			e.Outcome, e.Severity = "failure", 5
		}
	case mnemonic == "LOGOUT" || mnemonic == "SSH_USER_LOGOUT" || strings.Contains(mnemonic, "LOGOUT"):
		e.Action, e.Outcome = "auth.logout", "success"
	case strings.Contains(mnemonic, "FAIL") && (module == "SSH" || module == "CLI" || module == "AAA" || module == "SHELL"):
		e.Action, e.Outcome, e.Severity = "auth.login", "failure", 5
	case mnemonic == "CMDRECORD" || mnemonic == "CMDCONFIRM_TIMEOUT":
		e.Action, e.Outcome = "system.command", "success"
		if cmd := firstOf(kv, "Command", "command"); cmd != "" {
			e.Object = cmd
		}
	case strings.Contains(mnemonic, "CONFIG") || module == "CFM" || module == "CONFIGURATION":
		e.Action, e.Outcome, e.Severity = "system.config", "success", 4
	case module == "IFNET" || module == "IFPDT" || strings.Contains(mnemonic, "LINK"):
		e.Action = "net.link"
		if strings.Contains(lower, "down") {
			e.Outcome, e.Severity = "failure", 5
		} else if strings.Contains(lower, "up") {
			e.Outcome = "success"
		}
	default:
		e.Action = "vrp." + strings.ToLower(key)
	}
	if user != "" {
		e.ActorName, e.ActorKind = user, "user"
	}
	if ip != "" {
		e.SrcIP = ip
	}
	e.Ensure()
	return e, true
}

func firstOf(kv map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := kv[k]; v != "" {
			return v
		}
	}
	return ""
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
