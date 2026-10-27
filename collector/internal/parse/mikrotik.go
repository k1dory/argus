package parse

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/devitex-soft/argus/collector/internal/model"
)

/* ===== RouterOS (MikroTik) через syslog =====
   Сообщение начинается со списка топиков через запятую, последний из которых —
   уровень: «system,info,account user admin logged in from 10.0.0.5 via ssh»,
   «firewall,info drop-input: in:ether1 out:(unknown 0), connection-state:new
   proto TCP (SYN), 203.0.113.9:4444->185.25.9.1:22, len 60»,
   «dhcp,info dhcp1 assigned 192.168.12.5 for 7C:C2:55:4E:CC:A6 hostname».
   Формат заголовка роутер задаёт сам (bsd-syslog, время BSD или ISO) — его
   разбирает ParseSyslog; здесь только тело. */

var (
	mtTopicsRe   = regexp.MustCompile(`^([a-z0-9-]+(?:,[a-z0-9!-]+)+)\s+(.*)$`)
	mtLoginRe    = regexp.MustCompile(`^user (\S+) logged in from (\S+) via (\S+)`)
	mtLoginFail  = regexp.MustCompile(`^login failure for user (\S+) from (\S+) via (\S+)`)
	mtLogoutRe   = regexp.MustCompile(`^user (\S+) logged out from (\S+) via (\S+)`)
	mtFwIfRe     = regexp.MustCompile(`in:(\S+) out:(\S+?),?\s`)
	mtFwProtoRe  = regexp.MustCompile(`proto (\S+?)(?: \(([^)]*)\))?,`)
	mtFwAddrRe   = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)(?::(\d+))?->(\d+\.\d+\.\d+\.\d+)(?::(\d+))?`)
	mtFwLenRe    = regexp.MustCompile(`len (\d+)`)
	mtDhcpAssign = regexp.MustCompile(`^(\S+) assigned (\d+\.\d+\.\d+\.\d+) (?:for|to) (\S+)(?: (\S+))?`)
	mtDhcpFree   = regexp.MustCompile(`^(\S+) deassigned (\d+\.\d+\.\d+\.\d+) (?:from|for) (\S+)(?: (\S+))?`)
	mtChangedRe  = regexp.MustCompile(`changed by (\S+)`)
)

// mtKnownTopics — топики RouterOS; «a,b text» другого вендора сюда не попадает.
var mtKnownTopics = map[string]bool{
	"system": true, "firewall": true, "dhcp": true, "account": true, "info": true, "warning": true,
	"error": true, "critical": true, "wireless": true, "interface": true, "dns": true, "ppp": true,
	"l2tp": true, "ipsec": true, "ospf": true, "bgp": true, "route": true, "script": true,
	"e-mail": true, "ntp": true, "web-proxy": true, "hotspot": true, "caps": true, "wireguard": true,
}

// ParseMikroTik распознаёт syslog RouterOS. С bsd-syslog=yes роутер шлёт тело
// без списка топиков (уровень — в PRI), с bsd-syslog=no — «topics,level тело»;
// поэтому сначала топики, а без них — характерные строки RouterOS: вход/выход,
// аренды DHCP, журнал правил firewall, изменения конфигурации.
func ParseMikroTik(sl Syslog) (model.Event, bool) {
	msg := strings.TrimSpace(sl.Message)
	var topics []string
	body := msg
	if m := mtTopicsRe.FindStringSubmatch(msg); m != nil {
		for _, t := range strings.Split(m[1], ",") {
			if mtKnownTopics[strings.TrimPrefix(t, "!")] {
				topics = strings.Split(m[1], ",")
				body = strings.TrimSpace(m[2])
				break
			}
		}
	}
	// Без топиков ParseSyslog принимает префикс правила firewall («drop-input: in:…»)
	// за тег приложения — возвращаем его в тело.
	if topics == nil && sl.AppName != "" && sl.ProcID == "" {
		body = sl.AppName + ": " + body
	}
	has := func(t string) bool {
		for _, x := range topics {
			if x == t {
				return true
			}
		}
		return false
	}
	isFirewall := has("firewall") || (mtFwIfRe.MatchString(body) && mtFwAddrRe.MatchString(body))
	isDhcp := has("dhcp") || mtDhcpAssign.MatchString(body) || mtDhcpFree.MatchString(body)
	isAuth := mtLoginRe.MatchString(body) || mtLoginFail.MatchString(body) || mtLogoutRe.MatchString(body)
	isConfig := has("system") || (mtChangedRe.MatchString(body) && !strings.Contains(body, " ssh2"))
	if topics == nil && !isFirewall && !isDhcp && !isAuth && !isConfig {
		return model.Event{}, false
	}

	e := model.Event{
		Source: "net.routeros", SourceClass: "network", Vendor: "MikroTik", Product: "routeros",
		Node: sl.Hostname, Raw: sl.Message, Outcome: "unknown", Severity: 2,
		Attrs: map[string]string{},
	}
	if !sl.Timestamp.IsZero() {
		e.SetTS(sl.Timestamp, "")
	}
	if topics != nil {
		e.Attrs["topics"] = strings.Join(topics, ",")
		e.Action = "routeros." + topics[0]
		switch {
		case has("critical"):
			e.Severity = 8
		case has("error"):
			e.Severity = 6
		case has("warning"):
			e.Severity = 4
		}
	} else {
		e.Action = "routeros.event"
		if sl.Severity >= 0 && sl.Severity < 7 {
			e.Severity = uint8((7 - sl.Severity) * 10 / 7)
		}
	}

	// Вход/выход: успех идёт с топиком account, отказ — system,error,critical
	// без account, поэтому сначала по тексту, потом по топикам.
	switch {
	case mtLoginRe.MatchString(body):
		x := mtLoginRe.FindStringSubmatch(body)
		e.Action, e.Outcome, e.ActorName, e.ActorKind, e.SrcIP = "auth.login", "success", x[1], "user", x[2]
		e.Attrs["method"] = x[3]
	case mtLoginFail.MatchString(body):
		x := mtLoginFail.FindStringSubmatch(body)
		e.Action, e.Outcome, e.ActorName, e.ActorKind, e.SrcIP, e.Severity = "auth.login", "failure", x[1], "user", x[2], 5
		e.Attrs["method"] = x[3]
	case mtLogoutRe.MatchString(body):
		x := mtLogoutRe.FindStringSubmatch(body)
		e.Action, e.Outcome, e.ActorName, e.ActorKind, e.SrcIP = "auth.logout", "success", x[1], "user", x[2]
		e.Attrs["method"] = x[3]
	case has("account"):
		e.Action, e.Object = "auth.event", body
	case isFirewall:
		e.Action = "net.firewall"
		if col := strings.Index(body, ": in:"); col > 0 {
			e.Attrs["prefix"] = body[:col]
			p := strings.ToLower(body[:col])
			switch {
			case strings.Contains(p, "drop") || strings.Contains(p, "reject") || strings.Contains(p, "deny"):
				e.Outcome, e.Severity = "deny", 4
			case strings.Contains(p, "accept") || strings.Contains(p, "allow"):
				e.Outcome = "allow"
			}
		}
		if x := mtFwIfRe.FindStringSubmatch(body); x != nil {
			e.Attrs["in"], e.Attrs["out"] = x[1], x[2]
		}
		if x := mtFwProtoRe.FindStringSubmatch(body); x != nil {
			e.Proto = strings.ToLower(x[1])
			if x[2] != "" {
				e.Attrs["flags"] = x[2]
			}
		}
		if x := mtFwAddrRe.FindStringSubmatch(body); x != nil {
			e.SrcIP, e.DstIP = x[1], x[3]
			e.SrcPort, e.DstPort = port(x[2]), port(x[4])
		}
		if x := mtFwLenRe.FindStringSubmatch(body); x != nil {
			e.Bytes, _ = strconv.ParseUint(x[1], 10, 64)
		}
		if e.SrcIP == "" {
			e.Object = body
		}
	case isDhcp:
		if x := mtDhcpAssign.FindStringSubmatch(body); x != nil {
			e.Action, e.Outcome, e.Object = "dhcp.assign", "success", x[2]
			e.Attrs["server"], e.Attrs["mac"] = x[1], strings.ToLower(x[3])
			if x[4] != "" {
				e.Attrs["hostname"] = x[4]
			}
		} else if x := mtDhcpFree.FindStringSubmatch(body); x != nil {
			e.Action, e.Outcome, e.Object = "dhcp.release", "success", x[2]
			e.Attrs["server"], e.Attrs["mac"] = x[1], strings.ToLower(x[3])
			if x[4] != "" {
				e.Attrs["hostname"] = x[4]
			}
		} else {
			e.Action, e.Object = "dhcp.event", body
		}
	case isConfig:
		if x := mtChangedRe.FindStringSubmatch(body); x != nil {
			e.Action, e.Outcome, e.ActorName, e.ActorKind, e.Object, e.Severity = "system.config", "success", x[1], "user", body, 4
		} else if strings.Contains(body, "rebooted") || strings.Contains(body, "router was rebooted") {
			e.Action, e.Object, e.Severity = "system.reboot", body, 6
		} else {
			e.Action, e.Object = "system.event", body
		}
	default:
		e.Object = body
	}
	e.Ensure()
	return e, true
}

func port(s string) uint16 {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 65535 {
		return 0
	}
	return uint16(n)
}
