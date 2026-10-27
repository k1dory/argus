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
	mtDhcpFree   = regexp.MustCompile(`^(\S+) deassigned (\d+\.\d+\.\d+\.\d+) from (\S+)(?: (\S+))?`)
	mtChangedRe  = regexp.MustCompile(`changed by (\S+)`)
)

// ParseMikroTik распознаёт syslog RouterOS по списку топиков в начале сообщения.
func ParseMikroTik(sl Syslog) (model.Event, bool) {
	m := mtTopicsRe.FindStringSubmatch(strings.TrimSpace(sl.Message))
	if m == nil {
		return model.Event{}, false
	}
	topics := strings.Split(m[1], ",")
	body := strings.TrimSpace(m[2])
	has := func(t string) bool {
		for _, x := range topics {
			if x == t {
				return true
			}
		}
		return false
	}
	// Хотя бы один известный топик RouterOS: иначе «a,b text» любого вендора
	// попадёт сюда.
	known := false
	for _, t := range topics {
		switch t {
		case "system", "firewall", "dhcp", "account", "info", "warning", "error", "critical",
			"wireless", "interface", "dns", "ppp", "l2tp", "ipsec", "ospf", "bgp", "route", "script", "e-mail", "ntp", "web-proxy", "hotspot", "caps", "wireguard":
			known = true
		}
	}
	if !known {
		return model.Event{}, false
	}

	e := model.Event{
		Source: "net.routeros", SourceClass: "network", Vendor: "MikroTik", Product: "routeros",
		Node: sl.Hostname, Raw: sl.Message, Outcome: "unknown", Severity: 2,
		Attrs: map[string]string{"topics": m[1]},
	}
	if !sl.Timestamp.IsZero() {
		e.SetTS(sl.Timestamp, "")
	}
	switch {
	case has("critical"):
		e.Severity = 8
	case has("error"):
		e.Severity = 6
	case has("warning"):
		e.Severity = 4
	}
	first := topics[0]
	e.Action = "routeros." + first

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
	case has("firewall"):
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
	case has("dhcp"):
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
	case has("system"):
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
