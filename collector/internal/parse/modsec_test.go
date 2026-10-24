package parse

import "testing"

const modsecJSON = `{"transaction":{"client_ip":"203.0.113.9","time_stamp":"Sat Sep 13 12:00:01 2026","server_id":"a1b2","client_port":51234,"host_ip":"10.0.10.11","host_port":443,"unique_id":"172345.1","request":{"method":"GET","http_version":1.1,"uri":"/products?id=1'%20OR%201=1--","headers":{"Host":"shop.corp.local","User-Agent":"sqlmap/1.7"}},"response":{"http_code":403,"headers":{}},"producer":{"modsecurity":"ModSecurity v3.0.12 (Linux)","connector":"ModSecurity-nginx v1.0.3","secrules_engine":"Enabled","components":["OWASP_CRS/3.3.5"]}},"messages":[{"message":"SQL Injection Attack Detected via libinjection","details":{"match":"detected SQLi","reference":"v18,14","ruleId":"942100","file":"REQUEST-942-APPLICATION-ATTACK-SQLI.conf","lineNumber":"45","data":"Matched Data: s&1o found","severity":"2","ver":"OWASP_CRS/3.3.5","rev":"","tags":["application-multi","language-multi","platform-multi","attack-sqli","paranoia-level/1","OWASP_CRS","capec/1000/152/248/66"]}},{"message":"Inbound Anomaly Score Exceeded (Total Score: 5)","details":{"ruleId":"949110","severity":"2","tags":["anomaly-evaluation"]}}]}`

const corazaJSON = `{"transaction":{"timestamp":"2026-09-13T12:00:02Z","unix_timestamp":1789300802,"id":"XyZ123","client_ip":"198.51.100.77","client_port":40000,"host_ip":"10.0.10.12","host_port":443,"server_id":"git.corp.local","request":{"method":"GET","protocol":"HTTP/1.1","uri":"/.git/config","http_version":"1.1","headers":{"host":"git.corp.local","user-agent":"zgrab/0.x"}},"response":{"protocol":"HTTP/1.1","status":403,"headers":{}},"producer":{"connector":"coraza-caddy","version":"2.0.0","server":"Caddy","rule_engine":"On","rulesets":["OWASP_CRS/4.3.0"]},"messages":[{"actionset":"","message":"Possible Remote File Inclusion","data":{"file":"@owasp_crs/REQUEST-930-APPLICATION-ATTACK-LFI.conf","line":40,"id":930130,"rev":"","msg":"Restricted File Access Attempt","data":"Matched Data: .git/ found","severity":"critical","ver":"OWASP_CRS/4.3.0","maturity":0,"accuracy":0,"tags":["application-multi","attack-lfi","paranoia-level/1"],"raw":""}}]}}`

func TestParseWAFAuditModSecurity(t *testing.T) {
	w, ok := ParseWAFAudit([]byte(modsecJSON))
	if !ok {
		t.Fatal("not parsed")
	}
	if w.Product != "modsecurity" || w.ClientIP != "203.0.113.9" || w.Host != "shop.corp.local" || w.Status != 403 || w.Method != "GET" {
		t.Fatalf("%+v", w)
	}
	if len(w.Rules) != 2 || w.Rules[0].ID != "942100" || w.MaxSeverity != 2 || w.AnomalyIn != 5 || w.UserAgent != "sqlmap/1.7" {
		t.Fatalf("rules: %+v max=%d anomaly=%d", w.Rules, w.MaxSeverity, w.AnomalyIn)
	}
	if len(w.Categories) != 1 || w.Categories[0] != "sqli" || w.EngineMode != "Enabled" || !w.Blocked || !w.Final {
		t.Fatalf("categories %v mode %q blocked=%v", w.Categories, w.EngineMode, w.Blocked)
	}
}

func TestParseWAFAuditCoraza(t *testing.T) {
	w, ok := ParseWAFAudit([]byte(corazaJSON))
	if !ok {
		t.Fatal("not parsed")
	}
	if w.Product != "coraza" || w.ClientIP != "198.51.100.77" || w.Host != "git.corp.local" || w.Status != 403 || w.Time != "2026-09-13T12:00:02Z" {
		t.Fatalf("%+v", w)
	}
	if len(w.Rules) != 1 || w.Rules[0].ID != "930130" || w.Rules[0].Msg != "Restricted File Access Attempt" || w.Rules[0].Severity != 2 || w.Categories[0] != "lfi" || w.EngineMode != "On" {
		t.Fatalf("rules: %+v cats %v", w.Rules, w.Categories)
	}
	if _, ok := ParseWAFAudit([]byte(`{"foo":1}`)); ok {
		t.Fatal("чужой JSON не должен разбираться как WAF")
	}
	if !IsWAFAudit([]byte(corazaJSON)) || IsWAFAudit([]byte(`{"msg":"x"}`)) {
		t.Fatal("IsWAFAudit")
	}
}

func TestParseWAFErrorLineNginxAndCaddy(t *testing.T) {
	nginx := `2026/09/13 12:00:03 [error] 31#31: *7 [client 203.0.113.200] ModSecurity: Access denied with code 403 (phase 2). Matched "Operator ` + "`" + `PmFromFile' with parameter ` + "`" + `unix-shell.data' against variable ` + "`" + `ARGS:cmd' (Value: ` + "`" + `;cat /etc/passwd' ) [file "/etc/modsecurity/crs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf"] [line "78"] [id "932160"] [rev ""] [msg "Remote Command Execution: Unix Shell Code Found"] [data "Matched Data: cat /etc/passwd found within ARGS:cmd"] [severity "2"] [ver "OWASP_CRS/3.3.5"] [maturity "0"] [accuracy "0"] [tag "application-multi"] [tag "attack-rce"] [tag "paranoia-level/1"] [hostname "shop.corp.local"] [uri "/cgi-bin/test.cgi"] [unique_id "1789300803"] [ref "o0,5v13,14t:urlDecodeUni,t:cmdLine"], client: 203.0.113.200, server: shop.corp.local`
	w, ok := ParseWAFErrorLine(nginx)
	if !ok || w.Product != "modsecurity" || w.ClientIP != "203.0.113.200" || w.Status != 403 || w.Host != "shop.corp.local" || w.URI != "/cgi-bin/test.cgi" {
		t.Fatalf("nginx: ok=%v %+v", ok, w)
	}
	if len(w.Rules) != 1 || w.Rules[0].ID != "932160" || w.Rules[0].Severity != 2 || w.Categories[0] != "rce" || w.EngineMode != "On" {
		t.Fatalf("nginx rules: %+v", w.Rules)
	}
	caddy := `{"level":"error","ts":1789300804.1,"logger":"http.handlers.waf","msg":"[client \"192.0.2.44\"] Coraza: Warning. Matched \"Operator ` + "`" + `Rx' with parameter ` + "`" + `(?i)(?:\\.\\./)'\" [file \"@owasp_crs/REQUEST-930-APPLICATION-ATTACK-LFI.conf\"] [line \"12\"] [id \"930100\"] [msg \"Path Traversal Attack (/../) or (/.../)\"] [data \"\"] [severity \"critical\"] [tag \"attack-lfi\"] [tag \"paranoia-level/1\"] [hostname \"api.corp.local\"] [uri \"/v1/export\"] [unique_id \"c0ffee\"]","request_id":"abc"}`
	w, ok = ParseWAFErrorLine(caddy)
	if !ok || w.Product != "coraza" || w.ClientIP != "192.0.2.44" || w.Status != 0 || w.Host != "api.corp.local" || w.Rules[0].ID != "930100" || w.Rules[0].Severity != 2 || w.Categories[0] != "lfi" {
		t.Fatalf("caddy: ok=%v %+v", ok, w)
	}
	if _, ok := ParseWAFErrorLine("plain syslog line without waf"); ok {
		t.Fatal("обычная строка не WAF")
	}
	if w.Final || w.Blocked {
		t.Fatalf("caddy warning по одному правилу 930100 — промежуточная строка: final=%v blocked=%v", w.Final, w.Blocked)
	}
}

func TestParseWAFErrorLineSpoofingAndEscapes(t *testing.T) {
	// атакующий кладёт в параметр [client 8.8.8.8] [tag "attack-rce"] — не должно попасть ни в ClientIP, ни в теги
	spoof := `2026/09/13 12:00:05 [error] 1#1: *9 [client 203.0.113.9] ModSecurity: Warning. Matched "Operator ` + "`" + `Rx' with parameter ` + "`" + `x' against variable ` + "`" + `ARGS:q' (Value: ` + "`" + `[client 8.8.8.8] [tag "attack-rce"] [id "999999"]' ) [file "/crs/REQUEST-941-APPLICATION-ATTACK-XSS.conf"] [line "1"] [id "941100"] [msg "XSS Attack Detected via libinjection"] [data "Matched Data: say \"hi\" found within ARGS:q: [tag \"attack-rce\"]"] [severity "2"] [tag "attack-xss"] [hostname "shop.corp.local"] [uri "/search"] [unique_id "u1"]`
	w, ok := ParseWAFErrorLine(spoof)
	if !ok || w.ClientIP != "203.0.113.9" || len(w.Rules) != 1 || w.Rules[0].ID != "941100" {
		t.Fatalf("spoof: ok=%v %+v", ok, w)
	}
	if len(w.Categories) != 1 || w.Categories[0] != "xss" || w.Rules[0].Data != `Matched Data: say "hi" found within ARGS:q: [tag "attack-rce"]` {
		t.Fatalf("теги/данные из значения атакующего просочились: cats=%v data=%q", w.Categories, w.Rules[0].Data)
	}
	if w.Final {
		t.Fatal("одиночное Warning по правилу — промежуточная строка, не итог")
	}
	// без [client] в префиксе — адрес не берётся из значения атакующего
	noPrefix := `ModSecurity: Warning. (Value: ` + "`" + `[client 8.8.8.8]') [file "/crs/x.conf"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 10)"] [severity "2"]`
	w, _ = ParseWAFErrorLine(noPrefix)
	if w.ClientIP != "" || !w.Final || w.AnomalyIn != 10 {
		t.Fatalf("no prefix: %+v", w)
	}
	// Access denied with redirect (ModSecurity v2) — заблокировано, итог
	w, ok = ParseWAFErrorLine(`[client 203.0.113.9] ModSecurity: Access denied with redirect to /blocked (phase 2). [file "/x.conf"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"]`)
	if !ok || !w.Blocked || !w.Final || w.EngineMode != "On" {
		t.Fatalf("redirect: %+v", w)
	}
}
