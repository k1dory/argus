#!/usr/bin/env bash
# Генерирует sample/alerts.json — демо-алерты в формате alerts.json Wazuh
# за последний час, чтобы дашборды показывали данные без живого менеджера.
set -euo pipefail

out="$(cd "$(dirname "$0")/.." && pwd)/sample/alerts.json"
mkdir -p "$(dirname "$out")"

now=$(date -u +%s)

ts() { # $1 = секунд назад
    local t=$((now - $1))
    if date -u -r 0 +%Y >/dev/null 2>&1; then
        date -u -r "$t" +"%Y-%m-%dT%H:%M:%S.000+0000" # BSD (macOS)
    else
        date -u -d "@$t" +"%Y-%m-%dT%H:%M:%S.000+0000" # GNU
    fi
}

# Пишем во временный файл и подменяем через mv: шиппер отличает ротацию по
# inode (как у самого Wazuh). Обрезание файла на месте он тоже ловит, но
# только между опросами — если файл успевает вырасти больше старого offset,
# начало теряется.
tmp="$out.tmp.$$"
trap 'rm -f "$tmp" "$out.waf.tmp.$$" "$(dirname "$out")/waf/modsec_audit.log.tmp.$$"' EXIT
: >"$tmp"
i=0
count=240
while [ $i -lt $count ]; do
    ago=$(((count - i) * 30 + RANDOM % 30))
    t=$(ts "$ago")
    aid=$((1000000000 + RANDOM))
    case $((RANDOM % 9)) in
    0 | 1)
        ip="203.0.113.$((RANDOM % 254 + 1))"
        printf '{"timestamp":"%s","rule":{"level":10,"description":"sshd: brute force attack","id":"5763","firedtimes":%d,"groups":["syslog","sshd","authentication_failures"],"mitre":{"id":["T1110"],"tactic":["Credential Access"],"technique":["Brute Force"]}},"agent":{"id":"001","name":"web-01","ip":"10.0.10.11"},"manager":{"name":"wazuh-manager"},"decoder":{"name":"sshd"},"data":{"srcip":"%s"},"location":"/var/log/auth.log","full_log":"Failed password for root from %s port 22 ssh2","id":"%s.1"}\n' \
            "$t" $((RANDOM % 20 + 1)) "$ip" "$ip" "$aid" >>"$tmp"
        ;;
    2)
        # FIM: syscheck.* как в alerts.json 4.x (событие, путь, хэши, владелец, права)
        case $((RANDOM % 6)) in
        0) ev="modified" path="/etc/passwd"            rid="550" lvl=7  desc="Integrity checksum changed."           agid="002" agname="db-01"  ;;
        1) ev="modified" path="/etc/ssh/sshd_config"   rid="550" lvl=7  desc="Integrity checksum changed."           agid="001" agname="web-01" ;;
        2) ev="added"    path="/etc/cron.d/backup-sync" rid="554" lvl=5  desc="File added to the system."             agid="003" agname="app-01" ;;
        3) ev="deleted"  path="/var/www/html/.htaccess" rid="553" lvl=7  desc="File deleted."                          agid="001" agname="web-01" ;;
        4) ev="modified" path="/etc/sudoers.d/90-ops"  rid="550" lvl=7  desc="Integrity checksum changed."           agid="003" agname="app-01" ;;
        5) ev="added"    path="/usr/local/bin/kworkerd" rid="554" lvl=5  desc="File added to the system."             agid="002" agname="db-01"  ;;
        esac
        h1=$(printf '%08x%08x%08x%08x' $RANDOM$RANDOM $RANDOM$RANDOM $RANDOM$RANDOM $RANDOM$RANDOM | cut -c1-32)
        h2=$(printf '%08x%08x%08x%08x' $RANDOM$RANDOM $RANDOM$RANDOM $RANDOM$RANDOM $RANDOM$RANDOM | cut -c1-32)
        printf '{"timestamp":"%s","rule":{"level":%d,"description":"%s","id":"%s","firedtimes":%d,"groups":["ossec","syscheck","syscheck_file"],"mitre":{"id":["T1565.001"],"tactic":["Impact"],"technique":["Stored Data Manipulation"]}},"agent":{"id":"%s","name":"%s","ip":"10.0.10.%s"},"manager":{"name":"wazuh-manager"},"decoder":{"name":"syscheck_integrity_changed"},"syscheck":{"path":"%s","mode":"realtime","size_after":"%d","perm_after":"rw-r--r--","uid_after":"0","gid_after":"0","uname_after":"root","gname_after":"root","md5_before":"%s","md5_after":"%s","sha1_after":"%s%s","event":"%s","changed_attributes":["md5","sha1","size","mtime"]},"location":"syscheck","full_log":"File %s %s","id":"%s.2"}\n' \
            "$t" "$lvl" "$desc" "$rid" $((RANDOM % 5 + 1)) "$agid" "$agname" "$((10 + ${agid#00}))" "$path" $((RANDOM % 4000 + 200)) "$h1" "$h2" "$h2" "${h1:0:8}" "$ev" "$path" "$ev" "$aid" >>"$tmp"
        ;;
    7 | 8)
        # SCA: data.sca.* — результат проверки CIS-бенчмарка (и раз в ~10 — сводка политики)
        case $((RANDOM % 3)) in
        0) pol="CIS Benchmark for Ubuntu Linux 22.04 LTS" pid="cis_ubuntu22-04" agid="001" agname="web-01" ;;
        1) pol="CIS Benchmark for Ubuntu Linux 22.04 LTS" pid="cis_ubuntu22-04" agid="003" agname="app-01" ;;
        2) pol="CIS Benchmark for Debian Linux 12"        pid="cis_debian12"    agid="002" agname="db-01"  ;;
        esac
        if [ $((RANDOM % 10)) -eq 0 ]; then
            passed=$((RANDOM % 60 + 90)); failed=$((RANDOM % 50 + 20)); total=$((passed + failed + 3)); score=$((passed * 100 / (passed + failed)))
            printf '{"timestamp":"%s","rule":{"level":5,"description":"%s: Score less than 80%% (%d)","id":"19003","firedtimes":1,"groups":["sca"]},"agent":{"id":"%s","name":"%s","ip":"10.0.10.%s"},"manager":{"name":"wazuh-manager"},"decoder":{"name":"sca"},"data":{"sca":{"type":"summary","scan_id":"%d","policy":"%s","policy_id":"%s","description":"This document provides prescriptive guidance.","passed":"%d","failed":"%d","invalid":"3","total_checks":"%d","score":"%d","file":"%s.yml"}},"location":"sca","full_log":"","id":"%s.7"}\n' \
                "$t" "$pol" "$score" "$agid" "$agname" "$((10 + ${agid#00}))" $((RANDOM * 100)) "$pol" "$pid" "$passed" "$failed" "$total" "$score" "$pid" "$aid" >>"$tmp"
        else
            case $((RANDOM % 7)) in
            0) cid="28502" title="Ensure permissions on /etc/ssh/sshd_config are configured" res="failed" cis="5.2.1" pci="2.2.4" file="/etc/ssh/sshd_config" ;;
            1) cid="28520" title="Ensure SSH root login is disabled"                        res="failed" cis="5.2.10" pci="2.2.4" file="/etc/ssh/sshd_config" ;;
            2) cid="28600" title="Ensure password expiration is 365 days or less"           res="failed" cis="5.5.1.1" pci="8.2.4" file="/etc/login.defs" ;;
            3) cid="28100" title="Ensure /tmp is a separate partition"                      res="passed" cis="1.1.2.1" pci="" file="" ;;
            4) cid="28300" title="Ensure auditd is installed"                               res="passed" cis="4.1.1.1" pci="10.2" file="" ;;
            5) cid="28650" title="Ensure permissions on /etc/shadow are configured"         res="passed" cis="6.1.3" pci="8.2.1" file="/etc/shadow" ;;
            6) cid="28110" title="Ensure core dumps are restricted"                         res="failed" cis="1.5.1" pci="" file="/etc/security/limits.conf" ;;
            esac
            if [ "$res" = failed ]; then rid="19007"; lvl=7; else rid="19008"; lvl=3; fi
            printf '{"timestamp":"%s","rule":{"level":%d,"description":"%s: %s: %s","id":"%s","firedtimes":1,"groups":["sca"]},"agent":{"id":"%s","name":"%s","ip":"10.0.10.%s"},"manager":{"name":"wazuh-manager"},"decoder":{"name":"sca"},"data":{"sca":{"type":"check","scan_id":"%d","policy":"%s","policy_id":"%s","check":{"id":"%s","title":"%s","rationale":"See CIS benchmark.","remediation":"Follow the benchmark remediation.","compliance":{"cis":"%s","pci_dss":"%s"},"file":"%s","result":"%s"}}},"location":"sca","full_log":"","id":"%s.8"}\n' \
                "$t" "$lvl" "$pol" "$title" "$res" "$rid" "$agid" "$agname" "$((10 + ${agid#00}))" $((RANDOM * 100)) "$pol" "$pid" "$cid" "$title" "$cis" "$pci" "$file" "$res" "$aid" >>"$tmp"
        fi
        ;;
    3)
        ip="198.51.100.$((RANDOM % 254 + 1))"
        printf '{"timestamp":"%s","rule":{"level":7,"description":"SQL injection attempt.","id":"31103","firedtimes":%d,"groups":["web","accesslog","attack","sql_injection"],"mitre":{"id":["T1190"],"tactic":["Initial Access"],"technique":["Exploit Public-Facing Application"]}},"agent":{"id":"001","name":"web-01","ip":"10.0.10.11"},"manager":{"name":"wazuh-manager"},"decoder":{"name":"web-accesslog"},"data":{"srcip":"%s"},"location":"/var/log/nginx/access.log","full_log":"GET /products?id=1 UNION SELECT username,password FROM users","id":"%s.3"}\n' \
            "$t" $((RANDOM % 8 + 1)) "$ip" "$aid" >>"$tmp"
        ;;
    4)
        printf '{"timestamp":"%s","rule":{"level":3,"description":"Successful sudo to ROOT executed.","id":"5402","firedtimes":%d,"groups":["syslog","sudo"],"mitre":{"id":["T1548.003"],"tactic":["Privilege Escalation"],"technique":["Sudo and Sudo Caching"]}},"agent":{"id":"003","name":"app-01","ip":"10.0.10.13"},"manager":{"name":"wazuh-manager"},"decoder":{"name":"sudo"},"location":"/var/log/auth.log","full_log":"user : TTY=pts/0 ; COMMAND=/usr/bin/systemctl restart app","id":"%s.4"}\n' \
            "$t" $((RANDOM % 4 + 1)) "$aid" >>"$tmp"
        ;;
    5)
        printf '{"timestamp":"%s","rule":{"level":12,"description":"PsExec service running as NT AUTHORITY SYSTEM","id":"110011","firedtimes":1,"groups":["windows","sysmon"],"mitre":{"id":["T1543.003"],"tactic":["Persistence","Privilege Escalation"],"technique":["Windows Service"]}},"agent":{"id":"004","name":"win-dc-01","ip":"10.0.20.5"},"manager":{"name":"wazuh-manager"},"decoder":{"name":"windows_eventchannel"},"location":"EventChannel","full_log":"","id":"%s.5"}\n' \
            "$t" "$aid" >>"$tmp"
        ;;
    6)
        # Алерт vulnerability-detector: data.vulnerability.* как в 4.x
        case $((RANDOM % 4)) in
        0) cve="CVE-2024-6387"  sev="Critical" score="8.1" pkg="openssh-server" ver="9.2p1"  agid="001" agname="web-01"    st="Active" ;;
        1) cve="CVE-2023-44487" sev="High"     score="7.5" pkg="nginx"          ver="1.22.1" agid="001" agname="web-01"    st="Active" ;;
        2) cve="CVE-2023-2650"  sev="Medium"   score="6.5" pkg="openssl"        ver="3.0.8"  agid="002" agname="db-01"     st="Solved" ;;
        3) cve="CVE-2024-3094"  sev="Critical" score="10"  pkg="xz-utils"       ver="5.6.0"  agid="003" agname="app-01"    st="Active" ;;
        esac
        printf '{"timestamp":"%s","rule":{"level":10,"description":"%s affects %s","id":"23505","firedtimes":1,"groups":["vulnerability-detector"]},"agent":{"id":"%s","name":"%s","ip":"10.0.10.%s"},"manager":{"name":"wazuh-manager"},"decoder":{"name":"json"},"data":{"vulnerability":{"cve":"%s","severity":"%s","status":"%s","package":{"name":"%s","version":"%s"},"cvss":{"cvss3":{"base_score":"%s"}}}},"location":"vulnerability-detector","full_log":"","id":"%s.6"}\n' \
            "$t" "$cve" "$pkg" "$agid" "$agname" "$((10 + ${agid#00}))" "$cve" "$sev" "$st" "$pkg" "$ver" "$score" "$aid" >>"$tmp"
        ;;
    esac
    i=$((i + 1))
done

mv -f "$tmp" "$out"

# Демо audit-лог WAF (ModSecurity v3 JSON + Coraza JSON): читается tail-листенером
# коллектора при WAF_AUDIT_LOG=/logs/waf/modsec_audit.log и WAF_FROM_START=true.
# Пишем во временный файл и подменяем mv: tail-листенер видит новый inode и перечитывает
# (усечение на месте с дозаписью до того же размера он отличить не может).
wafdir="$(dirname "$out")/waf"; mkdir -p "$wafdir"; waffinal="$wafdir/modsec_audit.log"; waf="$waffinal.tmp.$$"; : >"$waf"
wts() { # RFC3339 UTC, $1 = секунд назад
    local t=$((now - $1))
    if date -u -r 0 +%Y >/dev/null 2>&1; then date -u -r "$t" +"%Y-%m-%dT%H:%M:%SZ"; else date -u -d "@$t" +"%Y-%m-%dT%H:%M:%SZ"; fi
}
for i in $(seq 1 12); do
    printf '{"transaction":{"client_ip":"203.0.113.9","timestamp":"%s","server_id":"shop.corp.local","client_port":%d,"host_ip":"10.0.10.11","host_port":443,"unique_id":"demo-%d","request":{"method":"GET","uri":"/products?id=1%%27%%20OR%%201=1--%d","headers":{"Host":"shop.corp.local","User-Agent":"sqlmap/1.7"}},"response":{"http_code":403},"producer":{"modsecurity":"ModSecurity v3.0.12","connector":"ModSecurity-nginx v1.0.3","secrules_engine":"Enabled","components":["OWASP_CRS/3.3.5"]}},"messages":[{"message":"SQL Injection Attack Detected via libinjection","details":{"ruleId":"942100","severity":"2","tags":["attack-sqli","paranoia-level/1"]}},{"message":"Inbound Anomaly Score Exceeded (Total Score: 15)","details":{"ruleId":"949110","severity":"2","tags":["anomaly-evaluation"]}}]}\n' \
        "$(wts $((3600 - i * 20)))" $((40000 + i)) "$i" "$i" >>"$waf"
done
for h in shop.corp.local api.corp.local git.corp.local mail.corp.local; do
    printf '{"transaction":{"timestamp":"%s","id":"cz-%s","client_ip":"198.51.100.77","client_port":40001,"host_ip":"10.0.10.12","host_port":443,"server_id":"%s","request":{"method":"GET","uri":"/.git/config","headers":{"host":"%s","user-agent":"zgrab/0.x"}},"response":{"status":403},"producer":{"connector":"coraza-caddy","server":"Caddy","rule_engine":"On","rulesets":["OWASP_CRS/4.3.0"]},"messages":[{"message":"Restricted File Access Attempt","data":{"id":930130,"msg":"Restricted File Access Attempt","severity":"critical","tags":["attack-lfi","paranoia-level/1"]}},{"message":"Inbound Anomaly Score Exceeded (Total Score: 5)","data":{"id":949110,"msg":"Inbound Anomaly Score Exceeded (Total Score: 5)","severity":"critical","tags":["anomaly-evaluation"]}}]}}\n' \
        "$(wts $((1800 - RANDOM % 300)))" "$h" "$h" "$h" >>"$waf"
done
printf '{"transaction":{"client_ip":"192.0.2.44","timestamp":"%s","server_id":"api.corp.local","client_port":40002,"host_ip":"10.0.10.12","host_port":443,"unique_id":"demo-do","request":{"method":"GET","uri":"/v1/export?path=../../../../etc/passwd","headers":{"Host":"api.corp.local","User-Agent":"curl/8.4"}},"response":{"http_code":500},"producer":{"modsecurity":"ModSecurity v3.0.12","connector":"ModSecurity-nginx v1.0.3","secrules_engine":"DetectionOnly","components":["OWASP_CRS/3.3.5"]}},"messages":[{"message":"Path Traversal Attack (/../)","details":{"ruleId":"930100","severity":"2","tags":["attack-lfi"]}},{"message":"Inbound Anomaly Score Exceeded (Total Score: 22)","details":{"ruleId":"949110","severity":"2","tags":["anomaly-evaluation"]}}]}\n' "$(wts 600)" >>"$waf"
mv -f "$waf" "$waffinal"
echo "wrote $(wc -l <"$waffinal" | tr -d ' ') WAF transactions to $waffinal"
echo "wrote $(wc -l <"$out" | tr -d ' ') alerts to $out"
