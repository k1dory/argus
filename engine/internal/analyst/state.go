package analyst

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

// Состояние инцидента для моделей решений (System One: Laya, Jev) и записи
// датасета. Записи уходят за пределы консоли (обучение, замеры, облачный Jev),
// поэтому состояние собирается по БЕЛОМУ списку: в него попадают только
// перечисленные ниже поля, а свободный текст — только из разобранных строк
// известного формата (цепочка incidents.chain, события обогащения
// enrich.events). Нераспознанное отбрасывается. Учётки, узлы и адреса
// заменяются псевдонимами (HMAC с солью Pseudonyms).
//
// Не входят никогда: номер инцидента, статус, владелец, заметка, похожие
// закрытые инциденты (в них ответы людей, в том числе по отложенной выборке),
// владелец/команда/заметка CMDB, сырые события.

// Pseudonyms — псевдонимы учёток, узлов и адресов с солью. Одна соль на
// выгрузку: внутри неё один и тот же узел — один псевдоним, между выгрузками
// псевдонимы не сопоставляются.
type Pseudonyms struct{ salt []byte }

// NewPseudonyms — псевдонимы с заданной солью (тесты) или со случайной (nil).
func NewPseudonyms(salt []byte) *Pseudonyms {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			panic("analyst: соль псевдонимов: " + err.Error())
		}
	}
	return &Pseudonyms{salt: salt}
}

// processPseudonyms — соль процесса: одна выгрузка = один запуск engine dataset export.
var processPseudonyms = NewPseudonyms(nil)

func (p *Pseudonyms) h(kind, s string) string {
	m := hmac.New(sha256.New, p.salt)
	m.Write([]byte(kind + "|" + strings.ToLower(s)))
	return hex.EncodeToString(m.Sum(nil))[:8]
}

// systemAccounts — служебные учётки: не ПДн и важны для решения (вход под root
// отличается от входа сотрудника), остаются как есть.
var systemAccounts = map[string]bool{
	"root": true, "admin": true, "administrator": true, "nobody": true, "daemon": true, "guest": true,
	"www-data": true, "nginx": true, "apache": true, "postgres": true, "mysql": true, "clickhouse": true,
	"git": true, "ubuntu": true, "debian": true, "centos": true, "ec2-user": true, "test": true, "user": true,
	"oracle": true, "ftp": true, "sshd": true, "system": true, "-": true,
}

// User — псевдоним учётки; адрес — как IP; служебные учётки — как есть.
func (p *Pseudonyms) User(s string) string {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return ""
	case net.ParseIP(s) != nil:
		return p.IP(s)
	case systemAccounts[strings.ToLower(s)]:
		return strings.ToLower(s)
	}
	return "user-" + p.h("user", s)
}

// Host — псевдоним узла; адрес — как IP.
func (p *Pseudonyms) Host(s string) string {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return ""
	case net.ParseIP(s) != nil:
		return p.IP(s)
	}
	return "host-" + p.h("host", s)
}

// IP — область адреса (public / private / loopback / link-local) и псевдоним
// сети (/24, /48) и узла: соседство адресов одного сканера сохраняется, сами
// адреса — нет.
func (p *Pseudonyms) IP(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return "[ip]"
	}
	scope := "public"
	switch {
	case ip.IsLoopback():
		scope = "loopback"
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
		scope = "link-local"
	case ip.IsPrivate():
		scope = "private"
	case ip.IsUnspecified():
		scope = "unspecified"
	}
	var netw string
	if v4 := ip.To4(); v4 != nil {
		netw = v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	} else {
		netw = ip.Mask(net.CIDRMask(48, 128)).String() + "/48"
	}
	return "ip-" + scope + "-" + p.h("net", netw) + "." + p.h("ip", ip.String())[:4]
}

var (
	safeTokenRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,63}$`) // источник, действие, тег
	ipPortRe    = regexp.MustCompile(`^\[?([0-9A-Fa-f:.]+?)\]?:(\d{1,5})$`)
	measureRe   = regexp.MustCompile(`^(.*?)\s*(-?[0-9][0-9.eE+-]*) ([a-z_]{1,16})$`)
	urlRe       = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9+.-]{1,15})://([^/?#\s]+)([^?#\s]*)`)
	segmentRe   = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,48}$`)
	extRe       = regexp.MustCompile(`^\.[A-Za-z0-9]{1,8}$`)
	clockRe     = regexp.MustCompile(`^\d{2}:\d{2}:\d{2}$`)
)

// systemDirs — каталоги, пути в которых — система, а не данные сотрудника.
var systemDirs = []string{"/etc/", "/usr/", "/bin/", "/sbin/", "/lib", "/opt/", "/var/", "/tmp/", "/proc/",
	"/dev/", "/boot/", "/sys/", "/run/", "/srv/"}

// homeDirs — домашние каталоги: имя учётки — псевдоним, остальное — только расширение.
var homeDirs = []string{"/home/", "/Users/"}

func token(s, fallback string) string {
	s = strings.TrimSpace(strings.TrimSuffix(s, "…"))
	if safeTokenRe.MatchString(s) && !strings.Contains(s, "@") {
		return s
	}
	return fallback
}

func ext(p string) string {
	if e := path.Ext(strings.TrimSuffix(p, "…")); extRe.MatchString(e) {
		return e
	}
	return ""
}

// Path — системный путь по сегментам из безопасных символов; домашний каталог
// — псевдоним учётки и расширение; прочее — «[path]» и расширение.
func (p *Pseudonyms) Path(s string) string {
	s = strings.TrimSuffix(s, "…")
	if strings.HasPrefix(s, "/root/") {
		return "/root/[path]" + ext(s)
	}
	for _, home := range homeDirs {
		if rest, ok := strings.CutPrefix(s, home); ok {
			user, _, _ := strings.Cut(rest, "/")
			return home + p.User(user) + "/[path]" + ext(s)
		}
	}
	for _, dir := range systemDirs {
		if strings.HasPrefix(s, dir) {
			segs := strings.Split(strings.TrimPrefix(s, "/"), "/")
			for i, seg := range segs {
				if seg != "" && (!segmentRe.MatchString(seg) || strings.Contains(seg, "@")) {
					segs[i] = "[x]"
				}
			}
			return "/" + strings.Join(segs, "/")
		}
	}
	return "[path]" + ext(s)
}

// Detail — деталь события (объект, адрес:порт, учётка, измерение) по виду.
func (p *Pseudonyms) Detail(s string) string {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "…"))
	if s == "" {
		return ""
	}
	if m := measureRe.FindStringSubmatch(s); m != nil {
		if _, err := strconv.ParseFloat(m[2], 64); err == nil {
			obj := ""
			if m[1] != "" {
				obj = p.Detail(m[1]) + " "
			}
			return obj + m[2] + " " + m[3]
		}
	}
	if net.ParseIP(s) != nil {
		return p.IP(s)
	}
	if m := ipPortRe.FindStringSubmatch(s); m != nil && net.ParseIP(m[1]) != nil {
		return p.IP(m[1]) + ":" + m[2]
	}
	if m := urlRe.FindStringSubmatch(s); m != nil {
		return strings.ToLower(m[1]) + "://" + p.Host(m[2]) + "/[path]" + ext(m[3])
	}
	if strings.HasPrefix(s, "/") {
		return p.Path(s)
	}
	if len(s) > 2 && s[1] == ':' && (s[2] == '\\' || s[2] == '/') {
		return "[path]" + ext(strings.ReplaceAll(s, "\\", "/"))
	}
	if !strings.ContainsAny(s, " \t") {
		return p.User(s) // одно слово без пути — учётка (в цепочке detail = actor_name)
	}
	return "[text]"
}

// columns — поля фиксированной ширины через пробел (fmt считает ширину в
// рунах) и остаток строки.
func columns(r []rune, widths ...int) ([]string, bool) {
	out := make([]string, 0, len(widths)+1)
	pos := 0
	for _, w := range widths {
		if pos+w >= len(r) || r[pos+w] != ' ' {
			return nil, false
		}
		out = append(out, strings.TrimSpace(string(r[pos:pos+w])))
		pos += w + 1
	}
	return append(out, strings.TrimSpace(string(r[pos:]))), true
}

// chainLine — «ts  источник(16) узел(14) действие(24) деталь» (incidents.chain)
// или «→ причина» движка.
func (p *Pseudonyms) chainLine(line string) (string, bool) {
	if reason, ok := strings.CutPrefix(line, "→ "); ok {
		return "→ " + p.reason(reason), true
	}
	r := []rune(line)
	if len(r) < 10 || !clockRe.MatchString(string(r[:8])) || string(r[8:10]) != "  " {
		return "", false
	}
	f, ok := columns(r[10:], 16, 14, 24)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%s  %s  %s  %s  %s", string(r[:8]), token(f[0], "[source]"), p.Host(strings.TrimSuffix(f[1], "…")),
		token(f[2], "[action]"), p.Detail(f[3])), true
}

var (
	enrichHeadRe = regexp.MustCompile(`^(edr\.process_tree|ngfw\.sessions): (\d+ событий за окно|событий в окне нет|ошибка запроса)`)
	cmdbCritRe   = regexp.MustCompile(`^cmdb: .* — владелец .*, команда .*, критичность (\S+)`)
)

// enrichLine — заголовки и события enrich.events («  ts  источник(14)
// действие(22) деталь»), из CMDB — только критичность.
func (p *Pseudonyms) enrichLine(line string) (string, bool) {
	if m := enrichHeadRe.FindStringSubmatch(line); m != nil {
		return m[1] + ": " + m[2], true
	}
	if m := cmdbCritRe.FindStringSubmatch(line); m != nil {
		return "cmdb: criticality " + token(m[1], "?"), true
	}
	if strings.HasPrefix(line, "cmdb: узел ") && strings.HasSuffix(line, " в CMDB не найден") {
		return "cmdb: node not in CMDB", true
	}
	r := []rune(line)
	if len(r) < 12 || string(r[:2]) != "  " || !clockRe.MatchString(string(r[2:10])) || string(r[10:12]) != "  " {
		return "", false
	}
	f, ok := columns(r[12:], 14, 22)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("  %s  %s  %s  %s", string(r[2:10]), token(f[0], "[source]"), token(f[1], "[action]"), p.Detail(f[2])), true
}

// reason — причина срабатывания от движка (порог, тишина, периодичность):
// числа и слова остаются; адреса — псевдонимы; всё похожее на имя узла,
// путь или учётку — «[x]».
func (p *Pseudonyms) reason(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		core := strings.Trim(w, "(),;")
		switch {
		case core == "":
		case net.ParseIP(core) != nil:
			words[i] = strings.Replace(w, core, p.IP(core), 1)
		case strings.ContainsAny(core, "@\\/_") || strings.Contains(core, ".") && strings.ContainsAny(strings.ToLower(core), "abcdefghijklmnopqrstuvwxyz"):
			words[i] = strings.Replace(w, core, "[x]", 1)
		}
	}
	return strings.Join(words, " ")
}

// redactPII — шаблоны ПДн (email, телефон, паспорт, ИНН, карта).
func redactPII(text string) string {
	for _, name := range []string{"email", "phone", "passport", "inn", "card"} {
		text = patterns[name].ReplaceAllString(text, "[REDACTED:"+name+"]")
	}
	return text
}

// DecisionState — пакет инцидента для моделей решений с солью процесса.
func DecisionState(inc *incidents.Incident) string { return DecisionStateWith(inc, processPseudonyms) }

// DecisionStateWith — пакет инцидента по белому списку полей (см. начало файла).
func DecisionStateWith(inc *incidents.Incident, p *Pseudonyms) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Rule: %s (%s), level %s\n", redactPII(inc.RuleTitle), token(inc.RuleID, "[rule]"), token(inc.Level, "?"))
	tags := make([]string, 0, len(inc.Tags))
	for _, t := range inc.Tags {
		tags = append(tags, token(t, "[tag]"))
	}
	sources := make([]string, 0, len(inc.Sources))
	for _, s := range inc.Sources {
		sources = append(sources, token(s, "[source]"))
	}
	fmt.Fprintf(&b, "Tags: %s\nSubject: %s\nNode: %s\nSources: %s\nEvents: %d\n\nEvent chain:\n",
		strings.Join(tags, ", "), p.User(inc.ActorName), p.Host(inc.Node), strings.Join(sources, ", "), inc.EventCount)
	dropped := 0
	for _, line := range inc.Chain {
		if s, ok := p.chainLine(line); ok {
			b.WriteString(neutralize(s) + "\n")
		} else {
			dropped++
		}
	}
	var enr []string
	for _, line := range inc.Enrichment {
		if s, ok := p.enrichLine(line); ok {
			enr = append(enr, neutralize(s))
		} else {
			dropped++
		}
	}
	if len(enr) > 0 {
		b.WriteString("\nEnrichment:\n" + strings.Join(enr, "\n") + "\n")
	}
	if dropped > 0 {
		fmt.Fprintf(&b, "\n(%d lines of unrecognized format omitted)\n", dropped)
	}
	return redactPII(b.String())
}
