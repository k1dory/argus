package analyst

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/registry"
)

// Состояние инцидента для моделей решений (System One: Laya, Jev) и записи
// датасета. Записи уходят за пределы консоли (обучение, замеры, облачный Jev),
// поэтому состояние собирается по БЕЛОМУ списку полей:
//
//   - правило (id, название, уровень), теги, источники, число событий;
//   - субъект и узел — псевдонимы;
//   - строки цепочки (incidents.chain) и событий обогащения (enrich.events)
//     известного формата: время, источник, узел (псевдоним), действие и деталь,
//     от которой остаются только псевдоним адреса или учётки, измерение с
//     единицей из постоянного списка или тип объекта ([path], [url], [text]) с
//     расширением из постоянного списка;
//   - из обогащения ещё — заголовки (сколько событий в окне) и критичность CMDB.
//
// Свободный текст (объект события, путь, URL, причина срабатывания, атрибуты,
// заметки) не попадает никогда — ни целиком, ни «безопасными» кусками:
// надёжно обезличить его нельзя. Всё нераспознанное отбрасывается, в
// состоянии остаётся только счётчик. Не входят также номер инцидента, статус,
// владелец, заметка и похожие закрытые инциденты (в них ответы людей, в том
// числе по отложенной выборке).

// Pseudonyms — псевдонимы учёток, узлов, адресов и ключей (group_id) с солью.
// Одна соль на выгрузку; в JSONL она не пишется: внутри выгрузки один узел —
// один псевдоним, между выгрузками псевдонимы не сопоставляются.
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

// processPseudonyms — соль процесса. engine dataset export задаёт её из
// ARGUS_DATASET_SECRET (SetDatasetSecret): тогда псевдонимы и разбиение
// train/holdout одинаковы во всех выгрузках, а без секрета не связываются.
var processPseudonyms = NewPseudonyms(nil)

// SetDatasetSecret — секрет выгрузки (до первого DecisionState).
func SetDatasetSecret(secret []byte) { processPseudonyms = NewPseudonyms(secret) }

// Process — псевдонимы процесса (соль выгрузки).
func Process() *Pseudonyms { return processPseudonyms }

// Key — псевдоним произвольного ключа (group_id датасета) с той же солью.
func (p *Pseudonyms) Key(kind, s string) string { return p.h(kind, s) }

func (p *Pseudonyms) h(kind, s string) string {
	m := hmac.New(sha256.New, p.salt)
	m.Write([]byte(kind + "|" + strings.ToLower(s)))
	return hex.EncodeToString(m.Sum(nil))[:12]
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

// IP — область адреса (public / private / loopback / link-local) и псевдонимы
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
	return "ip-" + scope + "-" + p.h("net", netw) + "." + p.h("ip", ip.String())
}

var (
	safeTokenRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,63}$`) // правило, тег, источник, действие
	measureRe   = regexp.MustCompile(`^(.*?)\s*(-?[0-9][0-9.eE+-]*) ([a-z_]{1,16})$`)
	urlRe       = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]{1,15}://([^/?#\s]+)`)
	clockRe     = regexp.MustCompile(`^\d{2}:\d{2}:\d{2}$`)
)

// knownExts — расширения, которые остаются у [path] и [url]. Только этот
// список: «расширение» из имени (alice.smirnov) — часть имени.
var knownExts = map[string]bool{
	"exe": true, "dll": true, "sys": true, "msi": true, "bat": true, "cmd": true, "ps1": true, "vbs": true,
	"sh": true, "py": true, "pl": true, "rb": true, "js": true, "php": true, "jar": true, "so": true, "elf": true,
	"zip": true, "rar": true, "7z": true, "tar": true, "gz": true, "tgz": true,
	"doc": true, "docx": true, "xls": true, "xlsx": true, "ppt": true, "pptx": true, "pdf": true, "csv": true,
	"txt": true, "log": true, "conf": true, "cfg": true, "ini": true, "yml": true, "yaml": true, "json": true,
	"xml": true, "html": true, "jpg": true, "png": true, "bak": true, "sql": true, "db": true,
	"key": true, "pem": true, "crt": true, "p12": true, "pfx": true, "kdbx": true, "ovpn": true,
}

// knownUnits — единицы, которые движок дописывает в деталь из полей события
// (model.Event.Value, Unit). Число перед другим словом — свободный текст.
var knownUnits = map[string]bool{
	"percent": true, "bytes": true, "celsius": true, "seconds": true, "ms": true, "count": true,
	"bps": true, "pps": true, "rpm": true, "volts": true, "watts": true, "hz": true,
}

var criticality = map[string]bool{"low": true, "medium": true, "high": true, "critical": true}

func token(s, fallback string) string {
	s = strings.TrimSpace(strings.TrimSuffix(s, "…"))
	if safeTokenRe.MatchString(s) && !strings.Contains(s, "@") {
		return s
	}
	return fallback
}

// knownExt — расширение последнего сегмента, если оно из knownExts.
func knownExt(s string) string {
	s = strings.TrimSuffix(s, "…")
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	s = s[strings.LastIndexAny(s, `/\`)+1:]
	i := strings.LastIndex(s, ".")
	if i <= 0 {
		return ""
	}
	if e := strings.ToLower(s[i+1:]); knownExts[e] {
		return "." + e
	}
	return ""
}

// ipPort — «адрес:порт» как его пишет движок (fmt "%s:%d", IPv6 без скобок):
// порт — после последнего двоеточия, если до него — адрес.
func ipPort(s string) (net.IP, string, bool) {
	i := strings.LastIndex(s, ":")
	if i <= 0 || i == len(s)-1 {
		return nil, "", false
	}
	port := s[i+1:]
	if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
		return nil, "", false
	}
	ip := net.ParseIP(strings.Trim(s[:i], "[]"))
	return ip, port, ip != nil
}

// Detail — деталь события по виду: адрес и адрес:порт — псевдонимы;
// измерение — число и единица из knownUnits; одно слово — учётка
// (псевдоним); прочее — только тип и известное расширение.
func (p *Pseudonyms) Detail(s string) string {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "…"))
	if s == "" {
		return ""
	}
	if m := measureRe.FindStringSubmatch(s); m != nil && knownUnits[m[3]] {
		if _, err := strconv.ParseFloat(m[2], 64); err == nil {
			obj := ""
			if m[1] != "" {
				obj = p.Detail(m[1]) + " "
			}
			return obj + m[2] + " " + m[3]
		}
	}
	// Сначала «адрес:порт»: движок пишет IPv6 с портом без скобок
	// (fd12::1:443), а такая строка — ещё и корректный IPv6.
	if ip, port, ok := ipPort(s); ok {
		return p.IP(ip.String()) + ":" + port
	}
	if net.ParseIP(s) != nil {
		return p.IP(s)
	}
	if m := urlRe.FindStringSubmatch(s); m != nil {
		host := m[1]
		if i := strings.LastIndex(host, "@"); i >= 0 {
			host = host[i+1:]
		}
		if ip, _, ok := ipPort(host); ok {
			return "[url " + p.IP(ip.String()) + "]" + knownExt(s)
		}
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
			return "[url " + p.IP(ip.String()) + "]" + knownExt(s)
		}
		return "[url]" + knownExt(s)
	}
	if strings.ContainsAny(s, `/\`) || (len(s) > 1 && s[1] == ':') || strings.HasPrefix(s, "~") {
		return "[path]" + knownExt(s)
	}
	if !strings.ContainsAny(s, " \t=@:,;\"'()[]{}<>|") {
		return p.User(s) // одно слово — учётка (в цепочке detail = actor_name)
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

// chainLine — «ts  источник(16) узел(14) действие(24) деталь» (incidents.chain).
// Строка «→ причина» движка — текст: отбрасывается (в счётчик).
func (p *Pseudonyms) chainLine(line string) (string, bool) {
	r := []rune(line)
	if len(r) < 10 || !clockRe.MatchString(string(r[:8])) || string(r[8:10]) != "  " {
		return "", false
	}
	f, ok := columns(r[10:], 16, 14, 24)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%s  %s  %s  %s  %s", string(r[:8]), Source(f[0]), p.Host(strings.TrimSuffix(f[1], "…")),
		Action(f[2]), p.Detail(f[3])), true
}

var (
	enrichHeadRe = regexp.MustCompile(`^(edr\.process_tree|ngfw\.sessions): (\d+ событий за окно|событий в окне нет|ошибка запроса)`)
	// Ленивые группы: критичность — первая после шаблона, а не слово из заметки.
	cmdbCritRe = regexp.MustCompile(`^cmdb: .*? — владелец .*?, команда .*?, критичность (\S+)`)
)

// enrichLine — заголовки и события enrich.events («  ts  источник(14)
// действие(22) деталь»), из CMDB — только критичность из шкалы.
func (p *Pseudonyms) enrichLine(line string) (string, bool) {
	if m := enrichHeadRe.FindStringSubmatch(line); m != nil {
		return m[1] + ": " + m[2], true
	}
	if m := cmdbCritRe.FindStringSubmatch(line); m != nil {
		crit := m[1]
		if !criticality[crit] {
			crit = "?"
		}
		return "cmdb: criticality " + crit, true
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
	return fmt.Sprintf("  %s  %s  %s  %s", string(r[2:10]), Source(f[0]), Action(f[1]), p.Detail(f[2])), true
}

// Source, Action — значение из постоянного реестра поставляемого набора
// (registry), иначе «[source]» / «[action]»: пользовательские источники и
// действия из свободного текста (CEF cat=…) могут называть людей и узлы.
func Source(s string) string {
	if s = strings.TrimSpace(s); registry.Source(s) {
		return s
	}
	return "[source]"
}

func Action(s string) string {
	if s = strings.TrimSpace(s); registry.Action(s) {
		return s
	}
	return "[action]"
}

// Rule — id, заголовок и теги правила для состояния и записи датасета.
// Поставляемое правило (registry) — id, заголовок из файла правила и теги из
// реестра; пользовательское — «[rule]» и только теги ATT&CK: его заголовок,
// id и теги пишет оператор, и в них бывают имена и узлы.
func Rule(inc *incidents.Incident) (id, title string, tags []string) {
	if r, ok := registry.LookupRule(inc.RuleID); ok {
		for _, t := range inc.Tags {
			if registry.Tag(t) {
				tags = append(tags, t)
			}
		}
		return inc.RuleID, r.Title, tags
	}
	for _, t := range inc.Tags {
		if registry.AttackTag(t) {
			tags = append(tags, t)
		}
	}
	return "[rule]", "[rule]", tags
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
	id, title, tags := Rule(inc)
	level := inc.Level
	if !criticality[level] {
		level = "?"
	}
	fmt.Fprintf(&b, "Rule: %s (%s), level %s\n", title, id, level)
	sources := make([]string, 0, len(inc.Sources))
	for _, s := range inc.Sources {
		sources = append(sources, Source(s))
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
		fmt.Fprintf(&b, "\n(%d lines omitted)\n", dropped)
	}
	return redactPII(b.String())
}
