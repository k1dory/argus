package incidents

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
)

// Склейка сработок по подсети (rules.Collapse). Инцидент ведётся под ключом
// группы «collapse:<группа>:<подсеть>» в GroupKey: он же ключ реестра, и после
// рестарта восстанавливается тем же путём, что group_key (0034). Участники —
// пары «правило|адрес»: у каждой своя сработка (порог считается на адрес), и
// каждый цикл она приходит заново целиком, как у обычного инцидента.

const (
	collapsePrefix = "collapse:"
	// maxMembers — адресов в карточке инцидента; у IPv6 /48 их может быть сколько
	// угодно. Сверх потолка остаются самые свежие, счёт — в MembersDropped.
	maxMembers = 256
	// maxCollapsedEvents — событий в памяти склеенного инцидента (цепочка,
	// автоответ, разбор): у подсети их может быть десятки тысяч.
	maxCollapsedEvents = 2000
	// minPartEvents — сколько свежих событий гарантировано каждой сработке в бюджете.
	minPartEvents = 4
)

// IsCollapsedKey — ключ группы склеенного инцидента.
func IsCollapsedKey(groupKey string) bool { return strings.HasPrefix(groupKey, collapsePrefix) }

// CollapsedKey — ключ группы склеенного инцидента.
func CollapsedKey(group, net string) string { return collapsePrefix + group + ":" + net }

// Member — адрес склеенного инцидента для карточки: когда появился, когда
// последний раз, сколько событий и какие правила сработали.
type Member struct {
	IP     string   `json:"ip"`
	First  string   `json:"first"`
	Last   string   `json:"last"`
	Events uint32   `json:"events"`
	Rules  []string `json:"rules"`
}

// MemberList пишется в колонку members (String, 0035) строкой JSON: так её
// принимает INSERT JSONEachRow, и так же она читается обратно.
type MemberList []Member

func (m MemberList) MarshalJSON() ([]byte, error) {
	if len(m) == 0 {
		return []byte(`""`), nil
	}
	b, err := json.Marshal([]Member(m))
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(b))
}

func (m *MemberList) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*m = nil
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []Member
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return err
	}
	*m = out
	return nil
}

// part — последняя сработка одного правила по одному адресу.
// События части держатся, только пока укладываются в общий бюджет инцидента
// (maxCollapsedEvents); у остальных частей остаются время и число событий —
// этого хватает, чтобы понять, есть ли у сработки новое.
type part struct {
	rule, ip    string
	level       string
	title       string
	tags        []string
	first, last string
	count       int
	events      []*model.Event
}

func newPart(d eval.Detection) *part {
	return &part{rule: d.Rule.ID, ip: d.Key, level: d.Rule.Level, title: d.Rule.Title, tags: d.Rule.Tags,
		first: model.FormatTS(d.First), last: model.FormatTS(d.Last), count: len(d.Events), events: d.Events}
}

// maxDroppedIPs — сколько вытесненных из списка адресов помнить, чтобы не
// посчитать один адрес в members_dropped дважды (только в памяти; сверх потолка
// и после рестарта счёт приблизительный, с запасом вверх).
const maxDroppedIPs = 4096

// applyCollapsed — сработка правила со склейкой: дописать участника в открытый
// инцидент подсети или завести новый. done=false — склеивать нечего (ключ не
// адрес), сработка идёт обычным путём.
func (r *Registry) applyCollapsed(d eval.Detection, net string, now time.Time, created, updated *[]*Incident, inUpdated map[*Incident]bool, dropped map[string]int) {
	key := CollapsedKey(d.Rule.CollapseGroup(), net)
	pk := d.Rule.ID + "|" + d.Key
	last := model.FormatTS(d.Last)
	if ex, ok := r.open[key]; ok {
		if p := ex.parts[pk]; p != nil && len(d.Events) <= p.count && last <= p.last {
			return // ничего нового
		}
		if ex.parts[pk] == nil && ex.memberCovers(d.Rule.ID, d.Key, last, len(d.Events)) {
			// Восстановленный после рестарта инцидент: адрес уже записан с этими
			// событиями — запомнить сработку, но не переписывать инцидент.
			ex.setPart(newPart(d))
			return
		}
		if !isFinal(ex.Status) {
			ex.setPart(newPart(d))
			ex.aggregate()
			ex.UpdatedAt = model.FormatTS(now)[:19]
			if !inUpdated[ex] {
				inUpdated[ex] = true
				*updated = append(*updated, ex)
			}
			return
		}
		// Закрытый инцидент подсети и новая активность — новый инцидент.
	}
	if r.maxNew > 0 && len(*created) >= r.maxNew {
		dropped[d.Rule.ID]++
		return
	}
	inc := build(d, now)
	inc.ActorName, inc.GroupKey = net, key
	inc.setPart(newPart(d))
	inc.aggregate()
	inc.noteSecrets(d)
	inc.IncidentID = fmt.Sprintf("INC-%d", r.next)
	r.next++
	r.open[key] = inc
	*created = append(*created, inc)
}

func (inc *Incident) setPart(p *part) {
	if inc.parts == nil {
		inc.parts = map[string]*part{}
	}
	inc.parts[p.rule+"|"+p.ip] = p
}

// memberCovers — сработка правила rule по адресу уже записана в списке участников
// (восстановленный инцидент): то же правило, не раньше last, не меньше событий.
// Другое правило по тому же адресу — новая сработка: старший обход хостов не
// прячется за уже записанной долбёжкой.
func (inc *Incident) memberCovers(rule, ip, last string, events int) bool {
	for _, m := range inc.Members {
		if m.IP == ip {
			return containsStr(m.Rules, rule) && m.Last >= last && int(m.Events) >= events
		}
	}
	return false
}

// aggregate пересчитывает инцидент по участникам. Записанная история адреса
// (первое появление, правила, число событий) только дополняется сработками из
// буфера: после рестарта буфер короче, и меньшее окно не должно её стирать.
// События — объединение без повторов (обход хостов и скан портов одного адреса —
// одни и те же потоки) в пределах maxCollapsedEvents; уровень — старший из правил.
func (inc *Incident) aggregate() {
	byIP := map[string]*Member{}
	for _, m := range inc.Members {
		cp := m
		cp.Rules = append([]string(nil), m.Rules...)
		byIP[m.IP] = &cp
	}
	ipEvents := map[string]map[*model.Event]bool{}
	var rep *part
	for _, p := range inc.parts {
		m := byIP[p.ip]
		if m == nil {
			m = &Member{IP: p.ip, First: p.first, Last: p.last}
			byIP[p.ip] = m
			if inc.droppedIPs[p.ip] {
				// Вытесненный адрес вернулся в список: в счёте вытесненных его больше нет.
				delete(inc.droppedIPs, p.ip)
				if inc.MembersDropped > 0 {
					inc.MembersDropped--
				}
			}
		}
		if p.first < m.First {
			m.First = p.first
		}
		if p.last > m.Last {
			m.Last = p.last
		}
		if !containsStr(m.Rules, p.rule) {
			m.Rules = append(m.Rules, p.rule)
		}
		if uint32(p.count) > m.Events {
			m.Events = uint32(p.count)
		}
		if ipEvents[p.ip] == nil {
			ipEvents[p.ip] = map[*model.Event]bool{}
		}
		for _, e := range p.events {
			ipEvents[p.ip][e] = true
		}
		// Инцидент представляет старшее правило группы (при равенстве — более
		// раннее): обход хостов важнее долбёжки в один порт того же адреса.
		if rep == nil || rankOf(p.level) > rankOf(rep.level) || (rankOf(p.level) == rankOf(rep.level) && p.first < rep.first) {
			rep = p
		}
	}
	// Только вверх: инцидент не понижается, когда старшая сработка ушла из буфера.
	if rep != nil && (inc.RuleID == "" || rankOf(rep.level) > rankOf(inc.Level)) {
		inc.RuleID, inc.RuleTitle, inc.Tags, inc.Level = rep.rule, rep.title, rep.tags, rep.level
	}
	members := make([]Member, 0, len(byIP))
	for ip, m := range byIP {
		if n := uint32(len(ipEvents[ip])); n > m.Events {
			m.Events = n
		}
		sort.Strings(m.Rules)
		members = append(members, *m)
	}
	sort.Slice(members, func(i, j int) bool {
		if members[i].Last != members[j].Last {
			return members[i].Last > members[j].Last
		}
		return members[i].IP < members[j].IP
	})
	if len(members) > maxMembers {
		// Вытесненные — самые давние: их сработки уходят из памяти вместе с ними,
		// а в счёт members_dropped каждый адрес попадает один раз.
		for _, m := range members[maxMembers:] {
			if !inc.droppedIPs[m.IP] {
				if inc.droppedIPs == nil {
					inc.droppedIPs = map[string]bool{}
				}
				if len(inc.droppedIPs) < maxDroppedIPs {
					inc.droppedIPs[m.IP] = true
				}
				inc.MembersDropped++
			}
			for k, p := range inc.parts {
				if p.ip == m.IP {
					delete(inc.parts, k)
				}
			}
		}
		members = members[:maxMembers]
	}
	inc.Members = members

	// Бюджет событий: у каждой сработки остаются её самые свежие события — сначала
	// по minPartEvents всем (адрес с большим сканом не должен пропасть из автоответа,
	// которому нужны события адреса), затем остаток бюджета по свежести сработок.
	// У давних, на которые бюджета не хватило, остаются время и счёт.
	parts := make([]*part, 0, len(inc.parts))
	for _, p := range inc.parts {
		parts = append(parts, p)
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].last > parts[j].last })
	seen := map[*model.Event]bool{}
	var evs []*model.Event
	keep := make(map[*part]int, len(parts))
	take := func(p *part, n int) {
		for i := len(p.events) - 1 - keep[p]; i >= 0 && n > 0 && len(evs) < maxCollapsedEvents; i-- {
			keep[p]++
			if e := p.events[i]; !seen[e] {
				seen[e] = true
				evs = append(evs, e)
				n--
			}
		}
	}
	for _, p := range parts {
		take(p, minPartEvents)
	}
	for _, p := range parts {
		take(p, maxCollapsedEvents)
	}
	for _, p := range parts {
		if k := keep[p]; k < len(p.events) {
			p.events = p.events[len(p.events)-k:]
		}
	}
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].TS < evs[j].TS })
	count := uint32(0)
	for _, m := range members {
		count += m.Events
	}
	if count > inc.EventCount {
		inc.EventCount = count
	}
	inc.Events = evs
	srcSet := map[string]bool{}
	for _, e := range evs {
		srcSet[e.Source] = true
		if e.PII == 1 {
			inc.PII = 1
		}
	}
	for _, s := range inc.Sources {
		srcSet[s] = true
	}
	inc.Sources = inc.Sources[:0]
	for s := range srcSet {
		inc.Sources = append(inc.Sources, s)
	}
	sort.Strings(inc.Sources)
	for _, m := range members {
		if inc.FirstTS == "" || m.First < inc.FirstTS {
			inc.FirstTS = m.First
		}
		if m.Last > inc.LastTS {
			inc.LastTS = m.Last
		}
	}
	inc.Chain = chain(evs, 12)
	inc.Chain = append(inc.Chain, fmt.Sprintf("→ адресов подсети %s: %d%s", inc.ActorName, len(members)+int(inc.MembersDropped), droppedNote(inc.MembersDropped)))
}

func droppedNote(n uint32) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(" (в списке %d самых свежих)", maxMembers)
}

// MemberIPs — записанные адреса склеенного инцидента.
func (inc *Incident) MemberIPs() []string {
	var out []string
	for _, m := range inc.Members {
		out = append(out, m.IP)
	}
	return out
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

var levelOrder = map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}

func rankOf(l string) int { return levelOrder[strings.ToLower(l)] }

// MemberRules — правила, сработавшие по адресу склеенного инцидента.
func (inc *Incident) MemberRules(ip string) []string {
	for _, m := range inc.Members {
		if m.IP == ip {
			return m.Rules
		}
	}
	return nil
}
