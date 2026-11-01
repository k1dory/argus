// Package incidents превращает сработки в инциденты: идентификатор, цепочка
// событий, уровень, флаг ПДн, склейка с уже открытым инцидентом.
package incidents

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// Статусы отработки — привычные для дежурного формы.
const (
	StatusNew           = "new"
	StatusEscalated     = "escalated"
	StatusInProgress    = "in_progress"
	StatusWaitingOwner  = "waiting_owner"
	StatusObserving     = "observing"
	StatusClosed        = "closed"
	StatusFalsePositive = "false_positive"
)

type Incident struct {
	IncidentID string   `json:"incident_id"`
	UpdatedAt  string   `json:"updated_at"`
	CreatedAt  string   `json:"created_at"`
	RuleID     string   `json:"rule_id"`
	RuleTitle  string   `json:"rule_title"`
	Level      string   `json:"level"`
	Tags       []string `json:"tags"`
	Status     string   `json:"status"`
	Owner      string   `json:"owner"`
	Note       string   `json:"note"`
	ActorName  string   `json:"actor_name"`
	Node       string   `json:"node"`
	// GroupKey — значение явного group_by правила, если он не сводится к
	// субъекту или узлу (node, object): иначе второй диск того же NAS склеивался
	// с первым под ключом «правило|субъект|узел» и уведомления не было.
	GroupKey   string   `json:"group_key"`
	Sources    []string `json:"sources"`
	EventCount uint32   `json:"event_count"`
	FirstTS    string   `json:"first_ts"`
	LastTS     string   `json:"last_ts"`
	PII        uint8    `json:"pii"`
	Chain      []string `json:"chain"`
	Enrichment []string `json:"enrichment"` // строки обогащения (EDR, NGFW, CMDB)
	Similar    []string `json:"similar"`    // похожие закрытые инциденты: «INC-12 · closed · заметка»
	// Members — адреса склеенного по подсети инцидента (collapse.go); у обычного пусто.
	// В incidents_current не выводится — движок и консоль читают его из incidents.
	Members        MemberList `json:"members,omitempty"`
	MembersDropped uint32     `json:"members_dropped,omitempty"`
	// Candidates — снимок сработок участников для автоответа (snapshotIncidents);
	// в реестре пуст, в таблицу не пишется.
	Candidates []Candidate `json:"-"`

	Events []*model.Event `json:"-"`

	// Секреты инцидента для close_match (правило с close_match): по ключу
	// «проект + секрет» — время самой свежей утечки (closeNeed) и самой
	// свежей ротации/отзыва (rotated). Закрыть можно, когда по каждому ключу
	// ротация позже утечки: движок каждый цикл заново прогоняет буфер (2×окно),
	// и старая ротация приходит снова — сравнение времени, а не флаг, не даёт
	// ей закрыть повторную утечку. unmatchable — было событие без ключа.
	// Только в памяти: после рестарта инцидент событием не закрывается.
	closeNeed   map[string]time.Time
	rotated     map[string]time.Time
	unmatchable bool
	// links — доказанная связь утёкшего секрета с токеном (secretLink); nil
	// под ключом — связи нет или утечки одного ключа дали разные токены.
	// confirmed — отозван именно этот токен (решение после ревью автозакрытия):
	// имя (secret_id) выбирает пользователь, и однофамилец любого возраста
	// иначе закрыл бы инцидент, пока настоящий секрет действует.
	links     map[string]*secretLink
	confirmed map[string]bool
	// groupPending — group_key присвоен старому инциденту, но ещё не записан:
	// Apply отдаёт инцидент на запись каждый цикл, пока движок не вызовет Persisted.
	groupPending bool
	// parts — сработки участников склеенного инцидента «правило|адрес» (collapse.go);
	// droppedIPs — адреса, вытесненные из Members (счёт MembersDropped без повторов).
	parts      map[string]*part
	droppedIPs map[string]bool
	// reviewNoted — ротация без подтверждения уже отмечена заметкой.
	reviewNoted bool
	// Review — причина пометки «закрыт автоматикой, нужна проверка» для
	// журнала статусов (в таблицу инцидентов не пишется).
	Review string `json:"-"`
}

// NeedsReviewTag — метка инцидента, который автоматика закрыла бы
// ротацией, но не смогла её подтвердить.
const NeedsReviewTag = "argus.needs_review"

func (inc *Incident) noteSecrets(d eval.Detection) {
	if d.Rule == nil || len(d.Rule.CloseMatch) == 0 {
		return
	}
	if inc.closeNeed == nil {
		inc.closeNeed = map[string]time.Time{}
	}
	for _, e := range d.Events {
		k, ok := d.Rule.CloseMatchKey(e)
		if !ok {
			inc.unmatchable = true
			continue
		}
		_, seen := inc.closeNeed[k]
		if ts := e.Time(); ts.After(inc.closeNeed[k]) {
			inc.closeNeed[k] = ts
			delete(inc.confirmed, k) // новая утечка — подтверждать заново
		} else if !seen {
			inc.closeNeed[k] = ts // событие без времени: нужна хоть какая-то ротация
		}
		if inc.links == nil {
			inc.links = map[string]*secretLink{}
		}
		l, ok := leakLink(e)
		switch prev, had := inc.links[k]; {
		case !ok || (had && (prev == nil || *prev != l)):
			inc.links[k] = nil // связи нет или токены разные — только человек
			// Подтверждение относилось к прежней связи: сбрасывается при любой
			// инвалидизации, даже если событие старше утечки: иначе подтверждение
			// прежней связи закрыло бы инцидент по уже другому токену.
			delete(inc.confirmed, k)
		case !had && !seen:
			inc.links[k] = &l
		}
	}
}

// secretLink — неизменяемый id токена у провайдера (vendor/product) и его
// экземпляра (attrs.instance). Утечку закрывает автоматикой только отзыв
// токена с тем же id в аудите того же провайдера и экземпляра.
type secretLink struct{ tokenID, vendor, product, instance string }

// leakLink — связь события утечки с токеном. Утечка из лога CI знает только
// имя переменной: связи нет, и автозакрытие для неё не срабатывает.
func leakLink(e *model.Event) (secretLink, bool) {
	l := secretLink{tokenID: e.Attrs["token_id"], vendor: strings.ToLower(e.Vendor), product: strings.ToLower(e.Product), instance: e.Attrs["instance"]}
	return l, l.tokenID != "" && l.vendor != "" && l.product != "" && l.instance != ""
}

// revokes — ev отзывает токен связи l: отзыв (не ротация: при ротации у
// GitLab появляется новый токен, и какой id в событии — не гарантировано),
// из аудита (source *.audit) того же провайдера и экземпляра, тот же id.
func (l *secretLink) revokes(ev *model.Event) bool {
	// Только успешный отзыв: failure или unknown не доказывают, что токен
	// перестал действовать.
	if l == nil || !strings.EqualFold(ev.Outcome, "success") || !strings.Contains(strings.ToLower(ev.Action), "_revoked") || !strings.HasSuffix(strings.ToLower(ev.Source), ".audit") {
		return false
	}
	got, ok := leakLink(ev)
	return ok && got == *l
}

// Registry — открытые инциденты по ключу «правило|группа»: новые события
// той же сработки дописываются в существующий, а не плодят дубли.
type Registry struct {
	mu     sync.Mutex
	next   int
	open   map[string]*Incident
	maxNew int // сколько новых инцидентов заводить за один Apply (0 — без предела)
}

// SetMaxNew — предел новых инцидентов за цикл: шторм событий по одному
// правилу иначе заводит тысячи инцидентов и столько же уведомлений.
func (r *Registry) SetMaxNew(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.maxNew = n
}

func NewRegistry(startFrom int, open []Incident) *Registry {
	r := &Registry{next: startFrom + 1, open: map[string]*Incident{}}
	for i := range open {
		inc := open[i]
		// Какие секреты утекли до рестарта, неизвестно (события не в памяти):
		// close_match такой инцидент не закроет — только оператор.
		inc.unmatchable = true
		r.open[inc.regKey()] = &inc
	}
	return r
}

// regKey — ключ реестра: правило, субъект, узел и, у явного group_by, его значение.
// У склеенного по подсети — ключ группы: в нём несколько правил и адресов.
func (inc *Incident) regKey() string {
	if IsCollapsedKey(inc.GroupKey) {
		return inc.GroupKey
	}
	k := inc.RuleID + "|" + inc.ActorName + "|" + inc.Node
	if inc.GroupKey != "" {
		k += "|" + inc.GroupKey
	}
	return k
}

// Apply возвращает инциденты, которые надо записать (новые или обновлённые),
// и сколько новых не завёл сверх предела SetMaxNew — по правилам.
func (r *Registry) Apply(dets []eval.Detection, now time.Time) (created, updated []*Incident, dropped map[string]int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	dropped = map[string]int{}
	inUpdated := map[*Incident]bool{}
	for _, d := range dets {
		inc := build(d, now)
		key := inc.regKey()
		if d.Rule.Collapsed() {
			// Открытый инцидент адреса, заведённый до склейки, дописывается как
			// раньше: живые инциденты задним числом не склеиваются.
			if ex, ok := r.open[key]; !ok || isFinal(ex.Status) {
				if net, ok := rules.NetKey(d.Key); ok {
					r.applyCollapsed(d, net, now, &created, &updated, inUpdated, dropped)
					continue
				}
			}
		}
		if _, ok := r.open[key]; !ok && inc.GroupKey != "" {
			// Инцидент, заведённый до group_key (или восстановленный без него), —
			// под старым ключом: его забирает первая сработка группы, а не новый инцидент.
			legacy := d.Rule.ID + "|" + inc.ActorName + "|" + inc.Node
			if ex, ok := r.open[legacy]; ok && ex.GroupKey == "" {
				delete(r.open, legacy)
				ex.GroupKey = inc.GroupKey
				r.open[key] = ex
				ex.groupPending = true
			}
		}
		if ex, ok := r.open[key]; ok && isFinal(ex.Status) && inc.LastTS <= ex.LastTS {
			// Закрытый инцидент по той же сработке без новых событий: absence
			// и склеенные окна иначе заводили бы новый инцидент каждый цикл.
			continue
		}
		if ex, ok := r.open[key]; ok && !isFinal(ex.Status) {
			if inc.EventCount <= ex.EventCount && inc.LastTS <= ex.LastTS {
				continue // ничего нового
			}
			ex.EventCount, ex.LastTS, ex.Chain, ex.Sources, ex.Events = inc.EventCount, inc.LastTS, inc.Chain, inc.Sources, inc.Events
			ex.noteSecrets(d)
			if inc.PII == 1 {
				ex.PII = 1
			}
			ex.UpdatedAt = model.FormatTS(now)[:19]
			if !inUpdated[ex] {
				inUpdated[ex] = true
				updated = append(updated, ex)
			}
			continue
		}
		if r.maxNew > 0 && len(created) >= r.maxNew {
			dropped[d.Rule.ID]++
			continue
		}
		inc.noteSecrets(d)
		inc.IncidentID = fmt.Sprintf("INC-%d", r.next)
		r.next++
		r.open[key] = inc
		created = append(created, inc)
	}
	// Присвоенный group_key, ещё не подтверждённый Persisted, записывается
	// отдельной версией строки каждый цикл — без новых событий и даже когда
	// исходная сработка уже ушла из буфера: иначе после рестарта инцидент
	// снова окажется без ключа.
	var pending []*Incident
	for _, inc := range r.open {
		if inc.groupPending && !inUpdated[inc] {
			pending = append(pending, inc.bumpUpdated(now))
		}
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].IncidentID < pending[j].IncidentID })
	updated = append(updated, pending...)
	return created, updated, dropped
}

// Persisted отмечает инциденты записанными: присвоенный group_key больше не
// нужно повторять. Вызывается после успешного INSERT.
func (r *Registry) Persisted(incs []*Incident) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make(map[string]bool, len(incs))
	for _, inc := range incs {
		ids[inc.IncidentID] = true
	}
	for _, inc := range r.open {
		if inc.groupPending && ids[inc.IncidentID] {
			inc.groupPending = false
		}
	}
}

// bumpUpdated продвигает updated_at к now, а если now не позже — на секунду
// вперёд: новая версия строки должна победить в argMax по updated_at.
func (inc *Incident) bumpUpdated(now time.Time) *Incident {
	ts := model.FormatTS(now)[:19]
	if ts <= inc.UpdatedAt {
		if t, err := time.Parse("2006-01-02 15:04:05", inc.UpdatedAt); err == nil {
			ts = model.FormatTS(t.Add(time.Second))[:19]
		}
	}
	inc.UpdatedAt = ts
	return inc
}

// Prune убирает из реестра финальные инциденты старше ttl после закрытия:
// они нужны только как якорь дедупликации, а вечно копить их — утечка памяти.
// keep(ruleID) == true — инцидент правила не чистится никогда (absence:
// без якоря молчание группы заводило бы новый инцидент каждый цикл); nil — чистить все.
func (r *Registry) Prune(now time.Time, ttl time.Duration, keep func(ruleID string) bool) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for k, inc := range r.open {
		if !isFinal(inc.Status) || (keep != nil && keep(inc.RuleID)) {
			continue
		}
		upd := (&model.Event{TS: inc.UpdatedAt}).Time()
		if upd.IsZero() || now.Sub(upd) >= ttl {
			delete(r.open, k)
			n++
		}
	}
	return n
}

// AddSystem регистрирует системный инцидент движка (шторм, диск) под своим
// ключом, чтобы OpenByRule находил его и после рестарта.
func (r *Registry) AddSystem(inc *Incident) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.open[inc.regKey()] = inc
}

// Shadowed — оператор поменял инцидент между чтением seen и нашей вставкой:
// среди сырых строк rows есть версия новее seen, но не новее нашей (наша
// перекрыла бы её в argMax; при равном updated_at выбор произволен) и с
// другими полями оператора. Возвращает самую новую такую версию или nil.
func Shadowed(inc *Incident, seen Operator, rows []Operator) *Operator {
	var best *Operator
	for i := range rows {
		op := rows[i]
		if op.UpdatedAt <= seen.UpdatedAt || op.UpdatedAt > inc.UpdatedAt {
			continue
		}
		if op.Status == inc.Status && op.Owner == inc.Owner && op.Note == inc.Note {
			continue
		}
		if best == nil || op.UpdatedAt > best.UpdatedAt {
			best = &op
		}
	}
	return best
}

// ApplyOperator переносит поля оператора в инцидент и сдвигает updated_at
// строго позже нашей предыдущей записи, чтобы новая версия победила в argMax.
func ApplyOperator(inc *Incident, op Operator) {
	inc.Status, inc.Owner, inc.Note = op.Status, op.Owner, op.Note
	if t, err := time.Parse("2006-01-02 15:04:05", inc.UpdatedAt); err == nil {
		inc.UpdatedAt = model.FormatTS(t.Add(time.Second))[:19]
	}
}

// Operator — то, что дежурный меняет из консоли.
type Operator struct {
	Status, Owner, Note, UpdatedAt string
}

// Reconcile сверяет инциденты, которые движок собирается записать, с тем,
// что уже лежит в базе от оператора. Возвращает список к записи:
//   - статус/владелец/заметку оператора движок не затирает;
//   - если оператор уже закрыл инцидент, «обновление» по нему не пишется;
//   - updated_at всегда строго позже операторской версии, иначе
//     ReplacingMergeTree/argMax выбрали бы строку произвольно.
func (r *Registry) Reconcile(toWrite []*Incident, ops map[string]Operator, engineClosed map[string]bool, now time.Time) []*Incident {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := toWrite[:0]
	for _, inc := range toWrite {
		op, ok := ops[inc.IncidentID]
		if !ok {
			out = append(out, inc)
			continue
		}
		if engineClosed[inc.IncidentID] {
			if isFinal(op.Status) || (inc.Status == StatusEscalated && op.Status != "" && op.Status != StatusNew) {
				// Оператор закрыл сам — движку нечего добавить; эскалация
				// тишиной не перебивает статус, который оператор уже поставил.
				inc.Status, inc.Owner, inc.Note = op.Status, op.Owner, op.Note
				if isFinal(op.Status) {
					// Финальный статус оператора: повторять присвоение незачем. У
					// открытого (escalated, in_progress…) ключ ещё не записан — повтор
					// остаётся, иначе после рестарта инцидент снова окажется без ключа.
					inc.groupPending = false
				}
				continue
			}
			// Закрытие движком: заметка оператора остаётся, наша дописывается.
			inc.Owner = op.Owner
			if op.Note != "" && !strings.Contains(inc.Note, op.Note) {
				inc.Note = strings.TrimSpace(op.Note + "\n" + inc.Note)
			}
		} else {
			inc.Status, inc.Owner, inc.Note = op.Status, op.Owner, op.Note
			if isFinal(op.Status) {
				// Оператор закрыл — новые события заведут новый инцидент, а
				// неподтверждённый group_key больше не повторяется (иначе каждый
				// цикл сдвигал бы updated_at, и Prune инцидент не убрал бы).
				inc.groupPending = false
				continue
			}
		}
		if op.UpdatedAt >= inc.UpdatedAt {
			if t, err := time.Parse("2006-01-02 15:04:05", op.UpdatedAt); err == nil {
				inc.UpdatedAt = model.FormatTS(t.Add(time.Second))[:19]
			}
		}
		out = append(out, inc)
	}
	return out
}

// OpenByRule — открытый инцидент правила (первый попавшийся), nil если нет.
// Нужен системным инцидентам движка, чтобы после рестарта закрывать свои же.
func (r *Registry) OpenByRule(ruleID string) *Incident {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, inc := range r.open {
		if inc.RuleID == ruleID && !isFinal(inc.Status) {
			return inc
		}
	}
	return nil
}

// OpenByRuleActor — открытый инцидент правила по субъекту (системные
// инциденты «шторм» ведутся по одному на правило-источник).
func (r *Registry) OpenByRuleActor(ruleID, actor string) *Incident {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, inc := range r.open {
		if inc.RuleID == ruleID && inc.ActorName == actor && !isFinal(inc.Status) {
			return inc
		}
	}
	return nil
}

// NextID выдаёт следующий идентификатор инцидента (для системных инцидентов
// движка, которые создаются мимо правил).
func (r *Registry) NextID() (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := fmt.Sprintf("INC-%d", r.next)
	r.next++
	return id, nil
}

func isFinal(status string) bool {
	return status == StatusClosed || status == StatusFalsePositive
}

// Close закрывает открытый инцидент правила по ключу (close_on-событие).
// evTS — время события восстановления: закрывает только событие позже
// последнего события инцидента. Буфер движка переоценивается целиком каждый
// цикл, и без этого сравнения старый нормальный замер (80 → 91 → 93 → 95)
// закрывал бы инцидент в тот же цикл, что его завёл.
func (r *Registry) Close(ruleID, key, note string, evTS, now time.Time) *Incident {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, inc := range r.open {
		if inc.RuleID != ruleID || isFinal(inc.Status) {
			continue
		}
		if last := (&model.Event{TS: inc.LastTS}).Time(); !evTS.IsZero() && !last.IsZero() && !evTS.After(last) {
			continue
		}
		// С group_key — только точное совпадение группы: префикс ключа реестра
		// «правило|admin|…» у составной группы admin|адрес закрывал бы чужой адрес.
		// Субъект, узел и префикс — для групп без ключа (и инцидентов до 0034).
		match := inc.GroupKey == key
		if inc.GroupKey == "" {
			match = inc.ActorName == key || inc.Node == key || strings.HasPrefix(k, ruleID+"|"+key+"|")
		}
		if match {
			inc.Status = StatusClosed
			inc.Note = strings.TrimSpace(inc.Note + "\n" + note)
			inc.UpdatedAt = model.FormatTS(now)[:19]
			return inc
		}
	}
	return nil
}

// CloseMatched — close_on правила с close_match: событие ev (ротация или
// отзыв) засчитывается секрету инцидента с тем же ключом, если оно позже
// самой свежей утечки этого секрета. Ключ группы (субъект) не сравнивается:
// ротацию часто делает человек, а не бот, который «утёк». Инцидент с
// событием без ключа событием не закрывается.
//
// Закрывается инцидент, только когда так перекрыты ВСЕ его секреты и каждый
// перекрыт отзывом доказанно того же токена (secretLink.revokes). Если все
// перекрыты, но связь не доказана хотя бы для одного, инцидент не
// закрывается, а возвращается в review с пометкой «закрыт автоматикой, нужна
// проверка» и эскалируется (new → escalated; статус, поставленный
// человеком, не меняется).
func (r *Registry) CloseMatched(ruleID string, ev *model.Event, rule *rules.Rule, note string, now time.Time) (closed, review []*Incident) {
	evKey, ok := rule.CloseMatchKey(ev)
	if !ok {
		return nil, nil
	}
	ts := ev.Time()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, inc := range r.open {
		if inc.RuleID != ruleID || isFinal(inc.Status) {
			continue
		}
		leak, ok := inc.closeNeed[evKey]
		if !ok {
			continue
		}
		if inc.rotated == nil {
			inc.rotated = map[string]time.Time{}
		}
		if ts.After(inc.rotated[evKey]) {
			inc.rotated[evKey] = ts
		}
		if ts.After(leak) && inc.links[evKey].revokes(ev) {
			if inc.confirmed == nil {
				inc.confirmed = map[string]bool{}
			}
			inc.confirmed[evKey] = true
		}
		if inc.unmatchable || !inc.allRotated() {
			continue
		}
		if inc.allConfirmed() {
			inc.Status = StatusClosed
			inc.Note = strings.TrimSpace(inc.Note + "\n" + note)
			inc.UpdatedAt = model.FormatTS(now)[:19]
			closed = append(closed, inc)
			continue
		}
		if inc.reviewNoted {
			continue // буфер прогоняется заново каждый цикл — пометка одна
		}
		inc.reviewNoted = true
		inc.Review = "закрыт автоматикой, нужна проверка: " + note + ", но не доказано, что отозван именно утёкший токен (тот же token_id у того же провайдера и экземпляра) — секрет может действовать"
		inc.Note = strings.TrimSpace(inc.Note + "\n" + inc.Review)
		if !slices.Contains(inc.Tags, NeedsReviewTag) {
			inc.Tags = append(slices.Clip(inc.Tags), NeedsReviewTag) // Tags делит массив с правилом
		}
		if inc.Status == StatusNew {
			inc.Status = StatusEscalated
		}
		inc.UpdatedAt = model.FormatTS(now)[:19]
		review = append(review, inc)
	}
	return closed, review
}

// allConfirmed — каждый секрет перекрыт отзывом доказанно того же токена, и
// связь секрета с токеном всё ещё действует (не инвалидирована поздним событием).
func (inc *Incident) allConfirmed() bool {
	for k := range inc.closeNeed {
		if !inc.confirmed[k] || inc.links[k] == nil {
			return false
		}
	}
	return true
}

// allRotated — по каждому секрету ротация позже последней утечки.
func (inc *Incident) allRotated() bool {
	if len(inc.closeNeed) == 0 {
		return false
	}
	for k, leak := range inc.closeNeed {
		rot, ok := inc.rotated[k]
		if !ok || !rot.After(leak) {
			return false
		}
	}
	return true
}

// AutoClose — политика тишины правила: через After без новых событий
// закрыть или (Escalate) эскалировать дежурному, оставив открытым.
type AutoClose struct {
	After    time.Duration
	Escalate bool
}

// Sweep — авто-закрытие: инциденты без новых событий дольше auto_close правила.
// Правила с auto_close_action: escalate не закрываются: новый инцидент
// эскалируется (один раз), остальные статусы не меняются.
func (r *Registry) Sweep(policy func(ruleID string) AutoClose, now time.Time) (closed, escalated []*Incident) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, inc := range r.open {
		if isFinal(inc.Status) || inc.Status == StatusInProgress || inc.Status == StatusWaitingOwner {
			continue // человек работает — автоматика не трогает
		}
		pol := policy(inc.RuleID)
		d := pol.After
		if d <= 0 {
			continue
		}
		// Точка отсчёта — позже из «последнее событие» и «создан»: у absence
		// последнее событие по определению старое, иначе закрылось бы сразу.
		last := (&model.Event{TS: inc.LastTS}).Time()
		if created := (&model.Event{TS: inc.CreatedAt}).Time(); created.After(last) {
			last = created
		}
		if last.IsZero() || now.Sub(last) < d {
			continue
		}
		if pol.Escalate {
			if inc.Status != StatusNew {
				continue // уже у дежурного или под наблюдением
			}
			inc.Status = StatusEscalated
			inc.Note = strings.TrimSpace(inc.Note + "\nэскалирован автоматикой: новых событий нет " + d.String() + ", но отзыва или ротации секрета не было — тишина не значит устранение")
			inc.UpdatedAt = model.FormatTS(now)[:19]
			escalated = append(escalated, inc)
			continue
		}
		inc.Status = StatusClosed
		inc.Note = strings.TrimSpace(inc.Note + "\nзакрыт автоматикой: новых событий нет " + d.String())
		inc.UpdatedAt = model.FormatTS(now)[:19]
		closed = append(closed, inc)
	}
	return closed, escalated
}

func build(d eval.Detection, now time.Time) *Incident {
	inc := &Incident{
		RuleID: d.Rule.ID, RuleTitle: d.Rule.Title, Level: d.Rule.Level, Tags: d.Rule.Tags,
		Status: StatusNew, CreatedAt: model.FormatTS(now)[:19], UpdatedAt: model.FormatTS(now)[:19],
		EventCount: uint32(len(d.Events)), FirstTS: model.FormatTS(d.First), LastTS: model.FormatTS(d.Last),
		Events: d.Events,
	}
	if inc.Level == "critical" {
		inc.Status = StatusEscalated // критичное сразу эскалируется дежурному
	}
	// Правило, сгруппированное по адресу (src.ip / dst.ip): субъект инцидента — сам адрес,
	// а не логин из первого события (при подборе это «root» или «admin», и карточка
	// называла атакующим перебираемую учётку). Перебранные логины остаются в цепочке.
	if gb := d.Rule.GroupBy(); (gb == "src.ip" || gb == "dst.ip") && d.Key != "" && d.Key != "-" {
		inc.ActorName = d.Key
	}
	srcSet := map[string]bool{}
	for _, e := range d.Events {
		srcSet[e.Source] = true
		if e.PII == 1 {
			inc.PII = 1
		}
		if inc.ActorName == "" && e.ActorName != "" {
			inc.ActorName = e.ActorName
		}
		if inc.Node == "" && e.Node != "" {
			inc.Node = e.Node
		}
	}
	for s := range srcSet {
		inc.Sources = append(inc.Sources, s)
	}
	sort.Strings(inc.Sources)
	if inc.ActorName == "" {
		inc.ActorName = d.Key
	}
	if explicitGroup(d.Rule) && d.Key != "" && d.Key != "-" {
		inc.GroupKey = d.Key
	}
	inc.Chain = chain(d.Events, 12)
	if d.Reason != "" {
		inc.Chain = append(inc.Chain, "→ "+d.Reason)
	}
	return inc
}

// chain — «ts  источник  узел  действие  деталь», не длиннее max строк.
func chain(evs []*model.Event, max int) []string {
	out := make([]string, 0, min(len(evs), max))
	step := 1
	if len(evs) > max {
		step = len(evs) / max
	}
	for i := 0; i < len(evs) && len(out) < max; i += step {
		e := evs[i]
		detail := e.Object
		if detail == "" && e.DstIP != "" {
			detail = fmt.Sprintf("%s:%d", e.DstIP, e.DstPort)
		}
		if detail == "" {
			detail = e.ActorName
		}
		if e.Unit != "" {
			// числовое измерение: «/var/lib/clickhouse 91.5 percent»
			detail = strings.TrimSpace(fmt.Sprintf("%s %s %s", detail, strconv.FormatFloat(e.Value, 'g', -1, 64), e.Unit))
		}
		ts := e.TS
		if len(ts) >= 19 {
			ts = ts[11:19]
		}
		out = append(out, fmt.Sprintf("%s  %-16s %-14s %-24s %s", ts, cut(e.Source, 16), cut(e.Node, 14), cut(e.Action, 24), cut(detail, 60)))
	}
	return out
}

// cut — не длиннее n символов (рун, не байт: кириллица в объекте или имени
// источника не должна давать битый UTF-8), последний символ — многоточие.
func cut(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// Summary — короткое описание для уведомления/лога.
func (i *Incident) Summary() string {
	return fmt.Sprintf("%s · %s · %s · %s · %d событий", i.IncidentID, strings.ToUpper(i.Level), i.RuleTitle, i.ActorName, i.EventCount)
}

// explicitGroup — group_by правила задан явно и не совпадает с тем, что уже
// в ключе реестра (субъект, узел; одиночный адрес становится субъектом в build).
// Составной ключ — всегда явный: адрес в нём в субъект не попадает, а close_on
// ищет инцидент по тому же составному ключу (admin|NAS-B) в GroupKey.
func explicitGroup(r *rules.Rule) bool {
	gb := r.Detection.GroupBy
	if r.Detection.Threshold != nil && r.Detection.Threshold.GroupBy != "" {
		gb = r.Detection.Threshold.GroupBy
	}
	if strings.Contains(gb, ",") {
		return true
	}
	switch strings.TrimSpace(gb) {
	case "", "actor.name", "node", "src.ip", "dst.ip":
		return false
	}
	return true
}
