package main

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

/* ===== каталоги правил =====
   Поставляемые правила (RULES_DIR) в проде — копия своей версии внутри образа
   (/usr/share/argus/shipped/rules, та же, что у реестра internal/registry):
   версия правил всегда совпадает с версией движка, и обновление кода на хосте
   не меняет их под ещё работающим старым движком (rc34, дубль INC-5312).
   Пользовательские правила — отдельный каталог хоста (RULES_USER_DIR,
   необязателен). Поставляемое правило главнее: пользовательское с тем же id
   отвергается, а не подменяет штатный детект; сбой разбора пользовательского
   каталога отвергает его целиком, но движок работает на поставляемых. Каждый
   отказ — в журнал, метрику argus_engine_rules_rejected и событие
   argus.system / rules.rejected (его ловит правило ops). */

// ruleSet — поставляемый и пользовательский каталоги правил.
type ruleSet struct {
	shipped string
	user    string // "" — без пользовательских правил
}

// userPrefix — префикс Rule.File пользовательского правила: в списке правил и
// в событии отказа видно, откуда оно.
const userPrefix = "user/"

// Причины отказа (attrs.reason события rules.rejected).
const (
	rejectShippedIDTaken = "shipped_id_taken"
	rejectDuplicateID    = "duplicate_id"
	rejectParseError     = "parse_error"
)

// rejectedRule — отвергнутое правило: файл (с префиксом каталога), id, если
// разобран, код причины и текст ошибки (только для журнала).
type rejectedRule struct {
	File, RuleID, Reason, Err string
}

// signature — отпечаток обоих каталогов: перечитывание при изменении любого.
func (s ruleSet) signature() string {
	sig := signature(s.shipped)
	if s.user != "" {
		sig += "||" + signature(s.user)
	}
	return sig
}

// load — правила обоих каталогов. Ошибка — только у поставляемого каталога
// (без него детекта нет); отказы пользовательских — в rejected.
func (s ruleSet) load() ([]*rules.Rule, []rejectedRule, error) {
	out, err := rules.Load(s.shipped)
	if err != nil {
		return nil, nil, err
	}
	if s.user == "" {
		return out, nil, nil
	}
	if _, err := os.Stat(s.user); errors.Is(err, fs.ErrNotExist) {
		return out, nil, nil
	}
	us, err := rules.Load(s.user)
	if err != nil {
		return out, []rejectedRule{{File: userPrefix, Reason: rejectParseError, Err: err.Error()}}, nil
	}
	taken := make(map[string]string, len(out)+len(us)) // id → файл
	for _, r := range out {
		taken[r.ID] = r.File
	}
	var rejected []rejectedRule
	for _, r := range us {
		file := userPrefix + r.File
		if owner, dup := taken[r.ID]; dup {
			reason := rejectDuplicateID
			if !strings.HasPrefix(owner, userPrefix) {
				reason = rejectShippedIDTaken
			}
			rejected = append(rejected, rejectedRule{File: file, RuleID: r.ID, Reason: reason, Err: "id " + r.ID + " уже занят: " + owner})
			continue
		}
		r.File = file
		taken[r.ID] = file
		out = append(out, r)
	}
	return out, rejected, nil
}

// reportRejected — отказы набора правил: журнал, метрика и по событию на каждый
// отказ (best effort: без хранилища — только журнал и метрика).
func (e *engine) reportRejected(ctx context.Context, rejected []rejectedRule, now time.Time) {
	e.m.rulesRejected.Store(int64(len(rejected)))
	if len(rejected) == 0 {
		return
	}
	events := make([]*model.Event, 0, len(rejected))
	for _, r := range rejected {
		slog.Error("правило отвергнуто — детект по нему не работает", "file", r.File, "rule", r.RuleID, "reason", r.Reason, "err", r.Err)
		events = append(events, rulesRejectedEvent(now, e.ch.Host(), r.File, r.RuleID, r.Reason))
	}
	if err := e.ch.InsertEvents(ctx, events); err != nil {
		slog.Warn("rules.rejected: события не записаны", "err", err)
	}
}

// rulesRejectedEvent — событие единой схемы об отвергнутом правиле. Текста
// ошибки и содержимого правила в нём нет: только файл, id и код причины.
func rulesRejectedEvent(now time.Time, node, file, ruleID, reason string) *model.Event {
	ev := &model.Event{
		TS: model.FormatTS(now), Source: systemSource, SourceClass: "telemetry", Vendor: "ARGUS", Product: "engine",
		Action: "rules.rejected", Outcome: "failure", ActorName: "argus-engine", ActorKind: "system",
		Object: file, Node: node,
		Attrs: map[string]string{"transport": "internal", "rule_id": ruleID, "reason": reason},
	}
	return ev
}
