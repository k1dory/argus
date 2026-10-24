package notify

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Aggregator — защита от шторма: в окне window по одному правилу отдельно
// уходят первые limit инцидентов, остальные копятся и по закрытии окна
// превращаются в одно сообщение «N инцидентов по правилу X (адреса: …)».
type Aggregator struct {
	mu     sync.Mutex
	window time.Duration
	limit  int
	nowFn  func() time.Time
	rules  map[string]*ruleWindow
}

type ruleWindow struct {
	start  time.Time
	title  string
	count  int
	direct int
	addrs  []string
	seen   map[string]bool
}

func NewAggregator(window time.Duration, limit int) *Aggregator {
	if window <= 0 {
		window = time.Minute
	}
	if limit <= 0 {
		limit = 5
	}
	return &Aggregator{window: window, limit: limit, nowFn: time.Now, rules: map[string]*ruleWindow{}}
}

// Add регистрирует инцидент правила; true — отправлять отдельным
// сообщением, false — он войдёт в сводку из Flush.
func (a *Aggregator) Add(ruleID, title, addr string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.nowFn()
	w := a.rules[ruleID]
	if w == nil || now.Sub(w.start) >= a.window {
		// окно закрылось без Flush — сводка пропала бы; Flush её заберёт, поэтому
		// новое окно открываем только если старое пустое либо уже отдано
		if w != nil && w.count > w.direct {
			w.count++
			a.remember(w, addr)
			return false
		}
		w = &ruleWindow{start: now, title: title, seen: map[string]bool{}}
		a.rules[ruleID] = w
	}
	w.count++
	a.remember(w, addr)
	if w.direct < a.limit {
		w.direct++
		return true
	}
	return false
}

func (a *Aggregator) remember(w *ruleWindow, addr string) {
	addr = strings.TrimSpace(addr)
	if addr == "" || w.seen[addr] {
		return
	}
	w.seen[addr] = true
	if len(w.addrs) < 10 {
		w.addrs = append(w.addrs, addr)
	}
}

// Flush — сводки по окнам, которые закрылись и в которых были подавленные
// инциденты; вызывать каждый цикл движка.
func (a *Aggregator) Flush() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.nowFn()
	var ids []string
	for id, w := range a.rules {
		if now.Sub(w.start) >= a.window {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	var out []string
	for _, id := range ids {
		w := a.rules[id]
		delete(a.rules, id)
		if w.count <= w.direct {
			continue
		}
		addrs := strings.Join(w.addrs, ", ")
		if len(w.seen) > len(w.addrs) {
			addrs += fmt.Sprintf(" и ещё %d", len(w.seen)-len(w.addrs))
		}
		if addrs == "" {
			addrs = "—"
		}
		out = append(out, fmt.Sprintf("⚠ %d инцидентов по правилу «%s» (%s) за %s, из них %d показаны отдельно (адреса: %s)",
			w.count, w.title, id, a.window, w.direct, addrs))
	}
	return out
}
