// Package enrich исполняет блок enrich правила: контекст вокруг инцидента
// из единой схемы событий и владелец узла из CMDB.
//   - edr.process_tree: 120s  — события класса edr на узле инцидента ±окно
//   - ngfw.sessions: 120s     — сессии NGFW того же субъекта / адреса ±окно
//   - cmdb.owner              — владелец, команда, критичность узла (cmdb.yml)
package enrich

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
)

// Source — откуда брать события (store.ClickHouse его реализует).
type Source interface {
	EventsAround(ctx context.Context, class string, node, actor, ip string, from, to time.Time, limit int) ([]*model.Event, error)
}

type cmdbNode struct {
	Owner       string `yaml:"owner"`
	Team        string `yaml:"team"`
	Criticality string `yaml:"criticality"`
	Note        string `yaml:"note"`
}

type Enricher struct {
	src  Source
	cmdb map[string]cmdbNode
}

func New(src Source, cmdbPath string) *Enricher {
	e := &Enricher{src: src, cmdb: map[string]cmdbNode{}}
	if cmdbPath != "" {
		if raw, err := os.ReadFile(cmdbPath); err == nil {
			var doc struct {
				Nodes map[string]cmdbNode `yaml:"nodes"`
			}
			if yaml.Unmarshal(raw, &doc) == nil {
				e.cmdb = doc.Nodes
			}
		}
	}
	return e
}

// Run возвращает строки обогащения по списку из правила.
func (en *Enricher) Run(ctx context.Context, inc *incidents.Incident, spec []any) []string {
	var out []string
	first := (&model.Event{TS: inc.FirstTS}).Time()
	last := (&model.Event{TS: inc.LastTS}).Time()
	if first.IsZero() || last.IsZero() {
		return nil
	}
	ip := ""
	if len(inc.Events) > 0 {
		ip = inc.Events[0].SrcIP
	}
	for _, item := range spec {
		name, arg := parseItem(item)
		switch name {
		case "edr.process_tree":
			d := dur(arg, 2*time.Minute)
			out = append(out, en.events(ctx, "edr", inc.Node, "", "", first.Add(-d), last.Add(d), "edr.process_tree")...)
		case "ngfw.sessions":
			d := dur(arg, 2*time.Minute)
			out = append(out, en.events(ctx, "ngfw", "", inc.ActorName, ip, first.Add(-d), last.Add(d), "ngfw.sessions")...)
		case "cmdb.owner":
			if n, ok := en.cmdb[inc.Node]; ok {
				out = append(out, fmt.Sprintf("cmdb: %s — владелец %s, команда %s, критичность %s %s",
					inc.Node, or(n.Owner, "?"), or(n.Team, "?"), or(n.Criticality, "?"), n.Note))
			} else if inc.Node != "" {
				out = append(out, "cmdb: узел "+inc.Node+" в CMDB не найден")
			}
		default:
			out = append(out, "enrich: неизвестный источник "+name)
		}
	}
	return out
}

func (en *Enricher) events(ctx context.Context, class, node, actor, ip string, from, to time.Time, label string) []string {
	if en.src == nil {
		return nil
	}
	evs, err := en.src.EventsAround(ctx, class, node, actor, ip, from, to, 12)
	if err != nil {
		return []string{label + ": ошибка запроса — " + err.Error()}
	}
	if len(evs) == 0 {
		return []string{label + ": событий в окне нет"}
	}
	out := make([]string, 0, len(evs)+1)
	out = append(out, fmt.Sprintf("%s: %d событий за окно", label, len(evs)))
	for _, e := range evs {
		ts := e.TS
		if len(ts) >= 19 {
			ts = ts[11:19]
		}
		detail := e.Object
		if detail == "" && e.DstIP != "" {
			detail = fmt.Sprintf("%s:%d", e.DstIP, e.DstPort)
		}
		out = append(out, fmt.Sprintf("  %s  %-14s %-22s %s", ts, cut(e.Source, 14), cut(e.Action, 22), cut(detail, 50)))
	}
	return out
}

func parseItem(item any) (string, string) {
	switch x := item.(type) {
	case string:
		return x, ""
	case map[string]any:
		for k, v := range x {
			return k, fmt.Sprint(v)
		}
	}
	return fmt.Sprint(item), ""
}

func dur(s string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
	}
	return def
}

func or(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
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
