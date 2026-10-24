package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/devitex-soft/argus/triage/redact"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// get_actor — паспорт субъекта: кто стоит за логином, адресом или почтой в
// момент «сейчас» и что этот человек делал за период (входы, узлы и сеансы,
// сеть, приложения, изменения, инциденты, таймлайн). Два запроса к консоли:
// GET /api/v1/actors?alias=&at= (резолв с учётом интервалов алиасов) и
// GET /api/v1/actors/{person_id}?range=&limit=. «Не привязан» и
// «неоднозначно» — обычный ответ инструмента, а не ошибка: модель должна
// видеть, что человека за алиасом нет или их несколько, и не выбирать первого.

type actorIn struct {
	Alias    string `json:"alias,omitempty" jsonschema:"алиас субъекта: логин, email, IP, uid, имя узла — значение из события или псевдоним subj-… из ответов MCP. Либо alias, либо person_id"`
	PersonID string `json:"person_id,omitempty" jsonschema:"идентификатор персоны из ответа резолва (person_id); в профиле triage — только псевдоним subj-… из ответов MCP"`
	Range    string `json:"range,omitempty" jsonschema:"период паспорта: 24h | 7d | 30d (по умолчанию 7d)"`
	Limit    int    `json:"limit,omitempty" jsonschema:"строк таймлайна и каждой секции (1..500), по умолчанию 100"`
}

const (
	actorDefaultLimit = 100
	actorMaxLimit     = 500
	actorDefaultRange = "7d"
)

var actorRanges = map[string]bool{"24h": true, "7d": true, "30d": true}

// Формы ответов консоли для профиля triage (разрешённые поля). person_id и
// display — субъекты (subjectKeys): в triage уходят псевдонимами; value
// алиасов и summary.nodes обрабатывает pretriage.
var (
	actorMatchRow = redact.Shape{
		"person_id": redact.Leaf, "display": redact.Leaf, "kind": redact.Leaf, "alias_kind": redact.Leaf,
		"valid_from": redact.Leaf, "valid_to": redact.Leaf,
	}
	actorResolveShape = redact.Shape{"alias": redact.Leaf, "at": redact.Leaf, "status": redact.Leaf, "matches": actorMatchRow}

	// actorItemRow — строка секции паспорта: поля строки ленты /api/v1/log плюс
	// агрегаты (count, first/last, success/failure) — консоль группирует
	// входы, сеансы, адреса и приложения.
	actorItemRow = func() redact.Shape {
		s := redact.Shape{}
		for k, v := range logRow {
			s[k] = v
		}
		for _, k := range []string{"count", "first", "last", "first_ts", "last_ts", "success", "failure", "failures", "sessions", "kind", "bytes", "packets", "proto", "src_port", "dst_port"} {
			s[k] = redact.Leaf
		}
		return s
	}()
	actorShape = redact.Shape{
		"person":  redact.Shape{"person_id": redact.Leaf, "display": redact.Leaf, "kind": redact.Leaf, "team": redact.Leaf, "note": redact.Leaf},
		"aliases": redact.Shape{"kind": redact.Leaf, "value": redact.Leaf, "valid_from": redact.Leaf, "valid_to": redact.Leaf, "source": redact.Leaf, "confidence": redact.Leaf},
		"range":   redact.Shape{"from": redact.Leaf, "to": redact.Leaf, "key": redact.Leaf},
		"summary": redact.Shape{
			"events": redact.Leaf, "by_source_class": redact.Leaf, "incidents": redact.Leaf,
			"nodes":   redact.Shape{"node": redact.Leaf, "count": redact.Leaf, "first_ts": redact.Leaf, "last_ts": redact.Leaf},
			"src_ips": redact.Shape{"src_ip": redact.Leaf, "count": redact.Leaf, "first_ts": redact.Leaf, "last_ts": redact.Leaf},
		},
		// ambiguous — алиасы, в окне действующие и у другой персоны: модель не должна склеивать людей.
		"ambiguous": redact.Shape{"kind": redact.Leaf, "value": redact.Leaf},
		// sources — покрытие источников и их период; missing — что не загрузилось (частичная деградация).
		"sources":      redact.Shape{"source": redact.Leaf, "source_class": redact.Leaf, "count": redact.Leaf, "first_ts": redact.Leaf, "last_ts": redact.Leaf},
		"missing":      redact.Leaf,
		"limit":        redact.Leaf,
		"generated_at": redact.Leaf,
		"logins":       actorItemRow, "hosts": actorItemRow, "network": actorItemRow, "apps": actorItemRow, "changes": actorItemRow,
		"incidents": redact.Shape{"id": redact.Leaf, "level": redact.Leaf, "status": redact.Leaf, "rule_id": redact.Leaf, "rule_title": redact.Leaf, "created_at": redact.Leaf},
		"timeline":  logRow,
		"error":     redact.Leaf,
	}
)

// actorQuery — проверка входа get_actor: ровно один из alias/person_id,
// период из перечисления, лимит в границах. В triage alias и person_id —
// только псевдонимы subj-…, выданные этим сервером (resolveSubjects).
// resolved — исходные значения, которые надо спрятать в тексте ответа.
func actorQuery(p *profile, in *actorIn) (resolved []string, err error) {
	in.Alias, in.PersonID = strings.TrimSpace(in.Alias), strings.TrimSpace(in.PersonID)
	switch {
	case in.Alias == "" && in.PersonID == "":
		return nil, errors.New("укажите alias (логин, email, IP, узел) или person_id")
	case in.Alias != "" && in.PersonID != "":
		return nil, errors.New("укажите либо alias, либо person_id, не оба")
	}
	if in.Range = strings.TrimSpace(in.Range); in.Range == "" {
		in.Range = actorDefaultRange
	} else if !actorRanges[in.Range] {
		return nil, fmt.Errorf("range=%q: ожидается 24h | 7d | 30d", in.Range)
	}
	switch {
	case in.Limit <= 0:
		in.Limit = actorDefaultLimit
	case in.Limit > actorMaxLimit:
		in.Limit = actorMaxLimit
	}
	node := ""
	if in.Alias != "" {
		r, err := p.resolveSubjects(&in.Alias, &node)
		if err != nil {
			return nil, err
		}
		if r != "" {
			resolved = append(resolved, r)
		}
	} else {
		r, err := p.resolveSubjects(&in.PersonID, &node)
		if err != nil {
			return nil, err
		}
		if r != "" {
			resolved = append(resolved, r)
		}
	}
	return resolved, nil
}

// actorResolution — часть ответа GET /api/v1/actors, нужная инструменту.
type actorResolution struct {
	Status  string `json:"status"`
	Matches []struct {
		PersonID string `json:"person_id"`
	} `json:"matches"`
}

func actorTool(c *client, ps *profiles, now func() time.Time) func(context.Context, *mcp.CallToolRequest, actorIn) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, in actorIn) (*mcp.CallToolResult, any, error) {
		p := ps.of(req)
		known, err := actorQuery(p, &in)
		if err != nil {
			return p.toolError(err, known...)
		}
		personID := in.PersonID
		if in.Alias != "" {
			body, err := c.get(ctx, "/api/v1/actors", url.Values{"alias": {in.Alias}, "at": {now().UTC().Format(time.RFC3339)}})
			if err != nil {
				return p.toolError(err, known...)
			}
			var res actorResolution
			if err := json.Unmarshal(body, &res); err != nil {
				return p.toolError(fmt.Errorf("ответ резолва не разбирается: %w", err), known...)
			}
			// Не привязан или неоднозначно — ответ как есть: модель решает,
			// что делать дальше (искать по сырому значению, спросить человека).
			if res.Status != "resolved" || len(res.Matches) != 1 || strings.TrimSpace(res.Matches[0].PersonID) == "" {
				return p.render(body, actorResolveShape, false, known...)
			}
			personID = res.Matches[0].PersonID
			known = append(known, personID)
		}
		q := url.Values{"range": {in.Range}, "limit": {strconv.Itoa(in.Limit)}}
		body, err := c.get(ctx, "/api/v1/actors/"+url.PathEscape(personID), q)
		if err != nil {
			return p.toolError(err, known...)
		}
		return p.render(body, actorShape, false, known...)
	}
}
