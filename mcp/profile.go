package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/devitex-soft/argus/triage/redact"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Профили выдачи. full — аналитик (Claude Code, Cursor): все поля, свободный
// DSL, include_raw; секреты и канарейки вырезаются всегда. triage — агент
// разбора алертов с облачной моделью: разрешённый набор полей, псевдонимы
// субъектов и ПДн, обезвреженные ссылки, только точные фильтры, без raw.
// Ограничение задаёт сервер, а не скилл: агент не может его снять.
const (
	profileFull   = "full"
	profileTriage = "triage"
)

// profileHeader — профиль запроса по HTTP. Ставит только guard по
// предъявленному токену; значение от клиента удаляется до проверки.
const profileHeader = "X-Argus-Mcp-Profile"

type profile struct {
	name string
	red  *redact.Redactor
}

func (p *profile) triage() bool { return p.name == profileTriage }

type profiles struct {
	byName map[string]*profile
	def    *profile // stdio и токен ARGUS_MCP_HTTP_TOKEN
}

// newProfiles — профили с общим ключом псевдонимов: тот же ключ у вебхука
// движка (ARGUS_PSEUDONYM_KEY), поэтому субъект в задаче агенту и в ответах
// MCP — один псевдоним.
func newProfiles(def string, key []byte, canaries, names []string) (*profiles, error) {
	ps := &profiles{byName: map[string]*profile{
		profileFull:   {name: profileFull, red: redact.New(redact.Options{Key: key, Canaries: canaries})},
		profileTriage: {name: profileTriage, red: redact.New(redact.Options{Key: key, Pseudonymize: true, Defang: true, Canaries: canaries, Names: names})},
	}}
	if def == "" {
		def = profileFull
	}
	p, ok := ps.byName[def]
	if !ok {
		return nil, fmt.Errorf("ARGUS_MCP_PROFILE=%q: ожидается full или triage", def)
	}
	ps.def = p
	return ps, nil
}

// profilesFromEnv — ARGUS_MCP_PROFILE, ARGUS_PSEUDONYM_KEY,
// ARGUS_REDACT_CANARIES (через запятую), ARGUS_REDACT_NAMES_FILE (по строке).
func profilesFromEnv() (*profiles, error) {
	key := os.Getenv("ARGUS_PSEUDONYM_KEY")
	def := strings.TrimSpace(os.Getenv("ARGUS_MCP_PROFILE"))
	triagePossible := def == profileTriage || os.Getenv("ARGUS_MCP_TRIAGE_TOKEN") != ""
	if triagePossible && len(key) < minHTTPTokenLen {
		return nil, fmt.Errorf("ARGUS_PSEUDONYM_KEY короче %d символов: профиль triage без общего ключа псевдонимов не запускается", minHTTPTokenLen)
	}
	var canaries, names []string
	for _, c := range strings.Split(os.Getenv("ARGUS_REDACT_CANARIES"), ",") {
		if c = strings.TrimSpace(c); c != "" {
			canaries = append(canaries, c)
		}
	}
	if f := os.Getenv("ARGUS_REDACT_NAMES_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("ARGUS_REDACT_NAMES_FILE: %w", err)
		}
		names = strings.Split(string(b), "\n")
	}
	return newProfiles(def, []byte(key), canaries, names)
}

// of — профиль вызова: по заголовку от guard (HTTP) или по умолчанию (stdio).
func (ps *profiles) of(req *mcp.CallToolRequest) *profile {
	if req != nil && req.Extra != nil && req.Extra.Header != nil {
		if p, ok := ps.byName[req.Extra.Header.Get(profileHeader)]; ok {
			return p
		}
	}
	return ps.def
}

// ---- политики редакции по ответам консоли ----

var dropRaw = map[string]bool{"raw": true, "full_log": true}

// subjectKeys — поля-субъекты во всех ответах консоли.
// person_id и display — персона паспорта субъекта (get_actor).
var subjectKeys = map[string]bool{"actor_name": true, "actor": true, "owner": true, "author": true, "user": true, "agent_user": true, "person_id": true, "display": true}

// hostKeys — поля-узлы: машина человека (ws-ivanov) — псевдонимом host-….
var hostKeys = map[string]bool{"node": true, "agent_name": true}

var (
	eventRow = redact.Shape{
		"time": redact.Leaf, "severity": redact.Leaf, "source": redact.Leaf, "source_class": redact.Leaf, "action": redact.Leaf,
		"outcome": redact.Leaf, "actor_name": redact.Leaf, "object": redact.Leaf, "node": redact.Leaf, "src_ip": redact.Leaf,
		"dst_ip": redact.Leaf, "src_port": redact.Leaf, "dst_port": redact.Leaf, "proto": redact.Leaf, "pii": redact.Leaf,
		"value": redact.Leaf, "unit": redact.Leaf, "attributes": redact.Leaf,
	}
	// logRow — строка ленты GET /api/v1/log (get_log): те же поля события
	// плюс level и измерение value/unit; attrs — объект, редактируется как текст.
	logRow = redact.Shape{
		"ts": redact.Leaf, "source": redact.Leaf, "source_class": redact.Leaf, "action": redact.Leaf, "outcome": redact.Leaf,
		"severity": redact.Leaf, "level": redact.Leaf, "actor_name": redact.Leaf, "actor_kind": redact.Leaf, "object": redact.Leaf,
		"node": redact.Leaf, "session_id": redact.Leaf, "src_ip": redact.Leaf, "dst_ip": redact.Leaf, "value": redact.Leaf,
		"unit": redact.Leaf, "attrs": redact.Leaf, "pii": redact.Leaf,
	}
	alertRow = redact.Shape{
		"time": redact.Leaf, "rule_level": redact.Leaf, "rule_id": redact.Leaf, "rule_description": redact.Leaf,
		"agent_name": redact.Leaf, "agent_id": redact.Leaf, "srcip": redact.Leaf, "location": redact.Leaf,
		"decoder_name": redact.Leaf, "groups": redact.Leaf, "mitre": redact.Leaf,
	}
	incidentRow = redact.Shape{
		"incident_id": redact.Leaf, "created_at": redact.Leaf, "updated_at": redact.Leaf, "rule_id": redact.Leaf,
		"rule_title": redact.Leaf, "level": redact.Leaf, "tags": redact.Leaf, "status": redact.Leaf, "owner": redact.Leaf,
		"note": redact.Leaf, "actor_name": redact.Leaf, "node": redact.Leaf, "sources": redact.Leaf, "event_count": redact.Leaf,
		"first_ts": redact.Leaf, "last_ts": redact.Leaf, "pii": redact.Leaf, "chain": redact.Leaf, "enrichment": redact.Leaf,
		"similar": redact.Leaf,
	}
)

func searchShape(index string) redact.Shape {
	row := eventRow
	if index == "alerts" {
		row = alertRow
	}
	return redact.Shape{
		"rows": row, "total": redact.Leaf, "page": redact.Leaf, "pageSize": redact.Leaf, "series": redact.Leaf,
		"facets": redact.Shape{"field": redact.Leaf, "label": redact.Leaf, "values": redact.Shape{"value": redact.Leaf, "count": redact.Leaf}},
		"error":  redact.Leaf, "ms": redact.Leaf, "exported_at": redact.Leaf,
	}
}

var (
	logShape       = redact.Shape{"items": logRow, "count": redact.Leaf, "error": redact.Leaf}
	incidentsShape = redact.Shape{"rows": incidentRow, "total": redact.Leaf, "page": redact.Leaf, "pageSize": redact.Leaf}
	cardShape      = redact.Shape{
		"incident": incidentRow, "first_response_at": redact.Leaf,
		"history": redact.Shape{"revision": redact.Leaf, "changed_at": redact.Leaf, "actor": redact.Leaf, "kind": redact.Leaf, "status": redact.Leaf, "owner": redact.Leaf, "reason": redact.Leaf},
		"verdict": redact.Shape{
			"incident_id": redact.Leaf, "evaluated_at": redact.Leaf, "profile": redact.Leaf, "summary_ru": redact.Leaf,
			"evidence": redact.Leaf, "first_action": redact.Leaf, "confidence": redact.Leaf, "confidence_kind": redact.Leaf,
			"missing": redact.Leaf, "actions": redact.Leaf, "error": redact.Leaf,
		},
		"actions":           redact.Shape{"ts": redact.Leaf, "user": redact.Leaf, "action": redact.Leaf, "target": redact.Leaf, "detail": redact.Leaf},
		"comments":          redact.Shape{"created_at": redact.Leaf, "author": redact.Leaf, "body": redact.Leaf},
		"history_truncated": redact.Leaf, "comments_truncated": redact.Leaf,
	}
)

// policy — редакция ответа для профиля. В full — только Drop raw (если не
// просили) и секреты; в triage — ещё и форма полей и субъекты.
func (p *profile) policy(shape redact.Shape, keepRaw bool) redact.Policy {
	pol := redact.Policy{Subjects: subjectKeys, Hosts: hostKeys}
	if !keepRaw {
		pol.Drop = dropRaw
	}
	if p.triage() {
		pol.Shape = shape
	}
	return pol
}

// piiMasked — чем заменяется свободный текст строки с pii=1 в triage.
const piiMasked = "[скрыто: событие с ПДн (pii=1), смотреть в консоли]"

// render — ответ консоли через редакцию профиля. Невалидный JSON — ошибка:
// сырое тело в модель не уходит.
// known — исходные значения субъектов, которые надо заменить и в тексте
// (разрешённый псевдоним фильтра: ответ может его процитировать).
func (p *profile) render(body []byte, shape redact.Shape, keepRaw bool, known ...string) (*mcp.CallToolResult, any, error) {
	v, err := decode(body)
	if err != nil {
		return toolError(err)
	}
	if p.triage() {
		p.pretriage(v)
	}
	out, err := json.Marshal(p.red.Document(v, p.policy(shape, keepRaw), known...))
	if err != nil {
		return toolError(fmt.Errorf("сериализация ответа: %w", err))
	}
	return rawResult(out)
}

// pretriage — то, что не выражается формой полей: фасеты субъектов → псевдонимы;
// у строк с pii=1 (rows поиска, items ленты get_log, секции паспорта) свободный текст (object,
// attributes/attrs) скрыт целиком — pii здесь дополнительный сигнал, редакция
// по шаблонам работает и без него.
func (p *profile) pretriage(v any) {
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	// rows — поиск, items — лента get_log, остальные — секции паспорта get_actor.
	for _, list := range []string{"rows", "items", "timeline", "logins", "hosts", "network", "apps", "changes"} {
		rows, ok := m[list].([]any)
		if !ok {
			continue
		}
		for _, r := range rows {
			if row, ok := r.(map[string]any); ok && isOne(row["pii"]) {
				for _, k := range []string{"object", "attributes", "attrs"} {
					if _, ok := row[k]; ok {
						row[k] = piiMasked
					}
				}
			}
		}
	}
	// Паспорт субъекта: значения алиасов-учёток (email, login, uid, sid, peer,
	// phone — номер телефона тоже идентифицирует человека) — псевдонимы
	// субъекта, имена узлов — как узлы; адреса остаются (как src_ip в
	// событиях). Неизвестный вид — по умолчанию субъект: безопаснее скрыть.
	for _, list := range []string{"aliases", "ambiguous"} {
		aliases, ok := m[list].([]any)
		if !ok {
			continue
		}
		for _, a := range aliases {
			am, ok := a.(map[string]any)
			if !ok {
				continue
			}
			v, ok := am["value"].(string)
			if !ok {
				continue
			}
			switch am["kind"] {
			case "ip":
			case "host":
				am["value"] = p.red.Host(v)
			case "email", "login", "uid", "sid", "peer", "phone":
				am["value"] = p.red.Subject(v)
			default:
				am["value"] = p.red.Subject(v)
			}
		}
	}
	// summary.nodes — [{node, count, …}] (или просто строки): узлы людей → host-….
	if summary, ok := m["summary"].(map[string]any); ok {
		if nodes, ok := summary["nodes"].([]any); ok {
			for i, n := range nodes {
				switch x := n.(type) {
				case string:
					nodes[i] = p.red.Host(x)
				case map[string]any:
					if s, ok := x["node"].(string); ok {
						x["node"] = p.red.Host(s)
					}
				}
			}
		}
	}
	if facets, ok := m["facets"].([]any); ok {
		for _, f := range facets {
			fm, ok := f.(map[string]any)
			if !ok {
				continue
			}
			var conv func(string) string
			switch fm["field"] {
			case "actor":
				conv = func(s string) string { return p.red.Subject(s) }
			case "node", "agent":
				conv = func(s string) string { return p.red.Host(s) }
			default:
				continue
			}
			vals, _ := fm["values"].([]any)
			for _, x := range vals {
				if xm, ok := x.(map[string]any); ok {
					if s, ok := xm["value"].(string); ok {
						xm["value"] = conv(s)
					}
				}
			}
		}
	}
}

func isOne(v any) bool {
	switch t := v.(type) {
	case json.Number:
		return t.String() == "1"
	case float64:
		return t == 1
	case string:
		return t == "1"
	case bool:
		return t
	}
	return false
}

// toolErrorFor — ошибка инструмента через редакцию профиля: текст ошибки
// консоли может содержать эхо запроса и данные событий.
// В triage процитированное в ошибке («before: '…'», «('…')») скрывается
// целиком: ClickHouse и консоль цитируют данные строк и запроса.
func (p *profile) toolError(err error, known ...string) (*mcp.CallToolResult, any, error) {
	if p.triage() {
		return toolError(errors.New(p.red.ErrorText(err.Error(), known...)))
	}
	return toolError(errors.New(p.red.TextWith(err.Error(), known...)))
}
