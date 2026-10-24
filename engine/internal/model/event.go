// Package model — единая схема события ARGUS: субъект, объект, действие,
// узел, сеанс. Ровно колонки таблицы argus.events (JSONEachRow).
package model

import "time"

type Event struct {
	TS          string `json:"ts"`
	Source      string `json:"source"`
	SourceClass string `json:"source_class"`
	Vendor      string `json:"vendor"`
	Product     string `json:"product"`
	Action      string `json:"action"`
	Outcome     string `json:"outcome"`
	Severity    uint8  `json:"severity"`
	ActorName   string `json:"actor_name"`
	ActorKind   string `json:"actor_kind"`
	Object      string `json:"object"`
	Node        string `json:"node"`
	SessionID   string `json:"session_id"`
	SrcIP       string `json:"src_ip"`
	SrcPort     uint16 `json:"src_port"`
	DstIP       string `json:"dst_ip"`
	DstPort     uint16 `json:"dst_port"`
	Proto       string `json:"proto"`
	Bytes       uint64 `json:"bytes"`
	Packets     uint64 `json:"packets"`
	// Value и Unit — числовое измерение (телеметрия: заполненность диска,
	// температура, длина очереди). Правило сравнивает его операторами
	// (value: '>= 90') так же, как поля безопасности; Unit — подпись
	// (percent, bytes, celsius), в сравнении не участвует.
	Value float64           `json:"value"`
	Unit  string            `json:"unit"`
	PII   uint8             `json:"pii"`
	Attrs map[string]string `json:"attrs"`
	Raw   string            `json:"raw"`

	// ReceivedAt — когда событие принято коллектором; буфер движка живёт по
	// нему, а окна правил считаются по ts источника.
	ReceivedAt time.Time `json:"-"`
}

const tsLayout = "2006-01-02 15:04:05.000"

func FormatTS(t time.Time) string {
	if t.IsZero() {
		t = time.Now()
	}
	return t.UTC().Format(tsLayout)
}

// Ensure заполняет обязательные поля, чтобы строка всегда вставилась.
func (e *Event) Ensure() {
	if e.TS == "" {
		e.TS = FormatTS(time.Now())
	}
	if e.Attrs == nil {
		e.Attrs = map[string]string{}
	}
	if e.Outcome == "" {
		e.Outcome = "unknown"
	}
	if e.ActorKind == "" {
		e.ActorKind = "unknown"
	}
	if e.Source == "" {
		e.Source = e.SourceClass
	}
	if e.SourceClass == "" {
		e.SourceClass = "syslog"
	}
}

// Time — разбор ts обратно во время (строка из ClickHouse / фикстур).
func (e *Event) Time() time.Time {
	for _, layout := range []string{tsLayout, "2006-01-02 15:04:05", time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, e.TS); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
