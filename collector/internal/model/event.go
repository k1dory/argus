// Package model — единая схема события ARGUS: субъект, объект, действие,
// узел, сеанс. Ровно колонки таблицы argus.events (JSONEachRow).
package model

import (
	"strings"
	"time"
	"unicode/utf8"
)

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
	PII         uint8  `json:"pii"`
	// Value/Unit — числовое измерение события (телеметрия: занятость диска
	// в percent, нагрузка, счётчики). Нормализаторы логов их не заполняют —
	// ставит источник, присылающий готовые события в POST /ingest/events.
	// Колонки добавляет миграция 0023; до неё ClickHouse пропускает поля
	// (input_format_skip_unknown_fields=1 у sink).
	Value float64           `json:"value"`
	Unit  string            `json:"unit"`
	Attrs map[string]string `json:"attrs"`
	Raw   string            `json:"raw"`
}

const tsLayout = "2006-01-02 15:04:05.000"

// Границы правдоподобного времени события: старее 10 лет или дальше суток в
// будущем — почти всегда сломанные часы источника или мусор в поле; такая
// строка ломала партиционирование (toYYYYMM(ts)) и весь батч с ней.
const (
	MaxPast   = 10 * 365 * 24 * time.Hour
	MaxFuture = 24 * time.Hour
)

// MaxFieldLen — потолок строкового поля, идущего в UI/уведомления/LLM.
const MaxFieldLen = 8 << 10

// MaxRawLen — потолок Raw: улика хранится целиком до 256 КБ, дальше — первые
// 256 КБ с пометкой attrs.truncated=1. Без потолка одна строка в мегабайты
// (аудит WAF с телом запроса) раздувала очередь до OOM.
const MaxRawLen = 256 << 10

// Now подменяется в тестах.
var Now = time.Now

// ClampTime возвращает t, если оно в допустимом окне, иначе текущее время и false.
// Нулевое время — «нет метки», а не выброс: тоже now, но ok=true.
func ClampTime(t time.Time) (time.Time, bool) {
	now := Now()
	if t.IsZero() {
		return now, true
	}
	if t.Before(now.Add(-MaxPast)) || t.After(now.Add(MaxFuture)) {
		return now, false
	}
	return t, true
}

// FormatTS форматирует время в колонку ts; выброс за окно молча заменяется на now.
// Если нужно сохранить исходное значение — SetTS.
func FormatTS(t time.Time) string {
	t, _ = ClampTime(t)
	return t.UTC().Format(tsLayout)
}

// SetTS ставит ts из t; если t вне окна, ts = now, а исходное значение (raw,
// либо t в RFC 3339) остаётся в attrs.ts_raw — событие не теряется и не
// отравляет батч, но видно, что часы источника врут.
//
// Нулевое t с непустым raw — «значение было, но не разобралось»: тоже ts_raw.
func (e *Event) SetTS(t time.Time, raw string) {
	c, ok := ClampTime(t)
	e.TS = c.UTC().Format(tsLayout)
	if ok && !(t.IsZero() && raw != "") {
		return
	}
	if e.Attrs == nil {
		e.Attrs = map[string]string{}
	}
	if raw == "" {
		raw = t.UTC().Format(time.RFC3339Nano)
	}
	e.Attrs["ts_raw"] = truncate(raw, 64)
}

// ParseTS разбирает строку ts в форматах, которые принимает колонка (наш
// tsLayout, RFC 3339, «2006-01-02 15:04:05»).
func ParseTS(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 64 {
		return time.Time{}, false
	}
	for _, layout := range []string{tsLayout, "2006-01-02 15:04:05", time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// Ensure заполняет обязательные поля, чтобы строка всегда вставилась:
// валидное ts в окне, непустые перечисления, санитизированные строки.
func (e *Event) Ensure() {
	if e.Attrs == nil {
		e.Attrs = map[string]string{}
	}
	if e.TS == "" {
		e.TS = FormatTS(Now())
	} else if t, ok := ParseTS(e.TS); !ok {
		e.Attrs["ts_raw"] = truncate(e.TS, 64)
		e.TS = FormatTS(Now())
	} else {
		e.SetTS(t, e.TS)
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
	e.Sanitize()
}

// Sanitize убирает управляющие символы (кроме \t) и ANSI-escape из строк,
// которые показываются в UI, уходят в уведомления и в LLM, и режет их до
// MaxFieldLen с пометкой attrs.truncated=1. Raw — улика: содержимое не
// чистим, только режем до MaxRawLen (первые байты, с той же пометкой).
func (e *Event) Sanitize() {
	truncated := false
	if len(e.Raw) > MaxRawLen {
		e.Raw = truncate(e.Raw, MaxRawLen)
		truncated = true
	}
	fix := func(s *string) {
		v, cut := Clean(*s)
		*s = v
		truncated = truncated || cut
	}
	fix(&e.Source)
	fix(&e.Vendor)
	fix(&e.Product)
	fix(&e.Action)
	fix(&e.ActorName)
	fix(&e.Object)
	fix(&e.Node)
	fix(&e.SessionID)
	fix(&e.Unit)
	for k, v := range e.Attrs {
		nv, cut := Clean(v)
		nk, kcut := Clean(k)
		truncated = truncated || cut || kcut
		if nk != k {
			delete(e.Attrs, k)
			if nk == "" {
				continue
			}
		}
		e.Attrs[nk] = nv
	}
	if truncated {
		e.Attrs["truncated"] = "1"
	}
}

// Clean — одна строка: без ESC-последовательностей и управляющих символов
// (\n и \r → пробел, \t остаётся), обрезанная до MaxFieldLen по границе руны.
// Второе значение — была ли обрезка.
func Clean(s string) (string, bool) {
	if s == "" {
		return s, false
	}
	if needsClean(s) {
		s = strip(s)
	}
	if len(s) <= MaxFieldLen {
		return s, false
	}
	return truncate(s, MaxFieldLen), true
}

func needsClean(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 && c != '\t' || c == 0x7f || c == 0xc2 { // 0xc2 — первый байт C1 (U+0080..U+009F)
			return true
		}
	}
	return false
}

func strip(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == 0x1b: // ESC: CSI «\x1b[...m», OSC «\x1b]...BEL», либо двухбайтовая
			i += skipEscape(s[i:])
		case c == '\n' || c == '\r':
			b.WriteByte(' ')
			i++
		case c < 0x20 && c != '\t', c == 0x7f:
			i++
		case c == 0xc2 && i+1 < len(s) && s[i+1] >= 0x80 && s[i+1] <= 0x9f: // C1
			i += 2
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// skipEscape возвращает длину ESC-последовательности, начинающейся в s[0].
func skipEscape(s string) int {
	if len(s) < 2 {
		return 1
	}
	switch s[1] {
	case '[': // CSI: параметры 0x30–0x3f, промежуточные 0x20–0x2f, финал 0x40–0x7e
		for i := 2; i < len(s); i++ {
			if s[i] >= 0x40 && s[i] <= 0x7e {
				return i + 1
			}
			if s[i] < 0x20 || s[i] > 0x3f {
				return i
			}
		}
		return len(s)
	case ']', 'P', '_', '^': // OSC/DCS/APC/PM: до BEL или ST (ESC \)
		for i := 2; i < len(s); i++ {
			if s[i] == 0x07 {
				return i + 1
			}
			if s[i] == 0x1b {
				if i+1 < len(s) && s[i+1] == '\\' {
					return i + 2
				}
				return i
			}
		}
		return len(s)
	}
	return 2
}

// truncate режет s до n байт по границе руны. Битые байты сначала заменяются
// на U+FFFD: иначе один невалидный байт в начале срезал бы строку до него.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\uFFFD")
		if len(s) <= n {
			return s
		}
	}
	// строка валидна: до начала руны — не больше 3 байт назад
	cut := n
	for i := 0; i < 3 && cut > 0 && !utf8.RuneStart(s[cut]); i++ {
		cut--
	}
	return s[:cut]
}

// ApproxSize — приближённый размер события в памяти (байты строк плюс
// фиксированная часть) для потолка очереди по байтам.
func (e *Event) ApproxSize() int {
	n := 256 + len(e.Raw) + len(e.Source) + len(e.SourceClass) + len(e.Vendor) + len(e.Product) +
		len(e.Action) + len(e.Outcome) + len(e.ActorName) + len(e.ActorKind) + len(e.Object) +
		len(e.Node) + len(e.SessionID) + len(e.SrcIP) + len(e.DstIP) + len(e.Proto) + len(e.TS) + len(e.Unit)
	for k, v := range e.Attrs {
		n += len(k) + len(v) + 32
	}
	return n
}
