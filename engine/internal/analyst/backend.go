package analyst

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Backend — способ получить вердикт от модели. Всё остальное — выбор
// профиля (Route), политика ПДн и egress, редакция и обезличивание данных,
// проверка схемы ответа и решение «показывать ли дежурному» (decideShown) —
// общее для всех бэкендов и выполняется снаружи: бэкенд получает уже
// подготовленные system prompt и текст запроса и возвращает только ответ
// модели и число потраченных токенов.
type Backend interface {
	Analyze(ctx context.Context, p Profile, client *http.Client, system, prompt string) (Verdict, uint32, error)
}

// Встроенные бэкенды. Пустое имя в профиле означает openai-compatible.
const (
	BackendOpenAI = "openai-compatible"
	BackendMock   = "mock"
)

var (
	backendsMu sync.RWMutex
	backends   = map[string]Backend{
		BackendOpenAI: openaiBackend{},
		BackendMock:   mockBackend{},
	}
)

// RegisterBackend добавляет (или заменяет) бэкенд под именем, которое затем
// можно указать в profiles.<name>.backend. Регистрация — до LoadConfig: он
// проверяет имена бэкендов по этому реестру.
func RegisterBackend(name string, b Backend) {
	backendsMu.Lock()
	defer backendsMu.Unlock()
	backends[strings.TrimSpace(name)] = b
}

// Backends — имена зарегистрированных бэкендов (для сообщений об ошибках).
func Backends() []string {
	backendsMu.RLock()
	defer backendsMu.RUnlock()
	names := make([]string, 0, len(backends))
	for n := range backends {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// backendName — имя бэкенда профиля с учётом умолчания.
func backendName(p Profile) string {
	if n := strings.TrimSpace(p.Backend); n != "" {
		return n
	}
	return BackendOpenAI
}

func backendFor(p Profile) (Backend, error) {
	backendsMu.RLock()
	defer backendsMu.RUnlock()
	name := backendName(p)
	b, ok := backends[name]
	if !ok {
		return nil, fmt.Errorf("backend %q неизвестен; доступны: %s", name, strings.Join(Backends(), ", "))
	}
	return b, nil
}

/* ===== openai-compatible ===== */

// openaiBackend — POST {endpoint}/chat/completions по схеме OpenAI Chat API:
// локальные серверы (vLLM, llama.cpp, Ollama) и облачные провайдеры с тем же
// контрактом. Ответ — JSON по схеме Verdict.
type openaiBackend struct{}

func (openaiBackend) Analyze(ctx context.Context, p Profile, client *http.Client, system, prompt string) (Verdict, uint32, error) {
	timeout := 30 * time.Second
	if d, err := time.ParseDuration(p.Timeout); err == nil && d > 0 {
		timeout = d
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	maxTokens := p.MaxTokens
	if maxTokens == 0 {
		maxTokens = 1024
	}
	body, _ := json.Marshal(map[string]any{
		"model":           p.Model,
		"temperature":     0.1,
		"max_tokens":      maxTokens,
		"response_format": map[string]string{"type": "json_object"},
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": prompt},
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.Endpoint, "/")+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Verdict{}, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.APIKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return Verdict{}, 0, fmt.Errorf("llm: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return Verdict{}, 0, fmt.Errorf("llm %s: %s", resp.Status, strings.TrimSpace(string(raw[:min(len(raw), 300)])))
	}
	var out struct {
		Choices []struct {
			Message struct{ Content string } `json:"message"`
		} `json:"choices"`
		Usage struct {
			TotalTokens uint32 `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Choices) == 0 {
		return Verdict{}, 0, errors.New("llm: пустой или нечитаемый ответ")
	}
	content := strings.TrimSpace(out.Choices[0].Message.Content)
	content = strings.TrimPrefix(strings.TrimSuffix(strings.TrimPrefix(content, "```json"), "```"), "```")
	var v Verdict
	if err := json.Unmarshal([]byte(strings.TrimSpace(content)), &v); err != nil {
		return Verdict{}, out.Usage.TotalTokens, fmt.Errorf("llm: ответ не по схеме: %w", err)
	}
	return v, out.Usage.TotalTokens, nil
}

/* ===== mock ===== */

// mockBackend — детерминированный разбор без модели: стенд без LLM и тесты.
// Работает по тому же промпту, что получила бы настоящая модель (шапка с
// уровнем и правилом, блок данных с субъектом, узлом и цепочкой), и его
// вердикт проходит те же validate и decideShown: у mock нет доступа к
// инциденту в обход общего пути.
type mockBackend struct{}

func (mockBackend) Analyze(_ context.Context, _ Profile, _ *http.Client, _ string, prompt string) (Verdict, uint32, error) {
	return mockVerdict(prompt), uint32(len(prompt) / 4), nil
}

var (
	mockLevelRe  = regexp.MustCompile(`(?m)^Правило: (.*?) \([^)]*\), уровень (\S+)$`)
	mockFieldRe  = regexp.MustCompile(`(?m)^(Субъект|Узел|Источники|Событий): (.*)$`)
	mockChainRe  = regexp.MustCompile(`(?s)Цепочка событий:\n(.*?)(?:\n\n|\nEVENT_DATA>>>|$)`)
	mockConfByLv = map[string]float32{"critical": 0.9, "high": 0.75, "low": 0.3}
)

func mockVerdict(prompt string) Verdict {
	title, level := "", ""
	if m := mockLevelRe.FindStringSubmatch(prompt); m != nil {
		title, level = m[1], m[2]
	}
	fields := map[string]string{}
	for _, m := range mockFieldRe.FindAllStringSubmatch(prompt, -1) {
		fields[m[1]] = strings.TrimSpace(m[2])
	}
	conf, ok := mockConfByLv[level]
	if !ok {
		conf = 0.55
	}
	ev := []string{"Событий: " + fields["Событий"]}
	if m := mockChainRe.FindStringSubmatch(prompt); m != nil {
		if first := strings.TrimSpace(strings.SplitN(m[1], "\n", 2)[0]); first != "" {
			ev = append(ev, "первое событие: "+first)
		}
	}
	return Verdict{
		SummaryRU:   fmt.Sprintf("Сработало правило «%s» по субъекту %s на узле %s: %s из источников %s. Разбор сформирован mock-профилем без обращения к модели.", title, fields["Субъект"], fields["Узел"], firstPart(fields["Событий"]), fields["Источники"]),
		Evidence:    ev,
		FirstAction: "Проверить цепочку событий и подтвердить владельцу узла " + fields["Узел"],
		Confidence:  conf,
		Missing:     "живая модель: профиль mock",
	}
}

// firstPart — «3, с 10:00 по 10:05» → «3 событий».
func firstPart(s string) string {
	if i := strings.IndexByte(s, ','); i > 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s) + " событий"
}
