// Package systemone — клиент протокола TypeSafe System One (POST /v1/systemone):
// состояние и типизированные вопросы на входе, ответы с распределениями на
// выходе. Один протокол у Jev (api.typesafe.ai или OpenRouter
// /api/alpha/decisions) и у локального laya-serve — модель выбирается
// конфигурацией, код один.
//
// Формат — https://docs.typesafe.ai/introduction/quickstart (Raw Response) и
// https://docs.typesafe.ai/primitives: choice — выбранный вариант,
// probabilities по всем вариантам и confidence; score — позиция на шкале,
// probabilities по уровням "0".."N-1" и confidence; noul — вероятность «да».
package systemone

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Типы вопросов.
const (
	Choice = "choice"
	Score  = "score"
	Noul   = "noul"
)

// Question — вопрос System One. Criteria: для choice — map[вариант]описание,
// для score — []уровень по возрастанию, для noul — необязательный
// map{"true": ..., "false": ...}.
type Question struct {
	Type         string `json:"type"`
	Instructions string `json:"instructions"`
	Criteria     any    `json:"criteria,omitempty"`
}

// Options — варианты ответа в порядке, в котором их ждёт probabilities:
// для choice — ключи criteria, для score — "0".."N-1", для noul — нет.
func (q Question) Options() []string {
	switch c := q.Criteria.(type) {
	case map[string]string:
		if q.Type != Choice {
			return nil
		}
		out := make([]string, 0, len(c))
		for k := range c {
			out = append(out, k)
		}
		return out
	case []string:
		if q.Type != Score {
			return nil
		}
		out := make([]string, len(c))
		for i := range c {
			out[i] = strconv.Itoa(i)
		}
		return out
	}
	return nil
}

// Answer — ответ на один вопрос.
type Answer struct {
	Type          string             `json:"type"`
	Choice        string             `json:"choice,omitempty"`
	Score         *float64           `json:"score,omitempty"`
	Noul          *float64           `json:"noul,omitempty"`
	Confidence    *float64           `json:"confidence,omitempty"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
}

// Usage — потраченные токены.
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// Response — ответ модели.
type Response struct {
	Model   string            `json:"model"`
	Answers map[string]Answer `json:"answers"`
	Usage   Usage             `json:"usage"`
}

type request struct {
	State     string              `json:"state"`
	Model     string              `json:"model,omitempty"`
	Questions map[string]Question `json:"questions"`
}

// Client — одна модель System One.
type Client struct {
	Name     string // laya | jev — имя источника ответов в датасете
	Endpoint string // полный URL: https://api.typesafe.ai/v1/systemone, http://laya:8080/v1/systemone
	APIKey   string // Bearer; у локального laya-serve может быть пустым
	Model    string
	HTTP     *http.Client
}

// maxResponse — потолок тела ответа: десяток вопросов с распределениями — килобайты.
const maxResponse = 1 << 20

// ErrDisabled — модель не включена в конфигурации.
var ErrDisabled = errors.New("systemone: модель не включена")

// Decide задаёт вопросы по состоянию и проверяет, что ответы полные и
// распределения корректны (Validate). Перенаправления запрещены: ключ не
// должен уйти на другой хост.
func (c *Client) Decide(ctx context.Context, state string, qs map[string]Question) (Response, error) {
	if c == nil || c.Endpoint == "" {
		return Response{}, ErrDisabled
	}
	body, err := json.Marshal(request{State: state, Model: c.Model, Questions: qs})
	if err != nil {
		return Response{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	noRedirect := *hc
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(req)
	if err != nil {
		return Response{}, c.fail(transportClass(ctx, err), 0)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return Response{}, c.fail(transportClass(ctx, err), 0)
	}
	if len(raw) > maxResponse {
		return Response{}, c.fail(ClassTooLarge, 0)
	}
	if resp.StatusCode != http.StatusOK {
		return Response{}, c.fail(ClassHTTP, resp.StatusCode)
	}
	var out Response
	if err := json.Unmarshal(raw, &out); err != nil {
		return Response{}, c.fail(ClassBadJSON, 0)
	}
	if err := Validate(qs, out); err != nil {
		// Validate не подставляет в текст строки из ответа — только id вопросов.
		return Response{}, &Error{Model: c.Name, Class: ClassInvalid, Detail: err.Error()}
	}
	return out, nil
}

// Классы ошибок Decide. Текст ответа, заголовки (Location, Content-Type) и
// ошибки транспорта наружу не отдаются: в них бывает эхо запроса и ключа, а
// ошибка пишется в лог и в запись датасета.
const (
	ClassTransport = "transport"
	ClassTimeout   = "timeout"
	ClassCanceled  = "canceled"
	ClassTooLarge  = "response too large"
	ClassHTTP      = "http"
	ClassBadJSON   = "malformed response"
	ClassInvalid   = "invalid answer"
)

// Error — ошибка Decide: модель, класс, HTTP-статус; Detail — только для
// ClassInvalid и только из наших данных (id вопроса, число вариантов).
type Error struct {
	Model  string
	Class  string
	Status int
	Detail string
}

func (e *Error) Error() string {
	switch {
	case e.Class == ClassHTTP:
		return fmt.Sprintf("systemone %s: HTTP %d", e.Model, e.Status)
	case e.Detail != "":
		return fmt.Sprintf("systemone %s: %s: %s", e.Model, e.Class, e.Detail)
	}
	return fmt.Sprintf("systemone %s: %s", e.Model, e.Class)
}

func (c *Client) fail(class string, status int) error {
	return &Error{Model: c.Name, Class: class, Status: status}
}

func transportClass(ctx context.Context, err error) string {
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return ClassCanceled
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded):
		return ClassTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ClassTimeout
	}
	return ClassTransport
}

// probTolerance — допуск суммы распределения (округление провайдера).
const probTolerance = 0.02

// Validate — у каждого вопроса есть ответ своего типа; у choice и score
// распределение по всем вариантам, без лишних, в [0,1] и с суммой ≈ 1;
// выбранный вариант choice — из списка; noul — в [0,1].
func Validate(qs map[string]Question, r Response) error {
	for id, q := range qs {
		a, ok := r.Answers[id]
		if !ok {
			return fmt.Errorf("нет ответа на %q", id)
		}
		if a.Type != q.Type {
			return fmt.Errorf("%q: тип ответа не %q", id, q.Type)
		}
		switch q.Type {
		case Noul:
			if a.Noul == nil || !unit(*a.Noul) {
				return fmt.Errorf("%q: noul вне [0,1]", id)
			}
		case Choice, Score:
			opts := q.Options()
			if len(opts) == 0 {
				return fmt.Errorf("%q: у вопроса нет вариантов", id)
			}
			if len(a.Probabilities) != len(opts) {
				return fmt.Errorf("%q: распределение по %d вариантам из %d", id, len(a.Probabilities), len(opts))
			}
			sum := 0.0
			for _, o := range opts {
				p, ok := a.Probabilities[o]
				if !ok || !unit(p) {
					return fmt.Errorf("%q: нет вероятности варианта %q или она вне [0,1]", id, o)
				}
				sum += p
			}
			if math.Abs(sum-1) > probTolerance {
				return fmt.Errorf("%q: сумма распределения %.3f", id, sum)
			}
			if q.Type == Choice {
				if _, ok := a.Probabilities[a.Choice]; !ok {
					return fmt.Errorf("%q: выбран вариант вне списка", id)
				}
			} else if a.Score == nil || *a.Score < 0 || *a.Score > float64(len(opts)-1) {
				return fmt.Errorf("%q: score вне шкалы", id)
			}
		default:
			return fmt.Errorf("%q: неизвестный тип вопроса", id)
		}
	}
	return nil
}

func unit(p float64) bool { return !math.IsNaN(p) && p >= 0 && p <= 1 }

// FromEnv — клиенты из окружения. Ничего не включено по умолчанию.
//
//	ARGUS_LAYA_ENDPOINT   — URL laya-serve (локальная модель); пусто — Laya выключена
//	ARGUS_LAYA_MODEL      — по умолчанию laya-multilingual
//	ARGUS_LAYA_TOKEN      — Bearer, если laya-serve за токеном
//	ARGUS_JEV_ENABLED=1   — явное включение облачного Jev (без него ключ игнорируется)
//	ARGUS_JEV_ENDPOINT    — по умолчанию https://openrouter.ai/api/alpha/decisions
//	ARGUS_JEV_API_KEY     — ключ (в инфраструктуре — vault_argus_*)
//	ARGUS_JEV_MODEL       — по умолчанию typesafe/jev-1.13
//
// Jev — облако: вызывающий обязан не передавать инциденты с ПДн (pii=1)
// и передавать только обезличенное состояние (analyst.DecisionState).
func FromEnv(getenv func(string) string) (laya, jev *Client) {
	or := func(k, def string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def
	}
	if ep := strings.TrimSpace(getenv("ARGUS_LAYA_ENDPOINT")); ep != "" {
		laya = &Client{Name: "laya", Endpoint: ep, APIKey: getenv("ARGUS_LAYA_TOKEN"), Model: or("ARGUS_LAYA_MODEL", "laya-multilingual")}
	}
	if getenv("ARGUS_JEV_ENABLED") == "1" {
		if key := strings.TrimSpace(getenv("ARGUS_JEV_API_KEY")); key != "" {
			jev = &Client{Name: "jev", Endpoint: or("ARGUS_JEV_ENDPOINT", "https://openrouter.ai/api/alpha/decisions"),
				APIKey: key, Model: or("ARGUS_JEV_MODEL", "typesafe/jev-1.13")}
		}
	}
	return laya, jev
}
