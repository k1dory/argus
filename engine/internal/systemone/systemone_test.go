package systemone

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var testQs = map[string]Question{
	"department":  {Type: Choice, Instructions: "Which team", Criteria: map[string]string{"billing": "b", "technical": "t", "sales": "s"}},
	"frustration": {Type: Score, Instructions: "How frustrated", Criteria: []string{"calm", "civil", "angry"}},
	"is_urgent":   {Type: Noul, Instructions: "Urgent"},
}

// Ответ из документации TypeSafe (quickstart, Raw Response).
const docResponse = `{
  "model": "jev-1.13.0",
  "answers": {
    "department": {"type": "choice", "choice": "technical", "confidence": 1.0,
      "probabilities": {"technical": 1.0, "billing": 0.0, "sales": 0.0}},
    "frustration": {"type": "score", "score": 0.67, "confidence": 0.5,
      "legend": {"0": "calm", "1": "civil", "2": "angry"},
      "probabilities": {"0": 0.33, "1": 0.67, "2": 0.0}},
    "is_urgent": {"type": "noul", "noul": 0.99}
  },
  "usage": {"input_tokens": 428, "output_tokens": 73}
}`

func TestDecideRequestAndDocResponse(t *testing.T) {
	var got struct {
		State     string                     `json:"state"`
		Model     string                     `json:"model"`
		Questions map[string]json.RawMessage `json:"questions"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer k" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("запрос: %s %q %q", r.Method, r.Header.Get("Authorization"), r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Error(err)
		}
		_, _ = io.WriteString(w, docResponse)
	}))
	defer srv.Close()
	c := &Client{Name: "jev", Endpoint: srv.URL, APIKey: "k", Model: "jev-latest"}
	resp, err := c.Decide(context.Background(), "state text", testQs)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "state text" || got.Model != "jev-latest" || len(got.Questions) != 3 {
		t.Fatalf("тело запроса: %+v", got)
	}
	if !strings.Contains(string(got.Questions["frustration"]), `"criteria":["calm","civil","angry"]`) {
		t.Fatalf("score criteria — массив уровней: %s", got.Questions["frustration"])
	}
	if resp.Model != "jev-1.13.0" || resp.Answers["department"].Choice != "technical" || *resp.Answers["is_urgent"].Noul != 0.99 || resp.Usage.InputTokens != 428 {
		t.Fatalf("ответ: %+v", resp)
	}
}

func TestDecideNoKeyHeaderWhenEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("без ключа заголовка Authorization быть не должно")
		}
		_, _ = io.WriteString(w, docResponse)
	}))
	defer srv.Close()
	if _, err := (&Client{Name: "laya", Endpoint: srv.URL}).Decide(context.Background(), "s", testQs); err != nil {
		t.Fatal(err)
	}
}

func TestDecideRejectsRedirectAndErrors(t *testing.T) {
	var leaked bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = true
		_, _ = io.WriteString(w, docResponse)
	}))
	defer other.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	if _, err := (&Client{Name: "jev", Endpoint: redir.URL, APIKey: "k"}).Decide(context.Background(), "s", testQs); err == nil {
		t.Fatal("перенаправление должно быть ошибкой")
	}
	if leaked {
		t.Fatal("запрос с ключом ушёл по перенаправлению")
	}

	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "echo: secret state", http.StatusTooManyRequests)
	}))
	defer fail.Close()
	_, err := (&Client{Name: "jev", Endpoint: fail.URL}).Decide(context.Background(), "s", testQs)
	if err == nil || !strings.Contains(err.Error(), "HTTP 429") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("ошибка без тела ответа: %v", err)
	}

	if _, err := (*Client)(nil).Decide(context.Background(), "s", testQs); !errors.Is(err, ErrDisabled) {
		t.Fatalf("nil-клиент: %v", err)
	}
}

func TestValidate(t *testing.T) {
	var ok Response
	if err := json.Unmarshal([]byte(docResponse), &ok); err != nil {
		t.Fatal(err)
	}
	if err := Validate(testQs, ok); err != nil {
		t.Fatalf("ответ из документации: %v", err)
	}
	mutate := func(f func(r *Response)) Response {
		var r Response
		_ = json.Unmarshal([]byte(docResponse), &r)
		f(&r)
		return r
	}
	f := func(v float64) *float64 { return &v }
	cases := map[string]Response{
		"нет ответа": mutate(func(r *Response) { delete(r.Answers, "is_urgent") }),
		"чужой тип": mutate(func(r *Response) {
			a := r.Answers["is_urgent"]
			a.Type = Choice
			r.Answers["is_urgent"] = a
		}),
		"noul > 1": mutate(func(r *Response) { r.Answers["is_urgent"] = Answer{Type: Noul, Noul: f(1.5)} }),
		"noul нет": mutate(func(r *Response) { r.Answers["is_urgent"] = Answer{Type: Noul} }),
		"сумма":    mutate(func(r *Response) { r.Answers["department"].Probabilities["sales"] = 0.5 }),
		"не все варианты": mutate(func(r *Response) {
			delete(r.Answers["department"].Probabilities, "sales")
		}),
		"выбор вне списка": mutate(func(r *Response) {
			a := r.Answers["department"]
			a.Choice = "hr"
			r.Answers["department"] = a
		}),
		"score вне шкалы": mutate(func(r *Response) {
			a := r.Answers["frustration"]
			a.Score = f(3)
			r.Answers["frustration"] = a
		}),
	}
	for name, r := range cases {
		if err := Validate(testQs, r); err == nil {
			t.Errorf("%s: ошибка не найдена", name)
		}
	}
}

func TestFromEnvOffByDefault(t *testing.T) {
	envs := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	laya, jev := FromEnv(envs(nil))
	if laya != nil || jev != nil {
		t.Fatal("без окружения обе модели выключены")
	}
	// Ключ без явного включения не включает облако.
	if _, jev = FromEnv(envs(map[string]string{"ARGUS_JEV_API_KEY": "k"})); jev != nil {
		t.Fatal("Jev включается только ARGUS_JEV_ENABLED=1")
	}
	if _, jev = FromEnv(envs(map[string]string{"ARGUS_JEV_ENABLED": "1"})); jev != nil {
		t.Fatal("Jev без ключа выключен")
	}
	laya, jev = FromEnv(envs(map[string]string{"ARGUS_JEV_ENABLED": "1", "ARGUS_JEV_API_KEY": "k", "ARGUS_LAYA_ENDPOINT": "http://laya:8080/v1/systemone"}))
	if jev == nil || jev.Endpoint != "https://openrouter.ai/api/alpha/decisions" || jev.Model != "typesafe/jev-1.13" {
		t.Fatalf("Jev: %+v", jev)
	}
	if laya == nil || laya.Model != "laya-multilingual" || laya.Name != "laya" {
		t.Fatalf("Laya: %+v", laya)
	}
}

// Вопрос, прочитанный обратно из JSON (датасет), даёт те же варианты.
func TestOptionsAfterJSONRoundTrip(t *testing.T) {
	for _, q := range []Question{
		{Type: Choice, Criteria: map[string]string{"a": "A", "b": "B"}},
		{Type: Score, Criteria: []string{"low", "mid", "high"}},
	} {
		raw, _ := json.Marshal(q)
		var back Question
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatal(err)
		}
		if len(back.Options()) != len(q.Options()) || len(q.Options()) == 0 {
			t.Fatalf("%s: %v против %v", q.Type, back.Options(), q.Options())
		}
	}
}
