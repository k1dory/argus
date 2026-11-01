package systemone

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestPR64RereviewRequestConstructionErrorsAreClassifiedAndPrivate(t *testing.T) {
	const secret = "pr64-dummy-gateway-token"
	client := &Client{
		Name: "laya", Model: "fixture-model",
		// A configured gateway may use a query token. A typo in its URL must
		// not make that credential part of the error exported into JSONL.
		Endpoint: "https://gateway.example.invalid/%zz?token=" + secret,
		HTTP: &http.Client{Transport: pr64ResponseTransport(func(*http.Request) (*http.Response, error) {
			t.Error("malformed endpoint must fail before any transport call")
			return nil, errors.New("unexpected transport call")
		})},
	}
	_, err := client.Decide(context.Background(), "safe fixture state", map[string]Question{
		"escalate": {Type: Noul, Instructions: "Needs escalation"},
	})
	if err == nil {
		t.Fatal("malformed endpoint must fail")
	}
	var classified *Error
	if !errors.As(err, &classified) || classified.Class == "" {
		t.Errorf("request construction bypassed systemone.Error: %T", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "gateway.example.invalid") {
		t.Error("error exposed the configured URL/token; exportDataset writes this error verbatim")
	}
}
