package systemone

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type pr64ResponseTransport func(*http.Request) (*http.Response, error)

func (f pr64ResponseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestPR64DecideErrorsDoNotExposeAPIKey(t *testing.T) {
	const key = "sk-or-v1-pr64-dummy-secret"
	qs := map[string]Question{"escalate": {Type: Noul, Instructions: "Needs escalation"}}
	tests := []struct {
		name     string
		status   int
		location string
		body     string
	}{
		// Positive control: provider error bodies are already suppressed.
		{name: "HTTP error echo", status: http.StatusUnauthorized, body: "invalid authorization: " + key},
		// net/http parses Location before calling CheckRedirect. A parse error
		// quotes the untrusted Location, including any echoed credentials.
		{name: "malformed redirect echo", status: http.StatusTemporaryRedirect,
			location: "https://decisions.example.invalid/%zz?token=" + key, body: "redirect"},
		// Validate also interpolates upstream strings into returned errors.
		{name: "invalid answer type echo", status: http.StatusOK,
			body: `{"answers":{"escalate":{"type":"` + key + `","noul":0.5}}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			client := &Client{Name: "jev", Endpoint: "https://decisions.example.invalid/v1/systemone", APIKey: key,
				HTTP: &http.Client{Transport: pr64ResponseTransport(func(req *http.Request) (*http.Response, error) {
					calls++
					if req.Header.Get("Authorization") != "Bearer "+key {
						t.Fatal("fixture must exercise the authenticated request path")
					}
					header := make(http.Header)
					if tt.location != "" {
						header.Set("Location", tt.location)
					}
					return &http.Response{StatusCode: tt.status, Header: header,
						Body: io.NopCloser(strings.NewReader(tt.body)), Request: req}, nil
				})}}
			_, err := client.Decide(context.Background(), "safe fixture state", qs)
			if err == nil {
				t.Fatal("invalid upstream response must fail")
			}
			if calls != 1 {
				t.Errorf("redirect must not make another request: %d calls", calls)
			}
			if strings.Contains(err.Error(), key) {
				t.Errorf("returned error exposes the API key: %v", err)
			}
		})
	}
}
