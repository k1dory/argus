package pull

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/model"
)

type pr116ObjectTransport func(*http.Request) (*http.Response, error)

func (f pr116ObjectTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// S3 удаляет ключи до Ensure, в отличие от HTTP. Ни точные, ни грязные
// написания не должны доживать до Emit или появляться при повторной чистке.
func TestPR116S3StripsEveryProvenanceAttribute(t *testing.T) {
	attrs := map[string]string{"payload": "keep-me"}
	keys := []string{"peer", "peer_cn", "scope", "transport", "ts_original"}
	for _, key := range keys {
		attrs[key] = "forged-" + key
		for _, dirty := range []string{"\x00", "\u0080", "\x1b[31m"} {
			attrs[key[:1]+dirty+key[1:]] = "forged-dirty-" + key
		}
	}
	payload, err := json.Marshal(model.Event{
		Source: "fixture.s3", SrcIP: "198.51.100.7", DstIP: "10.20.0.8", Attrs: attrs,
	})
	if err != nil {
		t.Fatal(err)
	}
	var events []model.Event
	s := NewS3(S3Config{
		Name: "fixture.s3", Endpoint: "https://storage.example.invalid", Bucket: "fixture-bucket",
		Format: "events", AccessKey: "dummy-access-key", SecretKey: "dummy-secret-key",
	}, func(e model.Event) { events = append(events, e) })
	requests := 0
	s.http = &http.Client{Transport: pr116ObjectTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.Method != http.MethodGet || r.URL.Path != "/fixture-bucket/events.ndjson" {
			t.Fatalf("unexpected fixture request: %s %s", r.Method, r.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header), Request: r,
			Body: io.NopCloser(strings.NewReader(string(payload) + "\n")),
		}, nil
	})}
	n, err := s.fetch(context.Background(), "events.ndjson")
	if err != nil || n != 1 || len(events) != 1 || requests != 1 {
		t.Fatalf("fetch: events=%d callbacks=%d requests=%d err=%v", n, len(events), requests, err)
	}
	e := events[0]
	if e.Source != "fixture.s3" || e.SrcIP != "198.51.100.7" || e.DstIP != "10.20.0.8" || e.Attrs["payload"] != "keep-me" {
		t.Fatalf("ordinary event data changed: %+v", e)
	}
	for pass := 0; pass < 2; pass++ {
		for _, key := range keys {
			if value, exists := e.Attrs[key]; exists {
				t.Errorf("pass=%d: object supplied attrs.%s=%q", pass, key, value)
			}
		}
		e.Sanitize()
	}
}
