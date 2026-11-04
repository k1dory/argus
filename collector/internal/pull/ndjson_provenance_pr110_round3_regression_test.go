package pull

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

type pr110Round3S3Transport func(*http.Request) (*http.Response, error)

func (f pr110Round3S3Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// Ветка S3 events читает ту же NDJSON-схему, что /ingest/events. В main emit
// меняет transport, но сохраняет peer/peer_cn: skew.apply затем использует
// peer для доверенной внутренней сводки collector.clock_skew. Автор объекта
// не должен приписать эту сводку чужому устройству или выдумать mTLS CN.
// Ответ хранилища подставлен через RoundTripper: внешних запросов нет.
func TestPR110Round3S3NDJSONCannotSupplyPeerIdentity(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	previousNow := model.Now
	model.Now = func() time.Time { return now }
	t.Cleanup(func() { model.Now = previousNow })

	for _, tc := range []struct {
		name, peerKey, cnKey string
	}{
		{"clean_keys", "peer", "peer_cn"},
		{"dirty_keys_control", "pe\x00er", "peer_\x00cn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const victim = "192.0.2.77"
			payload, err := json.Marshal(model.Event{
				TS:     model.FormatTS(now.Add(30 * time.Minute)),
				Source: "fixture.s3", Action: "fixture.event",
				Attrs: map[string]string{tc.peerKey: victim, tc.cnKey: "forged-client-cert"},
			})
			if err != nil {
				t.Fatal(err)
			}
			var emitted []model.Event
			s := NewS3(S3Config{
				Name: "fixture.s3", Endpoint: "https://storage.example.invalid", Bucket: "fixture-bucket",
				Format: "events", AccessKey: "dummy-access-key", SecretKey: "dummy-secret-key",
			}, func(e model.Event) { emitted = append(emitted, e) })
			requests := 0
			s.http = &http.Client{Transport: pr110Round3S3Transport(func(r *http.Request) (*http.Response, error) {
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
			if err != nil || n != 1 || len(emitted) != 1 || requests != 1 {
				t.Fatalf("fetch: events=%d callbacks=%d requests=%d err=%v", n, len(emitted), requests, err)
			}
			e := emitted[0]
			if e.TS != model.FormatTS(now.Add(30*time.Minute)) || e.Source != "fixture.s3" {
				t.Fatalf("fixture must retain its future timestamp before skew.apply: %+v", e)
			}
			if e.Attrs["peer"] == victim {
				t.Errorf("S3 object supplied peer=%q; emit/skew.apply will attribute collector.clock_skew to that unrelated device", victim)
			}
			if got := e.Attrs["peer_cn"]; got != "" {
				t.Errorf("S3 object supplied peer_cn=%q without a verified client certificate", got)
			}
		})
	}
}
