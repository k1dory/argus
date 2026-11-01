package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/registry"
)

type datasetRegistryTransport func(*http.Request) (*http.Response, error)

func (f datasetRegistryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// PR #73: reject an incomplete installed bundle before touching --out or
// ClickHouse. No sockets or model endpoints are used: the HTTP transport is
// intercepted in memory. The complete-bundle case checks the harness itself.
// Run from engine: go test ./cmd/engine -run TestDatasetRegistryPreflight -count=1
func TestDatasetRegistryPreflight(t *testing.T) {
	for _, layout := range []string{"missing-rules", "missing-fixtures", "empty-fixtures", "complete"} {
		t.Run(layout, func(t *testing.T) {
			t.Cleanup(func() {
				if err := registry.LoadRepo(); err != nil {
					t.Errorf("restore test registry: %v", err)
				}
			})
			dir := t.TempDir()
			if layout != "missing-rules" {
				if err := os.Mkdir(filepath.Join(dir, "rules"), 0o700); err != nil {
					t.Fatal(err)
				}
				const rule = "id: qa-shipped-ssh\ntitle: QA shipped SSH rule\nlevel: high\ndetection:\n  selection:\n    source: host.sshd\n    action: auth.ssh\n  condition: selection\n"
				if err := os.WriteFile(filepath.Join(dir, "rules", "ssh.yml"), []byte(rule), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if layout == "empty-fixtures" || layout == "complete" {
				if err := os.Mkdir(filepath.Join(dir, "fixtures"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if layout == "complete" {
				if err := os.WriteFile(filepath.Join(dir, "fixtures", "events.ndjson"),
					[]byte("{\"source\":\"edr.kaspersky\",\"action\":\"file.read\"}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			t.Setenv("ARGUS_SHIPPED_DIR", dir)
			t.Setenv("ARGUS_DATASET_SECRET", strings.Repeat("s", 32))
			t.Setenv("ARGUS_LAYA_ENDPOINT", "")
			t.Setenv("ARGUS_JEV_ENABLED", "0")
			t.Setenv("CLICKHOUSE_URL", "http://qa-clickhouse.invalid")
			t.Setenv("CLICKHOUSE_USER", "qa")
			t.Setenv("CLICKHOUSE_PASSWORD", "")
			var requests atomic.Int32
			previousTransport := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = previousTransport })
			http.DefaultTransport = datasetRegistryTransport(func(r *http.Request) (*http.Response, error) {
				requests.Add(1)
				return &http.Response{
					StatusCode: http.StatusOK, Header: make(http.Header),
					Body: io.NopCloser(strings.NewReader("")), Request: r,
				}, nil
			})

			out := filepath.Join(t.TempDir(), "existing.jsonl")
			const previousExport = "keep the previous export on registry failure\n"
			if err := os.WriteFile(out, []byte(previousExport), 0o600); err != nil {
				t.Fatal(err)
			}
			code := datasetCmd([]string{"export", "--out", out})
			data, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			if layout == "complete" {
				if code != 0 || requests.Load() == 0 || len(data) != 0 {
					t.Fatalf("complete bundle: exit=%d requests=%d output=%q", code, requests.Load(), data)
				}
				if !registry.Source("edr.kaspersky") || !registry.Action("file.read") {
					t.Error("CLI did not load the fixture vocabulary")
				}
				return
			}
			if code != 2 {
				t.Errorf("incomplete bundle: exit=%d, want configuration error 2", code)
			}
			if requests.Load() != 0 {
				t.Errorf("contacted ClickHouse %d times before rejecting the incomplete registry", requests.Load())
			}
			if string(data) != previousExport {
				t.Errorf("overwrote --out before rejecting the incomplete registry: %q", data)
			}
		})
	}
}
