package engine_test

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// PR #79: !engine/, !rules/ and !fixtures/events/ also re-include private
// files below those directories. With the new compose context, rules/.env
// and fixtures/events/.env reach COPY in the final image, even when git
// ignores them. Root-level .env being excluded does not cover this case.
//
// Use Docker CLI's real .dockerignore matcher, not a reimplementation.
// A loopback HTTP stub only receives the context tar; it never builds an
// image. No daemon, base images, credentials, buildx or downloads are used.
// Run in an isolated environment with Docker CLI available, from engine:
//
//	go test . -run '^TestPR79RootBuildContextExcludesSecrets$' -count=1
func TestPR79RootBuildContextExcludesSecrets(t *testing.T) {
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("Docker CLI is required to exercise its context filter; no daemon is needed")
	}
	ignore, err := os.ReadFile(filepath.Join("..", ".dockerignore"))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		include bool
	}{
		// Positive controls keep the engine and both shipped inputs buildable.
		{"engine/go.mod", true},
		{"engine/go.sum", true},
		{"engine/cmd/engine/main.go", true},
		{"engine/argus.analyst.yml", true},
		{"rules/host-ssh-bruteforce.yml", true},
		{"rules/ops/disk-usage-high.yml", true},
		{"fixtures/events/events.ndjson", true},
		// Files outside the allowlisted directories must stay excluded.
		{".env", false},
		{".env.ai", false},
		{".git/config", false},
		{"web/package.json", false},
		{"collector/certs/server.key", false},
		{"fixtures/private.ndjson", false},
		// Regression: the directory exceptions must not expose nested secrets.
		{"engine/.env", false},
		{"engine/.env.production", false},
		{"engine/config/.env", false},
		{"rules/.env", false},
		{"rules/local/.env.production", false},
		{"fixtures/events/.env", false},
		{"fixtures/events/private/client.key", false},
	}

	scratch := t.TempDir()
	contextDir := filepath.Join(scratch, "context")
	configDir := filepath.Join(scratch, "docker-config")
	for _, dir := range []string{contextDir, configDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name string, data []byte) {
		t.Helper()
		filename := filepath.Join(contextDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(".dockerignore", ignore)
	// The probe Dockerfile cannot pull an image or run a command, even if
	// someone accidentally points a copy of this probe at a real daemon.
	write("engine/Dockerfile", []byte("FROM scratch\nCOPY engine/ /src/\nCOPY rules/ /rules/\nCOPY fixtures/events/ /fixtures/\n"))
	for _, tc := range cases {
		write(tc.name, []byte("PR79_SYNTHETIC_DATA_ONLY\n"))
	}

	type capture struct {
		files map[string]bool
		err   error
	}
	received := make(chan capture, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/_ping"):
			w.Header().Set("API-Version", "1.45")
			w.Header().Set("OSType", "linux")
			w.Header().Set("Builder-Version", "1")
			_, _ = io.WriteString(w, "OK")
		case strings.HasSuffix(r.URL.Path, "/version"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ApiVersion":"1.45","MinAPIVersion":"1.24","Os":"linux"}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/build"):
			result := capture{files: make(map[string]bool)}
			tr := tar.NewReader(http.MaxBytesReader(w, r.Body, 1<<20))
			for {
				h, err := tr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					result.err = fmt.Errorf("read Docker context: %w", err)
					break
				}
				if h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA {
					result.files[path.Clean(h.Name)] = true
				}
			}
			select {
			case received <- result:
			default:
				http.Error(w, "unexpected second build", http.StatusBadRequest)
				return
			}
			if result.err != nil {
				http.Error(w, result.err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, "{\"stream\":\"Successfully built 0123456789ab\\n\"}\n")
		default:
			http.Error(w, "unexpected Docker API request", http.StatusNotFound)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, docker,
		"--host", strings.Replace(server.URL, "http://", "tcp://", 1),
		"--config", configDir, "build", "--network=none", "--pull=false",
		"--file", "engine/Dockerfile", ".")
	cmd.Dir = contextDir
	// Do not inherit Docker contexts, credentials, proxies, TLS settings,
	// plugins or endpoints from the developer's environment.
	cmd.Env = []string{
		"PATH=/usr/bin:/bin", "HOME=" + configDir, "TMPDIR=" + scratch,
		"DOCKER_CONFIG=" + configDir, "DOCKER_BUILDKIT=0", "DOCKER_API_VERSION=1.45",
		"DOCKER_CLI_HINTS=false", "LC_ALL=C",
	}
	cmd.WaitDelay = time.Second
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Docker CLI context probe failed: %v\n%s", err, out)
	}
	var result capture
	select {
	case result = <-received:
	default:
		t.Fatal("Docker CLI did not send a build context to the local stub")
	}
	if result.err != nil {
		t.Fatal(result.err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := result.files[tc.name]; got != tc.include {
				t.Errorf("Docker build context contains %q = %t, want %t", tc.name, got, tc.include)
			}
		})
	}
}
