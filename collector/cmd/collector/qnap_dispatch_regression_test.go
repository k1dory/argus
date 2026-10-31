package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// Run the real main in a child test process: on this branch the dispatcher is
// local to main and must not be copied into a test. All listeners except HTTP
// are disabled; HTTP and the fake ClickHouse sink use isolated loopback only.
func TestQNAPProductionDispatcherHelper(t *testing.T) {
	if os.Getenv("ARGUS_QNAP_DISPATCH_CHILD") != "1" {
		return
	}
	os.Args = []string{"collector"}
	main()
}

func TestQNAPProductionDispatcherPreservesFormatMarkersInFilenames(t *testing.T) {
	stored := make(chan model.Event, 16)
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Query().Get("query"), "INSERT INTO argus.events ") {
			http.Error(w, "unexpected query", http.StatusBadRequest)
			return
		}
		dec := json.NewDecoder(r.Body)
		for {
			var e model.Event
			if err := dec.Decode(&e); err == io.EOF {
				break
			} else if err != nil {
				t.Errorf("collector emitted invalid event JSON: %v", err)
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}
			stored <- e
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ch.Close)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "collector.yml")
	const token = "qnap-dispatch-regression-token"
	yml := fmt.Sprintf("listeners:\n  syslog:\n    udp: ''\n    tcp: ''\n    tls:\n      addr: ''\n  netflow:\n    udp: ''\n  http:\n    addr: %q\n    token: %q\nbatch:\n  size: 1\n  flush_ms: 10\n", addr, token)
	if err := os.WriteFile(config, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestQNAPProductionDispatcherHelper$", "-test.timeout=15s")
	cmd.Env = []string{
		"ARGUS_QNAP_DISPATCH_CHILD=1", "COLLECTOR_CONFIG=" + config,
		"CLICKHOUSE_URL=" + ch.URL, "CLICKHOUSE_DB=argus", "CLICKHOUSE_USER=default",
		"SINK_SPOOL_DIR=" + filepath.Join(dir, "spool"), "SINK_SPOOL_BYTES=1048576",
		"SINK_PENDING_ROWS=64", "SINK_PENDING_BYTES=1048576", "GOMAXPROCS=2",
		"HOME=" + dir, "TMPDIR=" + dir, "TZ=UTC",
	}
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(2 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
		if t.Failed() {
			t.Logf("collector process output:\n%s", logs.String())
		}
	})
	client := &http.Client{Timeout: time.Second}
	url := "http://" + addr
	ready := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		resp, err := client.Get(url + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("collector's production HTTP listener did not become ready")
	}
	for _, resource := range []string{
		"Public/report.txt",
		"Public/ModSecurity: Warning. report.txt",
		"Public/Coraza: Warning. report.txt",
		"Public/CEF:report.txt",
		"Public/LEEF:report.txt",
	} {
		t.Run(resource, func(t *testing.T) {
			line := fmt.Sprintf("<30>%s QNAP-2 qulogd[1]: conn log: Users: i.petrov, Source IP: 192.0.2.10, Computer name: client, Connection type: FTP, Accessed resources: %s, Action: Delete", time.Now().UTC().Format("Jan _2 15:04:05"), resource)
			req, err := http.NewRequest(http.MethodPost, url+"/ingest/syslog", strings.NewReader(line))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Argus-Token", token)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var ack struct {
				Accepted int `json:"accepted"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusAccepted || ack.Accepted != 1 {
				t.Fatalf("filename marker swallowed a QNAP deletion: status=%d accepted=%d resource=%q", resp.StatusCode, ack.Accepted, resource)
			}
			select {
			case e := <-stored:
				if e.Source != "nas.qnap" || e.Action != "file.delete" || e.Object != resource || e.ActorName != "i.petrov" || e.Node != "QNAP-2" {
					t.Fatalf("filename marker changed the parser instead of staying file data: %+v", e)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("acknowledged QNAP event never reached the sink")
			}
		})
	}
}
