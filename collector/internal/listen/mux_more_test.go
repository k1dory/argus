package listen

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/model"
)

const (
	k8sAuditBody = `{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[
	 {"level":"RequestResponse","auditID":"a1","stage":"ResponseComplete","requestURI":"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings","verb":"create",
	  "user":{"username":"oidc:i.petrov","groups":["dev"]},"sourceIPs":["10.0.5.5"],"userAgent":"kubectl/v1.30",
	  "objectRef":{"resource":"clusterrolebindings","name":"argo-admin","apiGroup":"rbac.authorization.k8s.io"},
	  "responseStatus":{"code":201},"stageTimestamp":"2026-09-05T04:38:07.120000Z"}]}`
	harborBody = `{"type":"DELETE_ARTIFACT","occur_at":1757066138,"operator":"i.petrov","event_data":{"resources":[{"digest":"sha256:abc","tag":"1.4.0","resource_url":"harbor.corp/sec/argus:1.4.0"}],"repository":{"name":"argus","namespace":"sec","repo_full_name":"sec/argus","repo_type":"private"}}}`
	argoBody   = `{"app":{"metadata":{"name":"payments","namespace":"argocd"},"spec":{"project":"prod","source":{"repoURL":"git@git:apps.git","path":"payments"}},"status":{"sync":{"status":"OutOfSync","revision":"deadbeef"},"health":{"status":"Degraded"}}},"action":"OnSyncFailed","user":"i.petrov","timestamp":"2026-09-05T04:38:07Z"}`
	gitlabBody = `{"id":1,"author_name":"i.petrov","entity_path":"sec/argus-rules","entity_type":"Project","event_type":"project_access_token_created","ip_address":"10.0.5.5","created_at":"2026-09-05T04:01:38Z","details":{"author_name":"i.petrov","custom_message":"Created project access token"}}`
)

// Вебхуки: валидное тело → 202 и событие нужного источника, мусор → 400,
// параметр cluster у k8s-audit перекрывает конфиг.
func TestWebhookRoutesParseAndReject(t *testing.T) {
	h, events, _ := newTestHandlers("")
	h.K8sCluster = "prod"
	srv := httptest.NewServer(h.Mux())
	defer srv.Close()

	for _, tc := range []struct {
		path, body, wantSource string
	}{
		{"/ingest/k8s-audit", k8sAuditBody, "k8s.audit"},
		{"/ingest/harbor", harborBody, "harbor.audit"},
		{"/ingest/argocd", argoBody, "argocd.audit"},
		{"/ingest/gitlab", gitlabBody, "gitlab.audit"},
	} {
		n := len(*events)
		code, resp := do(t, srv, "POST", tc.path, "", tc.body)
		if code != 202 || !strings.Contains(resp, `"accepted":1`) || len(*events) != n+1 {
			t.Errorf("%s: %d %q events=%d", tc.path, code, resp, len(*events)-n)
			continue
		}
		if got := (*events)[n].Source; got != tc.wantSource {
			t.Errorf("%s: source %q, want %q", tc.path, got, tc.wantSource)
		}
		if code, _ := do(t, srv, "POST", tc.path, "", `{"hello":"world"}`); code != 400 {
			t.Errorf("%s: мусор должен дать 400, got %d", tc.path, code)
		}
	}
	// k8s: кластер из конфига и из параметра
	k8s := func(q string) model.Event {
		n := len(*events)
		if code, _ := do(t, srv, "POST", "/ingest/k8s-audit"+q, "", k8sAuditBody); code != 202 {
			t.Fatalf("k8s-audit%s: %d", q, code)
		}
		return (*events)[n]
	}
	if e := k8s(""); e.Node != "prod" {
		t.Errorf("кластер из конфига: %q", e.Node)
	}
	if e := k8s("?cluster=lab"); e.Node != "lab" {
		t.Errorf("кластер из параметра: %q", e.Node)
	}
	if code, _ := do(t, srv, "POST", "/ingest/k8s-audit", "", "not json"); code != 400 {
		t.Errorf("k8s-audit мусор: %d", code)
	}
	if code, _ := do(t, srv, "GET", "/ingest/harbor", "", ""); code != 405 {
		t.Errorf("GET на вебхук: %d", code)
	}
}

// /ingest/syslog с ParseLine: строки разбираются в события, неразобранные
// пропускаются, accepted — число событий; peer передаётся парсеру.
func TestIngestSyslogWithParseLine(t *testing.T) {
	h, events, _ := newTestHandlers("")
	var peers []Peer
	h.ParseLine = func(line string, p Peer) (model.Event, bool) {
		peers = append(peers, p)
		if strings.Contains(line, "skip") {
			return model.Event{}, false
		}
		return model.Event{Source: "parsed", Object: line}, true
	}
	srv := httptest.NewServer(h.Mux())
	defer srv.Close()
	code, resp := do(t, srv, "POST", "/ingest/syslog", "", "one\nskip me\n  two  \n\n")
	if code != 202 || !strings.Contains(resp, `"accepted":2`) {
		t.Fatalf("%d %q", code, resp)
	}
	if len(*events) != 2 || (*events)[1].Object != "two" || len(peers) != 3 || peers[0].Transport != "http" {
		t.Errorf("events=%+v peers=%+v", *events, peers)
	}
}

// /ingest/modsecurity: NDJSON и массив транзакций, счётчик принятых по
// результату WAFAudit; с ParseWAFAudit — события через acceptEvents; обрыв JSON → 400.
func TestIngestModSecurityShapes(t *testing.T) {
	h, events, _ := newTestHandlers("")
	h.WAFAudit = func(raw json.RawMessage) bool { return strings.Contains(string(raw), `"ok"`) }
	srv := httptest.NewServer(h.Mux())
	defer srv.Close()

	code, resp := do(t, srv, "POST", "/ingest/modsecurity", "", `{"transaction":"ok"}`+"\n"+`{"transaction":"nope"}`+"\n")
	if code != 202 || !strings.Contains(resp, `"accepted":1`) {
		t.Errorf("NDJSON: %d %q", code, resp)
	}
	code, resp = do(t, srv, "POST", "/ingest/modsecurity", "", `[{"transaction":"ok"},{"transaction":"ok"}]`)
	if code != 202 || !strings.Contains(resp, `"accepted":2`) {
		t.Errorf("массив: %d %q", code, resp)
	}
	code, resp = do(t, srv, "POST", "/ingest/modsecurity", "", `{"transaction":`)
	if code != 400 || !strings.Contains(resp, "modsecurity") {
		t.Errorf("обрыв JSON: %d %q", code, resp)
	}
	if code, _ := do(t, srv, "POST", "/ingest/modsecurity", "", `[{"a":1},`); code != 400 {
		t.Errorf("обрыв массива: %d", code)
	}
	var auditPeers []Peer
	h.ParseWAFAudit = func(raw json.RawMessage, peer Peer) (model.Event, bool) {
		auditPeers = append(auditPeers, peer)
		if strings.Contains(string(raw), "drop") {
			return model.Event{}, false
		}
		return model.Event{Source: "waf.audit", Raw: string(raw)}, true
	}
	n := len(*events)
	code, resp = do(t, srv, "POST", "/ingest/modsecurity", "", `[{"t":"a"},{"t":"drop"}]`+"\n"+`{"t":"c"}`)
	if code != 202 || !strings.Contains(resp, `"accepted":2`) || len(*events) != n+2 {
		t.Errorf("ParseWAFAudit: %d %q events=%d", code, resp, len(*events)-n)
	}
	if len(auditPeers) != 3 {
		t.Fatalf("ParseWAFAudit called %d times, want 3", len(auditPeers))
	}
	for _, peer := range auditPeers {
		if peer.Transport != "http" || peer.Addr != "127.0.0.1" || peer.CN != "" {
			t.Errorf("ParseWAFAudit lost the HTTP sender identity: %+v", peer)
		}
	}
}

func TestIngestEventsRejectsBrokenJSON(t *testing.T) {
	h, events, _ := newTestHandlers("")
	srv := httptest.NewServer(h.Mux())
	defer srv.Close()
	code, resp := do(t, srv, "POST", "/ingest/events", "", `{"source":"a"}`+"\n"+`{"source":`)
	if code != 400 || !strings.Contains(resp, "events") || len(*events) != 0 {
		t.Errorf("обрыв NDJSON: %d %q events=%d", code, resp, len(*events))
	}
	// пустое тело — 202 с нулём принятых, Emit не вызван
	code, resp = do(t, srv, "POST", "/ingest/events", "", "")
	if code != 202 || !strings.Contains(resp, `"accepted":0`) {
		t.Errorf("пустое тело: %d %q", code, resp)
	}
}
