package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const testToken = "0123456789abcdef0123456789abcdef" // 32 символа

func newGuarded(t *testing.T, lim *limiter, origins ...string) (http.Handler, *int) {
	t.Helper()
	calls := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	})
	return guard(next, []bearer{{token: testToken}}, origins, lim), &calls
}

func do(h http.Handler, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.RemoteAddr = "10.0.0.7:41234"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestGuardOriginForbidden(t *testing.T) {
	h, calls := newGuarded(t, nil, "https://allowed.example")
	rec := do(h, map[string]string{"Origin": "https://evil.example", "Authorization": "Bearer " + testToken})
	if rec.Code != http.StatusForbidden || *calls != 0 {
		t.Fatalf("want 403 and no call, got %d calls=%d", rec.Code, *calls)
	}
}

func TestGuardOriginAllowed(t *testing.T) {
	h, calls := newGuarded(t, nil, " https://allowed.example ", "")
	rec := do(h, map[string]string{"Origin": "https://allowed.example", "Authorization": "Bearer " + testToken})
	if rec.Code != http.StatusOK || *calls != 1 {
		t.Fatalf("want 200 and one call, got %d calls=%d", rec.Code, *calls)
	}
}

func TestGuardBearerMissing(t *testing.T) {
	h, calls := newGuarded(t, nil)
	rec := do(h, nil)
	if rec.Code != http.StatusUnauthorized || *calls != 0 {
		t.Fatalf("want 401, got %d calls=%d", rec.Code, *calls)
	}
	if !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("WWW-Authenticate missing: %q", rec.Header().Get("WWW-Authenticate"))
	}
}

func TestGuardBearerInvalid(t *testing.T) {
	h, calls := newGuarded(t, nil)
	rec := do(h, map[string]string{"Authorization": "Bearer " + strings.Repeat("x", 32)})
	if rec.Code != http.StatusUnauthorized || *calls != 0 {
		t.Fatalf("want 401, got %d calls=%d", rec.Code, *calls)
	}
}

func TestGuardBearerValid(t *testing.T) {
	h, calls := newGuarded(t, nil)
	rec := do(h, map[string]string{"Authorization": "Bearer " + testToken})
	if rec.Code != http.StatusOK || *calls != 1 {
		t.Fatalf("want 200 and one call, got %d calls=%d", rec.Code, *calls)
	}
}

func TestGuardRateLimitPerToken(t *testing.T) {
	const limit = 5
	lim := newLimiter(limit, time.Minute)
	h, calls := newGuarded(t, lim)
	hdr := map[string]string{"Authorization": "Bearer " + testToken}
	for i := 1; i <= limit; i++ {
		if rec := do(h, hdr); rec.Code != http.StatusOK {
			t.Fatalf("request %d: want 200, got %d", i, rec.Code)
		}
	}
	rec := do(h, hdr)
	if rec.Code != http.StatusTooManyRequests || *calls != limit {
		t.Fatalf("request %d: want 429, got %d calls=%d", limit+1, rec.Code, *calls)
	}
	if rec.Header().Get("Retry-After") != "60" {
		t.Fatalf("Retry-After: %q", rec.Header().Get("Retry-After"))
	}
	// Другой IP с тем же токеном — то же окно: ключ не IP.
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.RemoteAddr = "10.0.0.8:5"
	req.Header.Set("Authorization", "Bearer "+testToken)
	other := httptest.NewRecorder()
	h.ServeHTTP(other, req)
	if other.Code != http.StatusTooManyRequests {
		t.Fatalf("same token from other ip: want 429, got %d", other.Code)
	}
	// Своя сессия — своё окно.
	rec = do(h, map[string]string{"Authorization": "Bearer " + testToken, "Mcp-Session-Id": "s-1"})
	if rec.Code != http.StatusOK {
		t.Fatalf("separate session: want 200, got %d", rec.Code)
	}
}

func TestGuardRateLimitAfterAuth(t *testing.T) {
	lim := newLimiter(1, time.Minute)
	h, calls := newGuarded(t, lim)
	// Неверные токены — 401, а не 429, и окно легитимного клиента не трогают.
	for i := 0; i < 3; i++ {
		if rec := do(h, map[string]string{"Authorization": "Bearer " + strings.Repeat("x", 32)}); rec.Code != http.StatusUnauthorized {
			t.Fatalf("bad token %d: want 401, got %d", i, rec.Code)
		}
	}
	if rec := do(h, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: want 401, got %d", rec.Code)
	}
	if len(lim.seen) != 0 {
		t.Fatalf("unauthenticated requests must not populate the limiter: %d keys", len(lim.seen))
	}
	if rec := do(h, map[string]string{"Authorization": "Bearer " + testToken}); rec.Code != http.StatusOK || *calls != 1 {
		t.Fatalf("valid token: want 200, got %d calls=%d", rec.Code, *calls)
	}
}

func TestClientKey(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	k1 := clientKey(req, "tok-a")
	if !strings.HasPrefix(k1, "tok:") || strings.Contains(k1, "tok-a") {
		t.Fatalf("token key must be a hash, got %q", k1)
	}
	if clientKey(req, "tok-a") != k1 || clientKey(req, "tok-b") == k1 {
		t.Fatal("token key must be stable per token and differ between tokens")
	}
	req.Header.Set("Mcp-Session-Id", " s-42 ")
	if got := clientKey(req, "tok-a"); got != "sid:s-42" {
		t.Fatalf("session id must take precedence, got %q", got)
	}
}

func TestRatePerMinute(t *testing.T) {
	cases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"", defaultRatePerMinute, false},
		{" 120 ", 120, false},
		{"0", 0, true},
		{"-5", 0, true},
		{"many", 0, true},
	}
	for _, c := range cases {
		got, err := ratePerMinute(c.in)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("ratePerMinute(%q) = %d, %v; want %d, err=%v", c.in, got, err, c.want, c.wantErr)
		}
	}
}

func TestLimiterWindowResets(t *testing.T) {
	lim := newLimiter(2, time.Minute)
	now := time.Unix(1_000_000, 0)
	if !lim.allow("a", now) || !lim.allow("a", now) {
		t.Fatal("first two must pass")
	}
	if lim.allow("a", now.Add(30*time.Second)) {
		t.Fatal("third in window must be rejected")
	}
	if !lim.allow("a", now.Add(time.Minute)) {
		t.Fatal("new window must pass")
	}
}

func TestLimiterEvictsStaleKeys(t *testing.T) {
	lim := newLimiter(1, time.Minute)
	now := time.Unix(1_000_000, 0)
	for i := 0; i <= limiterMaxKeys; i++ {
		lim.allow(fmt.Sprintf("ip-%d", i), now)
	}
	if len(lim.seen) != limiterMaxKeys+1 {
		t.Fatalf("seen=%d", len(lim.seen))
	}
	lim.allow("fresh", now.Add(2*time.Minute))
	if len(lim.seen) != 1 {
		t.Fatalf("stale keys must be evicted, seen=%d", len(lim.seen))
	}
}

func TestValidateHTTPToken(t *testing.T) {
	api := strings.Repeat("a", 40)
	cases := []struct {
		name, tok string
		wantErr   bool
	}{
		{"empty", "", true},
		{"short", "abc", true},
		{"same as api", api, true},
		{"ok", strings.Repeat("b", 32), false},
	}
	for _, c := range cases {
		err := validateHTTPToken(c.tok, api)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v wantErr=%v", c.name, err, c.wantErr)
		}
	}
}

func TestStripRaw(t *testing.T) {
	in := []byte(`{"rows":[{"time":"t","raw":"{\"x\":1}","full_log":"boom","nested":{"raw":"y","keep":1}}],"total":1,"facets":[{"raw":"z"}]}`)
	out, err := stripRaw(in)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), `"raw"`) || strings.Contains(string(out), `"full_log"`) {
		t.Fatalf("raw/full_log survived: %s", out)
	}
	rows := v["rows"].([]any)
	row := rows[0].(map[string]any)
	if row["time"] != "t" || row["nested"].(map[string]any)["keep"] != float64(1) || v["total"] != float64(1) {
		t.Fatalf("other fields lost: %s", out)
	}
}

func TestStripRawKeepsBigIntegers(t *testing.T) {
	// uint64 > 2^53 и дробное с точностью: через float64 они бы исказились.
	in := []byte(`{"id":18446744073709551615,"flow":9007199254740993,"score":0.1000000000000000055511151231257827,"raw":"x"}`)
	out, err := stripRaw(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, lit := range []string{`"id":18446744073709551615`, `"flow":9007199254740993`, `"score":0.1000000000000000055511151231257827`} {
		if !strings.Contains(string(out), lit) {
			t.Fatalf("number precision lost: want %s in %s", lit, out)
		}
	}
	if strings.Contains(string(out), `"raw"`) {
		t.Fatalf("raw survived: %s", out)
	}
}

func TestStripRawRejectsInvalidJSON(t *testing.T) {
	for _, in := range []string{`not json`, `{"raw":"secret"`, `{"a":1} {"raw":"secret"}`, `{"a":1} trailing`} {
		out, err := stripRaw([]byte(in))
		if err == nil {
			t.Fatalf("%q: want error, got %s", in, out)
		}
		if out != nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("%q: raw body must not leak: out=%q err=%v", in, out, err)
		}
	}
	res, _, err := toolError(errors.New("boom"))
	if err != nil || !res.IsError {
		t.Fatalf("toolError must set isError: %+v %v", res, err)
	}
	if tc := res.Content[0].(*mcp.TextContent); tc.Text != "boom" {
		t.Fatalf("toolError text: %q", tc.Text)
	}
}

func TestRawResultHasNotice(t *testing.T) {
	res, _, err := rawResult(json.RawMessage(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content type %T", res.Content[0])
	}
	if !strings.HasPrefix(tc.Text, untrustedNotice+"\n\n") || !strings.HasSuffix(tc.Text, `{"a":1}`) {
		t.Fatalf("notice missing: %q", tc.Text)
	}
}
