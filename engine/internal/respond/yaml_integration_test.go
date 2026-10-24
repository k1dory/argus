package respond_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/devitex-soft/argus/engine/internal/analyst"
	"github.com/devitex-soft/argus/engine/internal/respond"
)

// Интеграция с argus.analyst.yml: шаблон NGFW из настоящего конфига после
// подстановки окружения доходит до httpCall с живыми ${ip}/${incident}/${reason},
// и в теле запроса уходит адрес, а не пустота.
func TestHTTPCallWithTemplateFromYAML(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, r.URL.Path+" "+r.Header.Get("Authorization")+" "+string(b))
		mu.Unlock()
	}))
	defer srv.Close()
	raw, err := os.ReadFile(filepath.Join("..", "..", "argus.analyst.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"ip", "incident", "reason"} {
		os.Unsetenv(k)
	}
	t.Setenv("NGFW_BLOCK_URL", srv.URL+"/block")
	t.Setenv("NGFW_UNBLOCK_URL", srv.URL+"/unblock")
	t.Setenv("NGFW_TOKEN", "tok")
	t.Setenv("ARGUS_RESPOND_MODE", "ips")
	var doc struct {
		Respond respond.Config `yaml:"respond"`
	}
	if err := yaml.Unmarshal([]byte(analyst.ExpandEnv(string(raw))), &doc); err != nil {
		t.Fatal(err)
	}
	r := respond.New(doc.Respond)
	if m, _ := r.Mode(); m != respond.ModeIPS {
		t.Fatalf("режим из yml: %s, config_errors=%v", m, r.ConfigErrors())
	}
	res, applied, err := r.Auto(context.Background(), "203.0.113.77", "INC-42", "WAF RCE (t-waf)", time.Minute)
	if err != nil || !applied {
		t.Fatalf("%v %+v", err, res)
	}
	if _, err := r.Unblock(context.Background(), "203.0.113.77", "ложное"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("%v", bodies)
	}
	if !strings.Contains(bodies[0], `/block Bearer tok {"ip": "203.0.113.77", "comment": "ARGUS INC-42: WAF RCE (t-waf)"}`) {
		t.Fatalf("блокировка: %s", bodies[0])
	}
	if !strings.Contains(bodies[1], `/unblock Bearer tok {"ip": "203.0.113.77"}`) {
		t.Fatalf("снятие: %s", bodies[1])
	}
}
