package respond

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBlockIPTemplatesAndGuards(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 512)
		n, _ := r.Body.Read(b)
		got = r.Method + " " + r.URL.Path + " " + r.Header.Get("Authorization") + " " + string(b[:n])
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	r := New(Config{HTTP: []HTTPAction{{Name: "ngfw.test", Method: "POST", URL: srv.URL + "/block",
		Headers: map[string]string{"Authorization": "Bearer tok"}, Body: `{"ip":"${ip}","comment":"ARGUS ${incident}"}`}}})
	res, err := r.BlockIP(context.Background(), "203.0.113.9", "INC-1", "brute force")
	if err != nil || len(res) != 1 || !res[0].OK {
		t.Fatalf("%v %+v", err, res)
	}
	if !strings.Contains(got, `"ip":"203.0.113.9"`) || !strings.Contains(got, "Bearer tok") || !strings.Contains(got, "INC-1") {
		t.Fatalf("шаблон не подставлен: %s", got)
	}
	if _, err := r.BlockIP(context.Background(), "10.0.0.5", "INC-1", ""); err == nil {
		t.Fatal("приватный адрес блокировать нельзя")
	}
	if _, err := New(Config{}).BlockIP(context.Background(), "203.0.113.9", "INC-1", ""); err == nil {
		t.Fatal("без исполнителей — ошибка, а не тихий успех")
	}
}
