package respond

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConcurrentAutoBlocksCallExecutorOnce(t *testing.T) {
	var calls, applied atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond)
	}))
	defer srv.Close()
	r := New(cfg(srv, ModeIPS))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, ok, err := r.Auto(context.Background(), "192.0.2.80", "INC-1", "rule", time.Hour)
			if err != nil {
				t.Error(err)
			}
			if ok {
				applied.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if calls.Load() != 1 || applied.Load() != 1 {
		t.Fatalf("executor calls=%d applied=%d, want one", calls.Load(), applied.Load())
	}
}

func TestEquivalentIPAddressesShareBlockState(t *testing.T) {
	for _, aliases := range [][2]string{
		{"192.0.2.80", "::ffff:192.0.2.80"},
		{"2001:4860:4860::8888", "2001:4860:4860:0:0:0:0:8888"},
	} {
		t.Run(aliases[0], func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { calls.Add(1) }))
			defer srv.Close()
			r := New(cfg(srv, ModeIPS))
			for i, ip := range aliases {
				_, applied, err := r.Auto(context.Background(), ip, "INC-1", "rule", time.Hour)
				if err != nil || applied != (i == 0) {
					t.Fatalf("%s: applied=%v err=%v", ip, applied, err)
				}
			}
			if calls.Load() != 1 || len(r.Active()) != 1 {
				t.Fatal("equivalent addresses caused duplicate blocks")
			}
			if _, err := r.Unblock(context.Background(), aliases[1], "operator"); err != nil {
				t.Fatal(err)
			}
			if len(r.Active()) != 0 {
				t.Fatal("unblock using equivalent address left an active block")
			}
		})
	}
}

func TestExpirationCompletesBeforeManualBlock(t *testing.T) {
	unblocking := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	var mu sync.Mutex
	var completed []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/unblock" {
			close(unblocking)
			<-release
		}
		mu.Lock()
		completed = append(completed, req.URL.Path)
		mu.Unlock()
	}))
	defer srv.Close()
	defer unblock()
	r := New(cfg(srv, ModeIPS))
	now := time.Now()
	r.nowFn = func() time.Time { return now }
	if _, _, err := r.Auto(context.Background(), "192.0.2.80", "INC-1", "rule", time.Minute); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	expired := make(chan struct{})
	go func() { r.Expire(context.Background()); close(expired) }()
	<-unblocking
	manual := make(chan error, 1)
	go func() { _, err := r.BlockIP(context.Background(), "192.0.2.80", "INC-2", "operator"); manual <- err }()
	select {
	case err := <-manual:
		t.Fatalf("manual block overtook pending expiration: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	<-expired
	if err := <-manual; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(completed) != 3 || completed[1] != "/unblock" || completed[2] != "/block" {
		t.Fatalf("external operation order: %v", completed)
	}
	active := r.Active()
	if len(active) != 1 || !active[0].Manual || active[0].Incident != "INC-2" {
		t.Fatalf("manual block lost: %+v", active)
	}
}
