package listen

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func collect(t *testing.T, path string, fromStart bool) (func() []string, context.CancelFunc) {
	t.Helper()
	var mu sync.Mutex
	var got []string
	ctx, cancel := context.WithCancel(context.Background())
	tf := &TailFile{Path: path, FromStart: fromStart, Handle: func(l string) { mu.Lock(); got = append(got, l); mu.Unlock() }}
	go tf.Run(ctx)
	return func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), got...) }, cancel
}

func waitFor(t *testing.T, get func() []string, n int) []string {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if g := get(); len(g) >= n {
			return g
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("ждал %d строк, получил %v", n, get())
	return nil
}

func TestTailPartialLineTruncateAndRotate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	os.WriteFile(path, []byte("old-1\nold-2\n"), 0o644)
	get, cancel := collect(t, path, false)
	defer cancel()
	time.Sleep(1500 * time.Millisecond) // старт с конца — старое не читаем

	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString("new-1\npart")
	f.Close()
	got := waitFor(t, get, 1)
	if got[0] != "new-1" || len(got) != 1 {
		t.Fatalf("неполная строка не должна отдаваться: %v", got)
	}
	f, _ = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString("ial\n")
	f.Close()
	if got = waitFor(t, get, 2); got[1] != "partial" {
		t.Fatalf("неполная строка должна склеиваться: %v", got)
	}

	// усечение с быстрой дозаписью до прежнего размера
	os.WriteFile(path, []byte("c1-long-line-xxxxxxxxxx\n"), 0o644)
	if got = waitFor(t, get, 3); got[2] != "c1-long-line-xxxxxxxxxx" {
		t.Fatalf("после усечения строка должна читаться целиком: %v", got)
	}

	// ротация переименованием
	os.Rename(path, path+".1")
	os.WriteFile(path, []byte("after-rotate\n"), 0o644)
	if got = waitFor(t, get, 4); got[3] != "after-rotate" {
		t.Fatalf("после ротации: %v", got)
	}
}

func TestTailFromStartAndMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "later.log")
	get, cancel := collect(t, path, true)
	defer cancel()
	time.Sleep(1200 * time.Millisecond)
	os.WriteFile(path, []byte("a\nb\n"), 0o644)
	if got := waitFor(t, get, 2); got[0] != "a" || got[1] != "b" {
		t.Fatalf("появившийся позже файл читается с начала: %v", got)
	}
}
