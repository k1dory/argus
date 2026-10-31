package pull

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// resumeBucket — S3 с подменяемым ответом на GET: тело, статус или обрыв тела
// (Content-Length больше отданного — клиент получает unexpected EOF).
type resumeBucket struct {
	srv  *httptest.Server
	mu   sync.Mutex
	objs map[string][]byte
	gets map[string]int
	// serve — особое поведение для ключа по номеру попытки (1, 2, …); nil — отдать тело.
	serve func(key string, attempt int, w http.ResponseWriter) bool
}

func newResumeBucket(t *testing.T, objs map[string][]byte) *resumeBucket {
	b := &resumeBucket{objs: objs, gets: map[string]int{}}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("list-type") == "2" {
			after := r.URL.Query().Get("start-after")
			b.mu.Lock()
			var keys []string
			for k := range b.objs {
				if k > after {
					keys = append(keys, k)
				}
			}
			b.mu.Unlock()
			sort.Strings(keys)
			type c struct {
				Key  string `xml:"Key"`
				Size int64  `xml:"Size"`
			}
			out := struct {
				XMLName  xml.Name `xml:"ListBucketResult"`
				Contents []c      `xml:"Contents"`
			}{}
			for _, k := range keys {
				out.Contents = append(out.Contents, c{Key: k, Size: int64(len(b.objs[k]))})
			}
			_ = xml.NewEncoder(w).Encode(out)
			return
		}
		key := strings.TrimPrefix(r.URL.Path, "/bkt/")
		b.mu.Lock()
		b.gets[key]++
		attempt, body := b.gets[key], b.objs[key]
		b.mu.Unlock()
		if b.serve != nil && b.serve(key, attempt, w) {
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *resumeBucket) attempts(key string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.gets[key]
}

// run крутит Run до срока и возвращает действия выданных событий по порядку и файл состояния.
func (b *resumeBucket) run(t *testing.T, d time.Duration) (*S3, []string, string) {
	t.Helper()
	state := filepath.Join(t.TempDir(), "s3.state")
	var mu sync.Mutex
	var got []string
	s := NewS3(S3Config{Name: "bkt", Endpoint: b.srv.URL, Bucket: "bkt", AccessKey: "AK", SecretKey: "SK", Interval: "1ms", StateFile: state},
		func(e model.Event) { mu.Lock(); got = append(got, e.Action); mu.Unlock() })
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	s.Run(ctx)
	mu.Lock()
	defer mu.Unlock()
	st, _ := os.ReadFile(state)
	return s, append([]string{}, got...), strings.TrimSpace(string(st))
}

func ndjson(prefix string, n int) []byte {
	var b strings.Builder
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, `{"source":"s3.t","action":"%s%d"}`+"\n", prefix, i)
	}
	return []byte(b.String())
}

func gz(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func countDup(actions []string) (map[string]int, []string) {
	seen := map[string]int{}
	var dups []string
	for _, a := range actions {
		seen[a]++
		if seen[a] == 2 {
			dups = append(dups, a)
		}
	}
	return seen, dups
}

// Битое содержимое gzip (CRC, мусор после последнего члена) — повтор не поможет:
// объект дочитывается один раз, события не дублируются, курсор идёт к следующему.
func TestS3CorruptGzipIsSkippedOnceAndBucketContinues(t *testing.T) {
	good := gz(t, ndjson("a", 50))
	badCRC := append([]byte{}, good...)
	badCRC[len(badCRC)-8] ^= 0xff // CRC32 в трейлере
	padded := append(append([]byte{}, good...), make([]byte, 64)...)
	for _, tc := range []struct {
		name string
		body []byte
	}{{"CRC", badCRC}, {"нули после члена", padded}} {
		t.Run(tc.name, func(t *testing.T) {
			b := newResumeBucket(t, map[string][]byte{"1.json.gz": tc.body, "2.json": ndjson("b", 3)})
			s, got, state := b.run(t, 300*time.Millisecond)
			seen, dups := countDup(got)
			if len(dups) > 0 {
				t.Fatalf("события выданы повторно: %v", dups)
			}
			if seen["b1"] != 1 || seen["b3"] != 1 {
				t.Fatalf("следующий объект не прочитан: %v", got)
			}
			if state != "2.json" {
				t.Fatalf("курсор: %q", state)
			}
			if b.attempts("1.json.gz") != 1 {
				t.Fatalf("битое содержимое читается один раз, попыток %d", b.attempts("1.json.gz"))
			}
			if tc.name == "нули после члена" && seen["a50"] != 1 {
				t.Fatalf("все строки члена выданы: %d из 50", len(seen)-3)
			}
			if s.Skipped.Load() != 1 {
				t.Fatalf("Skipped=%d", s.Skipped.Load())
			}
		})
	}
}

// Обрезанный gzip (тело кончается посреди потока) неотличим от обрыва сети: до
// s3MaxAttempts попыток, каждая пропускает уже выданные строки, затем объект брошен.
func TestS3TruncatedGzipBoundedRetriesWithoutDuplicates(t *testing.T) {
	full := gz(t, ndjson("a", 2000))
	b := newResumeBucket(t, map[string][]byte{"1.json.gz": full[:len(full)/2], "2.json": ndjson("b", 2)})
	s, got, state := b.run(t, 500*time.Millisecond)
	seen, dups := countDup(got)
	if len(dups) > 0 {
		t.Fatalf("повтор выдал события ещё раз: %d дублей, напр. %v", len(dups), dups[:min(3, len(dups))])
	}
	if seen["a1"] != 1 || seen["b2"] != 1 {
		t.Fatalf("начало обрезанного и следующий объект: a1=%d b2=%d", seen["a1"], seen["b2"])
	}
	if n := b.attempts("1.json.gz"); n != s3MaxAttempts {
		t.Fatalf("попыток %d, ожидалось %d", n, s3MaxAttempts)
	}
	if state != "2.json" || s.Skipped.Load() != 1 {
		t.Fatalf("курсор %q, Skipped %d", state, s.Skipped.Load())
	}
}

// Обрыв сети посреди тела: следующая попытка дочитывает объект с места обрыва.
func TestS3BodyCutResumesFromLastEmittedLine(t *testing.T) {
	body := ndjson("a", 5)
	b := newResumeBucket(t, map[string][]byte{"1.json": body, "2.json": ndjson("b", 1)})
	first := bytes.Index(body, []byte("\n")) + 1
	b.serve = func(key string, attempt int, w http.ResponseWriter) bool {
		if key != "1.json" || attempt != 1 {
			return false
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = w.Write(body[:first+10]) // одна строка целиком и обрывок второй
		return true
	}
	s, got, state := b.run(t, 300*time.Millisecond)
	if strings.Join(got, ",") != "a1,a2,a3,a4,a5,b1" {
		t.Fatalf("каждое событие ровно один раз и по порядку: %v", got)
	}
	if b.attempts("1.json") != 2 || state != "2.json" || s.Skipped.Load() != 0 {
		t.Fatalf("попыток %d, курсор %q, Skipped %d", b.attempts("1.json"), state, s.Skipped.Load())
	}
}

// Сжатый ответ сначала оборвался после выданных строк и посреди следующей JSON-
// строки, но повтор вернул весь объект. Смещение считается по непустым входным
// строкам, включая невалидный JSON, а не по количеству успешно выданных событий.
func TestS3GzipRetryRecoversCompleteObjectWithoutReplayingPrefix(t *testing.T) {
	prefix := append(ndjson("a", 2), []byte("\nnot-json\n")...)
	suffix := ndjson("b", 2)
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(append(prefix, suffix[:10]...)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Flush(); err != nil {
		t.Fatal(err)
	}
	cut := compressed.Len()
	if _, err := zw.Write(suffix[10:]); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	body := compressed.Bytes()
	b := newResumeBucket(t, map[string][]byte{"1.json.gz": body, "2.json": ndjson("c", 1)})
	b.serve = func(key string, attempt int, w http.ResponseWriter) bool {
		if key != "1.json.gz" || attempt != 1 {
			return false
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = w.Write(body[:cut])
		return true
	}
	s, got, state := b.run(t, 500*time.Millisecond)
	if strings.Join(got, ",") != "a1,a2,b1,b2,c1" {
		t.Fatalf("принятый префикс не дублируется, хвост не теряется: %v", got)
	}
	if b.attempts("1.json.gz") != 2 || b.attempts("2.json") != 1 {
		t.Fatalf("попыток gzip=%d, следующий объект=%d", b.attempts("1.json.gz"), b.attempts("2.json"))
	}
	if state != "2.json" || s.Skipped.Load() != 0 {
		t.Fatalf("успешно дочитанный объект не считается пропущенным: курсор %q, Skipped %d", state, s.Skipped.Load())
	}
}

// Отказ хранилища на GET (нет прав) — не порча объекта: повтор без предела, объект
// не бросается и дальше по бакету чтение не идёт. 404 (удалён после листинга) — пропуск.
func TestS3AccessErrorNeverSkipsButNotFoundDoes(t *testing.T) {
	b := newResumeBucket(t, map[string][]byte{"1.json": ndjson("a", 1), "2.json": ndjson("b", 1), "3.json": ndjson("c", 1)})
	b.serve = func(key string, _ int, w http.ResponseWriter) bool {
		switch key {
		case "1.json":
			w.WriteHeader(http.StatusNotFound)
			return true
		case "2.json":
			w.WriteHeader(http.StatusForbidden)
			return true
		}
		return false
	}
	s, got, state := b.run(t, 200*time.Millisecond)
	if len(got) != 0 {
		t.Fatalf("за объектом без доступа ничего не читается: %v", got)
	}
	if state != "1.json" {
		t.Fatalf("404 пропущен, курсор стоит перед объектом без доступа: %q", state)
	}
	if b.attempts("2.json") <= s3MaxAttempts || b.attempts("3.json") != 0 || s.Skipped.Load() != 1 {
		t.Fatalf("попыток 2.json %d, 3.json %d, Skipped %d", b.attempts("2.json"), b.attempts("3.json"), s.Skipped.Load())
	}
}
