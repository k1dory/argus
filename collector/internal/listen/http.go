package listen

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
	"github.com/devitex-soft/argus/collector/internal/parse"
)

// HTTPHandlers — вебхуки: k8s audit, GitLab, сырой CEF/syslog по HTTPS и
// нормализованные события (replay демо-данных, свои интеграции).
type HTTPHandlers struct {
	Token         string
	K8sCluster    string
	Emit          func(model.Event)
	EmitBatch     func(context.Context, []model.Event) error // подтверждает запрос после записи на диск
	Lines         LineHandler
	ParseLine     func(string, Peer) (model.Event, bool)
	WAFAudit      func(json.RawMessage) bool                      // транзакция ModSecurity/Coraza в JSON
	ParseWAFAudit func(json.RawMessage, Peer) (model.Event, bool) // peer — для узла по умолчанию
	Health        func() any
	Metrics       func(full bool) string // full — с именами источников (по токену)
}

func (h *HTTPHandlers) Mux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(h.Health())
	})
	mux.HandleFunc("POST /ingest/k8s-audit", h.auth(func(w http.ResponseWriter, r *http.Request) {
		body, ok := readIngestBody(w, r, 16<<20)
		if !ok {
			return
		}
		cluster := r.URL.Query().Get("cluster")
		if cluster == "" {
			cluster = h.K8sCluster
		}
		events, err := parse.ParseK8sAudit(body, cluster)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.acceptEvents(w, r, events)
	}))
	// /metrics без токена — только агрегаты; с верным X-Argus-Token — и по источникам.
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		if h.Metrics != nil {
			_, _ = w.Write([]byte(h.Metrics(h.tokenOK(r))))
		}
	})
	mux.HandleFunc("POST /ingest/harbor", h.auth(func(w http.ResponseWriter, r *http.Request) {
		body, ok := readIngestBody(w, r, 4<<20)
		if !ok {
			return
		}
		e, err := parse.ParseHarbor(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.acceptEvents(w, r, []model.Event{e})
	}))
	mux.HandleFunc("POST /ingest/argocd", h.auth(func(w http.ResponseWriter, r *http.Request) {
		body, ok := readIngestBody(w, r, 4<<20)
		if !ok {
			return
		}
		e, err := parse.ParseArgoCD(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.acceptEvents(w, r, []model.Event{e})
	}))
	mux.HandleFunc("POST /ingest/gitlab", h.auth(func(w http.ResponseWriter, r *http.Request) {
		body, ok := readIngestBody(w, r, 4<<20)
		if !ok {
			return
		}
		e, err := parse.ParseGitLab(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.acceptEvents(w, r, []model.Event{e})
	}))
	// Построчный syslog/CEF/LEEF по HTTPS — для вендоров без syslog-TLS.
	// Сначала читается весь батч, потом эмитится: 413 на N-й строке после
	// N-1 принятых заставил бы клиента повторить и продублировать их.
	mux.HandleFunc("POST /ingest/syslog", h.auth(func(w http.ResponseWriter, r *http.Request) {
		peer := Peer{Addr: remoteHost(r), Transport: "http"}
		var lines []string
		sc := bufio.NewScanner(http.MaxBytesReader(w, r.Body, 16<<20))
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" {
				lines = append(lines, line)
			}
		}
		if err := sc.Err(); err != nil {
			writeIngestReadError(w, "syslog", err)
			return
		}
		if h.ParseLine != nil {
			events := make([]model.Event, 0, len(lines))
			for _, line := range lines {
				if e, ok := h.ParseLine(line, peer); ok {
					events = append(events, e)
				}
			}
			h.acceptEvents(w, r, events)
		} else {
			for _, line := range lines {
				h.Lines(line, peer)
			}
			accepted(w, len(lines))
		}
	}))
	// Audit-лог ModSecurity / Coraza в JSON (SecAuditLogFormat JSON): объект на транзакцию, NDJSON или массив.
	mux.HandleFunc("POST /ingest/modsecurity", h.auth(func(w http.ResponseWriter, r *http.Request) {
		// Сначала разбираем весь батч, потом эмитим: иначе ошибка на N-м объекте
		// вернёт 400 после N-1 принятых, клиент повторит — дубли.
		var objs []json.RawMessage
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<20))
		for {
			var obj json.RawMessage
			if err := dec.Decode(&obj); err == io.EOF {
				break
			} else if err != nil {
				writeIngestReadError(w, "modsecurity", err)
				return
			}
			if len(obj) > 0 && obj[0] == '[' {
				var arr []json.RawMessage
				if err := json.Unmarshal(obj, &arr); err != nil {
					http.Error(w, "modsecurity: "+err.Error(), http.StatusBadRequest)
					return
				}
				objs = append(objs, arr...)
				continue
			}
			objs = append(objs, obj)
		}
		if h.ParseWAFAudit != nil {
			peer := Peer{Addr: remoteHost(r), Transport: "http"}
			events := make([]model.Event, 0, len(objs))
			for _, o := range objs {
				if e, ok := h.ParseWAFAudit(o, peer); ok {
					events = append(events, e)
				}
			}
			h.acceptEvents(w, r, events)
		} else {
			n := 0
			for _, o := range objs {
				if h.WAFAudit(o) {
					n++
				}
			}
			accepted(w, n)
		}
	}))
	// Уже нормализованные события NDJSON: replay фикстур, свои коллекторы.
	mux.HandleFunc("POST /ingest/events", h.auth(func(w http.ResponseWriter, r *http.Request) {
		var events []model.Event
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<20))
		for {
			var e model.Event
			if err := dec.Decode(&e); err == io.EOF {
				break
			} else if err != nil {
				writeIngestReadError(w, "events", err)
				return
			}
			e.Ensure()
			parse.SecretAttrs(&e) // CI-логи своих коллекторов: имя утёкшей переменной
			events = append(events, e)
		}
		h.acceptEvents(w, r, events)
	}))
	return recoverHandler(mux)
}

func readIngestBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		writeIngestReadError(w, "ingest", err)
		return nil, false
	}
	return body, true
}

func writeIngestReadError(w http.ResponseWriter, source string, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) || errors.Is(err, bufio.ErrTooLong) {
		Metrics.Oversize.Add(1)
		http.Error(w, source+": запрос слишком велик", http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, source+": "+err.Error(), http.StatusBadRequest)
}

func (h *HTTPHandlers) acceptEvents(w http.ResponseWriter, r *http.Request, events []model.Event) {
	// Происхождение ставит только коллектор, как у syslog: peer — адрес соединения,
	// присланные peer/peer_cn не принимаются (иначе держатель ingest-токена приписал
	// бы свои события и сводки коллектора, например collector.clock_skew, чужому
	// устройству).
	addr := remoteHost(r)
	for i := range events {
		if events[i].Attrs == nil {
			events[i].Attrs = map[string]string{}
		}
		events[i].Attrs["peer"] = addr
		delete(events[i].Attrs, "peer_cn")
	}
	if h.EmitBatch != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		if err := h.EmitBatch(ctx, events); err != nil {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "очередь приёма недоступна — повторите запрос", http.StatusServiceUnavailable)
			return
		}
	} else {
		for _, e := range events {
			h.Emit(e)
		}
	}
	accepted(w, len(events))
}

// recoverHandler: паника в хендлере — 500 клиенту и счётчик, а не падение
// процесса (net/http сам ловит паники, но без метрики и с полной трассой в лог).
func recoverHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		done := false
		Guard("http "+r.URL.Path, func() {
			next.ServeHTTP(w, r)
			done = true
		})
		if !done {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	})
}

func (h *HTTPHandlers) tokenOK(r *http.Request) bool {
	if h.Token == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Argus-Token")), []byte(h.Token)) == 1
}

func (h *HTTPHandlers) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.tokenOK(r) {
			http.Error(w, "нужен заголовок X-Argus-Token", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func remoteHost(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func accepted(w http.ResponseWriter, n int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]int{"accepted": n})
}
