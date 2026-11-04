package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"time"
)

// pprofHandler — профили Go (heap, allocs, goroutine, profile, trace) за
// METRICS_TOKEN (Bearer, как /metrics). Отдельный порт ENGINE_PPROF_ADDR, по
// умолчанию выключен: профиль раскрывает адреса и имена из памяти процесса, ему
// не место рядом с управляющим API. Без профиля цикл OOM на argus1 (02.11)
// разбирался по косвенным признакам.
func (e *engine) pprofHandler() http.Handler {
	mux := http.NewServeMux()
	guard := func(h http.HandlerFunc) http.HandlerFunc { return requireToken(e.mtoken, h) }
	mux.HandleFunc("GET /debug/pprof/", guard(pprof.Index))
	mux.HandleFunc("GET /debug/pprof/cmdline", guard(pprof.Cmdline))
	mux.HandleFunc("GET /debug/pprof/profile", guard(pprof.Profile))
	mux.HandleFunc("GET /debug/pprof/symbol", guard(pprof.Symbol))
	mux.HandleFunc("GET /debug/pprof/trace", guard(pprof.Trace))
	return mux
}

func (e *engine) servePprof(ctx context.Context, addr string) {
	// Профиль CPU по умолчанию — 30 с: WriteTimeout выше него.
	srv := &http.Server{Addr: addr, Handler: e.pprofHandler(), ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 2 * time.Minute}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	slog.Info("pprof listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("pprof", "err", err)
	}
}
