// collector — приёмник событий ARGUS: syslog (RFC 5424/3164, CEF, LEEF),
// NetFlow v9 / IPFIX, вебхуки Kubernetes audit и GitLab. Всё нормализуется
// в единую схему и пишется батчами в argus.events.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/devitex-soft/argus/collector/internal/listen"
	"github.com/devitex-soft/argus/collector/internal/model"
	"github.com/devitex-soft/argus/collector/internal/normalize"
	"github.com/devitex-soft/argus/collector/internal/parse"
	"github.com/devitex-soft/argus/collector/internal/pull"
	"github.com/devitex-soft/argus/collector/internal/sink"
)

// TLSConfig — приёмник RFC 5425. Пустой Addr — выключен; с непустым Addr в
// проде обязательны Cert и Key.
type TLSConfig struct {
	Addr     string `yaml:"addr"` // ":6514" — RFC 5425; пусто — выключено
	Cert     string `yaml:"cert"`
	Key      string `yaml:"key"`
	ClientCA string `yaml:"client_ca"` // PEM с CA клиентов → mTLS
}

// check — можно ли стартовать с такой конфигурацией: addr без cert/key вне
// стенда — отказ, а не самоподписанный сертификат в проде.
func (t TLSConfig) check(dev bool) error {
	if t.Addr != "" && (t.Cert == "" || t.Key == "") && !dev {
		return fmt.Errorf("syslog tls: задан addr %q без cert/key — в проде самоподписанный сертификат недопустим; задайте SYSLOG_TLS_CERT/SYSLOG_TLS_KEY или SYSLOG_TLS_ADDR= (пусто — выключить)", t.Addr)
	}
	return nil
}

type Config struct {
	Listeners struct {
		Syslog struct {
			UDP           string    `yaml:"udp"`
			TCP           string    `yaml:"tcp"`
			TLS           TLSConfig `yaml:"tls"`
			MaxConns      int       `yaml:"max_conns"`        // одновременных TCP/TLS-соединений (SYSLOG_TCP_MAX_CONNS)
			MaxConnsPerIP int       `yaml:"max_conns_per_ip"` // с одного IP (SYSLOG_TCP_MAX_CONNS_PER_IP)
		} `yaml:"syslog"`
		NetFlow struct {
			UDP       string `yaml:"udp"`
			Source    string `yaml:"source"`
			Exporters string `yaml:"exporters"` // CIDR через запятую; пусто — все (NETFLOW_EXPORTERS)
		} `yaml:"netflow"`
		HTTP struct {
			Addr  string `yaml:"addr"`
			Token string `yaml:"token"`
		} `yaml:"http"`
		// Файлы на хосте (bind-mount): audit-лог WAF в JSON, error-лог, JSON-лог Caddy.
		Files []struct {
			Path      string `yaml:"path"`
			Format    string `yaml:"format"`     // waf-audit | lines
			Source    string `yaml:"source"`     // метка для health/metrics
			FromStart bool   `yaml:"from_start"` // читать с начала, а не с конца
			// Node — узел для событий, в которых отправитель его не назвал (Coraza в
			// error-логе пишет адрес контейнера, не имя); Attrs — постоянные атрибуты
			// файла (container: имя контейнера WAF). Пустые значения не ставятся.
			Node  string            `yaml:"node"`
			Attrs map[string]string `yaml:"attrs"`
		} `yaml:"files"`
	} `yaml:"listeners"`
	Sources   []normalize.SourceRule `yaml:"sources"`
	PIIFields []string               `yaml:"pii_fields"`
	K8s       struct {
		Cluster string `yaml:"cluster"`
	} `yaml:"k8s"`
	Batch struct {
		Size         int `yaml:"size"`
		FlushMs      int `yaml:"flush_ms"`
		PendingRows  int `yaml:"pending_rows"`  // потолок очереди батчей к ClickHouse по строкам (SINK_PENDING_ROWS)
		PendingBytes int `yaml:"pending_bytes"` // и по байтам (SINK_PENDING_BYTES, 512 МБ)
	} `yaml:"batch"`
	Falcon pull.FalconConfig `yaml:"falcon"`
	S3     []pull.S3Config   `yaml:"s3"`
}

func loadConfig(path string) (Config, error) {
	var c Config
	c.Listeners.Syslog.UDP, c.Listeners.Syslog.TCP = ":5514", ":5514"
	c.Listeners.NetFlow.UDP, c.Listeners.NetFlow.Source = ":2055", "netflow.core"
	c.Listeners.HTTP.Addr = ":8088"
	c.K8s.Cluster = "k8s"
	c.Batch.Size, c.Batch.FlushMs = 2000, 1000
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return c, err
		}
		if err := yaml.Unmarshal([]byte(expandEnv(string(raw))), &c); err != nil {
			return c, err
		}
	}
	// переменные окружения — поверх файла, чтобы compose мог задать лимиты без правки yml
	if v, err := strconv.Atoi(os.Getenv("SYSLOG_TCP_MAX_CONNS")); err == nil && v > 0 {
		c.Listeners.Syslog.MaxConns = v
	}
	if v, err := strconv.Atoi(os.Getenv("SYSLOG_TCP_MAX_CONNS_PER_IP")); err == nil && v > 0 {
		c.Listeners.Syslog.MaxConnsPerIP = v
	}
	if v := os.Getenv("NETFLOW_EXPORTERS"); v != "" {
		c.Listeners.NetFlow.Exporters = v
	}
	if v := os.Getenv("SYSLOG_TLS_CLIENT_CA"); v != "" {
		c.Listeners.Syslog.TLS.ClientCA = v
	}
	if v, err := strconv.Atoi(os.Getenv("SINK_PENDING_ROWS")); err == nil && v > 0 {
		c.Batch.PendingRows = v
	}
	if c.Batch.PendingRows <= 0 {
		c.Batch.PendingRows = 200_000
	}
	if v, err := strconv.Atoi(os.Getenv("SINK_PENDING_BYTES")); err == nil && v > 0 {
		c.Batch.PendingBytes = v
	}
	if c.Batch.PendingBytes <= 0 {
		c.Batch.PendingBytes = sink.DefaultPendingBytes
	}
	return c, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// mergeAttrs — постоянные атрибуты источника (attrs: в collector.yml): только
// непустые значения и только там, где событие их не назвало само.
func mergeAttrs(e *model.Event, attrs map[string]string) {
	for k, v := range attrs {
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k == "" || v == "" || e.Attrs[k] != "" {
			continue
		}
		if e.Attrs == nil {
			e.Attrs = map[string]string{}
		}
		e.Attrs[k] = v
	}
}

// parseSyslogLine — одна строка syslog/файла/HTTP в событие: CEF, LEEF, WAF
// error-лог, вендорные разборщики, иначе syslog. Происхождение (peer, peer_cn,
// scope) ставит только коллектор; в конце — повторная чистка значений, записанных
// после Ensure нормализатора.
func parseSyslogLine(norm *normalize.Normalizer, line string, peer listen.Peer) (model.Event, bool) {
	sl, _ := parse.ParseSyslog(line)
	var e model.Event
	switch {
	case hasCEF(line):
		c, _ := parse.ParseCEF(line)
		e = norm.FromCEF(c, sl, line)
	case hasLEEF(line):
		l, _ := parse.ParseLEEF(line)
		e = norm.FromLEEF(l, sl, line)
	case parse.IsWAFErrorLine(line):
		// error-лог ModSecurity (Apache/nginx) или Coraza (в т.ч. JSON-лог Caddy).
		// Строка может прийти в обёртке syslog (агент на хосте добавляет заголовок с
		// именем хоста) — тогда разбирается текст после заголовка.
		wafText := line
		if sl.Format != "raw" && parse.IsWAFErrorLine(sl.Message) {
			wafText = sl.Message
		}
		wf, ok := parse.ParseWAFErrorLine(wafText)
		if !ok {
			e = norm.FromSyslog(sl, line)
			break
		}
		if !wf.Final {
			return model.Event{}, false // промежуточная строка Warning по одному правилу
		}
		e = norm.FromWAF(wf, line)
		wafNode(&e, sl.Hostname, peer)
	default:
		if sq, ok := parse.ParseSquid(sl.Message, sl.Hostname); ok {
			e = sq
		} else if jk, ok := parse.ParseJenkins(sl.Message, sl.Hostname); ok {
			e = jk
		} else if mt, ok := parse.ParseMikroTik(sl); ok {
			e = mt
		} else if vr, ok := parse.ParseVRP(sl); ok {
			e = vr
		} else {
			e = norm.FromSyslog(sl, line)
		}
	}
	if e.Node == "" {
		e.Node = firstNonEmpty(peer.Node, peer.Addr)
	}
	attrsFromStructured(&e, sl.Structured)
	// Происхождение ставит только коллектор: peer — адрес соединения, peer_cn — только
	// из проверенного клиентского сертификата, scope считает emit по адресам.
	if e.Attrs == nil {
		e.Attrs = map[string]string{}
	}
	e.Attrs["peer"] = peer.Addr
	if peer.CN != "" {
		e.Attrs["peer_cn"] = peer.CN
	} else {
		delete(e.Attrs, "peer_cn")
	}
	delete(e.Attrs, "scope")
	// Узел из заголовка syslog и атрибуты SD пишутся после Ensure нормализатора:
	// повторная чистка — управляющие символы, ANSI и потолок длины.
	e.Sanitize()
	return e, true
}

// wafAuditEvent — транзакция audit-лога из POST /ingest/modsecurity: тот же
// выбор узла, что у файла и error-лога, и чистка после него.
func wafAuditEvent(norm *normalize.Normalizer, obj json.RawMessage, peer listen.Peer) (model.Event, bool) {
	wf, ok := parse.ParseWAFAudit(obj)
	if !ok {
		return model.Event{}, false
	}
	e := norm.FromWAF(wf, string(obj))
	wafNode(&e, "", peer)
	e.Sanitize()
	return e, true
}

// wafNode — узел события WAF, одно правило для error-лога, файла audit и
// POST /ingest/modsecurity:
//  1. имя хоста из заголовка syslog (агент на хосте WAF знает своё имя);
//  2. node: источника (WAF_NODE) — оператор назвал хост явно;
//  3. server_id audit-лога — тоже задаёт оператор в конфиге WAF, но для многих
//     серверов он один и тот же или пуст, поэтому ниже явного имени;
//  4. адрес сервера (host_ip audit-лога или IP из [hostname]) — разные серверы
//     дают разные узлы, на этом держится правило waf-scanner-multihost;
//  5. адрес отправителя.
//
// [hostname] error-лога и заголовок Host присылает клиент: узлом они не бывают
// (FromWAF кладёт имя в attrs.http_host).
func wafNode(e *model.Event, senderHost string, peer listen.Peer) {
	e.Node = firstNonEmpty(strings.TrimSpace(senderHost), strings.TrimSpace(peer.Node), e.Node,
		e.Attrs["server_addr"], e.DstIP, peer.Addr)
}

// sdAttrKeys — параметры SD-элемента «argus», которые агент на хосте может
// передать в заголовке RFC 5424: то, чего нет в строке лога. Остальное —
// происхождение (peer, peer_cn, transport, scope, server_addr…) — ставит только
// коллектор; иначе любой отправитель syslog подделал бы его.
var sdAttrKeys = map[string]bool{"container": true, "pod": true, "namespace": true, "service": true}

// sdAttrMax — потолок значения из SD: имена контейнеров и подов короче 253 байт.
const sdAttrMax = 253

// attrsFromStructured — разрешённые параметры SD-элемента «argus» → атрибуты
// события. Значение чистится и режется (обрезка — attrs.truncated=1); своё
// значение события важнее.
func attrsFromStructured(e *model.Event, sd map[string]string) {
	for k, v := range sd {
		name, ok := strings.CutPrefix(k, "argus.")
		if !ok || !sdAttrKeys[name] {
			continue
		}
		v, cut := model.Clean(strings.TrimSpace(v))
		if len(v) > sdAttrMax {
			v = strings.ToValidUTF8(v[:sdAttrMax], "")
			cut = true
		}
		if v == "" || e.Attrs[name] != "" {
			continue
		}
		if e.Attrs == nil {
			e.Attrs = map[string]string{}
		}
		e.Attrs[name] = v
		if cut {
			e.Attrs["truncated"] = "1"
		}
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// stats — счётчики событий по источнику за текущую минуту (для heartbeat).
type stats struct {
	mu       sync.Mutex
	perMin   map[string]uint32
	listener map[string]string
	total    atomic.Uint64
	dropped  atomic.Uint64
	bySource map[string]uint64 // накопительно, для /metrics
	lastSeen map[string]int64  // unix-время последнего события источника
}

func (s *stats) hit(source, listener string) {
	s.total.Add(1)
	s.mu.Lock()
	s.perMin[source]++
	s.bySource[source]++
	s.listener[source] = listener
	if s.lastSeen == nil {
		s.lastSeen = map[string]int64{}
	}
	s.lastSeen[source] = time.Now().Unix()
	s.mu.Unlock()
}

// prometheus — текстовый формат без клиентской библиотеки. Без full — только
// агрегаты: имена источников — это карта инфраструктуры, её не отдаём без токена.
func (s *stats) prometheus(queue, pending, pendingBytes int, ws *sink.Stats, full bool) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "argus_collector_events_total %d\n", s.total.Load())
	fmt.Fprintf(&b, "argus_collector_events_dropped_total %d\n", s.dropped.Load())
	fmt.Fprintf(&b, "argus_collector_queue_length %d\n", queue)
	fmt.Fprintf(&b, "argus_collector_pending_rows %d\n", pending)
	fmt.Fprintf(&b, "argus_collector_pending_bytes %d\n", pendingBytes)
	fmt.Fprintf(&b, "argus_collector_pending_dropped_total %d\n", ws.PendingDropped.Load())
	fmt.Fprintf(&b, "argus_collector_inserted_total %d\n", ws.Inserted.Load())
	fmt.Fprintf(&b, "argus_collector_insert_retries_total %d\n", ws.Retries.Load())
	fmt.Fprintf(&b, "argus_collector_insert_requeued_total %d\n", ws.Requeued.Load())
	fmt.Fprintf(&b, "argus_collector_dead_letter_total %d\n", ws.DeadLetter.Load())
	fmt.Fprintf(&b, "argus_collector_rejects_failed_total %d\n", ws.RejectsFailed.Load())
	lm := listen.Metrics
	fmt.Fprintf(&b, "argus_collector_panics_total %d\n", lm.Panics.Load())
	fmt.Fprintf(&b, "argus_collector_oversize_total %d\n", lm.Oversize.Load())
	fmt.Fprintf(&b, "argus_collector_conn_rejected_total %d\n", lm.ConnRejected.Load())
	fmt.Fprintf(&b, "argus_collector_active_conns %d\n", lm.ActiveConns.Load())
	fmt.Fprintf(&b, "argus_collector_sources %d\n", len(s.bySource))
	if !full {
		return b.String()
	}
	now := time.Now().Unix()
	for src, n := range s.bySource {
		fmt.Fprintf(&b, "argus_collector_source_events_total{source=%q,listener=%q} %d\n", src, s.listener[src], n)
		// сколько секунд источник молчит — для алерта «источник пропал»
		fmt.Fprintf(&b, "argus_collector_source_last_seen_seconds{source=%q} %d\n", src, now-s.lastSeen[src])
	}
	return b.String()
}

func (s *stats) snapshot() []sink.HealthRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := model.FormatTS(time.Now())[:19]
	rows := make([]sink.HealthRow, 0, len(s.perMin))
	for src, n := range s.perMin {
		rows = append(rows, sink.HealthRow{Source: src, Listener: s.listener[src], SeenAt: now, Events1m: n})
		s.perMin[src] = 0
	}
	return rows
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel()})))
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "replay-pcap":
			os.Exit(replayPcap(os.Args[2:]))
		case "healthcheck":
			os.Exit(healthcheck(healthURL(env("COLLECTOR_CONFIG", "")), 3*time.Second))
		}
	}
	cfg, err := loadConfig(env("COLLECTOR_CONFIG", ""))
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	dev := os.Getenv("ARGUS_DEV") == "1"
	ch := sink.New(env("CLICKHOUSE_URL", "http://localhost:8123"), env("CLICKHOUSE_DB", "argus"),
		env("CLICKHOUSE_USER", "default"), env("CLICKHOUSE_PASSWORD", ""))
	norm := &normalize.Normalizer{Rules: cfg.Sources, PIIFields: cfg.PIIFields}
	st := &stats{perMin: map[string]uint32{}, listener: map[string]string{}, bySource: map[string]uint64{}}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	queue := make(chan queuedEvent, cfg.Batch.PendingRows)
	// emit всегда сам проставляет attrs.transport: значение из тела события
	// (например, /ingest/events с "transport":"tls") доверять нельзя — по нему
	// движок решает, можно ли автоблокировать.
	emit := func(e model.Event, listener, transport string) {
		if e.Attrs == nil {
			e.Attrs = map[string]string{}
		}
		e.Attrs["transport"] = transport
		// Направление для любого события с двумя адресами (NGFW, firewall, syslog), не только
		// NetFlow: правила про «снаружи внутрь» одни на все источники.
		if e.SrcIP != "" && e.DstIP != "" && e.Attrs["scope"] == "" {
			e.Attrs["scope"] = norm.FlowScope(e.SrcIP, e.DstIP)
		}
		item := queuedEvent{event: e}
		if transport != "udp" {
			item.ack = make(chan error, 1)
		}
		select {
		case queue <- item:
			if item.ack == nil {
				st.hit(e.Source, listener)
				return
			}
		case <-ctx.Done():
			st.dropped.Add(1)
			slog.Warn("остановка приёмника, событие не принято", "source", e.Source)
			return
		}
		select {
		case err := <-item.ack:
			if err == nil {
				st.hit(e.Source, listener)
			} else {
				st.dropped.Add(1)
				slog.Error("событие не записано в spool", "source", e.Source, "err", err)
			}
		case <-ctx.Done():
			st.dropped.Add(1)
		}
	}
	if cfg.Listeners.HTTP.Token == "" {
		// Без токена /ingest/* принимает всё от кого угодно. В проде это отказ
		// в запуске; стенд и e2e явно включают ARGUS_DEV=1.
		if !dev {
			slog.Error("ARGUS_INGEST_TOKEN не задан: HTTP-приём без проверки допустим только на стенде (ARGUS_DEV=1)")
			os.Exit(2)
		}
		slog.Warn("ARGUS_DEV=1: /ingest/* принимает всё без проверки — только для стенда")
	}
	tlsCfg := cfg.Listeners.Syslog.TLS
	if err := tlsCfg.check(dev); err != nil {
		slog.Error(err.Error())
		os.Exit(2)
	}

	parseLine := func(line string, peer listen.Peer) (model.Event, bool) { return parseSyslogLine(norm, line, peer) }
	lines := func(line string, peer listen.Peer) {
		if e, ok := parseLine(line, peer); ok {
			emit(e, "syslog", peer.Transport)
		}
	}

	// Файлы на хосте: audit-лог WAF (JSON), error-лог ModSecurity/Coraza, JSON-лог Caddy.
	for _, fcfg := range cfg.Listeners.Files {
		if fcfg.Path == "" {
			continue
		}
		fcfg := fcfg
		src := fcfg.Source
		if src == "" {
			src = "file"
		}
		var handle func(string)
		if fcfg.Format == "waf-audit" {
			handle = func(line string) {
				if wf, ok := parse.ParseWAFAudit([]byte(line)); ok {
					e := norm.FromWAF(wf, line)
					wafNode(&e, "", listen.Peer{Addr: src, Transport: "file", Node: fcfg.Node})
					mergeAttrs(&e, fcfg.Attrs)
					e.Sanitize()
					emit(e, "file:"+src, "file")
				}
			}
		} else {
			peer := listen.Peer{Addr: src, Transport: "file", Node: fcfg.Node}
			handle = func(line string) {
				if e, ok := parseLine(line, peer); ok {
					mergeAttrs(&e, fcfg.Attrs)
					e.Sanitize()
					emit(e, "syslog", peer.Transport)
				}
			}
		}
		go (&listen.TailFile{Path: fcfg.Path, Source: src, FromStart: fcfg.FromStart, Handle: handle}).Run(ctx)
	}

	if v := strings.TrimSpace(os.Getenv("INTERNAL_NETS")); v != "" {
		for _, c := range strings.Split(v, ",") {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			pfx, perr := netip.ParsePrefix(c)
			if perr != nil {
				slog.Error("INTERNAL_NETS", "cidr", c, "err", perr)
				os.Exit(1)
			}
			norm.InternalNets = append(norm.InternalNets, pfx)
		}
	}
	dec := parse.NewDecoder()
	if dec.Allow, err = parse.ParseCIDRs(cfg.Listeners.NetFlow.Exporters); err != nil {
		slog.Error("NETFLOW_EXPORTERS", "err", err)
		os.Exit(1)
	}
	packets := func(pkt []byte, exporter string) {
		flows, err := dec.Decode(exporter, pkt)
		if err != nil {
			slog.Debug("netflow", "err", err, "exporter", exporter)
			return
		}
		for _, f := range flows {
			emit(norm.FromFlow(f, cfg.Listeners.NetFlow.Source, exporter), "netflow", "udp")
		}
	}

	ws := &sink.Stats{}
	spoolBytes := int64(8 << 30)
	if raw := os.Getenv("SINK_SPOOL_BYTES"); raw != "" {
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n > 0 {
			spoolBytes = n
		} else {
			slog.Error("SINK_SPOOL_BYTES должен быть положительным числом", "value", raw)
			os.Exit(2)
		}
	}
	pq, err := sink.NewDurableQueue(env("SINK_SPOOL_DIR", "/state/spool"), spoolBytes, ws)
	if err != nil {
		slog.Error("spool", "err", err)
		os.Exit(2)
	}
	emitHTTPBatch := func(requestCtx context.Context, events []model.Event) error {
		if len(events) == 0 {
			return nil
		}
		rows := make([]any, len(events))
		for i := range events {
			if events[i].Attrs == nil {
				events[i].Attrs = map[string]string{}
			}
			events[i].Attrs["transport"] = "http"
			// Направление — и для готовых событий NDJSON (агенты Vector, журналы фаерволов).
			if events[i].SrcIP != "" && events[i].DstIP != "" && events[i].Attrs["scope"] == "" {
				events[i].Attrs["scope"] = norm.FlowScope(events[i].SrcIP, events[i].DstIP)
			}
			rows[i] = events[i]
		}
		if err := pq.PushContext(requestCtx, rows); err != nil {
			st.dropped.Add(uint64(len(events)))
			slog.Error("http spool", "rows", len(events), "err", err)
			return err
		}
		for _, e := range events {
			st.hit(e.Source, "http")
		}
		return nil
	}
	handlers := &listen.HTTPHandlers{
		Token: cfg.Listeners.HTTP.Token, K8sCluster: cfg.K8s.Cluster,
		EmitBatch: emitHTTPBatch,
		ParseLine: parseLine,
		ParseWAFAudit: func(obj json.RawMessage, peer listen.Peer) (model.Event, bool) {
			return wafAuditEvent(norm, obj, peer)
		},
		Health: func() any {
			return map[string]any{"status": "ok", "events_total": st.total.Load(), "dropped": st.dropped.Load(),
				"queue": len(queue), "pending_rows": pq.Rows(), "pending_bytes": pq.Bytes(), "spool_bytes": pq.SpoolBytes(), "spool_capacity_bytes": pq.SpoolCapacityBytes(), "dead_letter": ws.DeadLetter.Load(), "panics": listen.Metrics.Panics.Load()}
		},
		Metrics: func(full bool) string {
			return st.prometheus(len(queue), pq.Rows(), pq.Bytes(), ws, full) + fmt.Sprintf("argus_collector_spool_bytes %d\nargus_collector_spool_capacity_bytes %d\n", pq.SpoolBytes(), pq.SpoolCapacityBytes())
		},
	}

	var wg sync.WaitGroup
	run := func(name string, f func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error(name, "err", err)
			}
		}()
	}
	tcpOpts := listen.TCPOptions{MaxConns: cfg.Listeners.Syslog.MaxConns, MaxConnsPerIP: cfg.Listeners.Syslog.MaxConnsPerIP}
	if a := cfg.Listeners.Syslog.UDP; a != "" {
		run("syslog udp", func() error { return listen.SyslogUDP(ctx, a, lines) })
	}
	if a := cfg.Listeners.Syslog.TCP; a != "" {
		run("syslog tcp", func() error { return listen.SyslogTCP(ctx, a, tcpOpts, lines) })
	}
	if a := tlsCfg.Addr; a != "" {
		to := listen.TLSOptions{Cert: tlsCfg.Cert, Key: tlsCfg.Key, ClientCA: tlsCfg.ClientCA, Dev: dev}
		run("syslog tls", func() error { return listen.SyslogTLS(ctx, a, to, tcpOpts, lines) })
	}
	if a := cfg.Listeners.NetFlow.UDP; a != "" {
		run("netflow udp", func() error { return listen.NetFlowUDP(ctx, a, packets) })
	}
	// Опрашиваемые источники: CrowdStrike Falcon, S3-бакеты (Yandex/VK Cloud).
	if cfg.Falcon.ClientID != "" {
		f := pull.NewFalcon(cfg.Falcon, func(e model.Event) { emit(e, "falcon", "pull") })
		run("falcon", func() error { listen.Guard("falcon", func() { f.Run(ctx) }); return nil })
	}
	for _, sc := range cfg.S3 {
		src := pull.NewS3(sc, func(e model.Event) { emit(e, "s3", "pull") })
		run("s3 "+sc.Name, func() error { listen.Guard("s3 "+sc.Name, func() { src.Run(ctx) }); return nil })
	}
	srv := &http.Server{Addr: cfg.Listeners.HTTP.Addr, Handler: handlers.Mux(), ReadHeaderTimeout: 5 * time.Second}
	run("http", func() error {
		slog.Info("http listening", "addr", cfg.Listeners.HTTP.Addr)
		return srv.ListenAndServe()
	})
	go func() { <-ctx.Done(); _ = srv.Shutdown(context.Background()) }()

	// Батчер собирает батчи в дисковую очередь pending, писатели (4 потока)
	// вставляют параллельно: вставка в ClickHouse не блокирует приём. Транспортная
	// ошибка — повторы с backoff, потом батч обратно в pending. При заполнении
	// диска приём блокируется; ошибка данных кладёт весь батч в ingest_rejects.
	// Остановка: батчер дочитывает queue, делает последний Push и закрывает
	// pending; писатели завершаются только по Close — иначе финальный батч терялся.
	var writers sync.WaitGroup
	for i := 0; i < 4; i++ {
		writers.Add(1)
		w := sink.NewWriter(ch, pq, ws)
		go func() { defer writers.Done(); listen.Guard("writer", func() { w.Run(ctx) }) }()
	}
	run("batcher", func() error {
		durableBatcher(ctx, queue, pq, cfg.Batch.Size, time.Duration(cfg.Batch.FlushMs)*time.Millisecond, 2*time.Second)
		writers.Wait()
		return nil
	})
	// Heartbeat раз в минуту — источник виден живым даже без событий.
	run("heartbeat", func() error {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if rows := st.snapshot(); len(rows) > 0 {
					if err := ch.InsertHealth(context.Background(), rows); err != nil {
						slog.Warn("heartbeat", "err", err)
					}
				}
			case <-ctx.Done():
				return nil
			}
		}
	})

	slog.Info("collector started", "batch", strconv.Itoa(cfg.Batch.Size), "sources", len(cfg.Sources),
		"max_conns", tcpOpts.MaxConns, "pending_rows", cfg.Batch.PendingRows, "netflow_exporters", len(dec.Allow))
	wg.Wait()
}

// drainIdle — тишина в queue, после которой при остановке считаем остаток вычитанным.
const drainIdle = 100 * time.Millisecond

type queuedEvent struct {
	event model.Event
	ack   chan error
}

// durableBatcher подтверждает источникам TCP/TLS/file/pull запись лишь после
// fsync батча. UDP не имеет подтверждения на уровне протокола, но тоже попадает
// в тот же spool до отправки в ClickHouse.
func durableBatcher(ctx context.Context, queue <-chan queuedEvent, pq *sink.Queue, size int, flushEvery, drainTimeout time.Duration) {
	if size <= 0 {
		size = 2000
	}
	if flushEvery <= 0 {
		flushEvery = 100 * time.Millisecond
	}
	batch := make([]any, 0, size)
	acks := make([]chan error, 0, size)
	ticker := time.NewTicker(flushEvery)
	defer ticker.Stop()
	flush := func(writeCtx context.Context, stopping bool) {
		if len(batch) == 0 {
			return
		}
		var err error
		for {
			err = pq.PushContext(writeCtx, batch)
			if err == nil || writeCtx.Err() != nil {
				break
			}
			slog.Error("spool: запись батча не удалась, повторяю", "rows", len(batch), "err", err)
			select {
			case <-writeCtx.Done():
			case <-time.After(time.Second):
			}
		}
		// Keep the current batch for the shutdown flush with a fresh deadline.
		if err != nil && !stopping && ctx.Err() != nil {
			return
		}
		for _, ack := range acks {
			if ack != nil {
				ack <- err
			}
		}
		if err != nil {
			slog.Error("spool: батч не сохранён", "rows", len(batch), "err", err)
		}
		batch = make([]any, 0, size)
		acks = acks[:0]
	}
	add := func(e queuedEvent, writeCtx context.Context, stopping bool) {
		batch = append(batch, e.event)
		acks = append(acks, e.ack)
		if len(batch) >= size {
			flush(writeCtx, stopping)
		}
	}
	for {
		select {
		case e := <-queue:
			add(e, ctx, false)
		case <-ticker.C:
			flush(ctx, false)
		case <-ctx.Done():
			writeCtx, cancel := context.WithTimeout(context.Background(), drainTimeout+10*time.Second)
			defer cancel()
			deadline, idle := time.NewTimer(drainTimeout), time.NewTimer(drainIdle)
			defer deadline.Stop()
			defer idle.Stop()
		drain:
			for {
				select {
				case e := <-queue:
					add(e, writeCtx, true)
					idle.Reset(drainIdle)
				case <-idle.C:
					break drain
				case <-deadline.C:
					break drain
				}
			}
			flush(writeCtx, true)
			pq.Close()
			return
		}
	}
}

// healthURL — адрес /healthz по конфигу (порт HTTP-приёмника); без конфига — :8088.
func healthURL(cfgPath string) string {
	addr := ":8088"
	if cfg, err := loadConfig(cfgPath); err == nil && cfg.Listeners.HTTP.Addr != "" {
		addr = cfg.Listeners.HTTP.Addr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://127.0.0.1:8088/healthz"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz"
}

// healthcheck — `collector healthcheck`: GET /healthz, 0 при 200, иначе 1.
// В distroless нет wget/curl — контейнерный healthcheck зовёт сам бинарь.
func healthcheck(url string, timeout time.Duration) int {
	resp, err := (&http.Client{Timeout: timeout}).Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck:", resp.Status)
		return 1
	}
	return 0
}

func logLevel() slog.Level {
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

func hasCEF(s string) bool  { return strings.Contains(s, "CEF:") }
func hasLEEF(s string) bool { return strings.Contains(s, "LEEF:") }

// replayPcap: collector replay-pcap file.pcap [--to http://host:8088] [--token T]
// Достаёт UDP/TCP-полезную нагрузку из записи tcpdump и шлёт построчно в /ingest/syslog.
func replayPcap(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "collector replay-pcap FILE [--to URL] [--token T]")
		return 2
	}
	path, to, token := args[0], "http://localhost:8088", os.Getenv("ARGUS_INGEST_TOKEN")
	for i := 1; i+1 < len(args); i += 2 {
		switch args[i] {
		case "--to":
			to = args[i+1]
		case "--token":
			token = args[i+1]
		}
	}
	f, err := os.Open(path)
	if err != nil {
		slog.Error("pcap", "err", err)
		return 1
	}
	defer f.Close()
	var lines []string
	err = parse.PcapPayloads(f, func(p []byte, src string, dport uint16) {
		for _, l := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				lines = append(lines, l)
			}
		}
	})
	if err != nil {
		slog.Error("pcap", "err", err)
		return 1
	}
	sent := 0
	for i := 0; i < len(lines); i += 500 {
		end := min(i+500, len(lines))
		req, _ := http.NewRequest(http.MethodPost, strings.TrimRight(to, "/")+"/ingest/syslog", strings.NewReader(strings.Join(lines[i:end], "\n")))
		req.Header.Set("X-Argus-Token", token)
		resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
		if err != nil {
			slog.Error("send", "err", err)
			return 1
		}
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			slog.Error("send", "status", resp.Status)
			return 1
		}
		sent += end - i
	}
	fmt.Printf("→ %d строк из %s отправлено в %s\n", sent, path, to)
	return 0
}

// expandEnv — ${VAR} и ${VAR:-default}: os.ExpandEnv не знает синтаксис
// умолчаний и молча подставлял пустоту вместо "${WAF_AUDIT_LOG:-}".
var envRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}`)

func expandEnv(s string) string {
	return envRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := envRe.FindStringSubmatch(m)
		if v, ok := os.LookupEnv(sub[1]); ok && v != "" {
			return v
		}
		return sub[2]
	})
}
