// Package respond — обратный канал: заблокировать адрес на агентах Wazuh
// (active-response firewall-drop) и/или на NGFW по HTTP-шаблону.
//
// Режимы (respond.mode в argus.analyst.yml, переключается из консоли):
//   - ids      — только детект; автоматика ничего не делает, кнопка оператора работает;
//   - simulate — автоматика считает, кого заблокировала бы, и пишет это в журнал
//     ответов (dry_run=1), но исполнителей не вызывает. Режим по умолчанию;
//   - ips      — автоблокировка по правилам с блоком respond, TTL, allowlist.
//
// Кого нельзя блокировать (Check):
//   - приватные сети, CGNAT, loopback, link-local — всегда;
//   - respond.allowlist — свои публичные сети, мониторинг, VPN администраторов;
//   - respond.never_block (+ env ARGUS_RESPOND_NEVER_BLOCK_1..N) — неснимаемый
//     deny-list инфраструктуры: NGFW, менеджер Wazuh, консоль, IdP, NAT-адреса
//     офисов. Отдельный от allowlist, чтобы его не «подчистили» вместе с ним.
//
// Кому верить (TrustedEvent): автоблокировка исполняется, только если каждое
// событие цепочки пришло по транспорту, который нельзя подделать адресом
// отправителя (file, http, tls, pull), либо от адреса из respond.trusted_sources
// (+ env ARGUS_RESPOND_TRUSTED_1..N). Событие по UDP/TCP-syslog от неизвестного
// пира заведёт инцидент, но не блокировку: иначе спуфленный syslog «атака с
// адреса X» блокирует любого X. Решение принимает движок, здесь — предикат.
//
// Срок блокировки: автоблокировки — respond.ttl или respond.ttl правила;
// ручные — respond.manual_ttl (env ARGUS_RESPOND_MANUAL_TTL, по умолчанию
// 24h; 0 — бессрочно, снимается только кнопкой). Снятие: NGFW — шаблон unblock (без него режим ips не
// стартует, откат в simulate); Wazuh — API 4.x не принимает TTL и не умеет
// «delete»: срок задаётся <timeout> в ossec.conf менеджера. Поэтому
// wazuh_active_response.timeout (секунды, то же значение, что в ossec.conf)
// подтверждает снятие по TTL, а unblock_command — кастомная AR-команда, через
// которую блок снимается досрочно (Unblock из консоли). Без обоих Expire не
// пишет OK и оставляет блок в списке.
//
// Подтверждение исполнителя: Wazuh — total_affected_items > 0; HTTP — 2xx и,
// если заданы, expect (регулярное выражение, ставьте якоря) и/или expect_json
// (ключи верхнего уровня или через точку: {"success": true}).
package respond

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ModeIDS      = "ids"
	ModeSimulate = "simulate"
	ModeIPS      = "ips"

	WazuhExecutor = "wazuh.active-response"

	executorTimeout  = 10 * time.Second
	maxRetries       = 3
	defaultManualTTL = 24 * time.Hour
)

var retryBackoff = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute}

type WazuhAR struct {
	APIURL   string `yaml:"api_url"`
	User     string `yaml:"user"`
	Password string `yaml:"password"` // ${WAZUH_API_PASSWORD}
	Command  string `yaml:"command"`  // firewall-drop
	Agents   string `yaml:"agents"`   // список id через запятую; all — все агенты (предупреждение)
	Insecure bool   `yaml:"insecure_tls"`
	// Timeout — значение <timeout> (секунды) из блока <active-response> в
	// ossec.conf менеджера: API не передаёт TTL, и без этого числа движок не
	// может подтвердить, что блок снят по сроку.
	Timeout int `yaml:"timeout"`
	// UnblockCommand — кастомная AR-команда снятия (скрипт, вызывающий
	// firewall-drop с "command":"delete"); пусто — досрочное снятие невозможно.
	UnblockCommand string `yaml:"unblock_command"`
}

// HTTPCall — шаблон запроса: ${ip}, ${reason}, ${incident} подставляются
// JSON-безопасно в тело и заголовки и URL-безопасно в адрес.
type HTTPCall struct {
	Method string `yaml:"method"` // POST
	URL    string `yaml:"url"`
	Body   string `yaml:"body"`
}

// HTTPAction — исполнитель NGFW: блокировка и снятие блокировки (unblock).
type HTTPAction struct {
	Name       string            `yaml:"name"`        // ngfw.usergate
	Method     string            `yaml:"method"`      // POST
	URL        string            `yaml:"url"`         // https://ug.corp/api/v1/objects/ip_lists/blocked/add
	Headers    map[string]string `yaml:"headers"`     // Authorization: Bearer ${NGFW_TOKEN}
	Body       string            `yaml:"body"`        // {"ip": "${ip}", "comment": "ARGUS ${incident}"}
	Expect     string            `yaml:"expect"`      // регулярное выражение по телу ответа 2xx, напр. '^\{"status":\s*"ok"'
	ExpectJSON map[string]any    `yaml:"expect_json"` // ключи ответа и ожидаемые значения: {"success": true, "data.status": "ok"}
	Insecure   bool              `yaml:"insecure_tls"`
	Unblock    *HTTPCall         `yaml:"unblock"` // снятие блокировки (TTL и ручное); в режиме ips обязателен

	expectRe *regexp.Regexp
}

type Config struct {
	Mode           string       `yaml:"mode"`            // ids | simulate | ips (по умолчанию simulate)
	Allowlist      []string     `yaml:"allowlist"`       // CIDR/адреса, которые не блокируются никогда
	NeverBlock     []string     `yaml:"never_block"`     // инфраструктура: NGFW, менеджер, консоль, IdP, NAT (+ env ARGUS_RESPOND_NEVER_BLOCK_N)
	TrustedSources []string     `yaml:"trusted_sources"` // CIDR отправителей, чьим UDP/TCP-событиям верит автоблокировка (+ env ARGUS_RESPOND_TRUSTED_N)
	TTL            string       `yaml:"ttl"`             // срок автоблокировки, по умолчанию 1h
	ManualTTL      string       `yaml:"manual_ttl"`      // срок ручной блокировки, по умолчанию 24h (env ARGUS_RESPOND_MANUAL_TTL)
	WazuhAR        *WazuhAR     `yaml:"wazuh_active_response"`
	HTTP           []HTTPAction `yaml:"http"`
}

type Result struct {
	Executor string `json:"executor"`
	OK       bool   `json:"ok"`
	Detail   string `json:"detail"`
	DryRun   bool   `json:"dry_run"`
	IP       string `json:"ip,omitempty"`
	Incident string `json:"incident,omitempty"`
	// Noop — исполнители не вызывались, потому что делать нечего (адрес уже
	// заблокирован): не успех исполнителя и не отказ.
	Noop bool `json:"noop,omitempty"`
}

// Noop — результат «делать нечего» (см. Result.Noop): один служебный
// результат без вызова исполнителей.
func Noop(results []Result) bool {
	return len(results) == 1 && results[0].Noop
}

// Block — активная блокировка. Until нулевой — постоянная (снятие не настроено).
type Block struct {
	IP        string    `json:"ip"`
	Incident  string    `json:"incident"`
	Until     time.Time `json:"until"`
	Manual    bool      `json:"manual"`
	Executors []string  `json:"executors"` // у кого блокировка реально стоит — снимаем только у них
}

type pending struct {
	ip, incident, reason string
	ttl                  time.Duration
	attempts             int
	next                 time.Time
}

type Responder struct {
	cfg        Config
	allow      []*net.IPNet
	never      []*net.IPNet
	trusted    []*net.IPNet
	ttl        time.Duration
	manualTTL  time.Duration
	mu         sync.Mutex
	operations [64]sync.Mutex // bounded locks serialize network operations for the same IP
	mode       string
	modeFrom   string // config | console
	active     map[string]Block
	retry      map[string]*pending
	secure     *http.Client
	insecure   *http.Client
	nowFn      func() time.Time
	cfgErrors  []string
	wzTok      string
	wzTokExp   time.Time
}

// csvList — список через запятую (INTERNAL_NETS), пустые элементы отбрасываются.
func csvList(v string) []string {
	var out []string
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// envList — <prefix>1..N: пустые пропускаются, ищем до 64.
func envList(prefix string) []string {
	var out []string
	for i := 1; i <= 64; i++ {
		if v := strings.TrimSpace(os.Getenv(prefix + strconv.Itoa(i))); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// parseCIDRs — адреса без маски получают /32 или /128; ошибки — в cfgErrors под именем списка.
func (r *Responder) parseCIDRs(name string, items []string) (nets []*net.IPNet, bad bool) {
	seen := map[string]bool{}
	for _, s := range items {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		c := s
		if !strings.Contains(c, "/") {
			if strings.Contains(c, ":") {
				c += "/128"
			} else {
				c += "/32"
			}
		}
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		} else {
			bad = true
			r.cfgErrors = append(r.cfgErrors, name+": "+s)
		}
	}
	return nets, bad
}

func New(cfg Config) *Responder {
	r := &Responder{cfg: cfg, active: map[string]Block{}, retry: map[string]*pending{}, nowFn: time.Now, modeFrom: "config"}
	r.secure, r.insecure = newClient(false), newClient(true)
	r.mode = normalizeMode(cfg.Mode)
	if r.ttl, _ = time.ParseDuration(cfg.TTL); r.ttl <= 0 {
		r.ttl = time.Hour
	}
	manual := strings.TrimSpace(cfg.ManualTTL)
	if manual == "" {
		manual = strings.TrimSpace(os.Getenv("ARGUS_RESPOND_MANUAL_TTL"))
	}
	r.manualTTL = parseManualTTL(manual, func(msg string) { r.cfgErrors = append(r.cfgErrors, msg) })
	// Исполнитель без адреса — не исполнитель: yaml создаёт секцию и с пустыми ${VAR}.
	if w := r.cfg.WazuhAR; w != nil {
		w.Agents = strings.TrimSpace(w.Agents)
		switch {
		case strings.TrimSpace(w.APIURL) == "":
			r.cfg.WazuhAR = nil
			r.cfgErrors = append(r.cfgErrors, "wazuh_active_response: api_url пуст — исполнитель выключен")
		case w.Agents == "":
			r.cfg.WazuhAR = nil
			r.cfgErrors = append(r.cfgErrors, "wazuh_active_response: agents не задан (список id через запятую) — исполнитель выключен; all — все агенты, только осознанно")
		default:
			if strings.EqualFold(w.Agents, "all") {
				r.cfgErrors = append(r.cfgErrors, "wazuh_active_response: agents: all — команда уйдёт на все агенты, включая узлы без iptables; укажите список id")
			}
			if w.Timeout <= 0 && w.UnblockCommand == "" {
				r.cfgErrors = append(r.cfgErrors, "wazuh_active_response: не заданы timeout (значение <timeout> из ossec.conf) и unblock_command — снятие по TTL не подтверждается")
			}
		}
	}
	kept := r.cfg.HTTP[:0]
	noUnblock := false
	for _, h := range r.cfg.HTTP {
		if strings.TrimSpace(h.URL) == "" {
			r.cfgErrors = append(r.cfgErrors, "http "+orDefault(h.Name, "?")+": url пуст — исполнитель выключен")
			continue
		}
		if h.Unblock != nil && strings.TrimSpace(h.Unblock.URL) == "" {
			h.Unblock = nil
		}
		if h.Unblock == nil {
			noUnblock = true
		}
		if strings.TrimSpace(h.Expect) != "" {
			re, err := regexp.Compile(h.Expect)
			if err != nil {
				r.cfgErrors = append(r.cfgErrors, "http "+h.Name+": expect не разбирается как регулярное выражение — исполнитель выключен: "+err.Error())
				continue
			}
			if !strings.HasPrefix(h.Expect, "^") && !strings.HasSuffix(h.Expect, "$") {
				r.cfgErrors = append(r.cfgErrors, "http "+h.Name+": expect без якорей ^/$ — подстрока совпадёт и с {\"success\": false}")
			}
			h.expectRe = re
		}
		kept = append(kept, h)
	}
	r.cfg.HTTP = kept
	var badAllow, badNever bool
	// Свои сети из INTERNAL_NETS (те же, что у коллектора для attrs.scope) — в allowlist:
	// белые блоки организации не должны блокироваться по ошибке оператора или правила.
	r.allow, badAllow = r.parseCIDRs("allowlist", append(append([]string{}, cfg.Allowlist...), csvList(os.Getenv("INTERNAL_NETS"))...))
	r.never, badNever = r.parseCIDRs("never_block", append(append([]string{}, cfg.NeverBlock...), envList("ARGUS_RESPOND_NEVER_BLOCK_")...))
	r.trusted, _ = r.parseCIDRs("trusted_sources", append(append([]string{}, cfg.TrustedSources...), envList("ARGUS_RESPOND_TRUSTED_")...))
	// В бой не стартуем, если можем заблокировать своих или не сможем снять блок:
	// откатываемся в симуляцию. Отсутствующие исполнители IPS не отменяют.
	if r.mode == ModeIPS {
		switch {
		case badAllow || badNever:
			r.cfgErrors = append(r.cfgErrors, "режим ips заменён на simulate: allowlist/never_block не разбирается")
			r.mode = ModeSimulate
		case noUnblock:
			r.cfgErrors = append(r.cfgErrors, "режим ips заменён на simulate: у HTTP-исполнителя нет unblock — блок нельзя было бы снять по TTL")
			r.mode = ModeSimulate
		}
	}
	return r
}

// parseManualTTL — срок ручной блокировки: пусто — 24h; "0" (и 0s/0m/0h) —
// бессрочно (Until нулевой, снимается только Unblock); иначе длительность > 0,
// а нечитаемое или отрицательное значение — 24h с записью в config_errors.
func parseManualTTL(s string, warn func(string)) time.Duration {
	if s == "" {
		return defaultManualTTL
	}
	if s == "0" {
		return 0
	}
	d, err := time.ParseDuration(s)
	switch {
	case err != nil:
		warn("manual_ttl: " + s + " не разбирается — взято 24h")
		return defaultManualTTL
	case d < 0:
		warn("manual_ttl: " + s + " отрицательный — взято 24h")
		return defaultManualTTL
	}
	return d
}

func newClient(insecure bool) *http.Client {
	return &http.Client{Timeout: executorTimeout, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure, MinVersion: tls.VersionTLS12}, //nolint:gosec // insecure_tls — осознанный флаг в конфиге
		IdleConnTimeout: 90 * time.Second, MaxIdleConnsPerHost: 4,
	}}
}

func (r *Responder) client(insecure bool) *http.Client {
	if insecure {
		return r.insecure
	}
	return r.secure
}

func normalizeMode(m string) string {
	switch strings.ToLower(strings.TrimSpace(m)) {
	case ModeIDS:
		return ModeIDS
	case ModeIPS:
		return ModeIPS
	default:
		return ModeSimulate
	}
}

// ValidMode — режим из консоли/конфига без нормализации к умолчанию.
func ValidMode(m string) bool {
	switch m {
	case ModeIDS, ModeSimulate, ModeIPS:
		return true
	}
	return false
}

func (r *Responder) Enabled() bool      { return r.cfg.WazuhAR != nil || len(r.cfg.HTTP) > 0 }
func (r *Responder) TTL() time.Duration { return r.ttl }

// ManualTTL — срок ручной блокировки; 0 — бессрочно.
func (r *Responder) ManualTTL() time.Duration { return r.manualTTL }
func (r *Responder) ConfigErrors() []string   { return r.cfgErrors }

// Mode — текущий режим и откуда он взят (config | console).
func (r *Responder) Mode() (string, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mode, r.modeFrom
}

// SetMode — переопределение из консоли (пустая строка — вернуться к конфигу).
// Возвращает false, если значение неизвестно и проигнорировано.
func (r *Responder) SetMode(m string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if m == "" {
		r.mode, r.modeFrom = normalizeMode(r.cfg.Mode), "config"
		return true
	}
	if !ValidMode(m) {
		return false
	}
	r.mode, r.modeFrom = m, "console"
	return true
}

func netStrings(nets []*net.IPNet) []string {
	out := make([]string, 0, len(nets))
	for _, n := range nets {
		out = append(out, n.String())
	}
	return out
}

// Allowlist, NeverBlock, TrustedSources — для показа в консоли.
func (r *Responder) Allowlist() []string      { return netStrings(r.allow) }
func (r *Responder) NeverBlock() []string     { return netStrings(r.never) }
func (r *Responder) TrustedSources() []string { return netStrings(r.trusted) }

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// Check — можно ли блокировать адрес: публичный unicast, не CGNAT, не в allowlist и не в never_block.
func (r *Responder) Check(ip string) error {
	p := net.ParseIP(ip)
	if p == nil || p.IsUnspecified() {
		return fmt.Errorf("адрес %q не разбирается", ip)
	}
	if p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast() || p.IsMulticast() || !p.IsGlobalUnicast() || cgnat.Contains(p) {
		return fmt.Errorf("адрес %s внутренний/служебный — не блокируется", ip)
	}
	for _, n := range r.never {
		if n.Contains(p) {
			return fmt.Errorf("адрес %s в never_block (%s) — инфраструктура, не блокируется", ip, n)
		}
	}
	for _, n := range r.allow {
		if n.Contains(p) {
			return fmt.Errorf("адрес %s в allowlist (%s) — не блокируется", ip, n)
		}
	}
	return nil
}

// TrustedTransports — транспорты, где адрес отправителя нельзя подделать.
var TrustedTransports = map[string]bool{"file": true, "http": true, "tls": true, "pull": true}

// TrustedEvent — можно ли верить событию как основанию для автоблокировки:
// транспорт из TrustedTransports либо отправитель (attrs.peer) из trusted_sources.
func (r *Responder) TrustedEvent(transport, peer string) bool {
	if TrustedTransports[strings.ToLower(strings.TrimSpace(transport))] {
		return true
	}
	host := strings.TrimSpace(peer)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	p := net.ParseIP(strings.Trim(host, "[]"))
	if p == nil {
		return false
	}
	for _, n := range r.trusted {
		if n.Contains(p) {
			return true
		}
	}
	return false
}

// Active — текущие блокировки (для консоли), постоянные — первыми.
func (r *Responder) Active() []Block {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Block, 0, len(r.active))
	for _, b := range r.active {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Until.IsZero() != out[j].Until.IsZero() {
			return out[i].Until.IsZero()
		}
		if !out[i].Until.Equal(out[j].Until) {
			return out[i].Until.Before(out[j].Until)
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// Pending — адреса в очереди повторов после неудачной автоблокировки.
func (r *Responder) Pending() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.retry)
}

// BlockIP — ручная блокировка оператором: выполняется в любом режиме, кроме
// адресов из allowlist/never_block. Срок — manual_ttl (по умолчанию 24h,
// 0 — бессрочно); автоматика её не перекрывает своим TTL, снимает — по сроку
// или через Unblock.
func (r *Responder) BlockIP(ctx context.Context, ip, incident, reason string) ([]Result, error) {
	ip = canonicalIP(ip)
	unlock := r.lockIP(ip)
	defer unlock()
	if !r.Enabled() {
		return nil, errors.New("обратный канал не настроен (respond в argus.analyst.yml)")
	}
	if strings.TrimSpace(reason) == "" {
		return nil, errors.New("нужна причина блокировки (reason)")
	}
	if err := r.Check(ip); err != nil {
		return nil, err
	}
	results := r.execute(ctx, ip, incident, reason)
	if ok := succeeded(results); len(ok) > 0 {
		r.mu.Lock()
		b := Block{IP: ip, Incident: incident, Manual: true, Executors: ok}
		if r.manualTTL > 0 {
			b.Until = r.nowFn().Add(r.manualTTL)
		}
		r.active[ip] = b
		delete(r.retry, ip)
		r.mu.Unlock()
	}
	return results, nil
}

// Auto — автоблокировка по правилу с учётом режима. Возвращает результаты
// (в simulate — с DryRun=true) и признак, что блокировка реально выполнена.
// В ips при отказе всех исполнителей адрес встаёт в очередь повторов (Retry).
func (r *Responder) Auto(ctx context.Context, ip, incident, reason string, ttl time.Duration) (results []Result, applied bool, err error) {
	ip = canonicalIP(ip)
	unlock := r.lockIP(ip)
	defer unlock()
	return r.auto(ctx, ip, incident, reason, ttl)
}

func canonicalIP(ip string) string {
	if c, ok := CanonicalIP(ip); ok {
		return c
	}
	return ip
}

// CanonicalIP — единственная запись адреса для ключей блокировки, журнала и
// очереди: netip, IPv4 из ::ffff:… — как IPv4, без зоны. Строка из события
// (src_ip — String) иначе давала бы разных владельцев одного адреса.
func CanonicalIP(ip string) (string, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return "", false
	}
	return a.WithZone("").Unmap().String(), true
}

// Outcome — итог одной попытки автоблокировки (Attempt).
type Outcome int

const (
	OutcomeBlocked       Outcome = iota + 1 // хотя бы один исполнитель заблокировал
	OutcomeNoop                             // адрес уже заблокирован (другим инцидентом или оператором)
	OutcomeSimulated                        // режим simulate: исполнители не вызывались
	OutcomeFailed                           // все исполнители отказали
	OutcomeRefused                          // адрес нельзя блокировать (allowlist, never_block, служебный)
	OutcomeReserveFailed                    // запись-резерв не сохранилась — исполнители не вызывались
)

// MaxAttempts и RetryDelay — расписание автоблокировки: первая попытка и maxRetries
// повторов с паузами retryBackoff, как у очереди Retry; в движке повторы ведёт
// автомат ключа (cmd/engine/respond_key.go).
const MaxAttempts = maxRetries + 1

func RetryDelay(attempt int) time.Duration {
	return retryBackoff[min(max(attempt-1, 0), len(retryBackoff)-1)]
}

// Attempt — одна попытка автоблокировки в режиме mode, снятом вызывающим один раз
// на попытку: переключение режима посреди попытки её не меняет. Очередь повторов
// не используется — повтор вызывающий проводит тем же путём. В ips перед
// исполнителями под блокировкой адреса вызывается reserve (запись вперёд); его
// ошибка — исполнители не вызываются (OutcomeReserveFailed). Режим ids — ошибка:
// решение «ничего не делать» принимает вызывающий.
func (r *Responder) Attempt(ctx context.Context, mode, ip, incident, reason string, ttl time.Duration, reserve func() error) ([]Result, Outcome, error) {
	ip = canonicalIP(ip)
	unlock := r.lockIP(ip)
	defer unlock()
	switch mode {
	case ModeSimulate, ModeIPS:
	default:
		return nil, 0, fmt.Errorf("режим %q: попытка блокировки не выполняется", mode)
	}
	if !r.Enabled() {
		return nil, 0, errors.New("обратный канал не настроен (respond в argus.analyst.yml)")
	}
	if err := r.Check(ip); err != nil {
		return []Result{{Executor: "argus", OK: true, IP: ip, Incident: incident, Detail: err.Error()}}, OutcomeRefused, nil
	}
	if ttl <= 0 {
		ttl = r.ttl
	}
	if mode == ModeSimulate {
		var results []Result
		for _, name := range r.executors() {
			results = append(results, Result{Executor: name, OK: true, DryRun: true, IP: ip, Incident: incident, Detail: fmt.Sprintf("симуляция: заблокировал бы %s на %s", ip, ttl)})
		}
		return results, OutcomeSimulated, nil
	}
	r.mu.Lock()
	if b, ok := r.active[ip]; ok && (b.Until.IsZero() || b.Until.After(r.nowFn())) {
		r.mu.Unlock()
		until := "постоянно (снятие не настроено)"
		if !b.Until.IsZero() {
			until = "до " + b.Until.Format(time.RFC3339)
			if b.Manual {
				until += " (оператор)"
			}
		}
		return []Result{{Executor: "argus", OK: true, Noop: true, IP: ip, Incident: incident, Detail: "уже заблокирован " + until}}, OutcomeNoop, nil
	}
	r.mu.Unlock()
	if reserve != nil {
		if err := reserve(); err != nil {
			return nil, OutcomeReserveFailed, err
		}
	}
	results := r.execute(ctx, ip, incident, reason)
	ok := succeeded(results)
	if len(ok) == 0 {
		return results, OutcomeFailed, nil
	}
	r.mu.Lock()
	delete(r.retry, ip)
	r.active[ip] = Block{IP: ip, Incident: incident, Until: r.nowFn().Add(ttl), Executors: ok}
	r.mu.Unlock()
	return results, OutcomeBlocked, nil
}

// lockIP covers both the external request and its state update. r.mu alone
// only protects maps and cannot prevent concurrent block/unblock requests.
func (r *Responder) lockIP(ip string) func() {
	h := fnv.New64a()
	_, _ = h.Write([]byte(ip))
	mu := &r.operations[h.Sum64()%uint64(len(r.operations))]
	mu.Lock()
	return mu.Unlock
}

func (r *Responder) auto(ctx context.Context, ip, incident, reason string, ttl time.Duration) (results []Result, applied bool, err error) {
	mode, _ := r.Mode()
	if mode == ModeIDS {
		return nil, false, nil
	}
	if !r.Enabled() {
		return nil, false, errors.New("обратный канал не настроен (respond в argus.analyst.yml)")
	}
	if err := r.Check(ip); err != nil {
		return nil, false, err
	}
	if ttl <= 0 {
		ttl = r.ttl
	}
	if mode == ModeSimulate {
		for _, name := range r.executors() {
			results = append(results, Result{Executor: name, OK: true, DryRun: true, IP: ip, Incident: incident, Detail: fmt.Sprintf("симуляция: заблокировал бы %s на %s", ip, ttl)})
		}
		return results, false, nil
	}
	r.mu.Lock()
	if b, ok := r.active[ip]; ok && (b.Until.IsZero() || b.Until.After(r.nowFn())) {
		r.mu.Unlock()
		until := "постоянно (снятие не настроено)"
		if !b.Until.IsZero() {
			until = "до " + b.Until.Format(time.RFC3339)
			if b.Manual {
				until += " (оператор)"
			}
		}
		return []Result{{Executor: "argus", OK: true, Noop: true, IP: ip, Incident: incident, Detail: "уже заблокирован " + until}}, false, nil
	}
	r.mu.Unlock()
	results = r.execute(ctx, ip, incident, reason)
	ok := succeeded(results)
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(ok) == 0 {
		p := r.retry[ip]
		if p == nil {
			p = &pending{ip: ip, incident: incident, reason: reason, ttl: ttl}
			r.retry[ip] = p
		}
		if p.attempts < maxRetries {
			p.next = r.nowFn().Add(retryBackoff[min(p.attempts, len(retryBackoff)-1)])
			p.attempts++
			results = append(results, Result{Executor: "argus", OK: false, IP: ip, Incident: incident, Detail: fmt.Sprintf("все исполнители отказали — повтор №%d в %s", p.attempts, p.next.Format("15:04:05"))})
		} else {
			delete(r.retry, ip)
			results = append(results, Result{Executor: "argus", OK: false, IP: ip, Incident: incident, Detail: "все исполнители отказали, попытки исчерпаны — заблокируйте вручную"})
		}
		return results, false, nil
	}
	delete(r.retry, ip)
	r.active[ip] = Block{IP: ip, Incident: incident, Until: r.nowFn().Add(ttl), Executors: ok}
	return results, true, nil
}

// Retry — повторные попытки автоблокировки из очереди (вызывать каждый цикл).
// Вне режима ips очередь не трогается: в simulate каждый повтор писал бы
// в журнал «симуляция», не убывая; адреса дождутся возврата в ips.
func (r *Responder) Retry(ctx context.Context) []Result {
	if mode, _ := r.Mode(); mode != ModeIPS {
		return nil
	}
	r.mu.Lock()
	var due []*pending
	for _, p := range r.retry {
		if !p.next.After(r.nowFn()) {
			due = append(due, p)
		}
	}
	r.mu.Unlock()
	var out []Result
	for _, p := range due {
		unlock := r.lockIP(p.ip)
		r.mu.Lock()
		stillDue := r.retry[p.ip] == p && !p.next.After(r.nowFn())
		r.mu.Unlock()
		if !stillDue {
			unlock()
			continue
		}
		res, _, err := r.auto(ctx, p.ip, p.incident, p.reason, p.ttl)
		unlock()
		if err != nil {
			out = append(out, Result{Executor: "argus", IP: p.ip, Incident: p.incident, Detail: err.Error()})
			continue
		}
		out = append(out, res...)
	}
	return out
}

// releaseStatus — чем закончилось снятие у одного исполнителя.
type releaseStatus int

const (
	released    releaseStatus = iota // блок снят (или подтверждённо снят таймаутом)
	releaseFail                      // исполнитель ответил ошибкой — повторить позже
	unsupported                      // снятие не настроено — блок остаётся, снимать вручную
)

// release — снятие блока у одного исполнителя. manual — по запросу оператора
// (Wazuh тогда не считает «снятие таймаутом» успехом: срок ещё не вышел).
func (r *Responder) release(ctx context.Context, name string, b Block, reason string, manual bool) (Result, releaseStatus) {
	res := Result{Executor: name + ".unblock", IP: b.IP, Incident: b.Incident}
	if name == WazuhExecutor {
		w := r.cfg.WazuhAR
		switch {
		case w == nil:
			res.Detail = "исполнитель Wazuh выключен в конфиге — снимите блок на агентах вручную"
			return res, unsupported
		case w.UnblockCommand != "":
			if err := r.wazuh(ctx, w, w.UnblockCommand, b.IP); err != nil {
				res.Detail = err.Error() + " — повтор через 5 мин"
				return res, releaseFail
			}
			res.OK, res.Detail = true, w.UnblockCommand+" → агенты "+w.Agents+": разблокирован "+b.IP
			return res, released
		case !manual && w.Timeout > 0:
			res.OK, res.Detail = true, fmt.Sprintf("TTL истёк для %s: снят таймаутом <timeout>=%d с на менеджере Wazuh", b.IP, w.Timeout)
			return res, released
		case !manual:
			res.Detail = "TTL не подтверждён: API Wazuh не принимает срок, задайте <timeout> в ossec.conf менеджера и wazuh_active_response.timeout — блок остаётся в списке"
			return res, unsupported
		default:
			res.Detail = "досрочное снятие через API Wazuh невозможно (firewall-drop снимается только таймаутом менеджера); задайте unblock_command"
			return res, unsupported
		}
	}
	h, found := r.httpByName(name)
	if !found || h.Unblock == nil {
		res.Detail = "снятие не настроено (unblock) — блок остаётся постоянным, снимите на NGFW вручную"
		return res, unsupported
	}
	call := HTTPAction{Name: h.Name, Method: h.Unblock.Method, URL: h.Unblock.URL, Body: h.Unblock.Body, Headers: h.Headers, Insecure: h.Insecure}
	if err := r.httpCall(ctx, call, b.IP, b.Incident, reason); err != nil {
		res.Detail = err.Error() + " — повтор через 5 мин"
		return res, releaseFail
	}
	res.OK, res.Detail = true, "разблокирован "+b.IP
	return res, released
}

// Expire снимает истёкшие блокировки (авто и ручные) у тех исполнителей, где
// они стояли: NGFW — через шаблон unblock; Wazuh — unblock_command либо
// подтверждённый timeout. Без способа снятия блок остаётся постоянным и виден
// в консоли; ошибка снятия — следующая попытка через 5 минут.
func (r *Responder) Expire(ctx context.Context) []Result {
	now := r.nowFn()
	r.mu.Lock()
	var due []Block
	for _, b := range r.active {
		if !b.Until.IsZero() && !b.Until.After(now) {
			due = append(due, b)
		}
	}
	r.mu.Unlock()
	var out []Result
	for _, b := range due {
		out = append(out, r.expireBlock(ctx, b, now)...)
	}
	return out
}

func (r *Responder) expireBlock(ctx context.Context, b Block, now time.Time) []Result {
	unlock := r.lockIP(b.IP)
	defer unlock()
	r.mu.Lock()
	current, ok := r.active[b.IP]
	if !ok || current.Incident != b.Incident || !current.Until.Equal(b.Until) {
		r.mu.Unlock()
		return nil
	}
	b = current
	r.mu.Unlock()
	var out []Result
	var failed, permanent bool
	var remaining []string
	for _, name := range b.Executors {
		res, st := r.release(ctx, name, b, "TTL истёк", false)
		out = append(out, res)
		switch st {
		case releaseFail:
			failed = true
			remaining = append(remaining, name)
		case unsupported:
			permanent = true
			remaining = append(remaining, name)
		}
	}
	r.mu.Lock()
	if len(remaining) > 0 {
		nb := Block{IP: b.IP, Incident: b.Incident, Manual: b.Manual, Executors: remaining}
		if failed && !permanent {
			nb.Until = now.Add(5 * time.Minute)
		}
		r.active[b.IP] = nb
	} else {
		delete(r.active, b.IP)
	}
	r.mu.Unlock()
	return out
}

// Unblock — снятие блокировки по запросу оператора (ручной или авто) у всех
// исполнителей, где она стоит. Ошибка — блок не найден или ни один исполнитель
// не умеет снимать; отказ исполнителя — в результатах с ok=false, блок остаётся.
func (r *Responder) Unblock(ctx context.Context, ip, reason string) ([]Result, error) {
	ip = canonicalIP(ip)
	unlock := r.lockIP(ip)
	defer unlock()
	if strings.TrimSpace(reason) == "" {
		return nil, errors.New("нужна причина снятия (reason)")
	}
	r.mu.Lock()
	b, ok := r.active[ip]
	if !ok {
		_, queued := r.retry[ip]
		delete(r.retry, ip)
		r.mu.Unlock()
		if queued {
			return []Result{{Executor: "argus", OK: true, IP: ip, Detail: "адрес был только в очереди повторов — убран из неё"}}, nil
		}
		return nil, fmt.Errorf("блокировка %s не найдена", ip)
	}
	r.mu.Unlock()
	var out []Result
	var remaining []string
	supported := 0
	for _, name := range b.Executors {
		res, st := r.release(ctx, name, b, reason, true)
		out = append(out, res)
		if st != unsupported {
			supported++
		}
		if st != released {
			remaining = append(remaining, name)
		}
	}
	r.mu.Lock()
	// Пока ходили по сети, блок могли снять по TTL и поставить заново (другой
	// инцидент, другой срок): чужую запись не трогаем.
	if cur, still := r.active[ip]; still && cur.Incident == b.Incident && cur.Until.Equal(b.Until) {
		if len(remaining) == 0 {
			delete(r.active, ip)
		} else {
			cur.Executors = remaining
			r.active[ip] = cur
		}
	}
	r.mu.Unlock()
	if supported == 0 {
		return out, fmt.Errorf("снятие блокировки %s не настроено ни у одного исполнителя (%s)", ip, strings.Join(b.Executors, ", "))
	}
	return out, nil
}

func (r *Responder) httpByName(name string) (HTTPAction, bool) {
	for _, h := range r.cfg.HTTP {
		if h.Name == name {
			return h, true
		}
	}
	return HTTPAction{}, false
}

func succeeded(results []Result) []string {
	var ok []string
	for _, res := range results {
		if res.OK {
			ok = append(ok, res.Executor)
		}
	}
	return ok
}

func (r *Responder) executors() []string {
	var names []string
	if r.cfg.WazuhAR != nil {
		names = append(names, WazuhExecutor)
	}
	for _, h := range r.cfg.HTTP {
		names = append(names, h.Name)
	}
	return names
}

func (r *Responder) execute(ctx context.Context, ip, incident, reason string) []Result {
	var out []Result
	if w := r.cfg.WazuhAR; w != nil {
		res := Result{Executor: WazuhExecutor, IP: ip, Incident: incident}
		cmd := orDefault(w.Command, "firewall-drop")
		if err := r.wazuh(ctx, w, cmd, ip); err != nil {
			res.Detail = err.Error()
		} else {
			res.OK, res.Detail = true, cmd+" → агенты "+w.Agents
		}
		out = append(out, res)
	}
	for _, h := range r.cfg.HTTP {
		res := Result{Executor: h.Name, IP: ip, Incident: incident}
		if err := r.httpCall(ctx, h, ip, incident, reason); err != nil {
			res.Detail = err.Error()
		} else {
			res.OK, res.Detail = true, orDefault(h.Method, http.MethodPost)+" "+h.URL
		}
		out = append(out, res)
	}
	return out
}

func (r *Responder) wazuhToken(ctx context.Context, w *WazuhAR) (string, error) {
	r.mu.Lock()
	if r.wzTok != "" && r.nowFn().Before(r.wzTokExp) {
		tok := r.wzTok
		r.mu.Unlock()
		return tok, nil
	}
	r.mu.Unlock()
	base := strings.TrimRight(w.APIURL, "/")
	ctx, cancel := context.WithTimeout(ctx, executorTimeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/security/user/authenticate?raw=true", nil)
	req.SetBasicAuth(w.User, w.Password)
	resp, err := r.client(w.Insecure).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	tok, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("wazuh auth %s", resp.Status)
	}
	t := strings.TrimSpace(string(tok))
	r.mu.Lock()
	r.wzTok, r.wzTokExp = t, r.nowFn().Add(10*time.Minute) // JWT Wazuh живёт 15 минут
	r.mu.Unlock()
	return t, nil
}

// wazuh — PUT /active-response (API 4.x): {"command", "arguments", "alert"}.
// Срок в запросе не передаётся — его определяет <timeout> на менеджере.
// Успех — только total_affected_items > 0: 200 приходит и при отключённых агентах.
func (r *Responder) wazuh(ctx context.Context, w *WazuhAR, command, ip string) error {
	tok, err := r.wazuhToken(ctx, w)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, executorTimeout)
	defer cancel()
	body, _ := json.Marshal(map[string]any{"command": command, "arguments": []string{ip}, "alert": map[string]any{"data": map[string]string{"srcip": ip}}})
	u := strings.TrimRight(w.APIURL, "/") + "/active-response?agents_list=" + url.QueryEscape(w.Agents)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client(w.Insecure).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode == http.StatusUnauthorized {
		r.mu.Lock()
		r.wzTok = ""
		r.mu.Unlock()
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("active-response %s: %s", resp.Status, strings.TrimSpace(string(out[:min(len(out), 200)])))
	}
	var ar struct {
		Data struct {
			TotalAffected int `json:"total_affected_items"`
			TotalFailed   int `json:"total_failed_items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &ar); err != nil {
		return fmt.Errorf("active-response: ответ 2xx не разбирается: %s", strings.TrimSpace(string(out[:min(len(out), 200)])))
	}
	if ar.Data.TotalAffected <= 0 {
		return fmt.Errorf("active-response: ни один агент не принял команду %s (affected=0, failed=%d)", command, ar.Data.TotalFailed)
	}
	return nil
}

// substitute — подстановка плейсхолдеров: в теле и заголовках значения
// экранируются как JSON-строки (без внешних кавычек), в URL — как компонент пути.
func substitute(tpl string, vals map[string]string, forURL bool) string {
	out := tpl
	for k, v := range vals {
		enc := v
		if forURL {
			enc = url.PathEscape(v)
		} else {
			b, _ := json.Marshal(v)
			enc = string(b[1 : len(b)-1])
		}
		out = strings.ReplaceAll(out, "${"+k+"}", enc)
	}
	return out
}

func (r *Responder) httpCall(ctx context.Context, h HTTPAction, ip, incident, reason string) error {
	vals := map[string]string{"ip": ip, "incident": incident, "reason": reason}
	ctx, cancel := context.WithTimeout(ctx, executorTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, orDefault(h.Method, http.MethodPost), substitute(h.URL, vals, true), strings.NewReader(substitute(h.Body, vals, false)))
	if err != nil {
		return err
	}
	for k, v := range h.Headers {
		req.Header.Set(k, substitute(v, vals, false))
	}
	if req.Header.Get("Content-Type") == "" && h.Body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.client(h.Insecure).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: %s", h.Name, resp.Status, strings.TrimSpace(string(out[:min(len(out), 200)])))
	}
	if h.expectRe != nil && !h.expectRe.Match(out) {
		return fmt.Errorf("%s: ответ 2xx не совпал с expect %q: %s", h.Name, h.Expect, strings.TrimSpace(string(out[:min(len(out), 200)])))
	}
	if len(h.ExpectJSON) > 0 {
		if err := expectJSON(out, h.ExpectJSON); err != nil {
			return fmt.Errorf("%s: %w: %s", h.Name, err, strings.TrimSpace(string(out[:min(len(out), 200)])))
		}
	}
	return nil
}

// expectJSON — каждый ключ (верхнего уровня или путь через точку) должен
// присутствовать в ответе и равняться ожидаемому значению.
func expectJSON(body []byte, want map[string]any) error {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return errors.New("ответ 2xx не JSON, expect_json не проверить")
	}
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		cur := doc
		for _, part := range strings.Split(k, ".") {
			m, ok := cur.(map[string]any)
			if !ok {
				return fmt.Errorf("expect_json: ключа %q нет в ответе", k)
			}
			if cur, ok = m[part]; !ok {
				return fmt.Errorf("expect_json: ключа %q нет в ответе", k)
			}
		}
		if !jsonEqual(cur, want[k]) {
			return fmt.Errorf("expect_json: %s = %v, ожидалось %v", k, cur, want[k])
		}
	}
	return nil
}

// jsonEqual — сравнение значения из ответа с ожиданием из YAML: числа
// приводятся к float64, остальное — по значению.
func jsonEqual(got, want any) bool {
	toF := func(v any) (float64, bool) {
		switch x := v.(type) {
		case float64:
			return x, true
		case float32:
			return float64(x), true
		case int:
			return float64(x), true
		case int64:
			return float64(x), true
		case uint64:
			return float64(x), true
		}
		return 0, false
	}
	if g, ok := toF(got); ok {
		w, ok2 := toF(want)
		return ok2 && g == w
	}
	return reflect.DeepEqual(got, want)
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
