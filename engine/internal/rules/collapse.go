package rules

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// Collapse — склейка сработок в один инцидент по подсети источника: сканы
// интернета идут с соседних адресов, и инцидент на каждый адрес забивает ленту.
// Порог правила по-прежнему считается на адрес (threshold.group_by: src.ip), а
// инцидент заводится на подсеть: /24 у IPv4, /48 у IPv6 (v4 и v6 не смешиваются).
// Group — общий ключ нескольких правил: обход хостов и скан портов с одного
// адреса — один инцидент, а не два. Блокировка остаётся по адресу.
type Collapse struct {
	By    string `yaml:"by"`    // src.net — подсеть src.ip (/24, IPv6 /48)
	Group string `yaml:"group"` // общий ключ правил (по умолчанию id правила)
	// BlockCap / BlockCapWindow — не больше стольких новых адресов инцидента
	// блокировать за окно (по умолчанию 32 за 1h); общие для группы.
	BlockCap       int    `yaml:"block_cap"`
	BlockCapWindow string `yaml:"block_cap_window"`
}

// Потолок новых блокировок одного инцидента за окно (collapse.block_cap):
// у склеенного инцидента адресов может быть сотни, и max_targets на сработку
// без общего потолка дал бы лавину блоков с одной подсети.
const (
	DefaultIncidentCap       = 32
	DefaultIncidentCapWindow = time.Hour
)

var collapseGroupRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// Collapsed — правило склеивает сработки по подсети.
func (r *Rule) Collapsed() bool { return r.Collapse != nil }

// CollapseGroup — ключ группы склейки (id правила, если group не задан).
func (r *Rule) CollapseGroup() string {
	if r.Collapse == nil {
		return ""
	}
	if r.Collapse.Group != "" {
		return r.Collapse.Group
	}
	return r.ID
}

// IncidentCap — сколько новых адресов инцидента блокировать за окно.
func (r *Rule) IncidentCap() (n int, window time.Duration) {
	n, window = DefaultIncidentCap, DefaultIncidentCapWindow
	if r.Collapse == nil {
		return n, window
	}
	if r.Collapse.BlockCap > 0 {
		n = r.Collapse.BlockCap
	}
	if d, err := time.ParseDuration(r.Collapse.BlockCapWindow); err == nil && d > 0 {
		window = d
	}
	return n, window
}

// NetKey — подсеть адреса для склейки: «203.0.113.0/24», «2001:db8:1::/48»;
// ok=false — не адрес (такая сработка заводит обычный инцидент на адрес).
// IPv4 в записи IPv6 (::ffff:a.b.c.d) считается IPv4.
func NetKey(ip string) (string, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return "", false
	}
	a = a.Unmap()
	bits := 48
	if a.Is4() {
		bits = 24
	}
	p, err := a.WithZone("").Prefix(bits)
	if err != nil {
		return "", false
	}
	return p.String(), true
}

func (r *Rule) validateCollapse() error {
	c := r.Collapse
	if c == nil {
		return nil
	}
	if c.By != "src.net" {
		return fmt.Errorf("collapse.by: поддерживается только src.net, получено %q", c.By)
	}
	if c.Group != "" && !collapseGroupRe.MatchString(c.Group) {
		return fmt.Errorf("collapse.group: строчные латинские буквы, цифры и дефис, получено %q", c.Group)
	}
	if !r.UsesThreshold() || r.IsAbsence() || r.GroupBy() != "src.ip" {
		return fmt.Errorf("collapse: нужен threshold с group_by: src.ip — порог считается на адрес")
	}
	if r.Respond != nil {
		if t := strings.TrimSpace(r.Respond.Target); t != "" && t != "src.ip" && t != "source.ip" {
			return fmt.Errorf("collapse: respond.target только src.ip — блокируется адрес участника, получено %q", t)
		}
	}
	if c.BlockCap < 0 {
		return fmt.Errorf("collapse.block_cap: %d, ожидалось ≥ 0", c.BlockCap)
	}
	if w := c.BlockCapWindow; w != "" {
		if d, err := time.ParseDuration(w); err != nil || d <= 0 {
			return fmt.Errorf("collapse.block_cap_window: %q", w)
		}
	}
	return nil
}

// checkCollapseGroups — правила одной группы склейки должны склеивать одинаково:
// общий инцидент закрывается по auto_close своего правила и считает один потолок
// блокировок, и разные by, auto_close или потолок дали бы разное поведение одного
// инцидента в зависимости от того, какое правило его представляет.
func checkCollapseGroups(rs []*Rule) error {
	first := map[string]*Rule{}
	for _, r := range rs {
		if !r.Collapsed() {
			continue
		}
		g := r.CollapseGroup()
		f, ok := first[g]
		if !ok {
			first[g] = r
			continue
		}
		if f.Collapse.By != r.Collapse.By || f.AutoClose != r.AutoClose {
			return fmt.Errorf("%s: collapse.group %q — by и auto_close должны совпадать с %s", r.File, g, f.File)
		}
		// respond у участников может отличаться (адрес блокируется по своему
		// правилу), но потолок блокировок у инцидента один.
		if a, b := capOf(f), capOf(r); a != b {
			return fmt.Errorf("%s: collapse.group %q — collapse.block_cap/block_cap_window должны совпадать с %s", r.File, g, f.File)
		}
	}
	return nil
}

func capOf(r *Rule) string {
	n, w := r.IncidentCap()
	return fmt.Sprint(n, w)
}
