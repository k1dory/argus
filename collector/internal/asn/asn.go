// Package asn сопоставляет публичный IP-адрес автономной системе по локальной
// таблице iptoasn.com (TSV: range_start, range_end, AS_number, country_code,
// AS_description; допускается .gz). Внешних запросов нет: файл кладёт и
// обновляет роль развёртывания, коллектор перечитывает его по mtime.
//
// Поля событий attrs.src_asn / src_as_org / dst_asn / dst_as_org ставит только
// коллектор (Enrich): значения из тела события удаляются всегда, у частных и
// зарезервированных адресов полей нет. По src_asn движок склеивает сканы, и
// подставленный отправителем ASN увёл бы адрес в чужую группу.
package asn

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Ключи attrs, которые ставит Enrich.
const (
	SrcASN   = "src_asn"
	SrcASOrg = "src_as_org"
	DstASN   = "dst_asn"
	DstASOrg = "dst_as_org"
)

// MaxOrgLen — предел длины названия AS в attrs (байт, по границе руны).
const MaxOrgLen = 256

type range4 struct {
	start, end uint32
	asn        uint32
	org        uint32
}

type range6 struct {
	start, end [16]byte
	asn        uint32
	org        uint32
}

// Table — неизменяемая таблица диапазонов, отсортированная по началу.
type Table struct {
	v4   []range4
	v6   []range6
	orgs []string
}

// Rows — число диапазонов (v4 + v6).
func (t *Table) Rows() int { return len(t.v4) + len(t.v6) }

// Lookup — ASN и название для адреса; AS 0 («Not routed») и адрес вне
// таблицы — ok = false.
func (t *Table) Lookup(a netip.Addr) (asn uint32, org string, ok bool) {
	if t == nil {
		return 0, "", false
	}
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		x := binary.BigEndian.Uint32(b[:])
		i := sort.Search(len(t.v4), func(i int) bool { return t.v4[i].end >= x })
		if i < len(t.v4) && t.v4[i].start <= x && t.v4[i].asn != 0 {
			return t.v4[i].asn, t.orgs[t.v4[i].org], true
		}
		return 0, "", false
	}
	x := a.As16()
	i := sort.Search(len(t.v6), func(i int) bool { return bytes.Compare(t.v6[i].end[:], x[:]) >= 0 })
	if i < len(t.v6) && bytes.Compare(t.v6[i].start[:], x[:]) <= 0 && t.v6[i].asn != 0 {
		return t.v6[i].asn, t.orgs[t.v6[i].org], true
	}
	return 0, "", false
}

// Parse читает TSV iptoasn (или его gzip) и проверяет: пять полей в строке,
// адреса одного семейства, start ≤ end, диапазоны семейства по возрастанию без
// пересечений, ASN — число, строк не меньше minRows. Любое нарушение — ошибка
// с номером строки: битая таблица не заменяет рабочую.
func Parse(r io.Reader, minRows int) (*Table, error) {
	br := bufio.NewReaderSize(r, 1<<16)
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer gz.Close()
		br = bufio.NewReaderSize(gz, 1<<16)
	}
	t := &Table{}
	orgIdx := map[string]uint32{}
	intern := func(s string) uint32 {
		if i, ok := orgIdx[s]; ok {
			return i
		}
		i := uint32(len(t.orgs))
		t.orgs = append(t.orgs, s)
		orgIdx[s] = i
		return i
	}
	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimRight(sc.Text(), "\r")
		if text == "" {
			continue
		}
		f := strings.Split(text, "\t")
		if len(f) != 5 {
			return nil, fmt.Errorf("строка %d: %d полей вместо 5", line, len(f))
		}
		start, err1 := netip.ParseAddr(f[0])
		end, err2 := netip.ParseAddr(f[1])
		if err1 != nil || err2 != nil || start.Zone() != "" || end.Zone() != "" {
			return nil, fmt.Errorf("строка %d: адрес диапазона не разобран", line)
		}
		start, end = start.Unmap(), end.Unmap()
		if start.Is4() != end.Is4() || end.Less(start) {
			return nil, fmt.Errorf("строка %d: начало и конец диапазона несовместимы", line)
		}
		n, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("строка %d: ASN не число", line)
		}
		org := intern(cleanOrg(f[4]))
		if start.Is4() {
			s4, e4 := start.As4(), end.As4()
			r := range4{start: binary.BigEndian.Uint32(s4[:]), end: binary.BigEndian.Uint32(e4[:]), asn: uint32(n), org: org}
			if k := len(t.v4); k > 0 && r.start <= t.v4[k-1].end {
				return nil, fmt.Errorf("строка %d: диапазоны IPv4 не по возрастанию или пересекаются", line)
			}
			t.v4 = append(t.v4, r)
		} else {
			r := range6{start: start.As16(), end: end.As16(), asn: uint32(n), org: org}
			if k := len(t.v6); k > 0 && bytes.Compare(r.start[:], t.v6[k-1].end[:]) <= 0 {
				return nil, fmt.Errorf("строка %d: диапазоны IPv6 не по возрастанию или пересекаются", line)
			}
			t.v6 = append(t.v6, r)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("чтение: %w", err)
	}
	if t.Rows() < minRows {
		return nil, fmt.Errorf("%d диапазонов, нужно не меньше %d", t.Rows(), minRows)
	}
	return t, nil
}

// cleanOrg — название без управляющих символов, не длиннее MaxOrgLen байт.
// Результат — собственная копия: подстрока поля держала бы всю строку файла.
func cleanOrg(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0xfffd {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > MaxOrgLen {
		cut := MaxOrgLen
		for cut > 0 && (s[cut]&0xc0) == 0x80 {
			cut--
		}
		s = s[:cut]
	}
	return strings.Clone(s)
}

func prefixes(list ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(list))
	for i, s := range list {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// special — блоки реестров IANA IPv4/IPv6 Special-Purpose Address Registry с
// Globally Reachable = False или N/A (сверено с реестрами 2025-10), плюс multicast
// и 255.255.255.255. Для них ASN не ставится, что бы ни вернула таблица.
var special = prefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "100:0:0:1::/64",
	"2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16",
	"fc00::/7", "fe80::/10", "ff00::/8",
)

// reachable — более узкие блоки внутри special с Globally Reachable = True:
// они публичные (AS112, AMT, ORCHIDv2, Drone DET, anycast PCP/TURN).
var reachable = prefixes(
	"192.0.0.9/32", "192.0.0.10/32",
	"2001:1::1/128", "2001:1::2/128", "2001:1::3/128", "2001:3::/32",
	"2001:4:112::/48", "2001:20::/28", "2001:30::/28",
)

// Public — адрес вне частных и зарезервированных диапазонов.
func Public(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.Zone() != "" {
		return false
	}
	for _, p := range reachable {
		if p.Contains(a) {
			return true
		}
	}
	for _, p := range special {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// DB — текущая таблица с перечитыванием файла по mtime. Пустая DB (без файла
// или до первой удачной загрузки) ничего не находит.
type DB struct {
	path    string
	minRows int
	table   atomic.Pointer[Table]
	mtime   time.Time
	size    int64
}

// Open загружает файл. Ошибка первой загрузки не фатальна: DB остаётся пустой,
// Watch повторит попытку, когда файл изменится.
func Open(path string, minRows int) *DB {
	db := &DB{path: path, minRows: minRows}
	if err := db.Reload(); err != nil {
		slog.Warn("asn: таблица не загружена, обогащения ASN нет", "path", path, "err", err)
	}
	return db
}

var errUnchanged = errors.New("не изменился")

// Reload перечитывает файл, если изменились mtime или размер. Битый файл —
// ошибка, прежняя таблица остаётся.
func (db *DB) Reload() error {
	fi, err := os.Stat(db.path)
	if err != nil {
		return err
	}
	if db.table.Load() != nil && fi.ModTime().Equal(db.mtime) && fi.Size() == db.size {
		return errUnchanged
	}
	f, err := os.Open(db.path)
	if err != nil {
		return err
	}
	defer f.Close()
	t, err := Parse(f, db.minRows)
	if err != nil {
		return err
	}
	db.table.Store(t)
	db.mtime, db.size = fi.ModTime(), fi.Size()
	slog.Info("asn: таблица загружена", "path", db.path, "rows", t.Rows())
	return nil
}

// Watch проверяет файл раз в every, пока ctx жив.
func (db *DB) Watch(ctx context.Context, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := db.Reload(); err != nil && !errors.Is(err, errUnchanged) {
				slog.Warn("asn: файл не перечитан, остаётся прежняя таблица", "path", db.path, "err", err)
			}
		}
	}
}

// Table — текущая таблица (nil, если не загружена).
func (db *DB) Table() *Table {
	if db == nil {
		return nil
	}
	return db.table.Load()
}

// Enrich убирает из attrs поля ASN, пришедшие с событием, и ставит свои для
// публичных src и dst. t == nil — только удаление.
func Enrich(attrs map[string]string, src, dst string, t *Table) {
	delete(attrs, SrcASN)
	delete(attrs, SrcASOrg)
	delete(attrs, DstASN)
	delete(attrs, DstASOrg)
	if t == nil {
		return
	}
	set := func(ip, kASN, kOrg string) {
		a, err := netip.ParseAddr(ip)
		if err != nil || !Public(a) {
			return
		}
		if n, org, ok := t.Lookup(a); ok {
			attrs[kASN] = strconv.FormatUint(uint64(n), 10)
			if org != "" {
				attrs[kOrg] = org
			}
		}
	}
	set(src, SrcASN, SrcASOrg)
	set(dst, DstASN, DstASOrg)
}
