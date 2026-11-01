package asn

import (
	"compress/gzip"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// These prefixes are explicitly not globally reachable in the IANA IPv6
// Special-Purpose Address Registry (last updated 2025-10-09):
// https://www.iana.org/assignments/iana-ipv6-special-registry/
// The table is deliberately given a nonzero ASN: Enrich promises to enforce
// the public-address boundary independently of the contents of the database.
func TestPR56EnrichRejectsSpecialIPv6(t *testing.T) {
	for _, ip := range []string{
		"100:0:0:1::1",                           // RFC 9780: dummy prefix, outside 100::/64.
		"3fff::1",                                // RFC 9637: documentation.
		"3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", // Last address in 3fff::/20.
		"5f00::1",                                // RFC 9602: SRv6 SIDs, not globally reachable.
	} {
		t.Run(ip, func(t *testing.T) {
			table := mustParse(t, fmt.Sprintf("%s\t%s\t64500\tZZ\tFIXTURE\n", ip, ip))
			if Public(netip.MustParseAddr(ip)) {
				t.Errorf("Public(%s) accepted an IANA non-global address", ip)
			}
			attrs := map[string]string{
				SrcASN: "1", SrcASOrg: "sender", DstASN: "2", DstASOrg: "sender",
				"keep": "value",
			}
			Enrich(attrs, ip, ip, table)
			for _, key := range []string{SrcASN, SrcASOrg, DstASN, DstASOrg} {
				if value, exists := attrs[key]; exists {
					t.Errorf("non-public %s retained %s=%q", ip, key, value)
				}
			}
			if attrs["keep"] != "value" {
				t.Fatal("unrelated attribute was removed")
			}
		})
	}
}

// AS112 has globally reachable IPv4 and IPv6 special-purpose allocations.
// Rejecting all of 2001::/23 incorrectly excludes its more-specific AS112
// allocation, while the analogous IPv4 allocation is already accepted.
func TestPR56EnrichKeepsGloballyReachableAS112(t *testing.T) {
	for _, ip := range []string{"192.31.196.1", "2001:4:112::1"} {
		t.Run(ip, func(t *testing.T) {
			table := mustParse(t, fmt.Sprintf("%s\t%s\t64500\tZZ\tFIXTURE\n", ip, ip))
			attrs := map[string]string{}
			Enrich(attrs, ip, ip, table)
			if !Public(netip.MustParseAddr(ip)) || attrs[SrcASN] != "64500" || attrs[DstASN] != "64500" {
				t.Fatalf("globally reachable AS112 address %s was excluded: %v", ip, attrs)
			}
		})
	}
}

// Exercise retained memory, not peak parsing allocations. A small compressed
// fixture expands to 64 rows with distinct names; after truncation the table
// only needs 64 * MaxOrgLen bytes for those names. The generous 4 MiB budget
// tolerates runtime overhead while detecting retention of the full 16 MiB TSV.
// This deliberately stays small and never attempts to exhaust process memory.
func TestPR56ParseDoesNotRetainTruncatedOrgBackingStorage(t *testing.T) {
	const rows = 64
	path := filepath.Join(t.TempDir(), "long-orgs.tsv.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := gzip.NewWriter(f)
	for i := 0; i < rows; i++ {
		_, err := fmt.Fprintf(w, "8.8.8.%d\t8.8.8.%d\t64500\tZZ\tAS-%03d-%s\n",
			i, i, i, strings.Repeat("x", 256<<10))
		if err != nil {
			_ = w.Close()
			_ = f.Close()
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f, err = os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	table, parseErr := Parse(f, rows)
	closeErr := f.Close()
	if parseErr != nil || closeErr != nil {
		t.Fatalf("parse=%v, close=%v", parseErr, closeErr)
	}
	if table.Rows() != rows || len(table.orgs) != rows {
		t.Fatalf("fixture lost distinct ranges/organizations: %d/%d", table.Rows(), len(table.orgs))
	}
	for _, org := range table.orgs {
		if len(org) != MaxOrgLen {
			t.Fatalf("fixture name was not truncated: %d bytes", len(org))
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(table)
	if after.HeapAlloc > before.HeapAlloc+(4<<20) {
		t.Fatalf("64 truncated organization names retained %d bytes; budget is 4 MiB",
			after.HeapAlloc-before.HeapAlloc)
	}
}

// Coverage control for atomic replacements: readers must always observe a
// complete immutable table. Both versions have the same length; only mtime
// changes. Run with -race to cover publication concurrent with lookups.
func TestPR56ReloadAtomicReplacementWhileReading(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asn.tsv")
	baseTime := time.Unix(1700000000, 0)
	install := func(version int) {
		t.Helper()
		body := fmt.Sprintf("8.8.8.0\t8.8.8.255\t%d\tZZ\tORG%d\n", 64500+version, version)
		staged := path + ".new"
		if err := os.WriteFile(staged, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		mtime := baseTime.Add(time.Duration(version) * time.Second)
		if err := os.Chtimes(staged, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(staged, path); err != nil {
			t.Fatal(err)
		}
	}
	install(0)
	db := Open(path, 1)
	if db.Table() == nil {
		t.Fatal("initial table did not load")
	}
	var readers sync.WaitGroup
	stop := make(chan struct{})
	defer func() { close(stop); readers.Wait() }()
	ip := netip.MustParseAddr("8.8.8.8")
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				n, org, ok := db.Table().Lookup(ip)
				if !ok || n < 64500 || n > 64508 || org != fmt.Sprintf("ORG%d", n-64500) {
					t.Errorf("reader saw an incomplete table: %d %q %v", n, org, ok)
					return
				}
			}
		}()
	}
	for version := 1; version <= 8; version++ {
		install(version)
		if err := db.Reload(); err != nil {
			t.Fatal(err)
		}
		if n, _, ok := db.Table().Lookup(ip); !ok || n != uint32(64500+version) {
			t.Fatalf("replacement %d was not published: %d %v", version, n, ok)
		}
	}
}

func TestPR56LookupIPv6InclusiveBoundaries(t *testing.T) {
	table := mustParse(t, "2606:4700::10\t2606:4700::ff\t13335\tUS\tFIRST\n"+
		"2606:4700::100\t2606:4700::1ff\t15169\tUS\tNEXT\n"+
		"2606:4700::201\t2606:4700::2ff\t0\tNone\tNot routed\n")
	for _, tc := range []struct {
		ip  string
		asn uint32
	}{
		{"2606:4700::f", 0}, {"2606:4700::10", 13335}, {"2606:4700::ff", 13335},
		{"2606:4700::100", 15169}, {"2606:4700::1ff", 15169}, {"2606:4700::200", 0},
		{"2606:4700::201", 0}, {"2606:4700::2ff", 0}, {"2606:4700::300", 0},
	} {
		if n, _, ok := table.Lookup(netip.MustParseAddr(tc.ip)); n != tc.asn || ok != (tc.asn != 0) {
			t.Errorf("Lookup(%s) = %d, %v; want %d, %v", tc.ip, n, ok, tc.asn, tc.asn != 0)
		}
	}
}
