package parse

import (
	"testing"
	"time"
)

func TestPeerZoneLocalNewYear(t *testing.T) {
	previous := now
	t.Cleanup(func() { now = previous })
	for _, tc := range []struct {
		name, received, zone, header, want string
	}{
		{"Moscow already in next year", "2026-12-31T22:00:00Z", "Europe/Moscow", "Jan  1 00:59:00", "2026-12-31T21:59:00Z"},
		{"Tokyo already in next year", "2026-12-31T16:00:00Z", "Asia/Tokyo", "Jan  1 00:59:00", "2026-12-31T15:59:00Z"},
		{"explicit year is preserved", "2026-12-31T22:00:00Z", "Europe/Moscow", "Jan  1 2027 00:59:00", "2026-12-31T21:59:00Z"},
		{"western peer still in previous year", "2027-01-01T01:00:00Z", "America/Los_Angeles", "Dec 31 16:59:00", "2027-01-01T00:59:00Z"},
		{"RFC5424 offset is authoritative", "2026-12-31T22:00:00Z", "Asia/Tokyo", "1 2027-01-01T00:59:00+03:00", "2026-12-31T21:59:00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			received, err := time.Parse(time.RFC3339, tc.received)
			if err != nil {
				t.Fatal(err)
			}
			now = func() time.Time { return received }
			loc, err := time.LoadLocation(tc.zone)
			if err != nil {
				t.Fatal(err)
			}
			line := "<30>" + tc.header + " QNAP-2 qulogd[1]: message"
			if tc.header[0] == '1' {
				line = "<30>" + tc.header + " QNAP-2 qulogd 1 - - message"
			}
			sl, err := ParseSyslog(line)
			if err != nil {
				t.Fatal(err)
			}
			if got := sl.InZone(loc).Timestamp.UTC().Format(time.RFC3339); got != tc.want {
				t.Fatalf("peer=%s received=%s header=%q: got %s, want %s; year must be inferred in the peer's zone", tc.zone, tc.received, tc.header, got, tc.want)
			}
		})
	}
}
