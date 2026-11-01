package store

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

// Cover the partial final batch and a late HTTP-200 exception: successful
// earlier batches must not leak a partially restored registry to the caller.
// This transport does not open sockets or require a ClickHouse instance.
func TestPR9GroupKeyBatchesAreAtomic(t *testing.T) {
	for _, failLast := range []bool{false, true} {
		t.Run(fmt.Sprintf("late_exception=%t", failLast), func(t *testing.T) {
			const count = 5001
			open := make([]incidents.Incident, count)
			ids := make([]string, count)
			for i := range open {
				ids[i] = fmt.Sprintf("INC-%d", i+1)
				open[i] = incidents.Incident{IncidentID: ids[i], GroupKey: "before-" + ids[i]}
			}
			calls := 0
			c := New("http://clickhouse.invalid", "argus", "", "")
			c.http = &http.Client{Transport: groupKeySizeTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				var batch []string
				switch calls {
				case 1:
					batch = ids[:5000]
				case 2:
					batch = ids[5000:]
				default:
					return nil, fmt.Errorf("unexpected group-key batch %d", calls)
				}
				if got, want := r.URL.Query().Get("param_ids"), chArray(batch); got != want {
					return nil, fmt.Errorf("batch %d must contain exactly its %d incident IDs", calls, len(batch))
				}
				query, err := io.ReadAll(r.Body)
				if err != nil {
					return nil, err
				}
				if !strings.Contains(string(query), "argMax(group_key,") {
					return nil, fmt.Errorf("unexpected group-key query: %s", query)
				}
				var body strings.Builder
				for _, id := range batch {
					key := "restored-" + id
					if id == ids[0] {
						key = "" // A real legacy row legitimately has an empty key.
					}
					fmt.Fprintf(&body, "{\"incident_id\":%q,\"group_key\":%q}\n", id, key)
				}
				if calls == 2 && failLast {
					fmt.Fprintln(&body, `{"exception":"Code: 159. DB::Exception: Timeout exceeded"}`)
				}
				return &http.Response{
					StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header),
					Body: io.NopCloser(strings.NewReader(body.String())),
				}, nil
			})}
			err := c.restoreGroupKeys(context.Background(), open)
			if (err != nil) != failLast {
				t.Fatalf("restore error=%v, want error=%t", err, failLast)
			}
			if calls != 2 {
				t.Fatalf("batch calls=%d, want 2 (5000+1 IDs)", calls)
			}
			for i, inc := range open {
				want := "restored-" + ids[i]
				if i == 0 {
					want = ""
				}
				if failLast {
					want = "before-" + ids[i]
				}
				if inc.GroupKey != want {
					t.Fatalf("incident %s group_key=%q, want %q", inc.IncidentID, inc.GroupKey, want)
				}
			}
		})
	}
}
