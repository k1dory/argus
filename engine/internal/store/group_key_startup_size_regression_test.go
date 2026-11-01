package store

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

type groupKeySizeTransport func(*http.Request) (*http.Response, error)

func (f groupKeySizeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// ClickHouse's default http_max_uri_size is 1 MiB, including URL-encoded
// query parameters: https://clickhouse.com/docs/interfaces/http . Restoring
// group keys must not make startup depend on the total open-incident count.
// This transport models that documented limit without running a server or
// sending a large request to a shared database.
func TestGroupKeyStartupFitsClickHouseURILimit(t *testing.T) {
	const count, firstID, maxURI = 60000, 100000, 1 << 20
	var current strings.Builder
	ids := make([]string, count)
	for i := range ids {
		ids[i] = fmt.Sprintf("INC-%d", firstID+i)
		fmt.Fprintf(&current, "{\"incident_id\":%q,\"status\":%q}\n", ids[i], incidents.StatusNew)
	}
	response := func(code int, body string) *http.Response {
		return &http.Response{
			StatusCode: code, Status: fmt.Sprintf("%d %s", code, http.StatusText(code)),
			Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)),
		}
	}
	idPattern := regexp.MustCompile(`INC-[0-9]+`)
	c := New("http://clickhouse.invalid", "argus", "", "")
	c.http = &http.Client{Transport: groupKeySizeTransport(func(r *http.Request) (*http.Response, error) {
		if size := len(r.URL.RequestURI()); size > maxURI {
			return response(http.StatusRequestURITooLong, fmt.Sprintf("URI is %d bytes; maximum is %d", size, maxURI)), nil
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		query := string(body)
		if strings.Contains(query, "FROM incidents_current") {
			return response(http.StatusOK, current.String()), nil
		}
		if strings.Contains(query, "group_key") {
			selected := ids
			if param := r.URL.Query().Get("param_ids"); param != "" {
				selected = idPattern.FindAllString(param, -1)
			}
			var keys strings.Builder
			for _, id := range selected {
				fmt.Fprintf(&keys, "{\"incident_id\":%q,\"group_key\":%q}\n", id, "object-"+id)
			}
			return response(http.StatusOK, keys.String()), nil
		}
		return nil, fmt.Errorf("unexpected startup query: %s", query)
	})}
	open, maxN, err := c.OpenIncidents(context.Background())
	if err != nil {
		t.Fatalf("restoring %d open incidents must fit ClickHouse's default URI limit; the engine startup loop otherwise retries forever: %v", count, err)
	}
	if len(open) != count || maxN != firstID+count-1 {
		t.Fatalf("incomplete restoration: incidents=%d maxN=%d", len(open), maxN)
	}
	for _, inc := range open {
		if inc.GroupKey != "object-"+inc.IncidentID {
			t.Fatalf("lost group key for %s: %q", inc.IncidentID, inc.GroupKey)
		}
	}
}
