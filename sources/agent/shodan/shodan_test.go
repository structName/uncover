package shodan

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/uncover/sources"
)

// TestQueryStopsAtExactLimitBoundary verifies the loop's >= check (not >)
// stops paging when numberOfResults exactly equals query.Limit.
//
// Shodan's /shodan/host/search has no page_size parameter (always returns
// up to 100 per page); the only knob the agent controls is when to stop.
// The previous code used `>` which always triggered an extra page request
// at exact-divisible limits (e.g., Limit=100 → fetched 200 then broke).
func TestQueryStopsAtExactLimitBoundary(t *testing.T) {
	t.Parallel()

	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		var items []string
		for i := 0; i < 100; i++ {
			items = append(items, fmt.Sprintf(
				`{"ip_str":"10.0.0.%d","port":80}`, i))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"total":1000,"matches":[` +
			strings.Join(items, ",") + `]}`))
	}))
	defer server.Close()

	session, err := sources.NewSession(
		&sources.Keys{
			Shodan:   "test-key",
			BaseURLs: map[string]string{"shodan": server.URL},
		},
		0, 10, 0,
		[]string{"shodan"},
		time.Second, "",
	)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	agent := &Agent{}
	ch, err := agent.Query(session, &sources.Query{Query: "port:80", Limit: 100})
	if err != nil {
		t.Fatalf("agent.Query failed: %v", err)
	}
	for range ch {
		// drain
	}

	if got := atomic.LoadInt32(&requestCount); got != 1 {
		t.Errorf("expected 1 API call when Limit=100 (exact page boundary), got %d (off-by-one regression)", got)
	}
}
