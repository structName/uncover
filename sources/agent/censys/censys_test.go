package censys

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/uncover/sources"
)

// makeHits builds N "webproperty hits" with empty endpoints — enough for
// the agent's loop to count `len(hits)` and apply the limit check, while
// avoiding the need to construct realistic asset payloads.
func makeHits(n int) string {
	items := make([]string, n)
	for i := 0; i < n; i++ {
		items[i] = `{"webproperty_v1":{"resource":{"endpoints":[]}}}`
	}
	return strings.Join(items, ",")
}

// TestQueryRespectsLimitWithSinglePage verifies Censys's pagination loop
// derives PageSize from query.Limit when Limit < MaxPerPage, so a single
// API call covers the requested rows.
func TestQueryRespectsLimitWithSinglePage(t *testing.T) {
	t.Parallel()

	var requestCount int32
	var capturedPageSize int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v3/global/search/query") {
			http.NotFound(w, r)
			return
		}
		atomic.AddInt32(&requestCount, 1)
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		if v, ok := req["page_size"].(float64); ok {
			atomic.StoreInt32(&capturedPageSize, int32(v))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w,
			`{"result":{"hits":[%s],"next_page_token":"","total_hits":1000}}`,
			makeHits(30))
	}))
	defer server.Close()

	session, err := sources.NewSession(
		&sources.Keys{
			CensysToken: "test-token",
			CensysOrgId: "test-org",
			BaseURLs:    map[string]string{"censys": server.URL},
		},
		0, 10, 0,
		[]string{"censys"},
		time.Second, "",
	)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	agent := &Agent{}
	ch, err := agent.Query(session, &sources.Query{Query: "service:http", Limit: 30})
	if err != nil {
		t.Fatalf("agent.Query failed: %v", err)
	}
	for range ch {
	}

	if got := atomic.LoadInt32(&requestCount); got != 1 {
		t.Errorf("expected 1 API call when Limit=30, got %d", got)
	}
	if got := atomic.LoadInt32(&capturedPageSize); got != 30 {
		t.Errorf("expected page_size=30 sent to Censys, got %d", got)
	}
}

// TestQueryStopsAtLimitNoExtraPage verifies the loop does NOT issue an
// extra page request after the limit boundary is hit. The previous code
// used `numberOfResults > query.Limit` BEFORE the increment, causing a
// guaranteed +1 API call on every multi-page search.
func TestQueryStopsAtLimitNoExtraPage(t *testing.T) {
	t.Parallel()

	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v3/global/search/query") {
			http.NotFound(w, r)
			return
		}
		atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/json")
		// Each page returns 100 hits with a non-empty next_page_token,
		// so the loop will only stop on the limit check (not on cursor
		// exhaustion).
		_, _ = fmt.Fprintf(w,
			`{"result":{"hits":[%s],"next_page_token":"page-%d","total_hits":1000}}`,
			makeHits(100), atomic.LoadInt32(&requestCount))
	}))
	defer server.Close()

	session, err := sources.NewSession(
		&sources.Keys{
			CensysToken: "test-token",
			CensysOrgId: "test-org",
			BaseURLs:    map[string]string{"censys": server.URL},
		},
		0, 10, 0,
		[]string{"censys"},
		time.Second, "",
	)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	agent := &Agent{}
	ch, err := agent.Query(session, &sources.Query{Query: "service:http", Limit: 200})
	if err != nil {
		t.Fatalf("agent.Query failed: %v", err)
	}
	for range ch {
	}

	if got := atomic.LoadInt32(&requestCount); got != 2 {
		t.Errorf("expected 2 API calls for Limit=200 with 100/page, got %d (extra page = off-by-one regression)", got)
	}
}
