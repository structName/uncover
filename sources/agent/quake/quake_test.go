package quake

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

// TestQueryRespectsLimitWithSinglePage verifies Quake's pagination loop
// derives request.size from query.Limit when Limit < engine max, so a
// single API call covers the requested rows.
func TestQueryRespectsLimitWithSinglePage(t *testing.T) {
	t.Parallel()

	var requestCount int32
	var capturedSize int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		body, _ := io.ReadAll(r.Body)
		var req Request
		_ = json.Unmarshal(body, &req)
		atomic.StoreInt32(&capturedSize, int32(req.Size))

		var items []string
		for i := 0; i < 30; i++ {
			items = append(items, fmt.Sprintf(`{"ip":"1.1.1.%d","port":80}`, i))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[` + strings.Join(items, ",") +
			`],"meta":{"pagination":{"count":30,"total":1000}}}`))
	}))
	defer server.Close()

	session, err := sources.NewSession(
		&sources.Keys{
			QuakeToken: "test-key",
			BaseURLs:   map[string]string{"quake": server.URL},
		},
		0, 10, 0,
		[]string{"quake"},
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
		// drain
	}

	if got := atomic.LoadInt32(&requestCount); got != 1 {
		t.Errorf("expected 1 API call when Limit=30, got %d", got)
	}
	if got := atomic.LoadInt32(&capturedSize); got != 30 {
		t.Errorf("expected request.size=30 sent to Quake, got %d", got)
	}
}

// TestQueryStopsAtLimitNoExtraPage verifies the loop does NOT issue an
// extra page request after the limit boundary is hit. The previous code
// had `if numberOfResults > query.Limit` placed BEFORE the increment,
// causing a guaranteed +1 API call on every multi-page search.
func TestQueryStopsAtLimitNoExtraPage(t *testing.T) {
	t.Parallel()

	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := atomic.AddInt32(&requestCount, 1)
		var items []string
		for i := 0; i < 100; i++ {
			items = append(items, fmt.Sprintf(`{"ip":"10.0.%d.%d","port":80}`, page, i))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[` + strings.Join(items, ",") +
			`],"meta":{"pagination":{"count":100,"total":1000}}}`))
	}))
	defer server.Close()

	session, err := sources.NewSession(
		&sources.Keys{
			QuakeToken: "test-key",
			BaseURLs:   map[string]string{"quake": server.URL},
		},
		0, 10, 0,
		[]string{"quake"},
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
