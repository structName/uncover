package hunter

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

// TestQueryRespectsLimitWithSinglePage verifies Hunter's pagination loop
// derives page_size from query.Limit when Limit < engine max, so a single
// API call covers the requested rows instead of always asking for 100.
func TestQueryRespectsLimitWithSinglePage(t *testing.T) {
	t.Parallel()

	var requestCount int32
	var capturedPageSize string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		capturedPageSize = r.URL.Query().Get("page_size")
		// Return exactly page_size items so the loop's >= Limit check
		// fires after the first page when Limit equals page_size.
		var arrItems []string
		for i := 0; i < 30; i++ {
			arrItems = append(arrItems, fmt.Sprintf(`{"ip":"1.1.1.%d","port":80}`, i))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200,"data":{"total":1000,"arr":[` +
			strings.Join(arrItems, ",") + `]}}`))
	}))
	defer server.Close()

	session, err := sources.NewSession(
		&sources.Keys{
			HunterToken: "test-key",
			BaseURLs:    map[string]string{"hunter": server.URL},
		},
		0, 10, 0,
		[]string{"hunter"},
		time.Second, "",
	)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	agent := &Agent{}
	ch, err := agent.Query(session, &sources.Query{Query: `domain="example.com"`, Limit: 30})
	if err != nil {
		t.Fatalf("agent.Query failed: %v", err)
	}
	for range ch {
		// drain channel until close
	}

	if got := atomic.LoadInt32(&requestCount); got != 1 {
		t.Errorf("expected 1 API call when Limit=30, got %d", got)
	}
	if capturedPageSize != "30" {
		t.Errorf("expected page_size=30 sent to Hunter, got %q", capturedPageSize)
	}
}

// TestQueryRespectsLimitAcrossPages verifies the loop stops as soon as the
// requested limit is reached (>=, post-increment) and does NOT issue an
// extra page request after the limit boundary is hit.
func TestQueryRespectsLimitAcrossPages(t *testing.T) {
	t.Parallel()

	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/json")
		// Each page returns 100 results; total advertised is 500.
		var arrItems []string
		for i := 0; i < 100; i++ {
			arrItems = append(arrItems, fmt.Sprintf(`{"ip":"10.0.%d.%d","port":80}`, page, i))
		}
		_, _ = w.Write([]byte(`{"code":200,"data":{"total":500,"arr":[` +
			strings.Join(arrItems, ",") + `]}}`))
	}))
	defer server.Close()

	session, err := sources.NewSession(
		&sources.Keys{
			HunterToken: "test-key",
			BaseURLs:    map[string]string{"hunter": server.URL},
		},
		0, 10, 0,
		[]string{"hunter"},
		time.Second, "",
	)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	agent := &Agent{}
	ch, err := agent.Query(session, &sources.Query{Query: `domain="example.com"`, Limit: 200})
	if err != nil {
		t.Fatalf("agent.Query failed: %v", err)
	}
	for range ch {
		// drain channel until close
	}

	if got := atomic.LoadInt32(&requestCount); got != 2 {
		t.Errorf("expected 2 API calls for Limit=200 with 100/page, got %d (extra page would mean off-by-one regression)", got)
	}
}
