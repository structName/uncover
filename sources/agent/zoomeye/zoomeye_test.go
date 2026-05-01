package zoomeye

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

// TestQueryRespectsLimitWithSinglePage verifies ZoomEye's pagination loop
// derives pagesize from query.Limit when Limit < engine max, so a single
// API call covers the requested rows instead of always asking for 100.
func TestQueryRespectsLimitWithSinglePage(t *testing.T) {
	t.Parallel()

	var requestCount int32
	var capturedPageSize int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		if v, ok := req["pagesize"].(float64); ok {
			atomic.StoreInt32(&capturedPageSize, int32(v))
		}

		var items []string
		for i := 0; i < 30; i++ {
			items = append(items, fmt.Sprintf(`{"ip":"1.1.1.%d","port":80}`, i))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"total":1000,"data":[` + strings.Join(items, ",") + `]}`))
	}))
	defer server.Close()

	session, err := sources.NewSession(
		&sources.Keys{
			ZoomEyeToken: "test-key",
			BaseURLs:     map[string]string{"zoomeye": server.URL},
		},
		0, 10, 0,
		[]string{"zoomeye"},
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
	if got := atomic.LoadInt32(&capturedPageSize); got != 30 {
		t.Errorf("expected pagesize=30 sent to ZoomEye, got %d", got)
	}
}
