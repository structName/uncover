package uncover

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/uncover/sources"
	"github.com/stretchr/testify/require"
)

func waitUntilGoroutinesAtMost(t *testing.T, limit int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= limit {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	var buf bytes.Buffer
	_ = pprof.Lookup("goroutine").WriteTo(&buf, 2)
	t.Fatalf("goroutine leak: got=%d want<=%d\n%s", runtime.NumGoroutine(), limit, buf.String())
}

func assertChannelCloses(t *testing.T, ch <-chan sources.Result, timeout time.Duration) {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		case <-timer.C:
			t.Fatal("timed out waiting for producer channel to close")
		}
	}
}

func TestExecuteTwoPageTimeoutClosesChannelAndExitsGoroutinesWhenCallerStopsReading(t *testing.T) {
	page2Entered := make(chan struct{})
	page2Exited := make(chan struct{})
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if r.URL.Query().Get("page") == "1" || n == 1 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":false,"page":1,"size":2,"results":[["1.2.3.4","443","p1.example"]]}`))
			return
		}
		close(page2Entered)
		<-r.Context().Done()
		close(page2Exited)
	}))
	defer srv.Close()

	baseline := runtime.NumGoroutine()
	svc, err := NewWithKeys(&Options{
		Agents:        []string{"fofa"},
		Queries:       []string{`ip="1.2.3.4"`},
		Limit:         2,
		MaxRetry:      0,
		Timeout:       1,
		RateLimit:     100,
		RateLimitUnit: time.Second,
	}, &sources.Keys{
		FofaKey:  "test-key",
		BaseURLs: map[string]string{"fofa": srv.URL},
	})
	require.NoError(t, err)
	defer svc.Close()
	svc.Session.UseHTTPClient(&http.Client{}, 0, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	ch, err := svc.Execute(ctx)
	require.NoError(t, err)

	select {
	case <-page2Entered:
	case <-time.After(2 * time.Second):
		t.Fatal("page 2 was never requested")
	}

	select {
	case <-page2Exited:
	case <-time.After(2 * time.Second):
		t.Fatal("page 2 handler did not observe request context cancellation")
	}
	<-ctx.Done()

	assertChannelCloses(t, ch, 2*time.Second)
	svc.Close()
	svc.Session.Client.HTTPClient.CloseIdleConnections()
	srv.Close()
	waitUntilGoroutinesAtMost(t, baseline, 2*time.Second)
}

func TestExecuteFullBufferTimeoutUnblocksRelayAndProducer(t *testing.T) {
	var rows strings.Builder
	rows.WriteString(`{"error":false,"page":1,"size":50,"results":[`)
	for i := 0; i < 40; i++ {
		if i > 0 {
			rows.WriteByte(',')
		}
		fmt.Fprintf(&rows, `["10.0.0.%d","80","h%d.example"]`, i+1, i+1)
	}
	rows.WriteString(`]}`)

	page2Entered := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(rows.String()))
			return
		}
		select {
		case <-page2Entered:
		default:
			close(page2Entered)
		}
		<-r.Context().Done()
	}))
	defer srv.Close()

	baseline := runtime.NumGoroutine()
	svc, err := NewWithKeys(&Options{
		Agents:        []string{"fofa"},
		Queries:       []string{`ip="10.0.0.1"`},
		Limit:         50,
		MaxRetry:      0,
		Timeout:       1,
		RateLimit:     100,
		RateLimitUnit: time.Second,
	}, &sources.Keys{
		FofaKey:  "test-key",
		BaseURLs: map[string]string{"fofa": srv.URL},
	})
	require.NoError(t, err)
	defer svc.Close()
	svc.Session.UseHTTPClient(&http.Client{}, 0, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	ch, err := svc.Execute(ctx)
	require.NoError(t, err)

	<-ctx.Done()
	assertChannelCloses(t, ch, 2*time.Second)
	svc.Close()
	svc.Session.Client.HTTPClient.CloseIdleConnections()
	srv.Close()
	waitUntilGoroutinesAtMost(t, baseline, 2*time.Second)
}

type stubbornExternalAgent struct {
	unblocked chan struct{}
}

func (a *stubbornExternalAgent) Name() string { return "stubborn" }

func (a *stubbornExternalAgent) Query(_ *sources.Session, _ *sources.Query) (chan sources.Result, error) {
	ch := make(chan sources.Result)
	go func() {
		defer close(ch)
		defer close(a.unblocked)
		for i := 0; i < 64; i++ {
			ch <- sources.Result{Source: a.Name(), IP: "1.1.1.1", Port: 80}
		}
	}()
	return ch, nil
}

func TestExecuteDrainsSlowExternalAgentOnContextDone(t *testing.T) {
	baseline := runtime.NumGoroutine()
	sess, err := sources.NewSession(&sources.Keys{FofaKey: "k"}, 0, 1, 100, []string{"stubborn"}, time.Second, "")
	require.NoError(t, err)
	defer sess.Close()

	agent := &stubbornExternalAgent{unblocked: make(chan struct{})}
	svc := &Service{
		Options:  &Options{Agents: []string{"stubborn"}, Queries: []string{"q"}, Limit: 100},
		Agents:   []sources.Agent{agent},
		Session:  sess,
		Provider: &sources.Provider{},
		Keys:     sources.Keys{FofaKey: "k"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	ch, err := svc.Execute(ctx)
	require.NoError(t, err)
	<-ctx.Done()

	assertChannelCloses(t, ch, 2*time.Second)
	select {
	case <-agent.unblocked:
	case <-time.After(2 * time.Second):
		t.Fatal("external agent stayed blocked after ctx.Done()")
	}
	svc.Close()
	waitUntilGoroutinesAtMost(t, baseline, 2*time.Second)
}

func TestServiceCloseReleasesRateLimitersAcrossRepeatedRuns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":false,"page":1,"size":1,"results":[["1.2.3.4","443","ok.example"]]}`))
	}))
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	baseline := runtime.NumGoroutine()
	for i := 0; i < 12; i++ {
		svc, err := NewWithKeys(&Options{
			Agents:        []string{"fofa"},
			Queries:       []string{`ip="1.2.3.4"`},
			Limit:         1,
			MaxRetry:      0,
			Timeout:       2,
			RateLimit:     100,
			RateLimitUnit: time.Second,
		}, &sources.Keys{
			FofaKey:  "test-key",
			BaseURLs: map[string]string{"fofa": srv.URL},
		})
		require.NoError(t, err)
		svc.Session.UseHTTPClient(client, 0, 2)
		ch, err := svc.Execute(context.Background())
		require.NoError(t, err)
		for range ch {
		}
		svc.Close()
	}
	srv.Close()
	waitUntilGoroutinesAtMost(t, baseline, 2*time.Second)
}
