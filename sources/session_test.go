package sources

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func TestSessionRetry(t *testing.T) {
	router := httprouter.New()
	router.GET("/", httprouter.Handle(func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		time.Sleep(10 * time.Second)
		t.Log("Slept for 10 seconds")
	}))
	ts := httptest.NewServer(router)
	engines := []string{"shodan", "publicwww"}
	session, err := NewSession(&Keys{}, 5, 3, 60, engines, time.Second, "")
	require.Nil(t, err)
	defer session.Close()
	req, err := retryablehttp.NewRequest(http.MethodGet, ts.URL, nil)
	require.Nil(t, err)
	resp, err := session.Do(req, engines[0])
	t.Log(resp, err)
	require.ErrorContains(t, err, "giving up after 6 attempts")
	require.Nil(t, resp)
}

type stubRoundTripper struct{}

func (stubRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
}

func TestUseHTTPClientBindsPolicyHTTPClient2(t *testing.T) {
	dialCalled := false
	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialCalled = true
		return nil, context.Canceled
	}
	proxyFn := func(*http.Request) (*url.URL, error) { return nil, nil }
	redirectFn := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	tr := &http.Transport{
		DialContext:     dialFn,
		Proxy:           proxyFn,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "policy.example"},
	}
	policyClient := &http.Client{
		Transport:     tr,
		CheckRedirect: redirectFn,
		Timeout:       12 * time.Second,
	}

	s := &Session{}
	s.UseHTTPClient(policyClient, 1, 5)
	require.NotNil(t, s.Client)
	require.NotSame(t, policyClient, s.Client.HTTPClient)
	require.Equal(t, 12*time.Second, policyClient.Timeout)
	require.Equal(t, 5*time.Second, s.Client.HTTPClient.Timeout)
	require.NotNil(t, s.Client.HTTPClient2)
	require.NotSame(t, policyClient, s.Client.HTTPClient2)
	require.Equal(t, 5*time.Second, s.Client.HTTPClient2.Timeout)
	require.Equal(t, reflect.ValueOf(redirectFn).Pointer(), reflect.ValueOf(s.Client.HTTPClient2.CheckRedirect).Pointer())

	tr2, ok := s.Client.HTTPClient2.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotSame(t, tr, tr2)
	require.Equal(t, reflect.ValueOf(dialFn).Pointer(), reflect.ValueOf(tr2.DialContext).Pointer())
	require.Equal(t, reflect.ValueOf(proxyFn).Pointer(), reflect.ValueOf(tr2.Proxy).Pointer())
	require.NotNil(t, tr2.TLSClientConfig)
	require.NotSame(t, tr.TLSClientConfig, tr2.TLSClientConfig)
	require.Equal(t, uint16(tls.VersionTLS13), tr2.TLSClientConfig.MinVersion)
	require.Equal(t, "policy.example", tr2.TLSClientConfig.ServerName)

	_, err := tr2.DialContext(context.Background(), "tcp", "example.com:443")
	require.ErrorIs(t, err, context.Canceled)
	require.True(t, dialCalled)

	customClient := &http.Client{Transport: stubRoundTripper{}, Timeout: 7 * time.Second}
	s.UseHTTPClient(customClient, 1, 5)
	require.NotSame(t, customClient, s.Client.HTTPClient)
	require.NotSame(t, customClient, s.Client.HTTPClient2)
	require.Same(t, s.Client.HTTPClient, s.Client.HTTPClient2)
	require.Equal(t, 7*time.Second, customClient.Timeout)
	require.Equal(t, 5*time.Second, s.Client.HTTPClient.Timeout)
	require.Equal(t, 5*time.Second, s.Client.HTTPClient2.Timeout)

	alreadyH2 := &http.Transport{DialContext: dialFn}
	require.NoError(t, http2.ConfigureTransport(alreadyH2))
	h2Client := &http.Client{Transport: alreadyH2, CheckRedirect: redirectFn, Timeout: 9 * time.Second}
	s.UseHTTPClient(h2Client, 1, 5)
	require.NotNil(t, s.Client.HTTPClient2)
	trH2, ok := s.Client.HTTPClient2.Transport.(*http.Transport)
	require.True(t, ok)
	require.Equal(t, reflect.ValueOf(dialFn).Pointer(), reflect.ValueOf(trH2.DialContext).Pointer())
	require.Equal(t, 9*time.Second, h2Client.Timeout)
	require.Equal(t, 5*time.Second, s.Client.HTTPClient.Timeout)
	require.Equal(t, 5*time.Second, s.Client.HTTPClient2.Timeout)

	s.UseHTTPClient(h2Client, 1, 0)
	require.Equal(t, 9*time.Second, s.Client.HTTPClient.Timeout)
	require.Equal(t, 9*time.Second, s.Client.HTTPClient2.Timeout)
}

func TestUseHTTPClientTimeoutAbortsWithoutMutatingCaller(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(4 * time.Second):
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	sharedClient := &http.Client{
		Transport: &http.Transport{},
		Timeout:   30 * time.Second,
	}
	sess, err := NewSession(&Keys{}, 0, 30, 10, []string{"fofa"}, time.Second, "")
	require.NoError(t, err)
	defer sess.Close()
	sess.UseHTTPClient(sharedClient, 0, 1)

	req, err := retryablehttp.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	start := time.Now()
	resp, err := sess.Do(req, "fofa")
	elapsed := time.Since(start)
	require.Error(t, err)
	require.Nil(t, resp)
	require.Less(t, elapsed, 2500*time.Millisecond)
	require.Equal(t, 30*time.Second, sharedClient.Timeout)
	require.Equal(t, 1*time.Second, sess.Client.HTTPClient.Timeout)
	require.Equal(t, 1*time.Second, sess.Client.HTTPClient2.Timeout)

	req2, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	start2 := time.Now()
	resp2, err2 := sess.Client.HTTPClient2.Do(req2)
	elapsed2 := time.Since(start2)
	require.Error(t, err2)
	require.Nil(t, resp2)
	require.Less(t, elapsed2, 2500*time.Millisecond)
}

func TestSendResultHonorsContextDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := (&Session{}).WithContext(ctx)

	ch := make(chan Result, 1)
	require.True(t, s.SendResult(ch, Result{Source: "fofa", IP: "1.1.1.1"}))
	got := <-ch
	require.Equal(t, "1.1.1.1", got.IP)

	cancel()
	require.False(t, s.SendResult(ch, Result{Source: "fofa", IP: "2.2.2.2"}))
	require.Empty(t, ch)

	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel2()
	s2 := (&Session{}).WithContext(ctx2)
	unbuffered := make(chan Result)
	require.False(t, s2.SendResult(unbuffered, Result{Source: "fofa", IP: "3.3.3.3"}))
}

type trackingReadCloser struct {
	reader io.Reader
	closed atomic.Bool
}

func (t *trackingReadCloser) Read(p []byte) (int, error) {
	return t.reader.Read(p)
}

func (t *trackingReadCloser) Close() error {
	t.closed.Store(true)
	return nil
}

type statusRoundTripper struct {
	status int
	last   *trackingReadCloser
}

func (rt *statusRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	body := &trackingReadCloser{reader: strings.NewReader("error payload")}
	rt.last = body
	return &http.Response{StatusCode: rt.status, Body: body}, nil
}

func TestSessionDoClosesBodyOnNon200AndPreservesStatusCode(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusNoContent, http.StatusInternalServerError} {
		rt := &statusRoundTripper{status: status}
		sess, err := NewSession(&Keys{}, 0, 5, 100, []string{"fofa"}, time.Second, "")
		require.NoError(t, err)
		defer sess.Close()
		sess.UseHTTPClient(&http.Client{Transport: rt}, 0, 5)

		req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.invalid/test", nil)
		require.NoError(t, err)

		resp, err := sess.Do(req, "fofa")
		require.Error(t, err)
		require.NotNil(t, resp)
		require.Equal(t, status, resp.StatusCode)
		require.NotNil(t, rt.last)
		require.True(t, rt.last.closed.Load())
		require.NoError(t, resp.Body.Close())
	}
}

func TestSessionCloseStopsRateLimiterGoroutines(t *testing.T) {
	baseline := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		sess, err := NewSession(&Keys{}, 0, 5, 10, []string{"fofa"}, time.Second, "")
		require.NoError(t, err)
		sess.Close()
		sess.Close()
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	require.LessOrEqual(t, runtime.NumGoroutine(), baseline)
}
