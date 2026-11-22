package sources

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
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
	require.Same(t, policyClient, s.Client.HTTPClient)
	require.NotNil(t, s.Client.HTTPClient2)
	require.NotSame(t, policyClient, s.Client.HTTPClient2)
	require.Equal(t, 12*time.Second, s.Client.HTTPClient2.Timeout)
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
	require.Same(t, customClient, s.Client.HTTPClient2)

	alreadyH2 := &http.Transport{DialContext: dialFn}
	require.NoError(t, http2.ConfigureTransport(alreadyH2))
	h2Client := &http.Client{Transport: alreadyH2, CheckRedirect: redirectFn, Timeout: 9 * time.Second}
	s.UseHTTPClient(h2Client, 1, 5)
	require.NotNil(t, s.Client.HTTPClient2)
	trH2, ok := s.Client.HTTPClient2.Transport.(*http.Transport)
	require.True(t, ok)
	require.Equal(t, reflect.ValueOf(dialFn).Pointer(), reflect.ValueOf(trH2.DialContext).Pointer())
	require.Equal(t, 9*time.Second, s.Client.HTTPClient2.Timeout)
}
