package sources

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/retryablehttp-go"
	errorutil "github.com/projectdiscovery/utils/errors"
	"golang.org/x/net/http2"
)

// DefaultRateLimits of all/most of sources are hardcoded by default to improve performance
// engine is not present in default ratelimits then user given ratelimit from cli options is used
var DefaultRateLimits = map[string]*ratelimit.Options{
	"shodan":     {Key: "shodan", MaxCount: 1, Duration: time.Second},
	"shodan-idb": {Key: "shodan-idb", MaxCount: 1, Duration: time.Second},
	"fofa":       {Key: "fofa", MaxCount: 1, Duration: time.Second},
	"censys":     {Key: "censys", MaxCount: 1, Duration: 3 * time.Second},
	"quake":      {Key: "quake", MaxCount: 1, Duration: time.Second},
	"hunter":     {Key: "hunter", MaxCount: 15, Duration: time.Second},
	"zoomeye":    {Key: "zoomeye", MaxCount: 1, Duration: time.Second},
	"netlas":     {Key: "netlas", MaxCount: 1, Duration: time.Second},
	"criminalip": {Key: "criminalip", MaxCount: 1, Duration: time.Second},
	"publicwww":  {Key: "publicwww", MaxCount: 1, Duration: time.Minute},
	"hunterhow":  {Key: "hunterhow", MaxCount: 1, Duration: 3 * time.Second},
	"google":     {Key: "google", MaxCount: 1, Duration: 3 * time.Second},
	"odin":       {Key: "odin", MaxCount: 1, Duration: time.Second},
	"binaryedge": {Key: "binaryedge", MaxCount: 1, Duration: time.Second},
	"onyphe":     {Key: "onyphe", MaxCount: 1, Duration: time.Second},
	"driftnet":   {Key: "driftnet", MaxCount: 5, Duration: time.Second},
	"greynoise":  {Key: "greynoise", MaxCount: 1, Duration: time.Second},
}

// Session handles session agent sessions
type Session struct {
	Keys       *Keys
	Client     *retryablehttp.Client
	RetryMax   int
	RateLimits *ratelimit.MultiLimiter
	ctx        context.Context
}

func (s *Session) WithContext(ctx context.Context) *Session {
	if s == nil {
		return nil
	}
	clone := *s
	clone.ctx = ctx
	return &clone
}

func (s *Session) Context() context.Context {
	if s != nil && s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

func (s *Session) Close() {
	if s == nil {
		return
	}
	if s.RateLimits != nil {
		s.RateLimits.Stop()
	}
}

func (s *Session) SendResult(results chan<- Result, res Result) bool {
	if results == nil {
		return false
	}
	ctx := s.Context()
	select {
	case <-ctx.Done():
		return false
	default:
	}
	select {
	case results <- res:
		return true
	case <-ctx.Done():
		return false
	}
}

// UseHTTPClient replaces the default transport with a caller-provided
// policy-enforcing *http.Client (e.g. security/outbound factory).
func (s *Session) UseHTTPClient(client *http.Client, retryMax int, timeoutSec int) {
	if s == nil || client == nil {
		return
	}
	primary := *client
	if timeoutSec > 0 {
		primary.Timeout = time.Duration(timeoutSec) * time.Second
	}
	options := retryablehttp.Options{RetryMax: retryMax}
	if timeoutSec > 0 {
		options.RetryWaitMax = time.Duration(timeoutSec) * time.Second
	}
	s.Client = retryablehttp.NewWithHTTPClient(&primary, options)
	if s.Client != nil {
		s.Client.HTTPClient2 = buildHTTP2FallbackClient(&primary)
	}
	s.RetryMax = retryMax
}

func buildHTTP2FallbackClient(client *http.Client) *http.Client {
	tr, ok := client.Transport.(*http.Transport)
	if !ok || tr == nil {
		return client
	}
	tr2 := tr.Clone()
	_ = http2.ConfigureTransport(tr2)
	return &http.Client{
		Transport:     tr2,
		CheckRedirect: client.CheckRedirect,
		Jar:           client.Jar,
		Timeout:       client.Timeout,
	}
}

func NewSession(keys *Keys, retryMax, timeout, rateLimit int, engines []string, duration time.Duration, proxy string) (*Session, error) {
	Transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ResponseHeaderTimeout: time.Duration(timeout) * time.Second,
		Proxy: func(req *http.Request) (*url.URL, error) {
			if proxy != "" {
				if proxyURL, err := url.Parse(proxy); err == nil {
					return http.ProxyURL(proxyURL)(req)
				}
			}
			return http.ProxyFromEnvironment(req)
		},
	}

	httpclient := &http.Client{
		Transport: Transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	options := retryablehttp.Options{RetryMax: retryMax}
	options.RetryWaitMax = time.Duration(timeout) * time.Second
	client := retryablehttp.NewWithHTTPClient(httpclient, options)

	session := &Session{
		Client:   client,
		Keys:     keys,
		RetryMax: retryMax,
	}

	var defaultRatelimit *ratelimit.Options
	switch {
	case rateLimit > 0:
		defaultRatelimit = &ratelimit.Options{Key: "default", MaxCount: uint(rateLimit), Duration: duration}
	default:
		defaultRatelimit = &ratelimit.Options{IsUnlimited: true, Key: "default"}
	}

	var err error
	session.RateLimits, err = ratelimit.NewMultiLimiter(context.Background(), defaultRatelimit)
	if err != nil {
		return nil, err
	}

	seenEngines := map[string]struct{}{"default": {}}
	for _, engine := range engines {
		if _, exists := seenEngines[engine]; exists {
			continue
		}
		seenEngines[engine] = struct{}{}
		rateLimitOpts := defaultRatelimit
		if rateLimit <= 0 {
			rateLimitOpts = DefaultRateLimits[engine]
			if rateLimitOpts == nil {
				rateLimitOpts = defaultRatelimit
			}
		}
		copied := *rateLimitOpts
		copied.Key = engine
		if err = session.RateLimits.Add(&copied); err != nil {
			session.Close()
			return nil, errorutil.NewWithErr(err).Msgf("failed to setup ratelimit of %v got %v", engine, err)
		}
	}

	return session, nil
}

func (s *Session) Do(request *retryablehttp.Request, source string) (*http.Response, error) {
	if err := s.Context().Err(); err != nil {
		return nil, err
	}
	err := s.RateLimits.Take(source)
	if err != nil {
		return nil, err
	}
	if err := s.Context().Err(); err != nil {
		return nil, err
	}
	if s.ctx != nil && request != nil && request.Context() == context.Background() {
		request = request.WithContext(s.ctx)
	}
	// close request connection (does not reuse connections)
	request.Close = true
	resp, err := s.Client.Do(request)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
		}
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		if resp.Body != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			resp.Body = http.NoBody
		}
		requestURL, _ := url.QueryUnescape(request.String())
		return resp, fmt.Errorf("unexpected status code %d received from %s", resp.StatusCode, requestURL)
	}
	return resp, nil
}
