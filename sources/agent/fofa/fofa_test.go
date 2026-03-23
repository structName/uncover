package fofa

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/projectdiscovery/uncover/sources"
)

func TestQueryDecodesResponseBodyAfterRead(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"error": false,
			"page": 1,
			"size": 1,
			"results": [["220.181.38.148", "443", "www.baidu.com"]]
		}`))
	}))
	defer server.Close()

	session, err := sources.NewSession(
		&sources.Keys{
			FofaKey: "test-key",
			BaseURLs: map[string]string{
				"fofa": server.URL,
			},
		},
		0,
		10,
		0,
		[]string{"fofa"},
		time.Second,
		"",
	)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	agent := &Agent{}
	results := make(chan sources.Result, 2)
	response := agent.query(
		session.ResolveURL(agent.Name(), URL),
		session,
		&FofaRequest{Query: `domain="baidu.com"`, Page: 1, Size: 1},
		results,
	)
	if response == nil {
		t.Fatal("expected fofa response")
	}
	if len(response.Results) != 1 {
		t.Fatalf("expected 1 raw result, got %d", len(response.Results))
	}

	select {
	case result := <-results:
		if result.Error != nil {
			t.Fatalf("expected decoded result, got error %v", result.Error)
		}
		if result.IP != "220.181.38.148" {
			t.Fatalf("expected IP to be decoded, got %q", result.IP)
		}
		if result.Port != 443 {
			t.Fatalf("expected port to be decoded, got %d", result.Port)
		}
		if result.Host != "www.baidu.com" {
			t.Fatalf("expected host to be decoded, got %q", result.Host)
		}
	default:
		t.Fatal("expected one decoded result")
	}
}

func TestQueryReturnsErrorForInvalidJSON(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html>bad gateway</html>`))
	}))
	defer server.Close()

	session, err := sources.NewSession(
		&sources.Keys{
			FofaKey: "test-key",
			BaseURLs: map[string]string{
				"fofa": server.URL,
			},
		},
		0,
		10,
		0,
		[]string{"fofa"},
		time.Second,
		"",
	)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	agent := &Agent{}
	results := make(chan sources.Result, 1)
	response := agent.query(
		session.ResolveURL(agent.Name(), URL),
		session,
		&FofaRequest{Query: `domain="baidu.com"`, Page: 1, Size: 1},
		results,
	)
	if response != nil {
		t.Fatal("expected nil response for invalid JSON")
	}

	select {
	case result := <-results:
		if result.Error == nil {
			t.Fatal("expected decode error")
		}
		if string(result.Raw) != `<html>bad gateway</html>` {
			t.Fatalf("expected raw response to be preserved, got %q", string(result.Raw))
		}
	default:
		t.Fatal("expected one error result")
	}
}
