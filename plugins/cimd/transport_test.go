package cimd

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Port of packages/cimd/src/node.test.ts. DNS and dialing are injected through
// TransportOptions (vi.mock of node:dns and node:https upstream); a local TLS server
// stands in for the pinned address and records Host, SNI and the request.

type transportHarness struct {
	mu          sync.Mutex
	lookups     []string
	dials       []string
	serverNames []string
	requests    []*http.Request
	server      *httptest.Server
	answers     []net.IPAddr
	handler     http.HandlerFunc
}

func newTransportHarness(t *testing.T, answers ...string) *transportHarness {
	h := &transportHarness{}
	for _, a := range answers {
		h.answers = append(h.answers, net.IPAddr{IP: net.ParseIP(a)})
	}
	h.handler = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("metadata"))
	}
	h.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.requests = append(h.requests, r)
		h.mu.Unlock()
		h.handler(w, r)
	}))
	h.server.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		h.mu.Lock()
		h.serverNames = append(h.serverNames, hello.ServerName)
		h.mu.Unlock()
		return nil, nil
	}}
	h.server.StartTLS()
	t.Cleanup(h.server.Close)
	return h
}

func (h *transportHarness) fetch() func(*http.Request) (*http.Response, error) {
	return NewClientMetadataResourceFetch(TransportOptions{
		LookupIPAddr: func(_ context.Context, host string) ([]net.IPAddr, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.lookups = append(h.lookups, host)
			return h.answers, nil
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			h.mu.Lock()
			h.dials = append(h.dials, addr)
			h.mu.Unlock()
			return (&net.Dialer{}).DialContext(ctx, network, h.server.Listener.Addr().String())
		},
		TLSConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server certificate
	})
}

func get(t *testing.T, fetch func(*http.Request) (*http.Response, error), method, target string, hdr http.Header) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, vs := range hdr {
		req.Header[k] = vs
	}
	return fetch(req)
}

func TestNodeCimdMetadataTransport(t *testing.T) {
	t.Run("rejects private DNS answers before opening a connection", func(t *testing.T) {
		h := newTransportHarness(t, "93.184.216.34", "127.0.0.1")
		_, err := get(t, h.fetch(), "GET", "https://client.example.com/client.json", nil)
		if err == nil || !strings.Contains(err.Error(), "public") {
			t.Fatal(err)
		}
		if len(h.dials) != 0 || len(h.requests) != 0 {
			t.Fatal(h.dials)
		}
	})

	t.Run("resolves once, pins an approved address, and preserves Host and TLS SNI", func(t *testing.T) {
		h := newTransportHarness(t, "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946")
		h.handler = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("ok"))
		}
		res, err := get(t, h.fetch(), "GET", "https://client.example.com/client.json", nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if string(body) != "ok" {
			t.Fatal(string(body))
		}
		if len(h.lookups) != 1 || h.lookups[0] != "client.example.com" {
			t.Fatal(h.lookups)
		}
		if len(h.dials) != 1 || h.dials[0] != "93.184.216.34:443" {
			t.Fatal(h.dials)
		}
		if h.serverNames[0] != "client.example.com" || h.requests[0].Host != "client.example.com" {
			t.Fatal(h.serverNames, h.requests[0].Host)
		}
	})

	// Node's lookup({all: true}) callback form has no Go counterpart; the equivalent is
	// that a multi-answer resolution still fetches through the first approved address.
	t.Run("fetches metadata when Node requests all addresses", func(t *testing.T) {
		h := newTransportHarness(t, "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946")
		h.handler = func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }
		res, err := get(t, h.fetch(), "GET", "https://client.example.com/client.json", nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if string(body) != "ok" {
			t.Fatal(string(body))
		}
	})

	t.Run("returns redirect responses without following them", func(t *testing.T) {
		h := newTransportHarness(t, "93.184.216.34")
		h.handler = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "https://other.example/client.json")
			w.WriteHeader(302)
		}
		res, err := get(t, h.fetch(), "GET", "https://client.example.com/client.json", nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if res.StatusCode != 302 || res.Header.Get("Location") != "https://other.example/client.json" || len(h.requests) != 1 {
			t.Fatal(res.StatusCode, res.Header, len(h.requests))
		}
	})

	t.Run("returns a 304 response without constructing a forbidden body", func(t *testing.T) {
		h := newTransportHarness(t, "93.184.216.34")
		h.handler = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Etag", `"current"`)
			w.WriteHeader(304)
		}
		res, err := get(t, h.fetch(), "GET", "https://client.example.com/client.json", nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode != 304 || len(body) != 0 || res.Header.Get("Etag") != `"current"` {
			t.Fatal(res.StatusCode, body, res.Header)
		}
	})

	t.Run("preserves supplied method, headers, and abort signal", func(t *testing.T) {
		h := newTransportHarness(t, "93.184.216.34")
		hdr := http.Header{}
		hdr.Set("Accept", "application/oauth-client-metadata+json")
		res, err := get(t, h.fetch(), "HEAD", "https://client.example.com/client.json", hdr)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if h.requests[0].Method != "HEAD" || h.requests[0].Header.Get("Accept") != "application/oauth-client-metadata+json" {
			t.Fatal(h.requests[0].Method, h.requests[0].Header)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://client.example.com/client.json", nil)
		if _, err := h.fetch()(req); err == nil {
			t.Fatal("expected the cancelled context to abort the request")
		}
	})

	t.Run("rejects unsupported methods instead of dropping their request body", func(t *testing.T) {
		h := newTransportHarness(t, "93.184.216.34")
		req, _ := http.NewRequest("POST", "https://client.example.com/client.json", strings.NewReader("must-not-be-dropped"))
		_, err := h.fetch()(req)
		if err == nil || !strings.Contains(err.Error(), "GET and HEAD") || len(h.lookups) != 0 || len(h.dials) != 0 {
			t.Fatal(err, h.lookups)
		}
	})

	t.Run("does not send SNI for an IP-literal URL", func(t *testing.T) {
		h := newTransportHarness(t, "8.8.8.8")
		res, err := get(t, h.fetch(), "GET", "https://8.8.8.8/client.json", nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if h.serverNames[0] != "" {
			t.Fatal(h.serverNames)
		}
	})

	// Go-only: non-HTTPS URLs are refused before resolution.
	t.Run("requires an HTTPS URL", func(t *testing.T) {
		h := newTransportHarness(t, "93.184.216.34")
		_, err := get(t, h.fetch(), "GET", "http://client.example.com/client.json", nil)
		if err == nil || !strings.Contains(err.Error(), "HTTPS") || len(h.lookups) != 0 {
			t.Fatal(err)
		}
	})
}
