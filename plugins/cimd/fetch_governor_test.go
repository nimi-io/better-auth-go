package cimd

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/plugins/oauthprovider"
)

// Port of packages/cimd/src/fetch-governor.test.ts.

const governorRedirectURI = "http://127.0.0.1:5199/callback"

var governorSeq = 0

func governorMetadata(clientID string) map[string]any {
	return map[string]any{"client_id": clientID, "client_name": "Governed Client", "redirect_uris": []any{governorRedirectURI},
		"application_type": "native", "token_endpoint_auth_method": "none", "grant_types": []any{"authorization_code"},
		"response_types": []any{"code"}}
}

func noStoreMetadata(clientID string) *http.Response {
	return jsonResponse(200, governorMetadata(clientID), "Cache-Control", "no-store")
}

type governorHarness struct {
	env     *testEnv
	ms      *metadataServer
	headers http.Header
	baseURL string
}

func createGovernorHarness(t *testing.T, policy *MetadataFetchPolicy, maxCacheEntries int) *governorHarness {
	t.Helper()
	governorSeq++
	baseURL := fmt.Sprintf("http://localhost:%d", 3300+governorSeq)
	ms := newMetadataServer()
	env := cimdEnv(t, baseURL, oauthprovider.Options{Scopes: []string{"openid"}}, Options{
		FetchClientMetadataResource: ms.fetch, MaxCacheEntries: intp(maxCacheEntries), MetadataFetchPolicy: policy})
	return &governorHarness{env: env, ms: ms, headers: env.signInWithTestUser(), baseURL: baseURL}
}

func (h *governorHarness) authorize(clientID string) (int, string) {
	return h.env.authorizeStatus(h.headers, authorizeURL(h.baseURL, clientID, governorRedirectURI, ""))
}

// deferred is a response the test resolves later.
type deferred struct {
	ch chan func() (*http.Response, error)
}

func newDeferred() *deferred { return &deferred{ch: make(chan func() (*http.Response, error), 1)} }

func (d *deferred) wait(*http.Request) (*http.Response, error) { return (<-d.ch)() }

func (d *deferred) resolve(r *http.Response) {
	d.ch <- func() (*http.Response, error) { return r, nil }
}

func (d *deferred) reject(err error) { d.ch <- func() (*http.Response, error) { return nil, err } }

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type authorizeResult struct {
	status   int
	location string
}

func (h *governorHarness) authorizeAsync(clientID string) chan authorizeResult {
	ch := make(chan authorizeResult, 1)
	go func() {
		s, l := h.authorize(clientID)
		ch <- authorizeResult{s, l}
	}()
	return ch
}

func networkFailure(*http.Request) (*http.Response, error) { return nil, errors.New("network failed") }

func TestCimdMetadataFetchGovernor(t *testing.T) {
	// Upstream uses 1.5 and NaN for the per-origin limits; Go ints cannot express them, so
	// those cases use other non-positive values.
	for _, c := range []struct {
		field  string
		policy MetadataFetchPolicy
	}{
		{"maximumConcurrentFetches", MetadataFetchPolicy{MaximumConcurrentFetches: intp(0)}},
		{"maximumConcurrentFetchesPerOrigin", MetadataFetchPolicy{MaximumConcurrentFetchesPerOrigin: intp(0)}},
		{"maximumFetchesPerMinute", MetadataFetchPolicy{MaximumFetchesPerMinute: intp(-1)}},
		{"maximumFetchesPerOriginPerMinute", MetadataFetchPolicy{MaximumFetchesPerOriginPerMinute: intp(-5)}},
	} {
		t.Run("rejects invalid "+c.field+" configuration", func(t *testing.T) {
			p := c.policy
			_, err := CreateCimdClientDiscovery(Options{FetchClientMetadataResource: networkFailure, MetadataFetchPolicy: &p})
			if err == nil || !strings.Contains(err.Error(), c.field) {
				t.Fatal(err)
			}
		})
	}

	t.Run("rejects an invalid minimum fetch interval as a configuration error", func(t *testing.T) {
		_, err := CreateCimdClientDiscovery(Options{FetchClientMetadataResource: networkFailure,
			MetadataFetchPolicy: &MetadataFetchPolicy{MinimumFetchInterval: -1}})
		if err == nil || !strings.Contains(err.Error(), "minimumFetchInterval") {
			t.Fatal(err)
		}
	})

	t.Run("defaults failed-fetch pacing to one second", func(t *testing.T) {
		clock := installClock(t, 1_800_000_000_000)
		h := createGovernorHarness(t, nil, 8)
		clientID := "https://default-pacing.example/client.json"
		h.ms.set(clientID, networkFailure)
		h.authorize(clientID)
		clock.advance(999)
		if s, _ := h.authorize(clientID); s != 429 {
			t.Fatal(s)
		}
		clock.advance(1)
		if s, _ := h.authorize(clientID); s == 429 {
			t.Fatal(s)
		}
		if h.ms.callCount() != 2 {
			t.Fatal(h.ms.callCount())
		}
	})

	for _, c := range []struct{ name, cacheControl string }{
		{"private", "private, max-age=0, must-revalidate"},
		{"no-store", "no-store"},
		{"no-cache", "no-cache"},
		{"immediately stale", "max-age=0, must-revalidate"},
	} {
		t.Run("does not pace successful "+c.name+" metadata fetches", func(t *testing.T) {
			h := createGovernorHarness(t, nil, 8)
			clientID := "https://connect.example/client.json"
			h.ms.setJSON(clientID, governorMetadata(clientID), "Cache-Control", c.cacheControl)
			for range 2 {
				if _, loc := h.authorize(clientID); !strings.Contains(loc, "/consent") {
					t.Fatal(loc)
				}
			}
			if h.ms.callCount() != 2 {
				t.Fatal(h.ms.callCount())
			}
		})
	}

	t.Run("paces repeated failed metadata fetches", func(t *testing.T) {
		clock := installClock(t, 1_800_000_000_000)
		h := createGovernorHarness(t, &MetadataFetchPolicy{MinimumFetchInterval: 10}, 8)
		clientID := "https://paced.example/client.json"
		h.ms.set(clientID, networkFailure)
		if s, _ := h.authorize(clientID); s == 429 {
			t.Fatal(s)
		}
		if s, _ := h.authorize(clientID); s != 429 {
			t.Fatal(s)
		}
		if h.ms.callCount() != 1 {
			t.Fatal(h.ms.callCount())
		}
		clock.advance(10_000)
		if s, _ := h.authorize(clientID); s == 429 {
			t.Fatal(s)
		}
		if h.ms.callCount() != 2 {
			t.Fatal(h.ms.callCount())
		}
	})

	t.Run("starts failed-fetch pacing when the failure settles", func(t *testing.T) {
		clock := installClock(t, 1_800_000_000_000)
		h := createGovernorHarness(t, &MetadataFetchPolicy{MinimumFetchInterval: 10}, 8)
		clientID := "https://slow-failure.example/client.json"
		h.ms.set(clientID, func(*http.Request) (*http.Response, error) {
			clock.advance(5_000)
			return nil, errors.New("network failed")
		})
		if s, _ := h.authorize(clientID); s == 429 {
			t.Fatal(s)
		}
		clock.advance(5_000)
		if s, _ := h.authorize(clientID); s != 429 {
			t.Fatal(s)
		}
		clock.advance(5_000)
		if s, _ := h.authorize(clientID); s == 429 {
			t.Fatal(s)
		}
		if h.ms.callCount() != 2 {
			t.Fatal(h.ms.callCount())
		}
	})

	t.Run("fully disables per-client pacing when the interval is zero", func(t *testing.T) {
		clock := installClock(t, 1_800_000_000_000)
		h := createGovernorHarness(t, &MetadataFetchPolicy{MinimumFetchInterval: 0}, 2)
		clients := []string{"https://unpaced.example/a.json", "https://unpaced.example/b.json", "https://unpaced.example/c.json"}
		for _, c := range clients {
			c := c
			h.ms.set(c, func(*http.Request) (*http.Response, error) { return noStoreMetadata(c), nil })
		}
		h.authorize(clients[0])
		h.authorize(clients[1])
		clock.advance(-1_000)
		if _, loc := h.authorize(clients[2]); !strings.Contains(loc, "/consent") {
			t.Fatal(loc)
		}
		if h.ms.callCount() != 3 {
			t.Fatal(h.ms.callCount())
		}
	})

	t.Run("coalesces concurrent same-client resolutions into one fetch", func(t *testing.T) {
		h := createGovernorHarness(t, &MetadataFetchPolicy{MinimumFetchInterval: 60}, 8)
		clientID := "https://coalesced.example/client.json"
		d := newDeferred()
		h.ms.set(clientID, d.wait)
		first := h.authorizeAsync(clientID)
		waitFor(t, func() bool { return h.ms.callCount() == 1 })
		second := h.authorizeAsync(clientID)
		time.Sleep(50 * time.Millisecond)
		d.resolve(noStoreMetadata(clientID))
		for _, ch := range []chan authorizeResult{first, second} {
			if r := <-ch; !strings.Contains(r.location, "/consent") {
				t.Fatal(r)
			}
		}
		if h.ms.callCount() != 1 {
			t.Fatal(h.ms.callCount())
		}
	})

	t.Run("rejects same-origin path spray and releases concurrency after success", func(t *testing.T) {
		h := createGovernorHarness(t, &MetadataFetchPolicy{MinimumFetchInterval: 0, MaximumConcurrentFetches: intp(4),
			MaximumConcurrentFetchesPerOrigin: intp(1)}, 8)
		firstID, secondID := "https://one-origin.example/a.json", "https://one-origin.example/b.json"
		d := newDeferred()
		h.ms.set(firstID, d.wait)
		h.ms.set(secondID, func(*http.Request) (*http.Response, error) { return noStoreMetadata(secondID), nil })
		first := h.authorizeAsync(firstID)
		waitFor(t, func() bool { return h.ms.callCount() == 1 })
		if s, _ := h.authorize(secondID); s != 429 {
			t.Fatal(s)
		}
		d.resolve(noStoreMetadata(firstID))
		<-first
		if _, loc := h.authorize(secondID); !strings.Contains(loc, "/consent") {
			t.Fatal(loc)
		}
	})

	t.Run("enforces the global concurrency cap and releases it after failure", func(t *testing.T) {
		h := createGovernorHarness(t, &MetadataFetchPolicy{MinimumFetchInterval: 0, MaximumConcurrentFetches: intp(1),
			MaximumConcurrentFetchesPerOrigin: intp(1)}, 8)
		firstID, secondID := "https://first-origin.example/a.json", "https://second-origin.example/b.json"
		d := newDeferred()
		h.ms.set(firstID, d.wait)
		h.ms.set(secondID, func(*http.Request) (*http.Response, error) { return noStoreMetadata(secondID), nil })
		first := h.authorizeAsync(firstID)
		waitFor(t, func() bool { return h.ms.callCount() == 1 })
		if s, _ := h.authorize(secondID); s != 429 {
			t.Fatal(s)
		}
		d.reject(errors.New("network failed"))
		if r := <-first; r.status < 400 {
			t.Fatal(r)
		}
		if _, loc := h.authorize(secondID); !strings.Contains(loc, "/consent") {
			t.Fatal(loc)
		}
	})

	t.Run("enforces rolling one-minute global and per-origin budgets", func(t *testing.T) {
		clock := installClock(t, 1_800_000_000_000)
		h := createGovernorHarness(t, &MetadataFetchPolicy{MinimumFetchInterval: 0, MaximumFetchesPerMinute: intp(2),
			MaximumFetchesPerOriginPerMinute: intp(1)}, 8)
		clients := []string{"https://budget-a.example/a.json", "https://budget-a.example/b.json",
			"https://budget-b.example/c.json", "https://budget-c.example/d.json"}
		for _, c := range clients {
			c := c
			h.ms.set(c, func(*http.Request) (*http.Response, error) { return noStoreMetadata(c), nil })
		}
		h.authorize(clients[0])
		if s, _ := h.authorize(clients[1]); s != 429 {
			t.Fatal(s)
		}
		h.authorize(clients[2])
		if s, _ := h.authorize(clients[3]); s != 429 {
			t.Fatal(s)
		}
		clock.advance(60_000)
		if _, loc := h.authorize(clients[3]); !strings.Contains(loc, "/consent") {
			t.Fatal(loc)
		}
	})

	t.Run("does not evict a live per-client minimum interval at capacity", func(t *testing.T) {
		clock := installClock(t, 1_800_000_000_000)
		h := createGovernorHarness(t, &MetadataFetchPolicy{MinimumFetchInterval: 60}, 2)
		clients := []string{"https://bounded.example/a.json", "https://bounded.example/b.json", "https://bounded.example/c.json"}
		for _, c := range clients {
			h.ms.set(c, networkFailure)
		}
		h.authorize(clients[0])
		h.authorize(clients[1])
		if s, _ := h.authorize(clients[2]); s != 429 {
			t.Fatal(s)
		}
		if s, _ := h.authorize(clients[0]); s != 429 {
			t.Fatal(s)
		}
		if h.ms.callCount() != 2 {
			t.Fatal(h.ms.callCount())
		}
		clock.advance(60_000)
		if s, _ := h.authorize(clients[2]); s == 429 {
			t.Fatal(s)
		}
		if h.ms.callCount() != 3 {
			t.Fatal(h.ms.callCount())
		}
	})

	t.Run("does not evict active per-client state after its interval expires", func(t *testing.T) {
		clock := installClock(t, 1_800_000_000_000)
		h := createGovernorHarness(t, &MetadataFetchPolicy{MinimumFetchInterval: 1}, 1)
		firstID, secondID := "https://active-state.example/a.json", "https://active-state.example/b.json"
		d := newDeferred()
		h.ms.set(firstID, d.wait)
		h.ms.set(secondID, networkFailure)
		first := h.authorizeAsync(firstID)
		waitFor(t, func() bool { return h.ms.callCount() == 1 })
		clock.advance(1_000)
		if s, _ := h.authorize(secondID); s != 429 {
			t.Fatal(s)
		}
		if h.ms.callCount() != 1 {
			t.Fatal(h.ms.callCount())
		}
		d.reject(errors.New("network failed"))
		if r := <-first; r.status < 400 {
			t.Fatal(r)
		}
	})

	t.Run("does not evict a live per-origin budget at capacity", func(t *testing.T) {
		clock := installClock(t, 1_800_000_000_000)
		h := createGovernorHarness(t, &MetadataFetchPolicy{MinimumFetchInterval: 0, MaximumFetchesPerOriginPerMinute: intp(1)}, 2)
		clients := []string{"https://origin-a.example/client.json", "https://origin-b.example/client.json", "https://origin-c.example/client.json"}
		for _, c := range clients {
			c := c
			h.ms.set(c, func(*http.Request) (*http.Response, error) { return noStoreMetadata(c), nil })
		}
		h.authorize(clients[0])
		h.authorize(clients[1])
		if s, _ := h.authorize(clients[2]); s != 429 {
			t.Fatal(s)
		}
		if s, _ := h.authorize(clients[0]); s != 429 {
			t.Fatal(s)
		}
		if h.ms.callCount() != 2 {
			t.Fatal(h.ms.callCount())
		}
		clock.advance(60_000)
		if _, loc := h.authorize(clients[2]); !strings.Contains(loc, "/consent") {
			t.Fatal(loc)
		}
		if h.ms.callCount() != 3 {
			t.Fatal(h.ms.callCount())
		}
	})
}
