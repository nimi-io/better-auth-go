package cimd

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider"
)

// Port of packages/cimd/src/cache.test.ts.

const (
	cacheBaseURL     = "http://localhost:3188"
	cacheRedirectURI = "http://127.0.0.1:5188/callback"
)

func cacheMetadata(clientID, name string) map[string]any {
	if name == "" {
		name = "Cached Client"
	}
	return map[string]any{"client_id": clientID, "client_name": name, "redirect_uris": []any{cacheRedirectURI},
		"application_type": "native", "token_endpoint_auth_method": "none", "grant_types": []any{"authorization_code"},
		"response_types": []any{"code"}}
}

// failingCreateAdapter fails the next oauthClient create once armed (the spied
// transactionAdapter.create upstream).
type failingCreateAdapter struct {
	adapter.Adapter
	armed *atomic.Bool
}

func (a failingCreateAdapter) Create(ctx context.Context, in adapter.CreateInput) (adapter.Record, error) {
	if in.Model == "oauthClient" && a.armed.CompareAndSwap(true, false) {
		return nil, errors.New("forced client persistence failure")
	}
	return a.Adapter.Create(ctx, in)
}

func (a failingCreateAdapter) Transaction(ctx context.Context, fn func(ctx context.Context, tx adapter.Adapter) error) error {
	return a.Adapter.Transaction(ctx, func(ctx context.Context, tx adapter.Adapter) error {
		return fn(ctx, failingCreateAdapter{tx, a.armed})
	})
}

func (a failingCreateAdapter) Custom() adapter.CustomAdapter {
	if c, ok := a.Adapter.(interface{ Custom() adapter.CustomAdapter }); ok {
		return c.Custom()
	}
	return nil
}

func httpDate(ms int64) string { return time.UnixMilli(ms).UTC().Format(http.TimeFormat) }

func TestCimdHTTPMetadataCache(t *testing.T) {
	ms := newMetadataServer()
	armed := &atomic.Bool{}
	env := cimdEnv(t, cacheBaseURL, oauthprovider.Options{Scopes: []string{"openid"}}, Options{
		MetadataRevalidationInterval: 10,
		MaxCacheEntries:              intp(2),
		MetadataFetchPolicy: &MetadataFetchPolicy{MinimumFetchInterval: 0, MaximumFetchesPerMinute: intp(1000),
			MaximumFetchesPerOriginPerMinute: intp(1000)},
		FetchClientMetadataResource: ms.fetch,
	}, func(c *betterauth.Config) {
		inner := c.Database
		c.Database = func(o adapter.Options) (adapter.Adapter, error) {
			a, err := inner(o)
			if err != nil {
				return nil, err
			}
			return failingCreateAdapter{a, armed}, nil
		}
	})
	authorize := func(clientID string) (int, string) {
		return env.authorizeStatus(env.signInWithTestUser(), authorizeURL(cacheBaseURL, clientID, cacheRedirectURI, ""))
	}
	run := func(name string, fn func(t *testing.T)) {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(ms.clear)
			fn(t)
		})
	}

	for _, c := range []struct {
		name, clientID string
		response       func() *http.Response
	}{
		{"wrong content type", "https://cache-tests.example/wrong-content-type.json", func() *http.Response {
			return jsonResponse(200, "not metadata", "Content-Type", "text/plain")
		}},
		{"oversized document", "https://cache-tests.example/oversized-document.json", func() *http.Response {
			return jsonResponse(200, strings.Repeat("x", 5*1024+1))
		}},
		{"invalid JSON", "https://cache-tests.example/invalid-json.json", func() *http.Response { return jsonResponse(200, "{") }},
		{"redirect response", "https://cache-tests.example/redirect-response.json", func() *http.Response {
			return emptyResponse(302, "Location", "https://other.example/client.json")
		}},
		{"201 response", "https://cache-tests.example/created-response.json", func() *http.Response { return jsonResponse(201, "{}") }},
	} {
		run("rejects a "+c.name+" before persistence", func(t *testing.T) {
			ms.set(c.clientID, func(*http.Request) (*http.Response, error) { return c.response(), nil })
			if status, _ := authorize(c.clientID); status < 400 {
				t.Fatal(status)
			}
			if env.findClient(c.clientID) != nil {
				t.Fatal("client persisted")
			}
		})
	}

	run("reuses a fresh response and caps max-age by metadataRevalidationInterval", func(t *testing.T) {
		clientID := "https://cache-tests.example/fresh-cache.json"
		clock := installClock(t, 1_800_000_000_000)
		ms.setJSON(clientID, cacheMetadata(clientID, ""), "Cache-Control", "max-age=3600")
		if _, loc := authorize(clientID); !strings.Contains(loc, "/consent") {
			t.Fatal(loc)
		}
		clock.advance(9_000)
		authorize(clientID)
		if ms.callCount() != 1 {
			t.Fatal(ms.callCount())
		}
		clock.advance(2_000)
		authorize(clientID)
		if ms.callCount() != 2 {
			t.Fatal(ms.callCount())
		}
	})

	run("honors Expires freshness", func(t *testing.T) {
		clientID := "https://cache-tests.example/expires-cache.json"
		now := time.Now().UnixMilli()
		ms.setJSON(clientID, cacheMetadata(clientID, ""), "Date", httpDate(now), "Expires", httpDate(now+5_000))
		authorize(clientID)
		authorize(clientID)
		if ms.callCount() != 1 {
			t.Fatal(ms.callCount())
		}
	})

	run("prefers shared-cache s-maxage over max-age and Expires", func(t *testing.T) {
		clientID := "https://cache-tests.example/shared-cache.json"
		clock := installClock(t, 1_800_000_000_000)
		now := clock.Now().UnixMilli()
		ms.setJSON(clientID, cacheMetadata(clientID, ""), "Cache-Control", "s-maxage=2, max-age=60", "Date", httpDate(now),
			"Expires", httpDate(now+120_000))
		authorize(clientID)
		clock.advance(1_000)
		authorize(clientID)
		if ms.callCount() != 1 {
			t.Fatal(ms.callCount())
		}
		clock.advance(2_000)
		authorize(clientID)
		if ms.callCount() != 2 {
			t.Fatal(ms.callCount())
		}
	})

	revalidating := func(clientID, cacheControl, etag string, extra ...string) *[]string {
		var seen []string
		count := 0
		ms.set(clientID, func(r *http.Request) (*http.Response, error) {
			count++
			if count == 1 {
				return jsonResponse(200, cacheMetadata(clientID, ""), append([]string{"Cache-Control", cacheControl, "Etag", etag}, extra...)...), nil
			}
			seen = append(seen, r.Header.Get("If-None-Match"))
			return emptyResponse(304, "Cache-Control", "s-maxage=60"), nil
		})
		return &seen
	}

	run("treats s-maxage=0 as requiring immediate revalidation", func(t *testing.T) {
		clientID := "https://cache-tests.example/shared-cache-revalidation.json"
		seen := revalidating(clientID, "s-maxage=0, max-age=60", `"shared-v1"`, "Expires", httpDate(time.Now().UnixMilli()+120_000))
		authorize(clientID)
		authorize(clientID)
		if ms.callCount() != 2 || (*seen)[0] != `"shared-v1"` {
			t.Fatal(ms.callCount(), *seen)
		}
		authorize(clientID)
		if ms.callCount() != 2 {
			t.Fatal(ms.callCount())
		}
	})

	for _, c := range []struct{ name, cacheControl, clientID string }{
		{"duplicate s-maxage", "s-maxage=0, s-maxage=600", "https://cache-tests.example/duplicate-shared-cache.json"},
		{"invalid s-maxage with valid max-age", "s-maxage=invalid, max-age=600", "https://cache-tests.example/invalid-shared-cache.json"},
		{"invalid max-age", "max-age=invalid", "https://cache-tests.example/invalid-private-cache.json"},
	} {
		run("immediately revalidates an ambiguous freshness policy: "+c.name, func(t *testing.T) {
			seen := revalidating(c.clientID, c.cacheControl, `"ambiguous-v1"`)
			authorize(c.clientID)
			authorize(c.clientID)
			if ms.callCount() != 2 || (*seen)[0] != `"ambiguous-v1"` {
				t.Fatal(ms.callCount(), *seen)
			}
		})
	}

	run("conditionally revalidates no-cache entries with ETag and accepts 304", func(t *testing.T) {
		clientID := "https://cache-tests.example/etag-cache.json"
		count := 0
		var seen string
		ms.set(clientID, func(r *http.Request) (*http.Response, error) {
			count++
			if count == 1 {
				return jsonResponse(200, cacheMetadata(clientID, ""), "Cache-Control", "no-cache", "Etag", `"metadata-v1"`), nil
			}
			seen = r.Header.Get("If-None-Match")
			return emptyResponse(304, "Cache-Control", "max-age=60"), nil
		})
		authorize(clientID)
		if status, _ := authorize(clientID); status >= 400 {
			t.Fatal(status)
		}
		if ms.callCount() != 2 || seen != `"metadata-v1"` {
			t.Fatal(ms.callCount(), seen)
		}
		authorize(clientID)
		if ms.callCount() != 2 {
			t.Fatal(ms.callCount())
		}
	})

	run("conditionally revalidates with Last-Modified", func(t *testing.T) {
		clientID := "https://cache-tests.example/last-modified.json"
		lastModified := "Wed, 29 Jul 2026 14:00:00 GMT"
		count := 0
		var seen string
		ms.set(clientID, func(r *http.Request) (*http.Response, error) {
			count++
			if count == 1 {
				return jsonResponse(200, cacheMetadata(clientID, ""), "Cache-Control", "no-cache", "Last-Modified", lastModified), nil
			}
			seen = r.Header.Get("If-Modified-Since")
			return emptyResponse(304), nil
		})
		authorize(clientID)
		authorize(clientID)
		if ms.callCount() != 2 || seen != lastModified {
			t.Fatal(ms.callCount(), seen)
		}
	})

	run("does not cache a no-store response", func(t *testing.T) {
		clientID := "https://cache-tests.example/no-store.json"
		conditional := false
		ms.set(clientID, func(r *http.Request) (*http.Response, error) {
			if r.Header.Get("If-None-Match") != "" {
				conditional = true
			}
			return jsonResponse(200, cacheMetadata(clientID, ""), "Cache-Control", "no-store", "Etag", `"must-not-be-stored"`), nil
		})
		authorize(clientID)
		authorize(clientID)
		if ms.callCount() != 2 || conditional {
			t.Fatal(ms.callCount(), conditional)
		}
	})

	for _, c := range []struct {
		name, clientID string
		headers        []string
	}{
		{"Cache-Control private", "https://cache-tests.example/private-cache.json", []string{"Cache-Control", "private, max-age=600"}},
		{"Vary wildcard", "https://cache-tests.example/vary-wildcard.json", []string{"Cache-Control", "max-age=600", "Vary", "*"}},
	} {
		run("does not cache a response with "+c.name, func(t *testing.T) {
			ms.setJSON(c.clientID, cacheMetadata(c.clientID, ""), c.headers...)
			authorize(c.clientID)
			authorize(c.clientID)
			if ms.callCount() != 2 {
				t.Fatal(ms.callCount())
			}
		})
	}

	run("evicts the least-recently-used entry at the configured bound", func(t *testing.T) {
		ids := []string{"https://cache-tests.example/bounded-cache-a.json", "https://cache-tests.example/bounded-cache-b.json",
			"https://cache-tests.example/bounded-cache-c.json"}
		for _, id := range ids {
			ms.setJSON(id, cacheMetadata(id, ""), "Cache-Control", "max-age=60")
		}
		for _, id := range ids {
			authorize(id)
		}
		authorize(ids[0])
		if ms.callCount() != 4 {
			t.Fatal(ms.callCount())
		}
	})

	run("rejects a 304 without a validated cache entry", func(t *testing.T) {
		clientID := "https://cache-tests.example/orphan-304.json"
		ms.set(clientID, func(*http.Request) (*http.Response, error) { return emptyResponse(304), nil })
		if status, _ := authorize(clientID); status < 400 {
			t.Fatal(status)
		}
		if env.findClient(clientID) != nil {
			t.Fatal("client persisted")
		}
	})

	run("rejects an unconditional 304 when a cached document has no validator", func(t *testing.T) {
		clientID := "https://cache-tests.example/unconditional-304.json"
		count := 0
		conditional := false
		ms.set(clientID, func(r *http.Request) (*http.Response, error) {
			count++
			if count == 1 {
				return jsonResponse(200, cacheMetadata(clientID, ""), "Cache-Control", "no-cache"), nil
			}
			conditional = r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != ""
			return emptyResponse(304), nil
		})
		authorize(clientID)
		if status, _ := authorize(clientID); status < 400 {
			t.Fatal(status)
		}
		if ms.callCount() != 2 || conditional {
			t.Fatal(ms.callCount(), conditional)
		}
	})

	run("fails closed on an invalid refresh while preserving DB and cache state", func(t *testing.T) {
		clientID := "https://cache-tests.example/invalid-refresh.json"
		count := 0
		ms.set(clientID, func(*http.Request) (*http.Response, error) {
			count++
			switch count {
			case 1:
				return jsonResponse(200, cacheMetadata(clientID, "Original Client"), "Cache-Control", "no-cache", "Etag", `"v1"`), nil
			case 2:
				doc := cacheMetadata(clientID, "Invalid Client")
				doc["application_type"] = "desktop"
				return jsonResponse(200, doc, "Cache-Control", "max-age=60"), nil
			}
			return emptyResponse(304, "Cache-Control", "max-age=60"), nil
		})
		authorize(clientID)
		if status, _ := authorize(clientID); status < 400 {
			t.Fatal(status)
		}
		if name := env.findClient(clientID)["name"]; name != "Original Client" {
			t.Fatal(name)
		}
		if status, _ := authorize(clientID); status >= 400 {
			t.Fatal(status)
		}
		if ms.callCount() != 3 {
			t.Fatal(ms.callCount())
		}
	})

	run("fails closed on a network refresh and retries later", func(t *testing.T) {
		clientID := "https://cache-tests.example/failed-refresh.json"
		count := 0
		ms.set(clientID, func(*http.Request) (*http.Response, error) {
			count++
			switch count {
			case 1:
				return jsonResponse(200, cacheMetadata(clientID, ""), "Cache-Control", "no-cache", "Etag", `"v1"`), nil
			case 2:
				return nil, errors.New("network unavailable")
			}
			return emptyResponse(304, "Cache-Control", "max-age=60"), nil
		})
		authorize(clientID)
		if status, _ := authorize(clientID); status < 400 {
			t.Fatal(status)
		}
		if status, _ := authorize(clientID); status >= 400 {
			t.Fatal(status)
		}
		if ms.callCount() != 3 {
			t.Fatal(ms.callCount())
		}
	})

	run("does not cache metadata when canonical persistence fails", func(t *testing.T) {
		clientID := "https://cache-tests.example/persistence-failure.json"
		ms.setJSON(clientID, cacheMetadata(clientID, ""), "Cache-Control", "max-age=60")
		armed.Store(true)
		t.Cleanup(func() { armed.Store(false) })
		if status, _ := authorize(clientID); status < 400 {
			t.Fatal(status)
		}
		if status, _ := authorize(clientID); status >= 400 {
			t.Fatal(status)
		}
		if ms.callCount() != 2 {
			t.Fatal(ms.callCount())
		}
	})
}
