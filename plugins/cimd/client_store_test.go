package cimd

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider"
)

// Port of packages/cimd/src/client-store.test.ts. Fake timers become a shortened
// fetchTimeout; the vi.getTimerCount() assertions have no Go counterpart (the deadline is
// a context cancelled on return).

const hangingClientIDURL = "https://hanging-body-client.example.com/client-metadata.json"

func expectAPIError(t *testing.T, err error, status int, code, description string) {
	t.Helper()
	e, ok := betterauth.AsAPIError(err)
	if !ok {
		t.Fatalf("expected APIError, got %v", err)
	}
	if e.StatusCode != status {
		t.Fatalf("status %d", e.StatusCode)
	}
	if v, _ := e.Body.Get("error"); v != code {
		t.Fatalf("error %v", v)
	}
	if v, _ := e.Body.Get("error_description"); v != description {
		t.Fatalf("error_description %q", v)
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

type failingCloser struct {
	io.Reader
}

func (failingCloser) Close() error { return errors.New("response cancellation failed") }

func storeOptions(fetch oauthprovider.ClientMetadataResourceFetch) *Options {
	return &Options{FetchClientMetadataResource: fetch}
}

func TestFetchClientMetadataDocument(t *testing.T) {
	ctx := &betterauth.EndpointContext{}

	t.Run("applies the fetch deadline while consuming the response body", func(t *testing.T) {
		prev := fetchTimeout
		fetchTimeout = 50 * time.Millisecond
		t.Cleanup(func() { fetchTimeout = prev })
		pr, pw := io.Pipe()
		t.Cleanup(func() { _ = pw.Close() })
		_, err := fetchClientMetadataDocument(ctx, hangingClientIDURL, storeOptions(func(*http.Request) (*http.Response, error) {
			h := http.Header{}
			h.Set("Content-Type", "application/json")
			return &http.Response{StatusCode: 200, Header: h, Body: pr}, nil
		}), nil)
		expectAPIError(t, err, 400, "invalid_client", "Metadata document fetch timed out after "+strconv.Itoa(int(fetchTimeout.Milliseconds()))+"ms")
	})

	t.Run("maps response stream failures to invalid_client", func(t *testing.T) {
		_, err := fetchClientMetadataDocument(ctx, hangingClientIDURL, storeOptions(func(*http.Request) (*http.Response, error) {
			h := http.Header{}
			h.Set("Content-Type", "application/json")
			return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(failingReader{errors.New("response stream failed")})}, nil
		}), nil)
		expectAPIError(t, err, 400, "invalid_client", "Failed to fetch metadata document (network error or redirect blocked)")
	})

	t.Run("preserves the metadata size-limit APIError", func(t *testing.T) {
		_, err := fetchClientMetadataDocument(ctx, hangingClientIDURL, storeOptions(func(*http.Request) (*http.Response, error) {
			r := jsonResponse(200, strings.Repeat("x", 5*1024+1))
			r.Header.Del("Content-Length")
			return r, nil
		}), nil)
		expectAPIError(t, err, 400, "invalid_client", "Metadata document exceeds 5KB size limit")
	})

	t.Run("maps response cancellation failures to invalid_client", func(t *testing.T) {
		_, err := fetchClientMetadataDocument(ctx, hangingClientIDURL, storeOptions(func(*http.Request) (*http.Response, error) {
			h := http.Header{}
			h.Set("Content-Type", "application/json")
			h.Set("Content-Length", strconv.Itoa(5*1024+1))
			return &http.Response{StatusCode: 200, Header: h, Body: failingCloser{strings.NewReader("")}}, nil
		}), nil)
		expectAPIError(t, err, 400, "invalid_client", "Failed to fetch metadata document (network error or redirect blocked)")
	})

	// Go-only: the request carries Accept and the conditional validators.
	t.Run("sends Accept and conditional validators", func(t *testing.T) {
		var got http.Header
		res, err := fetchClientMetadataDocument(ctx, hangingClientIDURL, storeOptions(func(r *http.Request) (*http.Response, error) {
			got = r.Header
			return emptyResponse(304), nil
		}), &conditionalValidators{etag: `"v1"`, lastModified: "Wed, 29 Jul 2026 14:00:00 GMT"})
		if err != nil || !res.notModified {
			t.Fatal(err, res)
		}
		if got.Get("Accept") != "application/json" || got.Get("If-None-Match") != `"v1"` || got.Get("If-Modified-Since") != "Wed, 29 Jul 2026 14:00:00 GMT" {
			t.Fatal(got)
		}
	})

	t.Run("reports Content-Type errors with the upstream message", func(t *testing.T) {
		_, err := fetchClientMetadataDocument(ctx, hangingClientIDURL, storeOptions(func(*http.Request) (*http.Response, error) {
			return jsonResponse(200, "{}", "Content-Type", ""), nil
		}), nil)
		expectAPIError(t, err, 400, "invalid_client", `Metadata document must be JSON (got Content-Type "(none)")`)
	})
}
