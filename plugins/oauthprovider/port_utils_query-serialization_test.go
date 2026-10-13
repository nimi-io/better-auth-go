package oauthprovider

import (
	"strconv"
	"testing"
	"time"
)

// Port of utils/query-serialization.test.ts.

func TestMx_SearchParamsToQuery(t *testing.T) {
	t.Run("preserves single-valued params as strings", func(t *testing.T) {
		mxExpectJSON(t, searchParamsToQuery(parseSearchParams("client_id=abc&scope=openid")),
			map[string]any{"client_id": "abc", "scope": "openid"})
	})
	t.Run("preserves multi-valued params as arrays", func(t *testing.T) {
		mxExpectJSON(t, searchParamsToQuery(parseSearchParams("resource=https://api.example.com&resource=https://other.example.com")),
			map[string]any{"resource": []any{"https://api.example.com", "https://other.example.com"}})
	})
	t.Run("handles a mix of single and multi-valued params", func(t *testing.T) {
		p := newSearchParams()
		p.append("client_id", "abc")
		p.append("resource", "https://api.example.com")
		p.append("resource", "https://other.example.com")
		p.append("scope", "openid profile")
		mxExpectJSON(t, searchParamsToQuery(p), map[string]any{
			"client_id": "abc",
			"resource":  []any{"https://api.example.com", "https://other.example.com"},
			"scope":     "openid profile",
		})
	})
	t.Run("handles empty params", func(t *testing.T) {
		mxExpectJSON(t, searchParamsToQuery(newSearchParams()), map[string]any{})
	})
}

func mxQueryGet(t *testing.T, p *searchParams) map[string]any {
	t.Helper()
	m, _ := mxJSON(t, searchParamsToQuery(p)).(map[string]any)
	return m
}

func TestMx_RemovePromptFromQuery(t *testing.T) {
	t.Run("removes a prompt value and preserves other params", func(t *testing.T) {
		r := mxQueryGet(t, removePromptFromQuery(parseSearchParams("client_id=abc&prompt=login consent&scope=openid"), "login"))
		if r["prompt"] != "consent" || r["client_id"] != "abc" || r["scope"] != "openid" {
			t.Fatalf("got %v", r)
		}
	})
	t.Run("deletes the prompt key when the last value is removed", func(t *testing.T) {
		r := mxQueryGet(t, removePromptFromQuery(parseSearchParams("client_id=abc&prompt=consent&scope=openid"), "consent"))
		if _, ok := r["prompt"]; ok || r["client_id"] != "abc" {
			t.Fatalf("got %v", r)
		}
	})
	t.Run("preserves multi-valued params through prompt deletion", func(t *testing.T) {
		p := newSearchParams()
		p.append("client_id", "abc")
		p.append("prompt", "login consent")
		p.append("resource", "https://api.example.com")
		p.append("resource", "https://other.example.com")
		r := mxQueryGet(t, removePromptFromQuery(p, "login"))
		if r["prompt"] != "consent" {
			t.Fatalf("got %v", r)
		}
		mxExpectJSON(t, r["resource"], []any{"https://api.example.com", "https://other.example.com"})
	})
	t.Run("does nothing when the prompt value is not present", func(t *testing.T) {
		r := mxQueryGet(t, removePromptFromQuery(parseSearchParams("client_id=abc&prompt=consent"), "login"))
		if r["prompt"] != "consent" {
			t.Fatalf("got %v", r)
		}
	})
	t.Run("does not mutate the original query", func(t *testing.T) {
		p := parseSearchParams("client_id=abc&prompt=login consent&scope=openid")
		removePromptFromQuery(p, "login")
		if p.getString("prompt") != "login consent" {
			t.Fatalf("mutated: %s", p.String())
		}
	})
}

func TestMx_RemoveMaxAgeFromQuery(t *testing.T) {
	t.Run("removes max_age and preserves other params", func(t *testing.T) {
		r := mxQueryGet(t, removeMaxAgeFromQuery(parseSearchParams("client_id=abc&max_age=0&prompt=login&scope=openid")))
		if _, ok := r["max_age"]; ok || r["client_id"] != "abc" || r["prompt"] != "login" || r["scope"] != "openid" {
			t.Fatalf("got %v", r)
		}
	})
	t.Run("does not mutate the original query", func(t *testing.T) {
		p := parseSearchParams("client_id=abc&max_age=0")
		removeMaxAgeFromQuery(p)
		if p.getString("max_age") != "0" {
			t.Fatalf("mutated: %s", p.String())
		}
	})
}

func TestMx_GetSignedQueryIssuedAt(t *testing.T) {
	t.Run("reads the signed query issue time when present", func(t *testing.T) {
		issuedAt := int64(1777026004123)
		p := newSearchParams()
		p.set("client_id", "abc")
		p.set(signedQueryIssuedAtParam, strconv.FormatInt(issuedAt, 10))
		got := getSignedQueryIssuedAt(p.String())
		if got == nil || got.UnixMilli() != issuedAt {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("returns null when ba_iat is absent", func(t *testing.T) {
		p := newSearchParams()
		p.set("client_id", "abc")
		p.set("exp", "1777026604")
		if got := getSignedQueryIssuedAt(p.String()); got != nil {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("returns null when ba_iat is not a positive finite number", func(t *testing.T) {
		p := newSearchParams()
		p.set("client_id", "abc")
		p.set(signedQueryIssuedAtParam, "not-a-number")
		if got := getSignedQueryIssuedAt(p.String()); got != nil {
			t.Fatalf("got %v", got)
		}
	})
}

// mxIsSessionFresh adapts isSessionFreshForSignedQuery to upstream's unknown createdAt
// (normalized through normalizeTimestampValue; undefined / invalid become the zero time).
func mxIsSessionFresh(createdAt any, issuedAt *time.Time) bool {
	var c time.Time
	if n := normalizeTimestampValue(createdAt); n != nil {
		c = *n
	}
	return isSessionFreshForSignedQuery(c, issuedAt)
}

func mxISO(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

func TestMx_IsSessionFreshForSignedQuery(t *testing.T) {
	t.Run("accepts a session created at or after the signed query issue time", func(t *testing.T) {
		issuedAt := mxISO(t, "2026-06-08T12:00:00.000Z")
		if !mxIsSessionFresh(issuedAt, &issuedAt) {
			t.Fatal("equal time should be fresh")
		}
		if !mxIsSessionFresh(mxISO(t, "2026-06-08T12:00:00.001Z"), &issuedAt) {
			t.Fatal("later time should be fresh")
		}
	})
	t.Run("rejects a session that predates the signed query issue time", func(t *testing.T) {
		issuedAt := mxISO(t, "2026-06-08T12:00:00.000Z")
		if mxIsSessionFresh(mxISO(t, "2026-06-08T11:59:59.999Z"), &issuedAt) {
			t.Fatal("earlier time should not be fresh")
		}
	})
	t.Run("rejects missing or invalid timestamps", func(t *testing.T) {
		issuedAt := mxISO(t, "2026-06-08T12:00:00.000Z")
		if mxIsSessionFresh(nil, &issuedAt) || mxIsSessionFresh("not-a-date", &issuedAt) || mxIsSessionFresh(issuedAt, nil) {
			t.Fatal("expected false")
		}
	})
}
