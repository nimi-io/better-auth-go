package oauthprovider

import "testing"

// Port of signed-query.test.ts.

func TestMx_SignedOAuthQuery(t *testing.T) {
	t.Run("builds oauth_query from declared signed params", func(t *testing.T) {
		signed := newSearchParams()
		signed.set("client_id", "client-a")
		signed.set("custom_authorization_context", "tenant-a")
		signed.append("resource", "https://api.example.com")
		signed.set("exp", "123")
		setSignedOAuthQueryParameterNames(signed)
		signed.set("sig", "test-sig")
		reordered := newSearchParams()
		for i := len(signed.list) - 1; i >= 0; i-- {
			reordered.append(signed.list[i].k, signed.list[i].v)
		}
		reordered.append("utm_email", "user@example.com")
		oauthQuery := BuildSignedOAuthQuery("?" + reordered.String())
		if oauthQuery == "" {
			t.Fatal("Expected signed OAuth query")
		}
		p := parseSearchParams(oauthQuery)
		if p.getString("custom_authorization_context") != "tenant-a" {
			t.Fatalf("context: %s", oauthQuery)
		}
		if p.getString("resource") != "https://api.example.com" {
			t.Fatalf("resource: %s", oauthQuery)
		}
		if p.has("utm_email") {
			t.Fatalf("utm_email leaked: %s", oauthQuery)
		}
		if !contains(p.getAll(signedQueryParameterNameParam), "custom_authorization_context") {
			t.Fatalf("ba_param: %s", oauthQuery)
		}
	})
	t.Run("ignores legacy signed queries without declared signed params", func(t *testing.T) {
		if got := BuildSignedOAuthQuery("?client_id=client-a&sig=test-sig"); got != "" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("canonicalizes repeated params by key and value", func(t *testing.T) {
		p := newSearchParams()
		p.append("resource", "https://b.example.com")
		p.append("client_id", "client-a")
		p.append("resource", "https://a.example.com")
		want := "client_id=client-a&resource=https%3A%2F%2Fa.example.com&resource=https%3A%2F%2Fb.example.com"
		if got := canonicalizeOAuthQueryParams(p).String(); got != want {
			t.Fatalf("got %q", got)
		}
	})
}
