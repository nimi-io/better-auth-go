package oauthprovider

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of resource-challenge.test.ts.

func rsCatchChallenge(t *testing.T, resources ...string) *betterauth.APIError {
	t.Helper()
	e, err := CreateResourceServerChallenge(betterauth.NewAPIError("UNAUTHORIZED", jsonx.O("message", "missing bearer token")), resources, nil)
	if err != nil || e == nil {
		t.Fatalf("challenge: %v %v", e, err)
	}
	return e
}

func rsExpectErrContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("expected error containing %q, got %v", want, err)
	}
}

func TestRs_ResourceServerChallenge(t *testing.T) {
	t.Run("derives the RFC 9728 metadata URL from the protected resource", func(t *testing.T) {
		e := rsCatchChallenge(t, "https://api.example.com/mcp/tools?tenant=a")
		if e.Status != "UNAUTHORIZED" {
			t.Fatal(e.Status)
		}
		if got := e.Headers.Get("WWW-Authenticate"); got != `Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp/tools?tenant=a"` {
			t.Fatal(got)
		}
	})
	t.Run("emits one resource_metadata challenge per protected resource", func(t *testing.T) {
		e := rsCatchChallenge(t, "https://api.example.com/calendar/", "https://files.example.com")
		if got := e.Headers.Get("WWW-Authenticate"); got != `Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/calendar", Bearer resource_metadata="https://files.example.com/.well-known/oauth-protected-resource"` {
			t.Fatal(got)
		}
	})
	t.Run("answers insufficient scope with an RFC 6750 403 challenge", func(t *testing.T) {
		e, err := CreateResourceServerChallenge(oauthcore.CreateInsufficientScopeError([]string{"files:write", "files:delete"}, ""),
			[]string{"https://api.example.com/mcp/tools"}, nil)
		if err != nil || e == nil {
			t.Fatal(err)
		}
		if e.Status != "FORBIDDEN" || e.StatusCode != 403 {
			t.Fatal(e.Status)
		}
		if got := e.Headers.Get("WWW-Authenticate"); got != `Bearer error="insufficient_scope", scope="files:write files:delete", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp/tools", error_description="access token is missing required scope: files:write files:delete"` {
			t.Fatal(got)
		}
	})
	t.Run("challenges for the scopes the token lacks, not the configured hint", func(t *testing.T) {
		e, err := CreateResourceServerChallenge(oauthcore.CreateInsufficientScopeError([]string{"files:write"}, ""),
			[]string{"https://api.example.com"}, &ResourceChallengeOptions{ChallengeScopes: []string{"files:read"}})
		if err != nil {
			t.Fatal(err)
		}
		if got := e.Headers.Get("WWW-Authenticate"); !strings.Contains(got, `scope="files:write"`) {
			t.Fatal(got)
		}
	})
	t.Run("propagates a forbidden error that is not a scope failure", func(t *testing.T) {
		denial := betterauth.NewAPIError("FORBIDDEN", jsonx.O("message", "user is not a member of this organization"))
		e, err := CreateResourceServerChallenge(denial, []string{"https://api.example.com"}, nil)
		if err != nil || e != nil {
			t.Fatalf("expected undefined, got %v %v", e, err)
		}
		if denial.Headers.Get("WWW-Authenticate") != "" {
			t.Fatal("header set on denial")
		}
	})
	t.Run("resolves a mapped resource_metadata URL in a 403 challenge", func(t *testing.T) {
		e, err := CreateResourceServerChallenge(oauthcore.CreateInsufficientScopeError([]string{"mcp:tools"}, ""),
			[]string{"urn:example:mcp"}, &ResourceChallengeOptions{ResourceMetadataMappings: map[string]string{
				"urn:example:mcp": "https://api.example.com/.well-known/oauth-protected-resource"}})
		if err != nil {
			t.Fatal(err)
		}
		if e.StatusCode != 403 {
			t.Fatal(e.StatusCode)
		}
		if got := e.Headers.Get("WWW-Authenticate"); got != `Bearer error="insufficient_scope", scope="mcp:tools", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource", error_description="access token is missing required scope: mcp:tools"` {
			t.Fatal(got)
		}
	})
	t.Run("rejects header-injection characters in challenge params", func(t *testing.T) {
		ie := oauthcore.CreateInsufficientScopeError([]string{"files:write"}, "")
		ie.Body.Set("error_description", "bad \"scope\"\r\nSet-Cookie: x=y")
		_, err := CreateResourceServerChallenge(ie, []string{"https://api.example.com"}, nil)
		rsExpectErrContains(t, err, "invalid error_description")
	})
	t.Run("retains serialization-time validation for a mutated typed scope error", func(t *testing.T) {
		ie := oauthcore.CreateInsufficientScopeError([]string{"files:write"}, "")
		ie.Body.Set("error_description", "café")
		_, err := CreateResourceServerChallenge(ie, []string{"https://api.example.com"}, nil)
		rsExpectErrContains(t, err, "invalid error_description")
	})
	for _, d := range []any{42, nil} {
		raw, _ := jsonx.Marshal(d)
		t.Run(fmt.Sprintf("rejects a non-string insufficient-scope error_description during serialization: %s", raw), func(t *testing.T) {
			ie := oauthcore.CreateInsufficientScopeError([]string{"files:write"}, "")
			ie.Body.Set("error_description", d)
			_, err := CreateResourceServerChallenge(ie, []string{"https://api.example.com"}, nil)
			if err == nil || err.Error() != "invalid error_description" {
				t.Fatalf("got %v", err)
			}
		})
	}
	t.Run("rejects invalid configured challenge scope tokens", func(t *testing.T) {
		_, err := CreateResourceServerChallenge(betterauth.NewAPIError("UNAUTHORIZED", jsonx.O("message", "missing bearer token")),
			[]string{"https://api.example.com"}, &ResourceChallengeOptions{ChallengeScopes: []string{"files:read injected"}})
		rsExpectErrContains(t, err, "invalid challenge scope")
	})
	t.Run("emits RFC 9449 DPoP challenges for invalid DPoP proofs", func(t *testing.T) {
		e, err := CreateResourceServerChallenge(betterauth.NewAPIError("UNAUTHORIZED", jsonx.O("message", "DPoP proof header is required",
			"error", "invalid_dpop_proof", "error_description", "DPoP proof header is required")),
			[]string{"https://api.example.com/mcp/tools"}, &ResourceChallengeOptions{DPoPSigningAlgorithms: []string{"ES256"}})
		if err != nil {
			t.Fatal(err)
		}
		if got := e.Headers.Get("WWW-Authenticate"); got != `DPoP error="invalid_dpop_proof", error_description="DPoP proof header is required", algs="ES256"` {
			t.Fatal(got)
		}
	})
	for _, d := range []string{`bad "quote"`, `bad\slash`, "café", "bad\r\ninjected"} {
		t.Run("rejects an invalid DPoP error_description: "+d, func(t *testing.T) {
			_, err := CreateResourceServerChallenge(betterauth.NewAPIError("UNAUTHORIZED", jsonx.O("message", d,
				"error", "invalid_dpop_proof", "error_description", d)), []string{"https://api.example.com"}, nil)
			rsExpectErrContains(t, err, "invalid error_description")
		})
	}
}
