package oauthprovider

import (
	"fmt"
	"regexp"
	"sync"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Port of claims.test.ts.

type mxCaptureLogger struct {
	mu    sync.Mutex
	warns []string
}

func (l *mxCaptureLogger) Debug(string, ...any) {}
func (l *mxCaptureLogger) Info(string, ...any)  {}
func (l *mxCaptureLogger) Error(string, ...any) {}
func (l *mxCaptureLogger) Warn(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warns = append(l.warns, fmt.Sprint(append([]any{msg}, args...)...))
}

func mxClaimsInput(log betterauth.Logger, o *resolved) accessTokenClaimsInput {
	if log == nil {
		log = betterauth.NopLogger{}
	}
	return accessTokenClaimsInput{
		ctx:    &betterauth.EndpointContext{Auth: &betterauth.AuthContext{Logger: log}},
		opts:   o,
		client: &SchemaClient{},
		scopes: []string{"openid"},
	}
}

func mxCustomClaims(kv ...any) func(AccessTokenClaimsInput) (*jsonx.Object, error) {
	return func(AccessTokenClaimsInput) (*jsonx.Object, error) { return jsonx.O(kv...), nil }
}

func TestMx_ResolveAccessTokenClaims(t *testing.T) {
	t.Run("returns an empty bag when no source contributes claims", func(t *testing.T) {
		in := mxClaimsInput(nil, &resolved{})
		in.resourcePolicyClaims = jsonx.NewObject()
		claims, err := resolveAccessTokenClaims(in)
		if err != nil {
			t.Fatal(err)
		}
		mxExpectJSON(t, claims, map[string]any{})
	})
	t.Run("merges plugin and resource claims, resource winning a collision", func(t *testing.T) {
		in := mxClaimsInput(nil, &resolved{Options: Options{CustomAccessTokenClaims: mxCustomClaims("tier", "free", "region", "eu")}})
		in.resourcePolicyClaims = jsonx.O("tier", "enterprise", "dept", "ops")
		claims, err := resolveAccessTokenClaims(in)
		if err != nil {
			t.Fatal(err)
		}
		mxExpectJSON(t, claims, map[string]any{"tier": "enterprise", "region": "eu", "dept": "ops"})
	})
	t.Run("strips reserved RFC 9068 names from every source", func(t *testing.T) {
		in := mxClaimsInput(nil, &resolved{Options: Options{CustomAccessTokenClaims: mxCustomClaims("sub", "evil", "role", "admin")}})
		in.resourcePolicyClaims = jsonx.O("iss", "evil", "scope", "evil", "dept", "ops")
		claims, err := resolveAccessTokenClaims(in)
		if err != nil {
			t.Fatal(err)
		}
		mxExpectJSON(t, claims, map[string]any{"role": "admin", "dept": "ops"})
		for _, r := range []string{"sub", "iss", "scope"} {
			if claims.Has(r) {
				t.Fatalf("%s not stripped", r)
			}
		}
	})
	t.Run("warns, naming the reserved claim names it stripped", func(t *testing.T) {
		log := &mxCaptureLogger{}
		in := mxClaimsInput(log, &resolved{Options: Options{CustomAccessTokenClaims: mxCustomClaims("jti", "evil", "role", "admin")}})
		in.resourcePolicyClaims = jsonx.O("iss", "evil")
		if _, err := resolveAccessTokenClaims(in); err != nil {
			t.Fatal(err)
		}
		if len(log.warns) != 1 {
			t.Fatalf("warns: %v", log.warns)
		}
		msg := log.warns[0]
		if !regexp.MustCompile(`(?i)stripped reserved access-token claim`).MatchString(msg) ||
			!regexp.MustCompile(`jti`).MatchString(msg) || !regexp.MustCompile(`iss`).MatchString(msg) {
			t.Fatalf("message: %s", msg)
		}
	})
	t.Run("hands derivable token context to customAccessTokenClaims", func(t *testing.T) {
		var received *AccessTokenClaimsInput
		in := mxClaimsInput(nil, &resolved{Options: Options{CustomAccessTokenClaims: func(info AccessTokenClaimsInput) (*jsonx.Object, error) {
			received = &info
			return jsonx.NewObject(), nil
		}}})
		in.scopes = []string{"openid", "email"}
		in.resources = []string{"https://api.example.com"}
		in.referenceID = "ref-1"
		in.metadata = jsonx.O("plan", "pro")
		in.resourcePolicyClaims = jsonx.NewObject()
		if _, err := resolveAccessTokenClaims(in); err != nil {
			t.Fatal(err)
		}
		if received == nil {
			t.Fatal("customAccessTokenClaims not called")
		}
		mxExpectJSON(t, map[string]any{"scopes": received.Scopes, "resources": received.Resources,
			"referenceId": received.ReferenceID, "metadata": received.Metadata},
			map[string]any{"scopes": []any{"openid", "email"}, "resources": []any{"https://api.example.com"},
				"referenceId": "ref-1", "metadata": map[string]any{"plan": "pro"}})
	})
	t.Run("passes sessionId to an access-token extension contributor", func(t *testing.T) {
		var received *ClaimExtensionInput
		in := mxClaimsInput(nil, &resolved{Options: Options{Extensions: []*Extension{{Claims: &ExtensionClaims{
			AccessToken: func(i ClaimExtensionInput) (*jsonx.Object, error) {
				received = &i
				return jsonx.NewObject(), nil
			},
		}}}}})
		in.sessionID = "sess-123"
		in.resourcePolicyClaims = jsonx.NewObject()
		if _, err := resolveAccessTokenClaims(in); err != nil {
			t.Fatal(err)
		}
		if received == nil || received.SessionID != "sess-123" {
			t.Fatalf("received: %+v", received)
		}
	})
}
