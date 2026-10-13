package oauthprovider

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Port of validation-flow.test.ts.

type mxBoot struct {
	env  *testEnv
	ctx  *betterauth.EndpointContext
	opts *resolved
}

// mxBootProvider mirrors bootProvider: jwt + oauth-provider with
// enforcePerClientResources=false by default, then a resource seed.
func mxBootProvider(t *testing.T, opts Options) *mxBoot {
	t.Helper()
	if opts.EnforcePerClientResources == nil {
		opts.EnforcePerClientResources = mxBoolPtr(false)
	}
	env := newEnv(t, opts, envOptions{disableTestUser: true})
	ResetSeedStateForTests(env.plugin)
	o := env.plugin.Options.(*resolved)
	ac := env.auth.Context()
	if err := seedResourcesOnce(context.Background(), ac, o); err != nil {
		t.Fatal(err)
	}
	return &mxBoot{env: env, opts: o, ctx: &betterauth.EndpointContext{Auth: ac, Body: map[string]any{}}}
}

func mxResources(ids ...string) []ResourceInput {
	out := make([]ResourceInput, len(ids))
	for i, id := range ids {
		out[i] = ResourceInput{Identifier: id}
	}
	return out
}

func (b *mxBoot) updateResource(id string, upd adapter.Record) {
	b.env.update("oauthResource", upd, eq("identifier", id))
}

func (b *mxBoot) policy(resource any, clientID string, scopes []string) (*resourcePolicy, error) {
	return resolveResourcePolicy(b.ctx, b.opts, resource, clientID, scopes)
}

func (b *mxBoot) mustPolicy(t *testing.T, resource any, clientID string, scopes []string) *resourcePolicy {
	t.Helper()
	p, err := b.policy(resource, clientID, scopes)
	if err != nil {
		t.Fatalf("resolveResourcePolicy: %v %v", err, mxErrBody(err))
	}
	return p
}

func mxErrBody(err error) map[string]any {
	if e, ok := betterauth.AsAPIError(err); ok {
		return errBody(e)
	}
	return nil
}

func mxExpectPolicyError(t *testing.T, err error, code, descContains string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got success", code)
	}
	body := mxErrBody(err)
	if body["error"] != code {
		t.Fatalf("expected %s, got %v (%v)", code, body, err)
	}
	if descContains != "" {
		d, _ := body["error_description"].(string)
		if !strings.Contains(d, descContains) {
			t.Fatalf("description %q does not contain %q", d, descContains)
		}
	}
}

func TestMx_ResolveResourcePolicyResourceOmission(t *testing.T) {
	t.Run("returns no aud claim when neither resource nor openid scope is present", func(t *testing.T) {
		b := mxBootProvider(t, Options{})
		p := b.mustPolicy(t, nil, "client-x", []string{})
		if toAudienceClaim(p.audience) != nil || p.accessTokenTTL != nil {
			t.Fatalf("policy: %+v", p)
		}
	})
	t.Run("does NOT add the implicit /oauth2/userinfo aud when no resource is requested", func(t *testing.T) {
		b := mxBootProvider(t, Options{})
		p := b.mustPolicy(t, nil, "client-x", []string{"openid", "profile"})
		if toAudienceClaim(p.audience) != nil {
			t.Fatalf("aud: %v", p.audience)
		}
	})
	t.Run("adds the implicit /oauth2/userinfo aud alongside a requested resource when openid is in scope", func(t *testing.T) {
		id := "https://api.example.com/openid-with-resource"
		b := mxBootProvider(t, Options{Resources: mxResources(id)})
		p := b.mustPolicy(t, id, "client-x", []string{"openid", "profile"})
		mxExpectJSON(t, toAudienceClaim(p.audience), []any{id, b.ctx.Auth.BaseURL + "/oauth2/userinfo"})
	})
	t.Run("dedupes the implicit /oauth2/userinfo aud when it was explicitly requested", func(t *testing.T) {
		id := "https://api.example.com/openid-with-explicit-userinfo"
		b := mxBootProvider(t, Options{Resources: mxResources(id)})
		ui := b.ctx.Auth.BaseURL + "/oauth2/userinfo"
		p := b.mustPolicy(t, []any{id, ui}, "client-x", []string{"openid", "profile"})
		mxExpectJSON(t, toAudienceClaim(p.audience), []any{id, ui})
	})
	t.Run("rejects baseURL when it is not configured as a resource", func(t *testing.T) {
		b := mxBootProvider(t, Options{})
		_, err := b.policy(b.ctx.Auth.BaseURL, "client-x", []string{})
		mxExpectPolicyError(t, err, "invalid_target", "")
	})
	t.Run("rejects unknown resources when no resource config is set", func(t *testing.T) {
		b := mxBootProvider(t, Options{})
		_, err := b.policy("https://api.example.com/unknown", "client-x", []string{})
		mxExpectPolicyError(t, err, "invalid_target", "")
	})
}

func TestMx_ResolveResourcePolicyEntityPath(t *testing.T) {
	t.Run("rejects unknown resource identifiers", func(t *testing.T) {
		b := mxBootProvider(t, Options{Resources: mxResources("https://api.example.com")})
		_, err := b.policy("https://api.example.com/not-configured", "client-x", []string{})
		mxExpectPolicyError(t, err, "invalid_target", "")
	})
	t.Run("rejects disabled resources", func(t *testing.T) {
		id := "https://api.example.com/disabled"
		b := mxBootProvider(t, Options{Resources: mxResources(id)})
		b.updateResource(id, adapter.Record{"disabled": true})
		_, err := b.policy(id, "client-x", []string{})
		mxExpectPolicyError(t, err, "invalid_target", "")
	})
	t.Run("returns per-resource TTL when set", func(t *testing.T) {
		id := "https://api.example.com/ttl-test"
		b := mxBootProvider(t, Options{Resources: mxResources(id)})
		b.updateResource(id, adapter.Record{"accessTokenTtl": 120})
		p := b.mustPolicy(t, id, "client-x", []string{})
		if p.accessTokenTTL == nil || *p.accessTokenTTL != 120 {
			t.Fatalf("ttl: %v", p.accessTokenTTL)
		}
	})
	t.Run("uses the minimum TTL across multiple requested resources", func(t *testing.T) {
		ids := []string{"https://api.example.com/a", "https://api.example.com/b", "https://api.example.com/c"}
		b := mxBootProvider(t, Options{Resources: mxResources(ids...)})
		for i, ttl := range []int{300, 60, 900} {
			b.updateResource(ids[i], adapter.Record{"accessTokenTtl": ttl})
		}
		p := b.mustPolicy(t, ids, "client-x", []string{})
		if p.accessTokenTTL == nil || *p.accessTokenTTL != 60 {
			t.Fatalf("ttl: %v", p.accessTokenTTL)
		}
	})
	t.Run("returns null TTL when no requested resource pins one", func(t *testing.T) {
		id := "https://api.example.com/no-ttl"
		b := mxBootProvider(t, Options{Resources: mxResources(id)})
		if p := b.mustPolicy(t, id, "client-x", []string{}); p.accessTokenTTL != nil {
			t.Fatalf("ttl: %v", *p.accessTokenTTL)
		}
	})
	t.Run("narrows requested scopes to the resource's allowedScopes intersection", func(t *testing.T) {
		id := "https://api.example.com/scope-restricted"
		b := mxBootProvider(t, Options{Resources: mxResources(id)})
		b.updateResource(id, adapter.Record{"allowedScopes": []string{"read:public"}})
		p := b.mustPolicy(t, id, "client-x", []string{"read:public", "admin:write"})
		mxExpectJSON(t, p.effectiveScopes, []any{"read:public"})
	})
	t.Run("rejects when no requested scope intersects allowedScopes", func(t *testing.T) {
		id := "https://api.example.com/scope-no-intersect"
		b := mxBootProvider(t, Options{Resources: mxResources(id)})
		b.updateResource(id, adapter.Record{"allowedScopes": []string{"read:public"}})
		_, err := b.policy(id, "client-x", []string{"admin:write"})
		mxExpectPolicyError(t, err, "invalid_scope", "")
	})
	t.Run("passes when requested scopes are within allowedScopes", func(t *testing.T) {
		id := "https://api.example.com/scope-ok"
		b := mxBootProvider(t, Options{Resources: mxResources(id)})
		b.updateResource(id, adapter.Record{"allowedScopes": []string{"read", "write"}})
		p := b.mustPolicy(t, id, "client-x", []string{"read"})
		if toAudienceClaim(p.audience) != id {
			t.Fatalf("aud: %v", p.audience)
		}
	})
	t.Run("treats null allowedScopes as 'no restriction'", func(t *testing.T) {
		id := "https://api.example.com/unrestricted"
		b := mxBootProvider(t, Options{Resources: mxResources(id)})
		p := b.mustPolicy(t, id, "client-x", []string{"read", "write", "anything"})
		if toAudienceClaim(p.audience) != id {
			t.Fatalf("aud: %v", p.audience)
		}
	})
	t.Run("returns single-resource signing config", func(t *testing.T) {
		id := "https://api.example.com/signed"
		b := mxBootProvider(t, Options{Resources: mxResources(id)})
		b.updateResource(id, adapter.Record{"signingAlgorithm": "EdDSA", "signingKeyId": "kid-xyz"})
		p := b.mustPolicy(t, id, "client-x", []string{})
		if p.signingAlgorithm != "EdDSA" || p.signingKeyID != "kid-xyz" {
			t.Fatalf("policy: %+v", p)
		}
	})
	t.Run("throws on multi-resource requests where resources pin conflicting signing keys", func(t *testing.T) {
		a, c := "https://api.example.com/sig-a", "https://api.example.com/sig-b"
		b := mxBootProvider(t, Options{Resources: mxResources(a, c)})
		b.updateResource(a, adapter.Record{"signingAlgorithm": "EdDSA", "signingKeyId": "kid-a"})
		b.updateResource(c, adapter.Record{"signingAlgorithm": "ES256", "signingKeyId": "kid-b"})
		_, err := b.policy([]any{a, c}, "client-x", []string{})
		mxExpectPolicyError(t, err, "invalid_request", "")
	})
	t.Run("accepts multi-resource requests when every pin agrees on alg and kid", func(t *testing.T) {
		a, c := "https://api.example.com/sig-agree-a", "https://api.example.com/sig-agree-b"
		b := mxBootProvider(t, Options{Resources: mxResources(a, c)})
		b.updateResource(a, adapter.Record{"signingAlgorithm": "EdDSA", "signingKeyId": "kid-shared"})
		b.updateResource(c, adapter.Record{"signingAlgorithm": "EdDSA", "signingKeyId": "kid-shared"})
		p := b.mustPolicy(t, []any{a, c}, "client-x", []string{})
		if p.signingAlgorithm != "EdDSA" || p.signingKeyID != "kid-shared" {
			t.Fatalf("policy: %+v", p)
		}
	})
	t.Run("accepts multi-resource requests where compatible pins are spread across resources", func(t *testing.T) {
		a, c := "https://api.example.com/sig-mixed-a", "https://api.example.com/sig-mixed-b"
		b := mxBootProvider(t, Options{Resources: mxResources(a, c)})
		b.updateResource(a, adapter.Record{"signingAlgorithm": "EdDSA", "signingKeyId": nil})
		b.updateResource(c, adapter.Record{"signingAlgorithm": nil, "signingKeyId": "kid-shared"})
		p := b.mustPolicy(t, []any{a, c}, "client-x", []string{})
		if p.signingAlgorithm != "EdDSA" || p.signingKeyID != "kid-shared" {
			t.Fatalf("policy: %+v", p)
		}
	})
	t.Run("accepts multi-resource requests where only one resource pins and others inherit defaults", func(t *testing.T) {
		a, c := "https://api.example.com/sig-partial-a", "https://api.example.com/sig-partial-b"
		b := mxBootProvider(t, Options{Resources: mxResources(a, c)})
		b.updateResource(a, adapter.Record{"signingAlgorithm": "EdDSA", "signingKeyId": "kid-only-a"})
		p := b.mustPolicy(t, []any{a, c}, "client-x", []string{})
		if p.signingAlgorithm != "EdDSA" || p.signingKeyID != "kid-only-a" {
			t.Fatalf("policy: %+v", p)
		}
	})
	t.Run("rejects when algs agree but kids conflict (partial conflict — kid)", func(t *testing.T) {
		a, c := "https://api.example.com/sig-kid-conflict-a", "https://api.example.com/sig-kid-conflict-b"
		b := mxBootProvider(t, Options{Resources: mxResources(a, c)})
		b.updateResource(a, adapter.Record{"signingAlgorithm": "EdDSA", "signingKeyId": "kid-a"})
		b.updateResource(c, adapter.Record{"signingAlgorithm": "EdDSA", "signingKeyId": "kid-b"})
		_, err := b.policy([]any{a, c}, "client-x", []string{})
		mxExpectPolicyError(t, err, "invalid_request", "signingKeyId")
	})
	t.Run("rejects when kids agree but algs conflict (partial conflict — alg)", func(t *testing.T) {
		a, c := "https://api.example.com/sig-alg-conflict-a", "https://api.example.com/sig-alg-conflict-b"
		b := mxBootProvider(t, Options{Resources: mxResources(a, c)})
		b.updateResource(a, adapter.Record{"signingAlgorithm": "EdDSA", "signingKeyId": "kid-shared"})
		b.updateResource(c, adapter.Record{"signingAlgorithm": "ES256", "signingKeyId": "kid-shared"})
		_, err := b.policy([]any{a, c}, "client-x", []string{})
		mxExpectPolicyError(t, err, "invalid_request", "signingAlgorithm")
	})
	t.Run("merges per-resource customClaims (later wins), returning reserved names raw for the claim resolver to strip", func(t *testing.T) {
		a, c := "https://api.example.com/claims-a", "https://api.example.com/claims-b"
		b := mxBootProvider(t, Options{Resources: mxResources(a, c)})
		b.updateResource(a, adapter.Record{"customClaims": jsonx.O("dept", "finance", "iss", "evil-A")})
		b.updateResource(c, adapter.Record{"customClaims": jsonx.O("dept", "ops", "region", "us")})
		p := b.mustPolicy(t, []any{a, c}, "client-x", []string{})
		mxExpectJSON(t, p.rawCustomClaims, map[string]any{"dept": "ops", "iss": "evil-A", "region": "us"})
	})
}

func TestMx_ResolveResourcePolicyEnforcePerClientResources(t *testing.T) {
	seedClientLink := func(b *mxBoot, clientID, resourceID string) {
		now := time.Now()
		if _, err := b.env.db.Create(context.Background(), adapter.CreateInput{Model: "oauthClient", Data: adapter.Record{
			"clientId": clientID, "redirectUris": []string{"https://example.com/callback"}, "createdAt": now, "updatedAt": now,
		}}); err != nil {
			b.env.t.Fatal(err)
		}
		if _, err := b.env.db.Create(context.Background(), adapter.CreateInput{Model: "oauthClientResource", Data: adapter.Record{
			"clientId": clientID, "resourceId": resourceID, "createdAt": now,
		}}); err != nil {
			b.env.t.Fatal(err)
		}
	}
	t.Run("rejects unlinked clients when enforcement is on", func(t *testing.T) {
		id := "https://api.example.com/locked"
		b := mxBootProvider(t, Options{Resources: mxResources(id), EnforcePerClientResources: mxBoolPtr(true)})
		_, err := b.policy(id, "client-not-linked", []string{})
		mxExpectPolicyError(t, err, "invalid_target", "")
	})
	t.Run("accepts linked clients when enforcement is on", func(t *testing.T) {
		id := "https://api.example.com/linked"
		b := mxBootProvider(t, Options{Resources: mxResources(id), EnforcePerClientResources: mxBoolPtr(true)})
		seedClientLink(b, "client-linked", id)
		if p := b.mustPolicy(t, id, "client-linked", []string{}); toAudienceClaim(p.audience) != id {
			t.Fatalf("aud: %v", p.audience)
		}
	})
	t.Run("skips linkage check when enforcement is explicitly off", func(t *testing.T) {
		id := "https://api.example.com/explicit-off-unlinked"
		b := mxBootProvider(t, Options{Resources: mxResources(id), EnforcePerClientResources: mxBoolPtr(false)})
		if p := b.mustPolicy(t, id, "client-unlinked", []string{}); toAudienceClaim(p.audience) != id {
			t.Fatalf("aud: %v", p.audience)
		}
	})
	t.Run("explicit enforcePerClientResources:false beats the smart default", func(t *testing.T) {
		id := "https://api.example.com/explicit-off"
		b := mxBootProvider(t, Options{Resources: mxResources(id), EnforcePerClientResources: mxBoolPtr(false)})
		if p := b.mustPolicy(t, id, "client-unlinked", []string{}); toAudienceClaim(p.audience) != id {
			t.Fatalf("aud: %v", p.audience)
		}
	})
}
