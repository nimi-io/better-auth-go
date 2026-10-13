package genericoauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

// Port of the IDP-initiated, validateUserInfo, id_token verification, discovery and
// dynamic baseURL cases of generic-oauth.test.ts.

func TestIDPInitiatedBounceAllowIdpInitiated(t *testing.T) {
	t.Run("should bounce a stateless callback to the provider's authorize endpoint when the provider opts in", func(t *testing.T) {
		setupIdP(t)
		in := newInst(t, genericPlugin(Config{ProviderID: "idp-initiated", DiscoveryURL: discoveryURL, ClientID: clientID, ClientSecret: clientSecret, AllowIDPInitiated: true}))
		res := in.client().get("/callback/idp-initiated?code=idp-issued-code")
		mustEqual(t, res.Status, 302)
		loc := res.location()
		mustContain(t, loc, idpBase+"/authorize")
		if queryParam(t, loc, "state") == "" {
			t.Fatal("expected state")
		}
		mustEqual(t, queryParam(t, loc, "client_id"), clientID)
		mustEqual(t, queryParam(t, loc, "redirect_uri"), "http://localhost:3000/api/auth/callback/idp-initiated")
		mustEqual(t, queryParam(t, loc, "code"), "")
		if queryParam(t, loc, "nonce") == "" {
			t.Fatal("expected nonce")
		}
	})
	t.Run("should redirect to the error page when a stateless callback arrives for a provider without the flag", func(t *testing.T) {
		setupIdP(t)
		in := newInst(t, genericPlugin(Config{ProviderID: "strict", DiscoveryURL: discoveryURL, ClientID: clientID, ClientSecret: clientSecret}))
		res := in.client().get("/callback/strict?code=idp-issued-code")
		mustEqual(t, res.Status, 302)
		mustContain(t, res.location(), "error=state_not_found")
	})
	t.Run("should not bounce on an empty `state=` parameter, only on truly stateless callbacks", func(t *testing.T) {
		setupIdP(t)
		in := newInst(t, genericPlugin(Config{ProviderID: "idp-initiated-empty-state", DiscoveryURL: discoveryURL, ClientID: clientID, ClientSecret: clientSecret, AllowIDPInitiated: true}))
		res := in.client().get("/callback/idp-initiated-empty-state?code=idp-issued-code&state=")
		mustEqual(t, res.Status, 302)
		mustNotContain(t, res.location(), idpBase+"/authorize")
		mustContain(t, res.location(), "error=state_not_found")
	})
	t.Run("should not bounce when state is present even if allowIdpInitiated is on", func(t *testing.T) {
		setupIdP(t)
		in := newInst(t, genericPlugin(Config{ProviderID: "idp-initiated-with-state", DiscoveryURL: discoveryURL, ClientID: clientID, ClientSecret: clientSecret, AllowIDPInitiated: true}))
		res := in.client().get("/callback/idp-initiated-with-state?code=abc&state=unknown-state")
		mustEqual(t, res.Status, 302)
		mustNotContain(t, res.location(), idpBase+"/authorize")
		mustContain(t, res.location(), "error=state_mismatch")
		mustNotContain(t, res.location(), "please_restart_the_process")
	})
}

func TestValidateUserInfoCallback(t *testing.T) {
	t.Run("should reject sign-in with provider metadata and raw profile", func(t *testing.T) {
		idp := setupIdP(t)
		idp.userinfoOnce(map[string]any{"email": "bad@blocked.com", "name": "Bad User", "sub": "bad-oauth", "email_verified": true, "custom_field": "custom-value"})
		var captured map[string]any
		in := newInst(t, func(c *betterauth.Config) {
			c.User = &betterauth.UserConfig{ValidateUserInfo: func(_ *betterauth.EndpointContext, user map[string]any, src betterauth.UserInfoSource) (*betterauth.ValidateUserInfoResult, error) {
				if src.Method != "oauth" {
					return nil, nil
				}
				mustEqual(t, src.Action, "create-user")
				mustEqual(t, src.ProviderID, "validate-generic")
				captured = src.Profile
				if e, _ := user["email"].(string); strings.HasSuffix(e, "@blocked.com") {
					return &betterauth.ValidateUserInfoResult{Error: "domain_blocked", ErrorDescription: "Only company emails are allowed for this provider"}, nil
				}
				return nil, nil
			}}
			genericPlugin(discoveryConfig("validate-generic"))(c)
		})
		c := in.client()
		_, u := c.signInSocial(signInBody("validate-generic"))
		cb := c.simulateOAuthFlow(u).callbackURL
		mustContain(t, cb, "error=domain_blocked")
		mustContain(t, cb, "error_description=Only+company+emails+are+allowed+for+this+provider")
		mustEqual(t, captured["custom_field"], any("custom-value"))
	})
	t.Run("should work in stateless mode (no database)", func(t *testing.T) {
		idp := setupIdP(t)
		idp.userinfoOnce(map[string]any{"email": "stateless@blocked.com", "name": "Stateless User", "sub": "stateless-oauth", "email_verified": true})
		in := newInst(t, func(c *betterauth.Config) {
			c.User = &betterauth.UserConfig{ValidateUserInfo: func(_ *betterauth.EndpointContext, user map[string]any, src betterauth.UserInfoSource) (*betterauth.ValidateUserInfoResult, error) {
				if src.Method != "oauth" {
					return nil, nil
				}
				mustEqual(t, src.ProviderID, "validate-stateless")
				if e, _ := user["email"].(string); strings.HasSuffix(e, "@blocked.com") {
					return &betterauth.ValidateUserInfoResult{Error: "stateless_blocked", ErrorDescription: "Stateless rejection test"}, nil
				}
				return nil, nil
			}}
			genericPlugin(discoveryConfig("validate-stateless"))(c)
		}, instOpts{noDatabase: true})
		c := in.client()
		_, u := c.signInSocial(signInBody("validate-stateless"))
		cb := c.simulateOAuthFlow(u).callbackURL
		mustContain(t, cb, "error=stateless_blocked")
		mustContain(t, cb, "error_description=Stateless+rejection+test")
	})
}

// forgeIdToken signs valid iss/aud/exp claims with a key unknown to the provider JWKS.
func forgeIdToken(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := float64(time.Now().Unix())
	tok, err := jose.SignJWT(jsonx.O("alg", "RS256"), jsonx.O("email", "forged@test.com", "email_verified", true, "name", "Forged User",
		"sub", "forged-user", "iss", idpBase, "aud", clientID, "iat", now, "exp", now+3600), key)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func getTokenWithIDToken(access string, idt func() string) func(context.Context, oauth2.CodeParams) (*oauth2.Tokens, error) {
	return func(context.Context, oauth2.CodeParams) (*oauth2.Tokens, error) {
		return &oauth2.Tokens{AccessToken: access, IDToken: idt(), TokenType: "bearer"}, nil
	}
}

func TestIDTokenVerification(t *testing.T) {
	t.Run("should reject an id_token not signed by the discovery JWKS", func(t *testing.T) {
		setupIdP(t)
		forged := forgeIdToken(t)
		cfg := discoveryConfig("verify-reject")
		cfg.GetToken = getTokenWithIDToken("forged-access-token", func() string { return forged })
		in := newInst(t, genericPlugin(cfg))
		c := in.client()
		_, u := c.signInSocial(signInBody("verify-reject"))
		mustContain(t, c.simulateOAuthFlow(u).callbackURL, "?error=")
	})
	t.Run("should use claims from an id_token verified against the discovery JWKS", func(t *testing.T) {
		idp := setupIdP(t)
		idp.onTokenSigning(func(p map[string]any, _ *oauth2test.Request) {
			p["email"], p["email_verified"], p["name"] = "idtoken-claims@test.com", true, "Id Token Claims"
		}, false)
		in := mainInst(t)
		c := in.client()
		_, u := c.signInSocial(signInBody(providerID, "newUserCallbackURL", "http://localhost:3000/new_user"))
		mustEqual(t, c.simulateOAuthFlow(u).callbackURL, "http://localhost:3000/new_user")
		mustEqual(t, sessionUser(c.session())["email"], any("idtoken-claims@test.com"))
	})
	t.Run("should bind a discovery id_token to the authorization request nonce", func(t *testing.T) {
		idp := setupIdP(t)
		nonce := ""
		cfg := discoveryConfig("nonce-match")
		cfg.AuthorizationURLParams = map[string]string{"nonce": "configured-nonce"}
		cfg.GetToken = getTokenWithIDToken("nonce-match-access-token", func() string {
			return idp.buildToken(map[string]any{"aud": clientID, "sub": "nonce-match-user", "email": "nonce-match@test.com", "email_verified": true, "name": "Nonce Match", "nonce": nonce})
		})
		in := newInst(t, genericPlugin(cfg))
		c := in.client()
		_, u := c.signInSocial(signInBody("nonce-match", "newUserCallbackURL", "http://localhost:3000/new_user"))
		nonce = queryParam(t, u, "nonce")
		if nonce == "" || nonce == "configured-nonce" {
			t.Fatalf("nonce %q", nonce)
		}
		mustEqual(t, c.simulateOAuthFlow(u).callbackURL, "http://localhost:3000/new_user")
		mustEqual(t, sessionUser(c.session())["email"], any("nonce-match@test.com"))
	})
	nonceCase := func(t *testing.T, id string, claims map[string]any, wantNonce bool, check func(cb string, c *client)) {
		idp := setupIdP(t)
		cfg := discoveryConfig(id)
		cfg.GetToken = getTokenWithIDToken(id+"-access-token", func() string { return idp.buildToken(claims) })
		if !wantNonce {
			cfg.DisableIDTokenNonceBinding = true
		}
		in := newInst(t, genericPlugin(cfg))
		c := in.client()
		_, u := c.signInSocial(signInBody(id, "newUserCallbackURL", "http://localhost:3000/new_user"))
		if got := queryParam(t, u, "nonce") != ""; got != wantNonce {
			t.Fatalf("nonce present=%v", got)
		}
		check(c.simulateOAuthFlow(u).callbackURL, c)
	}
	t.Run("should reject a discovery id_token with a mismatched nonce", func(t *testing.T) {
		nonceCase(t, "nonce-mismatch", map[string]any{"aud": clientID, "sub": "nonce-mismatch-user", "email": "nonce-mismatch@test.com", "email_verified": true,
			"name": "Nonce Mismatch", "nonce": "different-nonce"}, true, func(cb string, _ *client) { mustContain(t, cb, "?error=") })
	})
	t.Run("should reject a discovery id_token that omits the nonce claim", func(t *testing.T) {
		nonceCase(t, "nonce-missing", map[string]any{"aud": clientID, "sub": "nonce-missing-user", "email": "nonce-missing@test.com", "email_verified": true,
			"name": "Nonce Missing"}, true, func(cb string, _ *client) { mustContain(t, cb, "?error=") })
	})
	t.Run("should not bind a nonce when id_token nonce binding is disabled", func(t *testing.T) {
		nonceCase(t, "nonce-disabled", map[string]any{"aud": clientID, "sub": "nonce-disabled-user", "email": "nonce-disabled@test.com", "email_verified": true,
			"name": "Nonce Disabled"}, false, func(cb string, c *client) {
			mustEqual(t, cb, "http://localhost:3000/new_user")
			mustEqual(t, sessionUser(c.session())["email"], any("nonce-disabled@test.com"))
		})
	})
	t.Run("should drop a configured nonce param for providers without nonce binding", func(t *testing.T) {
		setupIdP(t)
		cfg := explicitEndpoints("nonce-static")
		cfg.AuthorizationURLParams = map[string]string{"nonce": "configured-nonce"}
		in := newInst(t, genericPlugin(cfg))
		_, u := in.client().signInSocial(signInBody("nonce-static"))
		mustEqual(t, queryParam(t, u, "nonce"), "")
	})
	t.Run("should reject a discovery id_token when state carries no expected nonce", func(t *testing.T) {
		idp := setupIdP(t)
		cfg := discoveryConfig("nonce-skew")
		cfg.GetToken = getTokenWithIDToken("nonce-skew-access-token", func() string {
			return idp.buildToken(map[string]any{"aud": clientID, "sub": "nonce-skew-user", "email": "nonce-skew@test.com", "email_verified": true, "name": "Nonce Skew"})
		})
		in := newInst(t, genericPlugin(cfg))
		settings := in.provider("nonce-skew").(*Provider).ProviderSettings()
		settings.RequiresIDTokenNonce = false
		c := in.client()
		_, u := c.signInSocial(signInBody("nonce-skew", "newUserCallbackURL", "http://localhost:3000/new_user"))
		mustEqual(t, queryParam(t, u, "nonce"), "")
		settings.RequiresIDTokenNonce = true
		mustContain(t, c.simulateOAuthFlow(u).callbackURL, "error=nonce_binding_missing")
	})
	t.Run("should sign in with a client-submitted id_token for a discovery provider", func(t *testing.T) {
		idp := setupIdP(t)
		in := mainInst(t)
		tok := idp.buildToken(map[string]any{"aud": clientID, "sub": "front-channel-user", "email": "front-channel@test.com", "email_verified": true, "name": "Front Channel"})
		res := in.client().post("/sign-in/social", map[string]any{"provider": providerID, "idToken": map[string]any{"token": tok}})
		if res.Status != 200 {
			t.Fatalf("status %d %s", res.Status, res.Body)
		}
		if s, _ := res.JSON(t)["token"].(string); s == "" {
			t.Fatal("expected token")
		}
	})
	t.Run("should keep the decode posture for providers without discovery", func(t *testing.T) {
		setupIdP(t)
		forged := forgeIdToken(t)
		cfg := explicitEndpoints("no-discovery")
		cfg.GetToken = getTokenWithIDToken("opaque-access-token", func() string { return forged })
		in := newInst(t, genericPlugin(cfg))
		c := in.client()
		_, u := c.signInSocial(signInBody("no-discovery", "newUserCallbackURL", "http://localhost:3000/new_user"))
		mustEqual(t, c.simulateOAuthFlow(u).callbackURL, "http://localhost:3000/new_user")
		mustEqual(t, sessionUser(c.session())["email"], any("forged@test.com"))
	})
	t.Run("skips a provider when required ID token verification metadata is unavailable", func(t *testing.T) {
		idp := setupIdP(t)
		idp.Handle("localhost:4999/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, 200, map[string]any{"issuer": idpBase, "authorization_endpoint": idpBase + "/authorize", "token_endpoint": idpBase + "/token"})
		})
		cfg := explicitEndpoints("verified-id-token-required")
		cfg.DiscoveryURL = "http://localhost:4999/.well-known/openid-configuration"
		cfg.RequireIDTokenVerification = true
		cfg.PKCE = nil
		in := newInst(t, genericPlugin(cfg), instOpts{disableTestUser: true})
		if contains(in.providerIDs(), "verified-id-token-required") {
			t.Fatal("expected provider to be skipped")
		}
	})
	t.Run("skips a provider when discovery returns a malformed jwks_uri", func(t *testing.T) {
		idp := setupIdP(t)
		idp.Handle("localhost:4999/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, 200, map[string]any{"issuer": idpBase, "authorization_endpoint": idpBase + "/authorize", "token_endpoint": idpBase + "/token",
				"userinfo_endpoint": idpBase + "/userinfo", "jwks_uri": "http://[malformed", "id_token_signing_alg_values_supported": []string{"RS256"}})
		})
		cfg := discoveryConfig("malformed-jwks")
		cfg.DiscoveryURL = "http://localhost:4999/.well-known/openid-configuration"
		in := newInst(t, genericPlugin(cfg), instOpts{disableTestUser: true})
		if contains(in.providerIDs(), "malformed-jwks") {
			t.Fatal("expected provider to be skipped")
		}
	})
}

func TestSkipsDiscoveryMissingEndpoints(t *testing.T) {
	for _, missing := range []string{"authorization", "token", "both"} {
		t.Run("skips discovery missing "+missing+" endpoints", func(t *testing.T) {
			idp := setupIdP(t)
			doc := map[string]any{"issuer": "https://incomplete-idp.test"}
			if missing == "token" {
				doc["authorization_endpoint"] = "https://incomplete-idp.test/authorize"
			}
			if missing == "authorization" {
				doc["token_endpoint"] = "https://incomplete-idp.test/token"
			}
			idp.JSON("incomplete-idp.test/.well-known/openid-configuration", 200, doc)
			in := newInst(t, genericPlugin(Config{ProviderID: "incomplete", ClientID: clientID, ClientSecret: clientSecret,
				DiscoveryURL: "https://incomplete-idp.test/.well-known/openid-configuration"}), instOpts{disableTestUser: true})
			if contains(in.providerIDs(), "incomplete") {
				t.Fatal("expected provider to be skipped")
			}
		})
	}
	for _, custom := range []bool{false, true} {
		name := "false"
		if custom {
			name = "true"
		}
		t.Run("keeps explicit token exchange with incomplete discovery (custom="+name+")", func(t *testing.T) {
			idp := setupIdP(t)
			idp.JSON("incomplete-idp.test/.well-known/openid-configuration", 200, map[string]any{"issuer": "https://incomplete-idp.test"})
			cfg := Config{ProviderID: "explicit", ClientID: clientID, ClientSecret: clientSecret,
				DiscoveryURL: "https://incomplete-idp.test/.well-known/openid-configuration", AuthorizationURL: "https://incomplete-idp.test/authorize"}
			if custom {
				cfg.GetToken = func(context.Context, oauth2.CodeParams) (*oauth2.Tokens, error) {
					return &oauth2.Tokens{AccessToken: "custom-token"}, nil
				}
			} else {
				cfg.TokenURL = "https://incomplete-idp.test/token"
			}
			in := newInst(t, genericPlugin(cfg), instOpts{disableTestUser: true})
			if !contains(in.providerIDs(), "explicit") {
				t.Fatal("expected provider")
			}
		})
	}
}

func TestDoesNotTakeDownTheAuthAPIWhenOneProvidersDiscoveryIsUnreachable(t *testing.T) {
	idp := setupIdP(t)
	idp.Handle("broken-idp.test/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) })
	in := newInst(t, genericPlugin(
		Config{ProviderID: "broken-idp", ClientID: "client", ClientSecret: "secret", DiscoveryURL: "https://broken-idp.test/.well-known/openid-configuration"},
		Config{ProviderID: "healthy-idp", ClientID: clientID, ClientSecret: clientSecret, DiscoveryURL: discoveryURL},
	), instOpts{disableTestUser: true})
	ids := in.providerIDs()
	if !contains(ids, "healthy-idp") || contains(ids, "broken-idp") {
		t.Fatalf("providers %v", ids)
	}
	res := in.client().post("/sign-up/email", map[string]any{"email": "isolated@example.test", "password": "correct-horse-battery-staple", "name": "Repro"})
	if s, _ := res.JSON(t)["token"].(string); s == "" {
		t.Fatalf("sign-up %d %s", res.Status, res.Body)
	}
}

// ---- redirect_uri composition under dynamic baseURL ----

func authorizeRedirectURI(t *testing.T, in *inst, signInURL, provider string) string {
	t.Helper()
	res := in.client().do("POST", signInURL, map[string]any{"provider": provider, "callbackURL": "/dashboard", "disableRedirect": true})
	u, _ := res.JSON(t)["url"].(string)
	if u == "" {
		t.Fatalf("no url: %d %s", res.Status, res.Body)
	}
	return queryParam(t, u, "redirect_uri")
}

func dynamic(mutate ...func(c *betterauth.Config)) func(c *betterauth.Config) {
	return func(c *betterauth.Config) {
		c.BaseURL = ""
		c.DynamicBaseURL = &betterauth.DynamicBaseURL{AllowedHosts: []string{"localhost:3000"}}
		for _, m := range mutate {
			m(c)
		}
	}
}

func TestRedirectURICompositionUnderDynamicBaseURL(t *testing.T) {
	gen := Config{ProviderID: "dynamic-oauth-test", DiscoveryURL: discoveryURL, ClientID: "test-client-id", ClientSecret: "test-client-secret"}
	t.Run("composes an absolute redirect_uri for a generic-oauth provider at the default basePath", func(t *testing.T) {
		setupIdP(t)
		in := newInst(t, dynamic(genericPlugin(gen)), instOpts{disableTestUser: true})
		mustEqual(t, authorizeRedirectURI(t, in, "http://localhost:3000/api/auth/sign-in/social", "dynamic-oauth-test"),
			"http://localhost:3000/api/auth/callback/dynamic-oauth-test")
	})
	t.Run("composes an absolute redirect_uri for a generic-oauth provider at a custom basePath", func(t *testing.T) {
		setupIdP(t)
		in := newInst(t, dynamic(genericPlugin(gen), func(c *betterauth.Config) { c.BasePath = "/auth" }), instOpts{disableTestUser: true})
		mustEqual(t, authorizeRedirectURI(t, in, "http://localhost:3000/auth/sign-in/social", "dynamic-oauth-test"),
			"http://localhost:3000/auth/callback/dynamic-oauth-test")
	})
	t.Run("composes an absolute redirect_uri for a built-in social provider", func(t *testing.T) {
		in := newInst(t, dynamic(func(c *betterauth.Config) { c.SocialProviders = []oauth2.Provider{googleProvider()} }), instOpts{disableTestUser: true})
		mustEqual(t, authorizeRedirectURI(t, in, "http://localhost:3000/api/auth/sign-in/social", "google"),
			"http://localhost:3000/api/auth/callback/google")
	})
	t.Run("normalizes custom callbackPath values without a leading slash", func(t *testing.T) {
		p := oauth2.NewProvider(oauth2.Spec{ID: "custom-oauth-test", Settings: oauth2.ProviderSettings{CallbackPath: "callback/custom-oauth-test"}})
		mustEqual(t, oauth2.CallbackPath(p), "/callback/custom-oauth-test")
	})
}
