package betterauth

// Port of better-auth/src/social.test.ts (upstream v1.7.7): "Multi-client ID support — other
// widened providers", "Apple Provider", "Microsoft Provider",
// "Reddit Provider — profile email mapping".

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/providers/apple"
	"github.com/nimi-io/better-auth-go/providers/cognito"
	"github.com/nimi-io/better-auth-go/providers/facebook"
	"github.com/nimi-io/better-auth-go/providers/microsoft"
	"github.com/nimi-io/better-auth-go/providers/reddit"
)

// ---- describe("Multi-client ID support — other widened providers") ----

func TestPortSocialMultiClientOtherProviders(t *testing.T) {
	psocMock(t)
	build := func(id string, clientIDs []string) oauth2.Provider {
		switch id {
		case "apple":
			return apple.New(apple.Options{ProviderOptions: oauth2.ProviderOptions{ClientIDs: clientIDs, ClientSecret: "apple-secret"}})
		case "facebook":
			return facebook.New(facebook.Options{ProviderOptions: oauth2.ProviderOptions{ClientIDs: clientIDs, ClientSecret: "fb-secret"}})
		default:
			return cognito.New(cognito.Options{ProviderOptions: oauth2.ProviderOptions{ClientIDs: clientIDs, ClientSecret: "cog-secret"},
				Domain: "test.auth.us-east-1.amazoncognito.com", Region: "us-east-1", UserPoolID: "us-east-1_testpool"})
		}
	}
	for _, tc := range []struct {
		id      string
		ids     []string
		firstID string
	}{
		{"apple", []string{"apple-web", "apple-ios"}, "apple-web"},
		{"facebook", []string{"fb-web", "fb-mobile"}, "fb-web"},
		{"cognito", []string{"cog-web", "cog-mobile"}, "cog-web"},
	} {
		t.Run(tc.id+" uses the first entry of the clientId array for the auth URL", func(t *testing.T) {
			env := psocEnv(t, func(c *Config) { c.SocialProviders = []oauth2.Provider{build(tc.id, tc.ids)} }, true)
			res := env.client().post("/sign-in/social", map[string]any{"provider": tc.id, "callbackURL": "/callback"})
			if res.Status != 200 {
				t.Fatalf("%d %s", res.Status, res.Body)
			}
			if u, _ := res.JSON(t)["url"].(string); !strings.Contains(u, tc.firstID) {
				t.Fatalf("url %s", u)
			}
		})
	}
	for _, id := range []string{"apple", "facebook", "cognito"} {
		t.Run(id+" rejects an empty clientId array", func(t *testing.T) {
			env := psocEnv(t, func(c *Config) { c.SocialProviders = []oauth2.Provider{build(id, []string{})} }, true)
			res := env.client().post("/sign-in/social", map[string]any{"provider": id, "callbackURL": "/callback"})
			if res.Status != 500 {
				t.Fatalf("expected 500, got %d %s", res.Status, res.Body)
			}
		})
	}
}

// ---- describe("Apple Provider") ----

func psocAppleEnv(t *testing.T, verify func(ctx context.Context, token, nonce string) (bool, error)) *testEnv {
	if verify == nil {
		verify = psocTrueVerifier
	}
	return psocEnv(t, func(c *Config) {
		c.SocialProviders = []oauth2.Provider{apple.New(apple.Options{ProviderOptions: oauth2.ProviderOptions{
			ClientID: "test-apple-client", ClientSecret: "test-apple-secret", VerifyIDToken: verify}})}
	}, true)
}

func TestPortSocialAppleProvider(t *testing.T) {
	m := psocMock(t)
	appleToken := func(profile map[string]any) {
		m.JSON("POST appleid.apple.com/auth/token", 200, map[string]any{"access_token": "apple_access_token",
			"id_token": m.IDToken(profile), "token_type": "Bearer", "expires_in": 3600})
	}
	appleProfile := func(sub, email string) map[string]any {
		return map[string]any{"sub": sub, "email": email, "email_verified": true, "is_private_email": true, "real_user_status": float64(2)}
	}

	t.Run("should not use email as fallback for name when name is not provided", func(t *testing.T) {
		appleToken(appleProfile("001341.example.1128", "user@privaterelay.appleid.com"))
		env := psocAppleEnv(t, nil)
		c := env.client()
		_, _, state := psocStart(t, c, map[string]any{"provider": "apple", "callbackURL": "/callback"})
		psocCallback(c, "apple", state, "apple_test_code")
		u := psocSessionUser(t, c)
		if u["name"] == "user@privaterelay.appleid.com" {
			t.Fatal("name must not be the email address")
		}
		if u["name"] != "" {
			t.Fatalf("name %v", u["name"])
		}
	})

	t.Run("should use firstName and lastName when provided in token.user", func(t *testing.T) {
		appleToken(appleProfile("001341.example.1129", "user2@privaterelay.appleid.com"))
		env := psocAppleEnv(t, nil)
		c := env.client()
		_, _, state := psocStart(t, c, map[string]any{"provider": "apple", "callbackURL": "/callback"})
		userData := `{"name":{"firstName":"Better","lastName":"Auth"},"email":"user2@privaterelay.appleid.com"}`
		res := c.post("/callback/apple", map[string]any{"state": state, "code": "apple_test_code", "user": userData})
		loc := psocExpect302(t, res)
		if !strings.Contains(loc, "/callback/apple") || !strings.Contains(loc, "user=") {
			t.Fatalf("location %s", loc)
		}
		ru, err := url.Parse(loc)
		if err != nil {
			t.Fatal(err)
		}
		c.get("/callback/apple?" + ru.Query().Encode())
		if u := psocSessionUser(t, c); u["name"] != "Better Auth" {
			t.Fatalf("name %v", u["name"])
		}
	})

	t.Run("should pass user name via idToken body for Apple sign-in", func(t *testing.T) {
		tok := m.IDToken(appleProfile("001341.example.idtoken", "idtoken-user@privaterelay.appleid.com"))
		env := psocAppleEnv(t, nil)
		res := env.client().post("/sign-in/social", map[string]any{"provider": "apple", "callbackURL": "/callback",
			"idToken": map[string]any{"token": tok, "user": map[string]any{
				"name": map[string]any{"firstName": "First", "lastName": "Last"}, "email": "idtoken-user@privaterelay.appleid.com"}}})
		if res.Status != 200 {
			t.Fatalf("%d %s", res.Status, res.Body)
		}
		d := res.JSON(t)
		u := d["user"].(map[string]any)
		if d["redirect"] != false || d["token"] == nil || u["email"] != "idtoken-user@privaterelay.appleid.com" || u["name"] != "First Last" {
			t.Fatalf("data %v", d)
		}
	})

	t.Run("should result in empty name when idToken body has no user field for Apple", func(t *testing.T) {
		tok := m.IDToken(appleProfile("001341.example.idtoken-noname", "noname-user@privaterelay.appleid.com"))
		env := psocAppleEnv(t, nil)
		res := psocIDTokenSignIn(env.client(), "apple", tok, map[string]any{"callbackURL": "/callback"})
		if res.Status != 200 {
			t.Fatalf("%d %s", res.Status, res.Body)
		}
		d := res.JSON(t)
		u := d["user"].(map[string]any)
		if d["redirect"] != false || d["token"] == nil || u["email"] != "noname-user@privaterelay.appleid.com" || u["name"] != "" {
			t.Fatalf("data %v", d)
		}
	})

	t.Run("should pass request ctx to verifyIdToken for id-token sign-in", func(t *testing.T) {
		tok := m.IDToken(appleProfile("001341.example.ctx-signin", "ctx-signin@privaterelay.appleid.com"))
		var seen *string
		env := psocAppleEnv(t, func(ctx context.Context, _, _ string) (bool, error) {
			var v string
			if ec := EndpointContextFrom(ctx); ec != nil && ec.Headers != nil {
				v = ec.Headers.Get("x-platform")
			}
			seen = &v
			return v == "ios", nil
		})
		platform := func(p string) func(*http.Request) { return func(r *http.Request) { r.Header.Set("x-platform", p) } }
		rejected := psocIDTokenSignIn(env.client(), "apple", tok, nil, platform("android"))
		if seen == nil || *seen != "android" {
			t.Fatalf("seenPlatform %v", seen)
		}
		if rejected.Status != 401 {
			t.Fatalf("expected 401, got %d %s", rejected.Status, rejected.Body)
		}
		accepted := psocIDTokenSignIn(env.client(), "apple", tok, nil, platform("ios"))
		if *seen != "ios" {
			t.Fatalf("seenPlatform %v", *seen)
		}
		if accepted.Status != 200 {
			t.Fatalf("%d %s", accepted.Status, accepted.Body)
		}
		d := accepted.JSON(t)
		if d["redirect"] != false || d["user"].(map[string]any)["email"] != "ctx-signin@privaterelay.appleid.com" {
			t.Fatalf("data %v", d)
		}
	})
}

// ---- describe("Microsoft Provider") ----

func psocMSEnv(t *testing.T, o microsoft.Options) *testEnv {
	return psocEnv(t, func(c *Config) { c.SocialProviders = []oauth2.Provider{microsoft.New(o)} }, true)
}

func TestPortSocialMicrosoftProvider(t *testing.T) {
	m := psocMock(t)
	msTokenEndpoint := "POST login.microsoftonline.com/common/oauth2/v2.0/token"
	// graph.microsoft.com/v1.0/me/photos/* is unregistered and answers 404.

	t.Run("should support verifyIdToken with custom function", func(t *testing.T) {
		m.JSON(msTokenEndpoint, 200, map[string]any{"access_token": "ms_access_token", "token_type": "Bearer", "expires_in": 3600,
			"id_token": m.IDToken(map[string]any{"sub": "ms-user-123", "iss": "https://login.microsoftonline.com/ms-tenant-123/v2.0",
				"email": "msuser@outlook.com", "name": "Microsoft User", "oid": "ms-oid-123", "tid": "ms-tenant-123"})})
		env := psocMSEnv(t, microsoft.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test-ms-client", ClientSecret: "test-ms-secret", VerifyIDToken: psocTrueVerifier}})
		c := env.client()
		_, _, state := psocStart(t, c, map[string]any{"provider": "microsoft", "callbackURL": "/callback"})
		psocCallback(c, "microsoft", state, "ms_test_code")
		u := psocSessionUser(t, c)
		if u["email"] != "msuser@outlook.com" || u["name"] != "Microsoft User" {
			t.Fatalf("user %v", u)
		}
	})

	t.Run("should verify id token using JWKS endpoint", func(t *testing.T) {
		tok := m.IDToken(map[string]any{"sub": "ms-jwks-user-456", "iss": "https://login.microsoftonline.com/ms-tenant-456/v2.0",
			"email": "jwksuser@outlook.com", "name": "JWKS User", "oid": "ms-oid-456", "tid": "ms-tenant-456", "aud": "test-ms-client-jwks"})
		m.ServeJWKS("GET login.microsoftonline.com/common/discovery/v2.0/keys")
		m.JSON(msTokenEndpoint, 200, map[string]any{"access_token": "ms_access_token_jwks", "id_token": tok, "token_type": "Bearer", "expires_in": 3600})
		env := psocMSEnv(t, microsoft.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test-ms-client-jwks", ClientSecret: "test-ms-secret-jwks"}})
		c := env.client()
		_, _, state := psocStart(t, c, map[string]any{"provider": "microsoft", "callbackURL": "/callback"})
		psocCallback(c, "microsoft", state, "ms_test_code_jwks")
		u := psocSessionUser(t, c)
		if u["email"] != "jwksuser@outlook.com" || u["name"] != "JWKS User" {
			t.Fatalf("user %v", u)
		}
		var accountID string
		for _, a := range psocAccounts(t, env, u["id"].(string)) {
			if a.ProviderID == "microsoft" {
				accountID = a.AccountID
			}
		}
		if accountID != "ms-oid-456" {
			t.Fatalf("accountId %q", accountID)
		}
	})

	t.Run("should support id token sign in", func(t *testing.T) {
		tok := m.IDToken(map[string]any{"sub": "ms-id-token-user-789", "email": "id-tokenuser@outlook.com", "name": "IdToken User",
			"oid": "ms-oid-789", "tid": "ms-tenant-789", "iss": "https://login.microsoftonline.com/ms-tenant-789/v2.0", "aud": "test-ms-client-id-token"})
		m.ServeJWKS("GET login.microsoftonline.com/common/discovery/v2.0/keys")
		env := psocMSEnv(t, microsoft.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test-ms-client-id-token", ClientSecret: "test-ms-secret-id-token"}})
		res := psocIDTokenSignIn(env.client(), "microsoft", tok, map[string]any{"callbackURL": "/callback"})
		if res.Status != 200 {
			t.Fatalf("%d %s", res.Status, res.Body)
		}
		d := res.JSON(t)
		u := d["user"].(map[string]any)
		if d["redirect"] != false || d["token"] == nil || u["email"] != "id-tokenuser@outlook.com" || u["name"] != "IdToken User" {
			t.Fatalf("data %v", d)
		}
		var accountID string
		for _, a := range psocAccounts(t, env, u["id"].(string)) {
			if a.ProviderID == "microsoft" {
				accountID = a.AccountID
			}
		}
		if accountID != "ms-oid-789" {
			t.Fatalf("accountId %q", accountID)
		}
	})

	t.Run("should reject id token sign in when oid is missing", func(t *testing.T) {
		tok := m.IDToken(map[string]any{"sub": "ms-missing-oid-user", "email": "missing-oid@outlook.com", "name": "Missing Oid User",
			"tid": "ms-tenant-missing-oid", "iss": "https://login.microsoftonline.com/ms-tenant-missing-oid/v2.0", "aud": "test-ms-client-missing-oid"})
		m.ServeJWKS("GET login.microsoftonline.com/common/discovery/v2.0/keys")
		env := psocMSEnv(t, microsoft.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test-ms-client-missing-oid", ClientSecret: "test-ms-secret-missing-oid"}})
		res := psocIDTokenSignIn(env.client(), "microsoft", tok, map[string]any{"callbackURL": "/callback"})
		if res.Status != 401 {
			t.Fatalf("expected 401, got %d %s", res.Status, res.Body)
		}
		accs, err := env.auth.Context().Adapter.FindMany(context.Background(), adapter.FindManyInput{Model: "account",
			Where: []adapter.Where{{Field: "providerId", Value: "microsoft"}}})
		if err != nil {
			t.Fatal(err)
		}
		if len(accs) != 0 {
			t.Fatalf("accounts %v", accs)
		}
	})

	t.Run("should report id_token sign-in unsupported when disableIdTokenSignIn is true", func(t *testing.T) {
		tok := m.IDToken(map[string]any{"sub": "ms-disabled-user", "email": "disabled@outlook.com", "name": "Disabled User", "aud": "test-ms-client-disabled"})
		m.ServeJWKS("GET login.microsoftonline.com/common/discovery/v2.0/keys")
		env := psocMSEnv(t, microsoft.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test-ms-client-disabled",
			ClientSecret: "test-ms-secret-disabled", DisableIDTokenSignIn: true}})
		res := psocIDTokenSignIn(env.client(), "microsoft", tok, map[string]any{"callbackURL": "/callback"})
		psocExpectAPIError(t, res, 404, "ID_TOKEN_NOT_SUPPORTED", "")
	})

	t.Run("should verify issuer when specific tenant is configured", func(t *testing.T) {
		const tenantID = "my-specific-tenant-id"
		claims := func(iss string) map[string]any {
			return map[string]any{"sub": "ms-tenant-user", "email": "tenant@outlook.com", "name": "Tenant User", "oid": "ms-tenant-oid",
				"tid": tenantID, "iss": iss, "aud": "test-ms-client-tenant"}
		}
		valid := m.IDToken(claims("https://login.microsoftonline.com/" + tenantID + "/v2.0"))
		wrong := m.IDToken(claims("https://login.microsoftonline.com/wrong-tenant/v2.0"))
		m.ServeJWKS("GET login.microsoftonline.com/" + tenantID + "/discovery/v2.0/keys")
		o := microsoft.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "test-ms-client-tenant", ClientSecret: "test-ms-secret-tenant"}, TenantID: tenantID}
		validRes := psocIDTokenSignIn(psocMSEnv(t, o).client(), "microsoft", valid, map[string]any{"callbackURL": "/callback"})
		if validRes.Status != 200 || validRes.JSON(t)["redirect"] != false {
			t.Fatalf("valid: %d %s", validRes.Status, validRes.Body)
		}
		invalidRes := psocIDTokenSignIn(psocMSEnv(t, o).client(), "microsoft", wrong, map[string]any{"callbackURL": "/callback"})
		if invalidRes.Status != 401 {
			t.Fatalf("expected 401, got %d %s", invalidRes.Status, invalidRes.Body)
		}
	})

	t.Run("builds an authorization URL without clientSecret (public client)", func(t *testing.T) {
		env := psocMSEnv(t, microsoft.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "public-ms-client"}})
		_, u, _ := psocStart(t, env.client(), map[string]any{"provider": "microsoft", "callbackURL": "/callback"})
		if !strings.Contains(u.String(), "public-ms-client") {
			t.Fatalf("url %s", u)
		}
	})
}

// ---- describe("Reddit Provider — profile email mapping") ----

func TestPortSocialRedditProfileEmailMapping(t *testing.T) {
	m := psocMock(t)
	profile := map[string]any{"id": "reddit-user-123", "name": "reddit_user", "icon_img": "https://example.com/avatar.png?x=1",
		"has_verified_email": true, "oauth_client_id": "shared-reddit-oauth-client-id", "verified": true}
	m.JSON("GET oauth.reddit.com/api/v1/me", 200, profile)
	params := oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "reddit-access-token"}}

	t.Run("never uses oauth_client_id as the email and falls back to a unique per-user email", func(t *testing.T) {
		p := reddit.New(reddit.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "reddit-client-id", ClientSecret: "reddit-client-secret"}})
		res, err := p.GetUserInfo(context.Background(), params)
		if err != nil || res == nil {
			t.Fatalf("%v %v", res, err)
		}
		if res.User.Email != "reddit-user-123@reddit.placeholder.invalid" || res.User.Email == profile["oauth_client_id"] || res.User.EmailVerified {
			t.Fatalf("user %+v", res.User)
		}
	})

	t.Run("uses the email supplied by mapProfileToUser and ignores oauth_client_id", func(t *testing.T) {
		p := reddit.New(reddit.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "reddit-client-id", ClientSecret: "reddit-client-secret",
			MapProfileToUser: func(p map[string]any) (map[string]any, error) {
				return map[string]any{"email": oauth2.String(p, "name") + "@example.com"}, nil
			}}})
		res, err := p.GetUserInfo(context.Background(), params)
		if err != nil || res == nil {
			t.Fatalf("%v %v", res, err)
		}
		if res.User.Email != "reddit_user@example.com" || res.User.Email == profile["oauth_client_id"] || res.User.EmailVerified {
			t.Fatalf("user %+v", res.User)
		}
	})
}
