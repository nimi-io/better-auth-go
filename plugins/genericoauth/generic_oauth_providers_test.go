package genericoauth

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

// Port of the provider helper describes of generic-oauth.test.ts.

func eqStrings(t *testing.T, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// ---- Okta Provider Helper ----

func TestOktaProviderHelper(t *testing.T) {
	base := BaseOptions{ClientID: "okta-client-id", ClientSecret: "okta-client-secret"}
	t.Run("should return correct GenericOAuthConfig", func(t *testing.T) {
		c := Okta(OktaOptions{BaseOptions: base, Issuer: "https://dev-12345.okta.com/oauth2/default"})
		mustEqual(t, c.ProviderID, "okta")
		mustEqual(t, c.DiscoveryURL, "https://dev-12345.okta.com/oauth2/default/.well-known/openid-configuration")
		eqStrings(t, c.Scopes, []string{"openid", "profile", "email"})
		mustEqual(t, c.ClientID, "okta-client-id")
		mustEqual(t, c.ClientSecret, "okta-client-secret")
		if c.GetUserInfo != nil {
			t.Fatal("expected no getUserInfo")
		}
	})
	t.Run("should handle issuer with trailing slash", func(t *testing.T) {
		c := Okta(OktaOptions{BaseOptions: base, Issuer: "https://dev-12345.okta.com/oauth2/default/"})
		mustEqual(t, c.DiscoveryURL, "https://dev-12345.okta.com/oauth2/default/.well-known/openid-configuration")
	})
	t.Run("should allow overriding scopes", func(t *testing.T) {
		b := base
		b.Scopes = []string{"openid", "profile"}
		eqStrings(t, Okta(OktaOptions{BaseOptions: b, Issuer: "https://dev-12345.okta.com/oauth2/default"}).Scopes, []string{"openid", "profile"})
	})
	t.Run("should allow overriding other options", func(t *testing.T) {
		b := base
		b.PKCE, b.DisableImplicitSignUp = ptrBool(true), true
		c := Okta(OktaOptions{BaseOptions: b, Issuer: "https://dev-12345.okta.com/oauth2/default"})
		mustEqual(t, *c.PKCE, true)
		mustEqual(t, c.DisableImplicitSignUp, true)
	})
}

// ---- Auth0 Provider Helper ----

func TestAuth0ProviderHelper(t *testing.T) {
	base := BaseOptions{ClientID: "auth0-client-id", ClientSecret: "auth0-client-secret"}
	t.Run("should return correct GenericOAuthConfig", func(t *testing.T) {
		c := Auth0(Auth0Options{BaseOptions: base, Domain: "dev-xxx.eu.auth0.com"})
		mustEqual(t, c.ProviderID, "auth0")
		mustEqual(t, c.DiscoveryURL, "https://dev-xxx.eu.auth0.com/.well-known/openid-configuration")
		eqStrings(t, c.Scopes, []string{"openid", "profile", "email"})
		mustEqual(t, c.ClientID, "auth0-client-id")
		mustEqual(t, c.ClientSecret, "auth0-client-secret")
		if c.GetUserInfo != nil {
			t.Fatal("expected no getUserInfo")
		}
	})
	for _, tc := range [][2]string{{"HTTP URL", "http://dev-xxx.eu.auth0.com"}, {"HTTPS URL", "https://dev-xxx.eu.auth0.com"}, {"trailing slashes", "https://dev-xxx.eu.auth0.com///"}} {
		t.Run("normalizes an Auth0 domain supplied as "+tc[0], func(t *testing.T) {
			mustEqual(t, Auth0(Auth0Options{BaseOptions: base, Domain: tc[1]}).DiscoveryURL, "https://dev-xxx.eu.auth0.com/.well-known/openid-configuration")
		})
	}
	t.Run("should allow overriding scopes", func(t *testing.T) {
		b := base
		b.Scopes = []string{"openid", "profile"}
		eqStrings(t, Auth0(Auth0Options{BaseOptions: b, Domain: "dev-xxx.eu.auth0.com"}).Scopes, []string{"openid", "profile"})
	})
	t.Run("should allow overriding other options", func(t *testing.T) {
		b := base
		b.PKCE, b.DisableImplicitSignUp = ptrBool(true), true
		c := Auth0(Auth0Options{BaseOptions: b, Domain: "dev-xxx.eu.auth0.com"})
		mustEqual(t, *c.PKCE, true)
		mustEqual(t, c.DisableImplicitSignUp, true)
	})
}

// ---- Microsoft Entra ID Provider Helper ----

const msTenant = "12345678-1234-1234-1234-123456789012"

func msBase() BaseOptions {
	return BaseOptions{ClientID: "ms-client-id", ClientSecret: "ms-client-secret"}
}

func mustMS(t *testing.T, o MicrosoftEntraIDOptions) Config {
	t.Helper()
	c, err := MicrosoftEntraID(o)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func createMicrosoftIDToken(t *testing.T, payload map[string]any) string {
	t.Helper()
	o := jsonx.NewObject()
	for k, v := range payload {
		o.Set(k, v)
	}
	tok, err := bacrypto.SignJWT(o, "microsoft-test-secret", 0)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func graphUserinfo(srv *oauth2test.Server, status int, body any, calls *int) {
	srv.Handle("graph.microsoft.com/oidc/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		if calls != nil {
			*calls++
		}
		if body == nil {
			w.WriteHeader(status)
			return
		}
		writeJSON(w, status, body)
	})
}

func matchObject(t *testing.T, got map[string]any, want map[string]any) {
	t.Helper()
	for k, v := range want {
		if !reflect.DeepEqual(got[k], v) {
			t.Fatalf("%s: got %#v, want %#v (in %v)", k, got[k], v, got)
		}
	}
}

func TestMicrosoftEntraIDProviderHelper(t *testing.T) {
	t.Run("should return correct GenericOAuthConfig", func(t *testing.T) {
		c := mustMS(t, MicrosoftEntraIDOptions{BaseOptions: msBase(), TenantID: msTenant})
		mustEqual(t, c.ProviderID, "microsoft-entra-id")
		mustEqual(t, c.AuthorizationURL, "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789012/oauth2/v2.0/authorize")
		mustEqual(t, c.TokenURL, "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789012/oauth2/v2.0/token")
		mustEqual(t, c.UserInfoURL, "https://graph.microsoft.com/oidc/userinfo")
		mustEqual(t, c.DiscoveryURL, "https://login.microsoftonline.com/"+msTenant+"/v2.0/.well-known/openid-configuration")
		eqStrings(t, c.Scopes, []string{"openid", "profile", "email"})
		mustEqual(t, c.ClientID, "ms-client-id")
		mustEqual(t, c.ClientSecret, "ms-client-secret")
		if c.GetUserInfo == nil {
			t.Fatal("expected getUserInfo")
		}
		mustEqual(t, c.RequireIDTokenVerification, true)
	})
	t.Run("should handle tenant ID as GUID", func(t *testing.T) {
		c := mustMS(t, MicrosoftEntraIDOptions{BaseOptions: msBase(), TenantID: msTenant})
		mustEqual(t, c.AuthorizationURL, "https://login.microsoftonline.com/"+msTenant+"/oauth2/v2.0/authorize")
	})
	t.Run("should allow overriding scopes", func(t *testing.T) {
		b := msBase()
		b.Scopes = []string{"openid", "profile"}
		eqStrings(t, mustMS(t, MicrosoftEntraIDOptions{BaseOptions: b, TenantID: msTenant}).Scopes, []string{"openid", "profile"})
	})
	t.Run("should allow overriding other options", func(t *testing.T) {
		b := msBase()
		b.PKCE, b.DisableImplicitSignUp = ptrBool(true), true
		c := mustMS(t, MicrosoftEntraIDOptions{BaseOptions: b, TenantID: msTenant})
		mustEqual(t, *c.PKCE, true)
		mustEqual(t, c.DisableImplicitSignUp, true)
	})
	t.Run("skips the Microsoft provider when discovery is unavailable", func(t *testing.T) {
		srv := oauth2test.New(t)
		srv.Handle("login.microsoftonline.com/"+msTenant+"/v2.0/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) })
		in := newInst(t, genericPlugin(mustMS(t, MicrosoftEntraIDOptions{BaseOptions: msBase(), TenantID: msTenant})), instOpts{disableTestUser: true})
		if contains(in.providerIDs(), "microsoft-entra-id") {
			t.Fatal("expected provider to be skipped")
		}
	})
	for _, tenant := range []string{"common", "organizations", "consumers"} {
		t.Run("rejects the multi-tenant "+tenant+" endpoint because it cannot provide a stable issuer", func(t *testing.T) {
			_, err := MicrosoftEntraID(MicrosoftEntraIDOptions{BaseOptions: msBase(), TenantID: tenant})
			if err == nil || !strings.Contains(err.Error(), "requires a concrete Microsoft Entra tenant GUID") {
				t.Fatalf("err %v", err)
			}
		})
	}
	t.Run("rejects a missing tenant ID from an untyped runtime configuration", func(t *testing.T) {
		_, err := MicrosoftEntraID(MicrosoftEntraIDOptions{BaseOptions: msBase()})
		if err == nil || !strings.Contains(err.Error(), "requires a concrete Microsoft Entra tenant GUID") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("should use oid from the ID token as the account id instead of sub", func(t *testing.T) {
		srv := oauth2test.New(t)
		c := mustMS(t, MicrosoftEntraIDOptions{BaseOptions: msBase(), TenantID: msTenant})
		graphUserinfo(srv, 200, map[string]any{"sub": "token-pairwise-sub", "email": "graph@example.com", "name": "Graph User", "picture": "https://example.com/graph.png"}, nil)
		idt := createMicrosoftIDToken(t, map[string]any{"sub": "token-pairwise-sub", "oid": "token-stable-oid", "tid": "token-tenant-id", "email": "token@example.com", "name": "Token User"})
		info, err := c.GetUserInfo(context.Background(), &oauth2.Tokens{AccessToken: "ms-access-token", IDToken: idt})
		if err != nil || info == nil {
			t.Fatalf("info %v %v", info, err)
		}
		matchObject(t, info, map[string]any{"sub": "token-pairwise-sub", "oid": "token-stable-oid", "tid": "token-tenant-id",
			"email": "token@example.com", "name": "Token User", "image": "https://example.com/graph.png"})
		sub, _ := c.AccountSubject(context.Background(), &oauth2.Tokens{AccessToken: "ms-access-token", IDToken: idt}, info)
		mustEqual(t, sub, any("token-stable-oid"))
	})
	for _, tc := range []struct {
		name string
		sub  any
	}{{"does not match", "different-graph-sub"}, {"is missing", nil}} {
		t.Run("should ignore Graph userinfo when its subject "+tc.name, func(t *testing.T) {
			srv := oauth2test.New(t)
			c := mustMS(t, MicrosoftEntraIDOptions{BaseOptions: msBase(), TenantID: msTenant})
			body := map[string]any{"email": "graph@example.com", "name": "Graph User", "picture": "https://example.com/graph.png"}
			if tc.sub != nil {
				body["sub"] = tc.sub
			}
			graphUserinfo(srv, 200, body, nil)
			idt := createMicrosoftIDToken(t, map[string]any{"sub": "token-pairwise-sub", "oid": "token-stable-oid", "tid": "token-tenant-id"})
			info, _ := c.GetUserInfo(context.Background(), &oauth2.Tokens{AccessToken: "ms-access-token", IDToken: idt})
			matchObject(t, info, map[string]any{"sub": "token-pairwise-sub", "oid": "token-stable-oid", "tid": "token-tenant-id",
				"email": "token-stable-oid@microsoft-entra-id.placeholder.invalid", "emailVerified": false})
			if _, ok := info["name"]; ok {
				t.Fatal("expected no name")
			}
			if _, ok := info["image"]; ok {
				t.Fatal("expected no image")
			}
		})
	}
	t.Run("keeps the placeholder unverified for an unexpected null Graph email claim", func(t *testing.T) {
		srv := oauth2test.New(t)
		c := mustMS(t, MicrosoftEntraIDOptions{BaseOptions: msBase(), TenantID: msTenant})
		graphUserinfo(srv, 200, map[string]any{"sub": "token-pairwise-sub", "name": "Graph User", "email": nil, "email_verified": true}, nil)
		idt := createMicrosoftIDToken(t, map[string]any{"sub": "token-pairwise-sub", "oid": "token-stable-oid", "tid": "token-tenant-id"})
		info, _ := c.GetUserInfo(context.Background(), &oauth2.Tokens{AccessToken: "ms-access-token", IDToken: idt})
		matchObject(t, info, map[string]any{"name": "Graph User", "email": "token-stable-oid@microsoft-entra-id.placeholder.invalid", "emailVerified": false})
	})
	t.Run("should normalize personal Microsoft account givenname and familyname claims", func(t *testing.T) {
		srv := oauth2test.New(t)
		c := mustMS(t, MicrosoftEntraIDOptions{BaseOptions: msBase(), TenantID: msTenant})
		graphUserinfo(srv, 200, map[string]any{"sub": "token-pairwise-sub"}, nil)
		idt := createMicrosoftIDToken(t, map[string]any{"sub": "token-pairwise-sub", "oid": "token-stable-oid", "tid": "token-tenant-id", "givenname": "Personal", "familyname": "Account"})
		info, _ := c.GetUserInfo(context.Background(), &oauth2.Tokens{AccessToken: "ms-access-token", IDToken: idt})
		mustEqual(t, info["name"], any("Personal Account"))
	})
	t.Run("should fall back to ID token claims when Graph userinfo fails", func(t *testing.T) {
		srv := oauth2test.New(t)
		c := mustMS(t, MicrosoftEntraIDOptions{BaseOptions: msBase(), TenantID: msTenant})
		calls := 0
		graphUserinfo(srv, 503, nil, &calls)
		idt := createMicrosoftIDToken(t, map[string]any{"sub": "token-pairwise-sub", "oid": "token-stable-oid", "tid": "token-tenant-id",
			"email": "token@example.com", "name": "Token User", "picture": "https://example.com/token.png"})
		info, _ := c.GetUserInfo(context.Background(), &oauth2.Tokens{AccessToken: "ms-access-token", IDToken: idt})
		matchObject(t, info, map[string]any{"sub": "token-pairwise-sub", "oid": "token-stable-oid", "tid": "token-tenant-id",
			"email": "token@example.com", "name": "Token User", "image": "https://example.com/token.png", "emailVerified": false})
		mustEqual(t, calls, 1)
	})
	t.Run("should return token claims without fetching Graph when accessToken is missing", func(t *testing.T) {
		srv := oauth2test.New(t)
		c := mustMS(t, MicrosoftEntraIDOptions{BaseOptions: msBase(), TenantID: msTenant})
		calls := 0
		graphUserinfo(srv, 200, map[string]any{"sub": "token-pairwise-sub", "email": "graph@example.com", "name": "Graph User"}, &calls)
		idt := createMicrosoftIDToken(t, map[string]any{"sub": "token-pairwise-sub", "oid": "token-stable-oid", "tid": "token-tenant-id", "email": "token@example.com", "name": "Token User"})
		info, _ := c.GetUserInfo(context.Background(), &oauth2.Tokens{IDToken: idt})
		matchObject(t, info, map[string]any{"sub": "token-pairwise-sub", "oid": "token-stable-oid", "tid": "token-tenant-id",
			"email": "token@example.com", "name": "Token User", "emailVerified": false})
		mustEqual(t, calls, 0)
	})
	for _, tc := range []struct {
		name string
		oid  any
	}{{"missing", nil}, {"not a string", float64(123)}, {"blank", " \t"}} {
		t.Run("rejects an ID token whose oid is "+tc.name, func(t *testing.T) {
			srv := oauth2test.New(t)
			c := mustMS(t, MicrosoftEntraIDOptions{BaseOptions: msBase(), TenantID: msTenant})
			calls := 0
			graphUserinfo(srv, 200, map[string]any{"sub": "legacy-sub", "email": "legacy@example.com", "name": "Legacy User"}, &calls)
			claims := map[string]any{"sub": "legacy-sub", "email": "legacy@example.com", "name": "Legacy User"}
			if tc.oid != nil {
				claims["oid"] = tc.oid
			}
			info, err := c.GetUserInfo(context.Background(), &oauth2.Tokens{AccessToken: "ms-access-token", IDToken: createMicrosoftIDToken(t, claims)})
			if info != nil || err != nil {
				t.Fatalf("expected nil, got %v %v", info, err)
			}
			mustEqual(t, calls, 0)
		})
	}
}

// ---- Slack Provider Helper ----

func TestSlackProviderHelper(t *testing.T) {
	base := BaseOptions{ClientID: "slack-client-id", ClientSecret: "slack-client-secret"}
	t.Run("should return correct GenericOAuthConfig", func(t *testing.T) {
		c := Slack(SlackOptions{base})
		mustEqual(t, c.ProviderID, "slack")
		mustEqual(t, c.AuthorizationURL, "https://slack.com/openid/connect/authorize")
		mustEqual(t, c.TokenURL, "https://slack.com/api/openid.connect.token")
		mustEqual(t, c.UserInfoURL, "https://slack.com/api/openid.connect.userInfo")
		eqStrings(t, c.Scopes, []string{"openid", "profile", "email"})
		mustEqual(t, c.ClientID, "slack-client-id")
		mustEqual(t, c.ClientSecret, "slack-client-secret")
		if c.GetUserInfo == nil {
			t.Fatal("expected getUserInfo")
		}
	})
	t.Run("should allow overriding scopes", func(t *testing.T) {
		b := base
		b.Scopes = []string{"openid", "profile"}
		eqStrings(t, Slack(SlackOptions{b}).Scopes, []string{"openid", "profile"})
	})
	t.Run("should allow overriding other options", func(t *testing.T) {
		b := base
		b.PKCE, b.DisableImplicitSignUp = ptrBool(true), true
		c := Slack(SlackOptions{b})
		mustEqual(t, *c.PKCE, true)
		mustEqual(t, c.DisableImplicitSignUp, true)
	})
}

// ---- Yandex Provider Helper ----

func TestYandexProviderHelper(t *testing.T) {
	t.Run("should return correct GenericOAuthConfig", func(t *testing.T) {
		c := Yandex(YandexOptions{BaseOptions{ClientID: "yandex-client-id", ClientSecret: "yandex-client-secret",
			EndSessionEndpoint: "https://oauth.yandex.com/logout", PostLogoutRedirectURI: "https://example.com/signed-out", DisableProviderLogout: true}})
		mustEqual(t, c.ProviderID, "yandex")
		mustEqual(t, c.AuthorizationURL, "https://oauth.yandex.com/authorize")
		mustEqual(t, c.TokenURL, "https://oauth.yandex.com/token")
		eqStrings(t, c.Scopes, []string{"login:info", "login:email", "login:avatar"})
		mustEqual(t, c.ClientID, "yandex-client-id")
		mustEqual(t, c.ClientSecret, "yandex-client-secret")
		mustEqual(t, c.EndSessionEndpoint, "https://oauth.yandex.com/logout")
		mustEqual(t, c.PostLogoutRedirectURI, "https://example.com/signed-out")
		mustEqual(t, c.DisableProviderLogout, true)
		if c.GetUserInfo == nil {
			t.Fatal("expected getUserInfo")
		}
	})
	t.Run("returns null when Yandex does not return an email", func(t *testing.T) {
		srv := oauth2test.New(t)
		srv.JSON("login.yandex.ru/info", 200, map[string]any{"id": "yandex-user-id", "login": "yandex-user", "client_id": "yandex-client-id",
			"psuid": "yandex-psuid", "emails": []any{}})
		c := Yandex(YandexOptions{BaseOptions{ClientID: "yandex-client-id", ClientSecret: "yandex-client-secret"}})
		info, err := c.GetUserInfo(context.Background(), &oauth2.Tokens{AccessToken: "yandex-access-token"})
		if info != nil || err != nil {
			t.Fatalf("expected nil, got %v %v", info, err)
		}
	})
}

// ---- Keycloak Provider Helper ----

func TestKeycloakProviderHelper(t *testing.T) {
	base := BaseOptions{ClientID: "keycloak-client-id", ClientSecret: "keycloak-client-secret"}
	t.Run("should return correct GenericOAuthConfig", func(t *testing.T) {
		c := Keycloak(KeycloakOptions{BaseOptions: base, Issuer: "https://my-domain.com/realms/MyRealm"})
		mustEqual(t, c.ProviderID, "keycloak")
		mustEqual(t, c.DiscoveryURL, "https://my-domain.com/realms/MyRealm/.well-known/openid-configuration")
		eqStrings(t, c.Scopes, []string{"openid", "profile", "email"})
		mustEqual(t, c.ClientID, "keycloak-client-id")
		mustEqual(t, c.ClientSecret, "keycloak-client-secret")
		if c.GetUserInfo != nil {
			t.Fatal("expected no getUserInfo")
		}
	})
	t.Run("should handle issuer with trailing slash", func(t *testing.T) {
		mustEqual(t, Keycloak(KeycloakOptions{BaseOptions: base, Issuer: "https://my-domain.com/realms/MyRealm/"}).DiscoveryURL,
			"https://my-domain.com/realms/MyRealm/.well-known/openid-configuration")
	})
	t.Run("should allow overriding scopes", func(t *testing.T) {
		b := base
		b.Scopes = []string{"openid", "profile"}
		eqStrings(t, Keycloak(KeycloakOptions{BaseOptions: b, Issuer: "https://my-domain.com/realms/MyRealm"}).Scopes, []string{"openid", "profile"})
	})
	t.Run("should allow overriding other options", func(t *testing.T) {
		b := base
		b.PKCE, b.DisableImplicitSignUp = ptrBool(true), true
		c := Keycloak(KeycloakOptions{BaseOptions: b, Issuer: "https://my-domain.com/realms/MyRealm"})
		mustEqual(t, *c.PKCE, true)
		mustEqual(t, c.DisableImplicitSignUp, true)
	})
}

// ---- integration with genericOAuth ----

func integrate(t *testing.T, cfg Config) {
	t.Helper()
	oauth2test.New(t) // discovery hosts are unreachable (the providers are skipped)
	in := newInst(t, genericPlugin(cfg))
	if in.auth == nil {
		t.Fatal("expected auth")
	}
}

func TestShouldIntegrateOktaProviderHelperWithGenericOAuth(t *testing.T) {
	integrate(t, Okta(OktaOptions{BaseOptions: BaseOptions{ClientID: "okta-client-id", ClientSecret: "okta-client-secret"}, Issuer: "https://dev-12345.okta.com/oauth2/default"}))
}

func TestShouldIntegrateAuth0ProviderHelperWithGenericOAuth(t *testing.T) {
	integrate(t, Auth0(Auth0Options{BaseOptions: BaseOptions{ClientID: "auth0-client-id", ClientSecret: "auth0-client-secret"}, Domain: "dev-xxx.eu.auth0.com"}))
}

func TestShouldIntegrateMicrosoftEntraIDProviderHelperWithGenericOAuth(t *testing.T) {
	srv := oauth2test.New(t)
	issuer := "https://login.microsoftonline.com/" + msTenant + "/v2.0"
	srv.JSON("login.microsoftonline.com/"+msTenant+"/v2.0/.well-known/openid-configuration", 200, map[string]any{
		"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token",
		"userinfo_endpoint": "https://graph.microsoft.com/oidc/userinfo", "jwks_uri": issuer + "/discovery/v2.0/keys",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
	in := newInst(t, genericPlugin(mustMS(t, MicrosoftEntraIDOptions{BaseOptions: msBase(), TenantID: msTenant})))
	if !contains(in.providerIDs(), "microsoft-entra-id") {
		t.Fatal("expected provider")
	}
}

func TestShouldIntegrateSlackProviderHelperWithGenericOAuth(t *testing.T) {
	integrate(t, Slack(SlackOptions{BaseOptions{ClientID: "slack-client-id", ClientSecret: "slack-client-secret"}}))
}

func TestShouldIntegrateKeycloakProviderHelperWithGenericOAuth(t *testing.T) {
	integrate(t, Keycloak(KeycloakOptions{BaseOptions: BaseOptions{ClientID: "keycloak-client-id", ClientSecret: "keycloak-client-secret"}, Issuer: "https://my-domain.com/realms/MyRealm"}))
}

// ---- custom getToken ----

func TestShouldSupportCustomGetTokenForNonStandardProviders(t *testing.T) {
	setupIdP(t)
	called, capturedCode := false, ""
	raw := map[string]any{"access_token": "custom-access-token", "refresh_token": "custom-refresh-token", "expires_in": float64(3600),
		"openid": "custom-openid-123", "unionid": "custom-unionid-456", "scope": "snsapi_login"}
	cfg := discoveryConfig("custom-provider")
	cfg.Scopes = []string{"snsapi_login"}
	cfg.AccountSubject = func(_ context.Context, _ *oauth2.Tokens, p map[string]any) (any, error) {
		if p["id"] == nil {
			return "", nil
		}
		return p["id"], nil
	}
	cfg.GetToken = func(_ context.Context, p oauth2.CodeParams) (*oauth2.Tokens, error) {
		called, capturedCode = true, p.Code
		tok := oauth2.TokensFromResponse(raw)
		tok.Scopes = strings.Split("snsapi_login", ",")
		return tok, nil
	}
	cfg.GetUserInfo = func(_ context.Context, tok *oauth2.Tokens) (map[string]any, error) {
		mustEqual(t, tok.Raw["openid"], any("custom-openid-123"))
		mustEqual(t, tok.Raw["unionid"], any("custom-unionid-456"))
		return map[string]any{"id": tok.Raw["unionid"], "name": "Custom Provider User", "email": "custom@test.com", "emailVerified": true}, nil
	}
	in := newInst(t, genericPlugin(cfg))
	c := in.client()
	_, u := c.signInSocial(signInBody("custom-provider", "newUserCallbackURL", "http://localhost:3000/new_user"))
	mustContain(t, u, idpBase+"/authorize")
	cb := c.simulateOAuthFlow(u).callbackURL
	if !called || capturedCode == "" {
		t.Fatal("getToken not called")
	}
	mustEqual(t, cb, "http://localhost:3000/new_user")
}

func TestShouldHandleErrorsInCustomGetToken(t *testing.T) {
	idp := setupIdP(t)
	idp.userinfoOnce(map[string]any{"email": "error-test@test.com", "name": "Error Test User", "sub": "error-test", "picture": "https://test.com/picture.png", "email_verified": true})
	cfg := discoveryConfig("error-provider")
	cfg.GetToken = func(context.Context, oauth2.CodeParams) (*oauth2.Tokens, error) {
		return nil, errors.New("Token exchange failed")
	}
	in := newInst(t, genericPlugin(cfg))
	c := in.client()
	_, u := c.signInSocial(signInBody("error-provider", "errorCallbackURL", "http://localhost:3000/error"))
	mustContain(t, u, idpBase+"/authorize")
	cb := c.simulateOAuthFlow(u).callbackURL
	mustContain(t, cb, "http://localhost:3000/error")
	mustContain(t, cb, "error=")
}

func TestShouldSupportGETBasedTokenEndpointsForNonStandardProviders(t *testing.T) {
	setupIdP(t)
	raw := map[string]any{"access_token": "custom-access-token-xyz", "refresh_token": "custom-refresh-token-xyz", "expires_in": float64(7200),
		"user_id": "user_12345", "custom_field": "custom_value", "scope": "profile email"}
	method, used := "", ""
	cfg := discoveryConfig("custom-get-provider")
	cfg.Scopes = []string{"profile", "email"}
	cfg.AccountSubject = func(_ context.Context, _ *oauth2.Tokens, p map[string]any) (any, error) {
		if p["id"] == nil {
			return "", nil
		}
		return p["id"], nil
	}
	cfg.GetToken = func(context.Context, oauth2.CodeParams) (*oauth2.Tokens, error) {
		method = "GET"
		return oauth2.TokensFromResponse(raw), nil
	}
	cfg.GetUserInfo = func(_ context.Context, tok *oauth2.Tokens) (map[string]any, error) {
		used = tok.AccessToken
		mustEqual(t, tok.Raw["user_id"], any("user_12345"))
		mustEqual(t, tok.Raw["custom_field"], any("custom_value"))
		uid := tok.Raw["user_id"].(string)
		return map[string]any{"id": uid, "name": "Test User", "email": uid + "@example.com", "image": "https://example.com/avatar.png", "emailVerified": true}, nil
	}
	in := newInst(t, genericPlugin(cfg))
	c := in.client()
	_, u := c.signInSocial(signInBody("custom-get-provider", "newUserCallbackURL", "http://localhost:3000/welcome"))
	mustContain(t, u, idpBase+"/authorize")
	scope := queryParam(t, u, "scope")
	mustContain(t, scope, "profile")
	mustContain(t, scope, "openid")
	mustEqual(t, c.simulateOAuthFlow(u).callbackURL, "http://localhost:3000/welcome")
	mustEqual(t, method, "GET")
	mustEqual(t, used, "custom-access-token-xyz")
	user := sessionUser(c.session())
	mustEqual(t, user["name"], any("Test User"))
	mustEqual(t, user["image"], any("https://example.com/avatar.png"))
}

// ---- Duplicate Provider ID Detection ----

func captureWarn(t *testing.T) *[]string {
	t.Helper()
	var calls []string
	prev := warn
	warn = func(m string) { calls = append(calls, m) }
	t.Cleanup(func() { warn = prev })
	return &calls
}

func dupConfigs(ids ...string) []Config {
	var out []Config
	for i, id := range ids {
		out = append(out, Config{ProviderID: id, DiscoveryURL: discoveryURL, ClientID: "client-" + string(rune('1'+i)), ClientSecret: "secret-" + string(rune('1'+i))})
	}
	return out
}

func TestDuplicateProviderIDDetection(t *testing.T) {
	t.Run("should warn when duplicate provider IDs are detected", func(t *testing.T) {
		setupIdP(t)
		calls := captureWarn(t)
		newInst(t, genericPlugin(dupConfigs("duplicate-id", "duplicate-id")...))
		if len(*calls) != 1 || (*calls)[0] != "Duplicate provider IDs found: duplicate-id" {
			t.Fatalf("warns %v", *calls)
		}
	})
	t.Run("should warn about multiple duplicate provider IDs", func(t *testing.T) {
		setupIdP(t)
		calls := captureWarn(t)
		newInst(t, genericPlugin(dupConfigs("dup-1", "dup-1", "dup-2", "dup-2")...))
		if len(*calls) == 0 {
			t.Fatal("expected warning")
		}
		mustContain(t, (*calls)[0], "Duplicate provider IDs found:")
		mustContain(t, (*calls)[0], "dup-1")
		mustContain(t, (*calls)[0], "dup-2")
	})
	t.Run("should not warn when all provider IDs are unique", func(t *testing.T) {
		setupIdP(t)
		calls := captureWarn(t)
		newInst(t, genericPlugin(dupConfigs("unique-1", "unique-2")...))
		if len(*calls) != 0 {
			t.Fatalf("warns %v", *calls)
		}
	})
	t.Run("should not warn when only one provider is configured", func(t *testing.T) {
		setupIdP(t)
		calls := captureWarn(t)
		newInst(t, genericPlugin(dupConfigs("single-provider")...))
		if len(*calls) != 0 {
			t.Fatalf("warns %v", *calls)
		}
	})
	t.Run("should warn when provider ID appears more than twice", func(t *testing.T) {
		setupIdP(t)
		calls := captureWarn(t)
		newInst(t, genericPlugin(dupConfigs("triple-dup", "triple-dup", "triple-dup")...))
		if len(*calls) != 1 || (*calls)[0] != "Duplicate provider IDs found: triple-dup" {
			t.Fatalf("warns %v", *calls)
		}
	})
}

// ---- storeIdentifier: hashed ----

func TestStoreIdentifierHashedShouldCompleteOAuthFlowWhenVerificationIdentifiersAreHashed(t *testing.T) {
	idp := setupIdP(t)
	idp.userinfoOnce(map[string]any{"email": "hashed-oauth@test.com", "name": "Hashed OAuth Test", "sub": "hashed-oauth", "picture": "https://test.com/picture.png", "email_verified": true})
	in := newInst(t, func(c *betterauth.Config) {
		c.Verification = &betterauth.VerificationConfig{StoreIdentifier: &betterauth.StoreIdentifier{Mode: "hashed"}}
		genericPlugin(discoveryConfig("test-hashed"))(c)
	})
	c := in.client()
	_, u := c.signInSocial(signInBody("test-hashed"))
	mustContain(t, u, idpBase+"/authorize")
	mustEqual(t, c.simulateOAuthFlow(u).callbackURL, "http://localhost:3000/dashboard")
}

func TestShouldMergeClientRequestedScopesWithConfigScopes(t *testing.T) {
	setupIdP(t)
	in := newInst(t, genericPlugin(Config{ProviderID: "scopes-test", DiscoveryURL: discoveryURL, ClientID: clientID, ClientSecret: clientSecret,
		Scopes: []string{"openid", "email", "profile"}}))
	_, u := in.client().signInSocial(signInBody("scopes-test", "scopes", []string{"custom_scope"}))
	scopes := strings.Split(queryParam(t, u, "scope"), " ")
	for _, s := range []string{"custom_scope", "openid", "email", "profile"} {
		if !contains(scopes, s) {
			t.Fatalf("missing %s in %v", s, scopes)
		}
	}
}

func TestShouldWarnWhenGenericProviderIDShadowsABuiltInSocialProvider(t *testing.T) {
	setupIdP(t)
	in := newInst(t, func(c *betterauth.Config) {
		c.SocialProviders = []oauth2.Provider{googleProvider()}
		genericPlugin(Config{ProviderID: "google", AuthorizationURL: idpBase + "/authorize", TokenURL: idpBase + "/token", ClientID: "override-id", ClientSecret: "override-secret"})(c)
	})
	if !in.logs.contains(`Generic OAuth provider "google" shadows a built-in social provider with the same ID`) {
		t.Fatal("expected shadow warning")
	}
	if _, ok := in.provider("google").(*Provider); !ok {
		t.Fatal("expected the generic provider to win")
	}
}

func TestShouldPassDiscoveredIssuerToTheProviderForRFC9207Validation(t *testing.T) {
	setupIdP(t)
	in := newInst(t, genericPlugin(Config{ProviderID: "issuer-test", DiscoveryURL: discoveryURL, ClientID: clientID, ClientSecret: clientSecret}))
	p := in.provider("issuer-test")
	if p == nil {
		t.Fatal("provider missing")
	}
	mustEqual(t, oauth2.SettingsOf(p).Issuer, idpBase)
}

// ---- tokenEndpointAuth ----

func TestTokenEndpointAuth(t *testing.T) {
	t.Run("should send client_assertion instead of client_secret at the token endpoint", func(t *testing.T) {
		idp := setupIdP(t)
		var calls [][3]string
		var body map[string][]string
		idp.onTokenSigning(func(_ map[string]any, r *oauth2test.Request) { body = r.Form }, true)
		in := newInst(t, genericPlugin(Config{ProviderID: "test-assertion", DiscoveryURL: discoveryURL, ClientID: clientID, PKCE: ptrBool(true),
			TokenEndpointAuth: &oauth2.TokenEndpointAuth{Method: oauth2.AuthPrivateKeyJWT, GetClientAssertion: func(cid, ep, gt string) (string, error) {
				calls = append(calls, [3]string{cid, ep, gt})
				return "test-client-assertion-jwt", nil
			}}}))
		c := in.client()
		_, u := c.signInSocial(signInBody("test-assertion"))
		mustEqual(t, c.simulateOAuthFlow(u).callbackURL, "http://localhost:3000/dashboard")
		if len(calls) != 1 || calls[0][0] != clientID || !strings.Contains(calls[0][1], idpHost) || calls[0][2] != "authorization_code" {
			t.Fatalf("assertion calls %v", calls)
		}
		if body == nil {
			t.Fatal("no token request")
		}
		get := func(k string) string {
			if v := body[k]; len(v) > 0 {
				return v[0]
			}
			return ""
		}
		mustEqual(t, get("grant_type"), "authorization_code")
		mustEqual(t, get("client_id"), clientID)
		if _, ok := body["client_secret"]; ok {
			t.Fatal("unexpected client_secret")
		}
		mustEqual(t, get("client_assertion_type"), "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		mustEqual(t, get("client_assertion"), "test-client-assertion-jwt")
	})
	t.Run("should reject secretless token endpoint auth combined with clientSecret", func(t *testing.T) {
		setupIdP(t)
		_, err := newInstE(t, genericPlugin(Config{ProviderID: "test-assertion-with-secret", DiscoveryURL: discoveryURL, ClientID: clientID, ClientSecret: clientSecret,
			PKCE: ptrBool(true), TokenEndpointAuth: &oauth2.TokenEndpointAuth{Method: oauth2.AuthPrivateKeyJWT,
				GetClientAssertion: func(string, string, string) (string, error) { return "client-assertion", nil }}}), instOpts{})
		if err == nil || !strings.Contains(err.Error(), `Provider "test-assertion-with-secret": tokenEndpointAuth.method "private_key_jwt" cannot be combined with clientSecret`) {
			t.Fatalf("err %v", err)
		}
	})
	for _, m := range []oauth2.TokenEndpointAuthMethod{oauth2.AuthClientSecretBasic, oauth2.AuthClientSecretPost} {
		t.Run("should reject "+string(m)+" token endpoint auth without clientSecret", func(t *testing.T) {
			setupIdP(t)
			id := "test-" + string(m) + "-without-secret"
			_, err := newInstE(t, genericPlugin(Config{ProviderID: id, DiscoveryURL: discoveryURL, ClientID: clientID, PKCE: ptrBool(true),
				TokenEndpointAuth: &oauth2.TokenEndpointAuth{Method: m}}), instOpts{})
			want := `Provider "` + id + `": tokenEndpointAuth.method "` + string(m) + `" requires clientSecret`
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("err %v", err)
			}
		})
	}
}

func TestShouldUseCustomNameWhenProvidedInConfig(t *testing.T) {
	setupIdP(t)
	cfg := explicitEndpoints("named-provider")
	cfg.Name = "My Custom Provider"
	in := newInst(t, genericPlugin(cfg))
	mustEqual(t, in.provider("named-provider").Name(), "My Custom Provider")
}
