package betterauth

// Port of better-auth/src/social.test.ts (upstream v1.7.7): describe("validateUserInfo callback").

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/providers/google"
)

func psocValidateEnv(t *testing.T, o oauth2.ProviderOptions, validate func(ctx *EndpointContext, user map[string]any, source UserInfoSource) (*ValidateUserInfoResult, error), mutate func(c *Config)) *testEnv {
	return psocEnv(t, func(c *Config) {
		c.User = &UserConfig{ValidateUserInfo: validate}
		c.SocialProviders = []oauth2.Provider{google.New(google.Options{ProviderOptions: o})}
		if mutate != nil {
			mutate(c)
		}
	}, true)
}

func psocTestGoogle() oauth2.ProviderOptions {
	return oauth2.ProviderOptions{ClientID: "test", ClientSecret: "test"}
}

func psocTrueVerifier(context.Context, string, string) (bool, error) { return true, nil }

func TestPortSocialValidateUserInfo(t *testing.T) {
	m := psocMock(t)
	googleToken := func(claims map[string]any) {
		m.JSON("POST oauth2.googleapis.com/token", 200, map[string]any{"access_token": "test", "id_token": m.IDToken(claims)})
	}

	t.Run("should allow sign-in when validateUserInfo returns void", func(t *testing.T) {
		psocTokenEndpoint(m, "POST oauth2.googleapis.com/token", psocProfile(), nil)
		env := psocValidateEnv(t, psocTestGoogle(), func(*EndpointContext, map[string]any, UserInfoSource) (*ValidateUserInfoResult, error) {
			return nil, nil
		}, nil)
		c := env.client()
		psocSignInFlow(t, c, "google", map[string]any{"callbackURL": "/dashboard"})
		if u := psocSessionUser(t, c); u["email"] != "user@email.com" {
			t.Fatalf("user %v", u)
		}
	})

	t.Run("should reject redirect sign-in with source metadata and raw profile", func(t *testing.T) {
		googleToken(map[string]any{"email": "user@blocked.com", "email_verified": true, "name": "Blocked User",
			"picture": "https://test.com/picture.png", "sub": "blocked-user-id", "iat": float64(1234567890),
			"exp": float64(1234567890), "aud": "test", "azp": "test", "iss": "test"})
		var captured map[string]any
		var srcErr string
		env := psocValidateEnv(t, psocTestGoogle(), func(_ *EndpointContext, user map[string]any, source UserInfoSource) (*ValidateUserInfoResult, error) {
			if source.Action != "create-user" || source.Method != "oauth" || source.ProviderID != "google" {
				srcErr = source.Action + "/" + source.Method + "/" + source.ProviderID
			}
			captured = source.Profile
			if e, _ := user["email"].(string); strings.HasSuffix(e, "@blocked.com") {
				return &ValidateUserInfoResult{Error: "domain_blocked", ErrorDescription: "Only company emails are allowed"}, nil
			}
			return nil, nil
		}, nil)
		res := psocSignInFlow(t, env.client(), "google", map[string]any{"callbackURL": "/dashboard"})
		if srcErr != "" {
			t.Fatalf("unexpected source %s", srcErr)
		}
		loc := res.Header.Get("Location")
		if !strings.Contains(loc, "error=domain_blocked") || !strings.Contains(loc, "error_description=Only+company+emails+are+allowed") {
			t.Fatalf("location %s", loc)
		}
		if captured == nil || captured["sub"] != "blocked-user-id" {
			t.Fatalf("captured profile %v", captured)
		}
	})

	t.Run("should work in stateless mode (no database)", func(t *testing.T) {
		psocTokenEndpoint(m, "POST oauth2.googleapis.com/token", psocProfile(), nil)
		var srcErr string
		env := psocValidateEnv(t, psocTestGoogle(), func(_ *EndpointContext, user map[string]any, source UserInfoSource) (*ValidateUserInfoResult, error) {
			if source.Method != "oauth" || source.ProviderID != "google" {
				srcErr = source.Method + "/" + source.ProviderID
			}
			if e, _ := user["email"].(string); !strings.HasSuffix(e, "@allowed.com") {
				return &ValidateUserInfoResult{Error: "email_not_allowed", ErrorDescription: "Only allowed.com emails are permitted"}, nil
			}
			return nil, nil
		}, func(c *Config) { c.Database = nil })
		res := psocSignInFlow(t, env.client(), "google", map[string]any{"callbackURL": "/dashboard"})
		if srcErr != "" {
			t.Fatalf("unexpected source %s", srcErr)
		}
		if loc := res.Header.Get("Location"); !strings.Contains(loc, "error=email_not_allowed") {
			t.Fatalf("location %q (%d %s)", loc, res.Status, res.Body)
		}
	})

	t.Run("should reject idToken sign-in when validateUserInfo returns error", func(t *testing.T) {
		o := psocTestGoogle()
		o.VerifyIDToken = psocTrueVerifier
		var srcErr string
		env := psocValidateEnv(t, o, func(_ *EndpointContext, _ map[string]any, source UserInfoSource) (*ValidateUserInfoResult, error) {
			if source.Action != "create-user" || source.Method != "oauth" {
				srcErr = source.Action + "/" + source.Method
			}
			return &ValidateUserInfoResult{Error: "user_blocked"}, nil
		}, nil)
		tok := m.IDToken(map[string]any{"email": "blocked@email.com", "email_verified": true, "name": "Blocked User", "sub": "blocked-id"})
		res := psocIDTokenSignIn(env.client(), "google", tok, map[string]any{"callbackURL": "/dashboard"})
		if srcErr != "" {
			t.Fatalf("unexpected source %s", srcErr)
		}
		if res.Status != 403 {
			t.Fatalf("expected 403, got %d %s", res.Status, res.Body)
		}
	})

	t.Run("fires create-user on first OAuth sign-in and sign-in on the return", func(t *testing.T) {
		psocTokenEndpoint(m, "POST oauth2.googleapis.com/token", psocProfile(), nil)
		var actions []string
		env := psocValidateEnv(t, psocTestGoogle(), func(_ *EndpointContext, _ map[string]any, source UserInfoSource) (*ValidateUserInfoResult, error) {
			actions = append(actions, source.Action)
			return nil, nil
		}, nil)
		psocSignInFlow(t, env.client(), "google", map[string]any{"callbackURL": "/dashboard"})
		psocSignInFlow(t, env.client(), "google", map[string]any{"callbackURL": "/dashboard"})
		if !reflect.DeepEqual(actions, []string{"create-user", "sign-in"}) {
			t.Fatalf("actions %v", actions)
		}
	})

	t.Run("re-validates a returning OAuth user against the fresh provider identity", func(t *testing.T) {
		tokenFor := func(email, name string, verified bool) {
			googleToken(map[string]any{"email": email, "email_verified": verified, "name": name,
				"picture": "https://test.com/picture.png", "sub": "mover-sub", "iat": float64(1234567890),
				"exp": float64(1234567890), "aud": "test", "azp": "test", "iss": "test"})
		}
		var emailSeen, nameSeen, idSeen any
		var verifiedSeen any
		env := psocValidateEnv(t, psocTestGoogle(), func(_ *EndpointContext, user map[string]any, source UserInfoSource) (*ValidateUserInfoResult, error) {
			if source.Action != "sign-in" {
				return nil, nil
			}
			emailSeen, verifiedSeen, nameSeen, idSeen = user["email"], user["emailVerified"], user["name"], user["id"]
			if e, _ := user["email"].(string); strings.HasSuffix(e, "@blocked.com") {
				return &ValidateUserInfoResult{Error: "domain_revoked", ErrorDescription: "Your account is no longer allowed"}, nil
			}
			return nil, nil
		}, nil)

		tokenFor("mover@allowed.com", "Allowed Mover", true)
		first := env.client()
		psocSignInFlow(t, first, "google", map[string]any{"callbackURL": "/dashboard"})
		u := psocSessionUser(t, first)
		if u["email"] != "mover@allowed.com" || u["name"] != "Allowed Mover" {
			t.Fatalf("user %v", u)
		}

		tokenFor("mover@blocked.com", "Blocked Mover", false)
		second := psocSignInFlow(t, env.client(), "google", map[string]any{"callbackURL": "/dashboard"})
		if emailSeen != "mover@blocked.com" || nameSeen != "Blocked Mover" || verifiedSeen != false || idSeen != u["id"] {
			t.Fatalf("seen email=%v name=%v verified=%v id=%v (want id %v)", emailSeen, nameSeen, verifiedSeen, idSeen, u["id"])
		}
		if loc := second.Header.Get("Location"); !strings.Contains(loc, "error=domain_revoked") {
			t.Fatalf("location %s", loc)
		}
	})

	t.Run("re-validates a returning OAuth user on the id-token (API) surface", func(t *testing.T) {
		o := psocTestGoogle()
		o.VerifyIDToken = psocTrueVerifier
		env := psocValidateEnv(t, o, func(_ *EndpointContext, user map[string]any, source UserInfoSource) (*ValidateUserInfoResult, error) {
			if e, _ := user["email"].(string); source.Action == "sign-in" && strings.HasSuffix(e, "@blocked.com") {
				return &ValidateUserInfoResult{Error: "domain_revoked"}, nil
			}
			return nil, nil
		}, nil)
		idTokenFor := func(email string) string {
			return m.IDToken(map[string]any{"email": email, "email_verified": true, "name": "Mover", "sub": "idtoken-mover"})
		}
		created := psocIDTokenSignIn(env.client(), "google", idTokenFor("mover@allowed.com"), map[string]any{"callbackURL": "/dashboard"})
		if created.Status != 200 {
			t.Fatalf("created: %d %s", created.Status, created.Body)
		}
		blocked := psocIDTokenSignIn(env.client(), "google", idTokenFor("mover@blocked.com"), map[string]any{"callbackURL": "/dashboard"})
		psocExpectAPIError(t, blocked, 403, "domain_revoked", "")
	})

	t.Run("reports link-account for an implicit link and persists no orphaned link when rejected", func(t *testing.T) {
		googleToken(map[string]any{"email": "implicit-link@example.com", "email_verified": true, "name": "Implicit Link",
			"picture": "https://test.com/picture.png", "sub": "implicit-link-sub", "iat": float64(1234567890),
			"exp": float64(1234567890), "aud": "test", "azp": "test", "iss": "test"})
		var seenAction string
		env := psocValidateEnv(t, psocTestGoogle(), func(_ *EndpointContext, _ map[string]any, source UserInfoSource) (*ValidateUserInfoResult, error) {
			if source.Action == "link-account" {
				seenAction = source.Action
				return &ValidateUserInfoResult{Error: "linking_blocked"}, nil
			}
			return nil, nil
		}, func(c *Config) {
			c.EmailAndPassword = &EmailAndPasswordConfig{Enabled: true}
			c.Account = &AccountConfig{AccountLinking: &AccountLinkingConfig{TrustedProviders: []string{"google"}, RequireLocalEmailVerified: Bool(false)}}
		})
		env.client().signUp("implicit-link@example.com", "password", "Existing User")

		res := psocSignInFlow(t, env.client(), "google", map[string]any{"callbackURL": "/dashboard"})
		if seenAction != "link-account" {
			t.Fatalf("seenAction %q", seenAction)
		}
		if loc := res.Header.Get("Location"); !strings.Contains(loc, "error=linking_blocked") {
			t.Fatalf("location %s", loc)
		}

		c := env.client()
		if r := c.post("/sign-in/email", map[string]any{"email": "implicit-link@example.com", "password": "password"}); r.Status != 200 {
			t.Fatalf("sign-in email: %d %s", r.Status, r.Body)
		}
		var providers []string
		for _, a := range c.get("/list-accounts").JSON2(t) {
			providers = append(providers, a["providerId"].(string))
		}
		has := func(p string) bool {
			for _, x := range providers {
				if x == p {
					return true
				}
			}
			return false
		}
		if !has("credential") || has("google") {
			t.Fatalf("providers %v", providers)
		}
	})
}
