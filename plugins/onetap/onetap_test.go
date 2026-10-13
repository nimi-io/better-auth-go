package onetap

import (
	"context"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
	"github.com/nimi-io/better-auth-go/providers/google"
)

// Port of packages/better-auth/src/plugins/one-tap/one-tap.test.ts. Upstream mocks jose; here
// real RS256 tokens are signed by a fake Google JWKS (oauth2test).

type tokenIssuer struct {
	srv    *oauth2test.Server
	claims map[string]any
}

func defaultClaims() map[string]any {
	return map[string]any{"email": "one-tap-user@example.com", "email_verified": true, "name": "One Tap User",
		"picture": "https://example.com/photo.jpg", "sub": "google_oauth_sub_one_tap"}
}

func newIssuer(t *testing.T) *tokenIssuer {
	srv := oauth2test.New(t)
	srv.ServeJWKS("www.googleapis.com/oauth2/v3/certs")
	return &tokenIssuer{srv: srv, claims: defaultClaims()}
}

func (ti *tokenIssuer) token(aud string) string {
	c := map[string]any{"iss": "https://accounts.google.com", "aud": aud}
	for k, v := range ti.claims {
		c[k] = v
	}
	return ti.srv.IDToken(c)
}

func googleCfg(mutate func(o *google.Options)) func(c *betterauth.Config) {
	return func(c *betterauth.Config) {
		c.SocialProviders = []oauth2.Provider{googleProvider(func(o *google.Options) {
			o.ClientID, o.ClientSecret = "test-client", "test-secret"
			if mutate != nil {
				mutate(o)
			}
		})}
	}
}

func plugin(o Options) func(c *betterauth.Config) {
	return func(c *betterauth.Config) { c.Plugins = append(c.Plugins, New(o)) }
}

func all(fs ...func(c *betterauth.Config)) func(c *betterauth.Config) {
	return func(c *betterauth.Config) {
		for _, f := range fs {
			f(c)
		}
	}
}

func accountLinking(al betterauth.AccountLinkingConfig) func(c *betterauth.Config) {
	return func(c *betterauth.Config) { c.Account = &betterauth.AccountConfig{AccountLinking: &al} }
}

func (in *inst) googleAccounts(accountID string) []map[string]any {
	in.t.Helper()
	where := []adapter.Where{{Field: "providerId", Value: "google"}}
	if accountID != "" {
		where = append(where, adapter.Where{Field: "accountId", Value: accountID})
	}
	recs, err := in.ctx().Adapter.FindMany(context.Background(), adapter.FindManyInput{Model: "account", Where: where})
	if err != nil {
		in.t.Fatal(err)
	}
	var out []map[string]any
	for _, r := range recs {
		out = append(out, r)
	}
	return out
}

func signUp(t *testing.T, in *inst, email, name string) {
	t.Helper()
	res := in.client().post("/sign-up/email", map[string]any{"email": email, "password": "password123", "name": name})
	if res.Status != 200 {
		t.Fatalf("sign-up %d %s", res.Status, res.Body)
	}
}

func oneTap(in *inst, token string, extra ...any) *response {
	body := map[string]any{"idToken": token}
	for i := 0; i+1 < len(extra); i += 2 {
		body[extra[i].(string)] = extra[i+1]
	}
	return in.client().post("/one-tap/callback", body)
}

func TestOneTapImplicitLinkingGate(t *testing.T) {
	t.Run("rejects implicit linking when the local user is unverified", func(t *testing.T) {
		ti := newIssuer(t)
		in := newInst(t, all(googleCfg(nil), plugin(Options{})))
		signUp(t, in, "one-tap-user@example.com", "Pre-existing Unverified")
		mustEqual(t, oneTap(in, ti.token("test-client")).Status, 401)
	})
	t.Run("allows implicit linking once the local user is verified", func(t *testing.T) {
		ti := newIssuer(t)
		in := newInst(t, all(googleCfg(nil), plugin(Options{}), emailVerifiedOnCreate))
		signUp(t, in, "one-tap-user@example.com", "Pre-existing Verified")
		res := oneTap(in, ti.token("test-client"))
		mustEqual(t, res.Status, 200)
		if len(in.googleAccounts("")) < 1 {
			t.Fatal("expected google account")
		}
	})
	t.Run("links the account when requireLocalEmailVerified is opted out, even for an unverified local user", func(t *testing.T) {
		ti := newIssuer(t)
		in := newInst(t, all(googleCfg(nil), accountLinking(betterauth.AccountLinkingConfig{RequireLocalEmailVerified: betterauth.Bool(false)}), plugin(Options{})))
		signUp(t, in, "one-tap-user@example.com", "Pre-existing Unverified (Opted-out)")
		mustEqual(t, oneTap(in, ti.token("test-client")).Status, 200)
		if len(in.googleAccounts("")) < 1 {
			t.Fatal("expected google account")
		}
	})
	t.Run("returns 403 EMAIL_NOT_VERIFIED when the provider requires a verified email", func(t *testing.T) {
		ti := newIssuer(t)
		ti.claims["email"], ti.claims["email_verified"], ti.claims["sub"] = "one-tap-unverified@example.com", false, "one_tap_unverified_sub"
		in := newInst(t, all(googleCfg(func(o *google.Options) { o.RequireEmailVerification = true }), plugin(Options{})))
		mustEqual(t, oneTap(in, ti.token("test-client")).Status, 403)
	})
	t.Run("links Google One Tap when another provider has the same account ID", func(t *testing.T) {
		ti := newIssuer(t)
		ti.claims["email"], ti.claims["sub"] = "one-tap-provider-collision@example.com", "shared-one-tap-provider-account-id"
		in := newInst(t, all(googleCfg(nil), accountLinking(betterauth.AccountLinkingConfig{RequireLocalEmailVerified: betterauth.Bool(false)}), plugin(Options{})))
		ia := in.ctx().InternalAdapter
		other, err := ia.CreateUser(context.Background(), adapter.Record{"name": "Other Provider User", "email": "one-tap-other-provider@example.com"}, betterauth.UserInfoSource{Method: "test"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ia.CreateAccount(context.Background(), adapter.Record{"userId": other.ID, "providerId": "github", "accountId": "shared-one-tap-provider-account-id"}); err != nil {
			t.Fatal(err)
		}
		signUp(t, in, "one-tap-provider-collision@example.com", "Pre-existing Local User")
		mustEqual(t, oneTap(in, ti.token("test-client")).Status, 200)
		mustEqual(t, len(in.googleAccounts("shared-one-tap-provider-account-id")), 1)
	})
	t.Run("does not duplicate the Google account when the same user signs in again", func(t *testing.T) {
		ti := newIssuer(t)
		ti.claims["email"], ti.claims["sub"] = "one-tap-returning-user@example.com", "returning-user-google-sub"
		in := newInst(t, all(googleCfg(nil), plugin(Options{})))
		for i := 0; i < 2; i++ {
			res := oneTap(in, ti.token("test-client"))
			if res.Status != 200 {
				t.Fatalf("one-tap %d %s", res.Status, res.Body)
			}
			if s, _ := res.JSON(t)["token"].(string); s == "" {
				t.Fatal("expected token")
			}
		}
		mustEqual(t, len(in.googleAccounts("returning-user-google-sub")), 1)
	})
	t.Run("signs in the account that owns the Google sub, not the email-matched user", func(t *testing.T) {
		ti := newIssuer(t)
		ti.claims["email"], ti.claims["sub"] = "one-tap-email-collision-b@example.com", "one-tap-sub-owned-by-user-a"
		in := newInst(t, all(googleCfg(nil), plugin(Options{})))
		ia := in.ctx().InternalAdapter
		a, _ := ia.CreateUser(context.Background(), adapter.Record{"name": "Sub Owner A", "email": "one-tap-sub-owner-a@example.com"}, betterauth.UserInfoSource{Method: "test"})
		if _, err := ia.CreateAccount(context.Background(), adapter.Record{"userId": a.ID, "providerId": "google", "accountId": "one-tap-sub-owned-by-user-a"}); err != nil {
			t.Fatal(err)
		}
		b, _ := ia.CreateUser(context.Background(), adapter.Record{"name": "Email Match B", "email": "one-tap-email-collision-b@example.com"}, betterauth.UserInfoSource{Method: "test"})
		res := oneTap(in, ti.token("test-client"))
		mustEqual(t, res.Status, 200)
		uid := res.JSON(t)["user"].(map[string]any)["id"]
		mustEqual(t, uid, any(a.ID))
		if uid == b.ID {
			t.Fatal("signed in the email-matched user")
		}
	})
	t.Run("honors accountLinking.disableImplicitLinking even when the local user is verified", func(t *testing.T) {
		ti := newIssuer(t)
		in := newInst(t, all(googleCfg(nil), accountLinking(betterauth.AccountLinkingConfig{DisableImplicitLinking: true}), plugin(Options{}), emailVerifiedOnCreate))
		signUp(t, in, "one-tap-user@example.com", "Pre-existing Verified, Linking Disabled")
		mustEqual(t, oneTap(in, ti.token("test-client")).Status, 401)
		mustEqual(t, len(in.googleAccounts("")), 0)
	})
}

func originChecked(c *betterauth.Config) {
	c.Advanced = &betterauth.AdvancedConfig{DisableOriginCheck: betterauth.Bool(false)}
}

func TestOneTapCallbackURLOriginValidation(t *testing.T) {
	t.Run("rejects an untrusted callbackURL via the global origin check", func(t *testing.T) {
		ti := newIssuer(t)
		in := newInst(t, all(googleCfg(nil), plugin(Options{}), originChecked))
		mustEqual(t, oneTap(in, ti.token("test-client"), "callbackURL", "https://untrusted.example/callback").Status, 403)
	})
	t.Run("accepts a relative callbackURL (origin check passes)", func(t *testing.T) {
		ti := newIssuer(t)
		in := newInst(t, all(googleCfg(nil), plugin(Options{}), originChecked))
		if oneTap(in, ti.token("test-client"), "callbackURL", "/dashboard").Status == 403 {
			t.Fatal("origin check blocked a relative callbackURL")
		}
	})
}

func noSocial(c *betterauth.Config) { c.SocialProviders = nil }

func TestOneTapAudienceEnforcement(t *testing.T) {
	t.Run("rejects the callback when no Google client ID is configured", func(t *testing.T) {
		ti := newIssuer(t)
		in := newInst(t, all(noSocial, plugin(Options{})))
		res := oneTap(in, ti.token("test-client"))
		mustEqual(t, res.Status, 400)
		mustContain(t, res.JSON(t)["message"].(string), "Google client ID is required")
		if len(ti.srv.Requests) != 0 {
			t.Fatal("verification must not run")
		}
	})
	t.Run("accepts the oneTap-level clientId as the audience without a Google provider", func(t *testing.T) {
		ti := newIssuer(t)
		in := newInst(t, all(noSocial, plugin(Options{ClientID: "explicit-one-tap-client"})))
		res := oneTap(in, ti.token("explicit-one-tap-client"))
		mustNotContain(t, string(res.Body), "Google client ID is required")
		mustEqual(t, res.Status, 200)
		// a token minted for a different client is rejected (audience enforced)
		mustEqual(t, oneTap(in, ti.token("other-client")).Status, 400)
	})
	t.Run("rejects the callback when the verified token has no email", func(t *testing.T) {
		ti := newIssuer(t)
		ti.claims["email"] = ""
		in := newInst(t, all(noSocial, plugin(Options{ClientID: "explicit-one-tap-client"})))
		res := oneTap(in, ti.token("explicit-one-tap-client"))
		mustEqual(t, res.Status, 400)
		mustContain(t, res.JSON(t)["message"].(string), "Email not available in token")
	})
}

func TestOneTapHostedDomainHd(t *testing.T) {
	withHD := func(hd string) func(c *betterauth.Config) {
		return googleCfg(func(o *google.Options) { o.HD = hd })
	}
	cases := []struct {
		name, email, sub, tokenHD, configured string
		ok                                    bool
	}{
		{"rejects a token whose hd does not match the configured value", "one-tap-hd-mismatch@other.com", "one-tap-hd-mismatch-sub", "other.com", "company.com", false},
		{"rejects a token with no hd when one is configured", "one-tap-hd-missing@company.com", "one-tap-hd-missing-sub", "", "company.com", false},
		{"accepts a token whose hd matches the configured value", "one-tap-hd-match@company.com", "one-tap-hd-match-sub", "company.com", "company.com", true},
		{"accepts any Workspace hd when the configured value is a wildcard", "one-tap-hd-wildcard@company.com", "one-tap-hd-wildcard-sub", "company.com", "*", true},
		{"rejects a token with no hd when the configured value is a wildcard", "one-tap-hd-wildcard-missing@example.com", "one-tap-hd-wildcard-missing-sub", "", "*", false},
		{"ignores the token hd when no hosted domain is configured", "one-tap-no-hd-config@anywhere.com", "one-tap-no-hd-config-sub", "anywhere.com", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ti := newIssuer(t)
			ti.claims["email"], ti.claims["sub"] = tc.email, tc.sub
			if tc.tokenHD != "" {
				ti.claims["hd"] = tc.tokenHD
			}
			in := newInst(t, all(withHD(tc.configured), plugin(Options{})))
			res := oneTap(in, ti.token("test-client"))
			if tc.ok {
				mustEqual(t, res.Status, 200)
				if s, _ := res.JSON(t)["token"].(string); s == "" {
					t.Fatal("expected token")
				}
			} else {
				mustEqual(t, res.Status, 400)
			}
		})
	}
}

func TestOneTapDisableSignUp(t *testing.T) {
	run := func(t *testing.T, email, sub string, o Options) {
		ti := newIssuer(t)
		ti.claims["email"], ti.claims["sub"] = email, sub
		in := newInst(t, all(googleCfg(func(o *google.Options) { o.DisableSignUp = true }), plugin(o)))
		_, err := in.auth.API.Call(context.Background(), "oneTapCallback", betterauth.CallInput{Body: map[string]any{"idToken": ti.token("test-client")}})
		e, ok := betterauth.AsAPIError(err)
		if !ok || e.StatusCode != 401 || e.Status != "UNAUTHORIZED" || e.Message() != "signup disabled" {
			t.Fatalf("err %v", err)
		}
		recs, _ := in.ctx().Adapter.FindMany(context.Background(), adapter.FindManyInput{Model: "user", Where: []adapter.Where{{Field: "email", Value: email}}})
		mustEqual(t, len(recs), 0)
	}
	t.Run("rejects provider-disabled sign-up without creating a user", func(t *testing.T) {
		run(t, "one-tap-disable-signup@example.com", "one-tap-disable-signup-sub", Options{})
	})
	t.Run("keeps provider sign-up disabled when One Tap enables it", func(t *testing.T) {
		run(t, "one-tap-signup-override@example.com", "one-tap-signup-override-sub", Options{DisableSignup: false})
	})
}

func TestOneTapClientTypes(t *testing.T) {
	t.Skip("oneTapClient types: TypeScript declaration/type-level checks of the browser client plugin; TS-only")
}
