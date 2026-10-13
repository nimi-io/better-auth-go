package oauthpopup

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/bearer"
	"github.com/nimi-io/better-auth-go/plugins/genericoauth"
)

// Port of packages/better-auth/src/plugins/oauth-popup/oauth-popup.test.ts.
// oauth-popup.client.test.ts exercises the browser client plugin (postMessage gate,
// localStorage bearer fetch plugin) and has no server-side equivalent.

func TestOAuthPopupCompletionScriptPinsTheScriptsSha256InTheResponseCSPHash(t *testing.T) {
	sum := sha256.Sum256([]byte(CompleteScript))
	mustEqual(t, ScriptCSPHash, "sha256-"+base64.StdEncoding.EncodeToString(sum[:]))
}

const popupOrigin = "http://localhost:3000"

func popupInst(t *testing.T) *inst {
	t.Helper()
	idp := newIdP(t)
	idp.onUserinfo(func(b *map[string]any, s *int) {
		*b = map[string]any{"email": "popup@test.com", "name": "Popup User", "sub": "popup", "email_verified": true}
		*s = 200
	}, false)
	return newInst(t, func(c *betterauth.Config) {
		c.Session = &betterauth.SessionConfig{CookieCache: &betterauth.CookieCacheConfig{Enabled: true}}
		emailVerifiedOnCreate(c)
		c.Plugins = append(c.Plugins, genericoauth.New(genericoauth.Options{Config: []genericoauth.Config{{ProviderID: "test",
			DiscoveryURL: discoveryURL, ClientID: "test-client-id", ClientSecret: "test-client-secret", PKCE: ptrBool(true)}}}), New(), bearer.New())
	})
}

var startURL = popupOrigin + "/api/auth/oauth-popup/start?provider=test&popupOrigin=" + url.QueryEscape(popupOrigin) +
	"&popupNonce=n1&callbackURL=" + url.QueryEscape(popupOrigin+"/dashboard")

func runPopupFlow(t *testing.T, in *inst) (startRes, callbackRes *response) {
	t.Helper()
	c := in.client()
	startRes = c.get(startURL)
	req, _ := http.NewRequest("GET", startRes.location(), nil)
	res, err := oauth2HTTP(req)
	if err != nil {
		t.Fatal(err)
	}
	callbackRes = c.get(res.Header.Get("Location"))
	return
}

func TestOAuthPopupServerFlow(t *testing.T) {
	t.Run("redirects to the provider and sets the opener marker cookie", func(t *testing.T) {
		in := popupInst(t)
		s, _ := runPopupFlow(t, in)
		mustContain(t, strings.Join(s.Header.Values("Set-Cookie"), ", "), "better-auth.oauth_popup")
	})
	t.Run("returns the completion page instead of redirecting", func(t *testing.T) {
		in := popupInst(t)
		_, cb := runPopupFlow(t, in)
		mustEqual(t, cb.Status, 200)
		mustContain(t, cb.Header.Get("Content-Type"), "text/html")
		mustContain(t, cb.Header.Get("Cache-Control"), "no-store")
		body := string(cb.Body)
		mustContain(t, body, DataElementID)
		mustContain(t, body, "postMessage")
		cookies := strings.Join(cb.Header.Values("Set-Cookie"), ", ")
		mustContain(t, cookies, "better-auth.session_token")
		mustContain(t, cookies, "better-auth.session_data")
	})
	t.Run("hands off a token that authenticates via the bearer plugin", func(t *testing.T) {
		in := popupInst(t)
		_, cb := runPopupFlow(t, in)
		token, _, _ := cb.setCookie("better-auth.session_token")
		if token == "" {
			t.Fatal("expected token")
		}
		mustContain(t, string(cb.Body), `"token":"`+token+`"`)
		h := http.Header{}
		h.Set("Authorization", "Bearer "+token)
		s, err := in.auth.API.GetSession(context.Background(), h)
		if err != nil || s == nil || s.User.Email != "popup@test.com" {
			t.Fatalf("session %v %v", s, err)
		}
	})
	t.Run("keeps the redirect when it is not a popup flow", func(t *testing.T) {
		in := popupInst(t)
		c := in.client()
		res := c.do("POST", popupOrigin+"/api/auth/sign-in/social", map[string]any{"provider": "test", "callbackURL": popupOrigin + "/dashboard", "disableRedirect": true})
		u, _ := res.JSON(t)["url"].(string)
		req, _ := http.NewRequest("GET", u, nil)
		r, err := oauth2HTTP(req)
		if err != nil {
			t.Fatal(err)
		}
		cb := c.get(r.Header.Get("Location"))
		mustEqual(t, cb.Status, 302)
		mustEqual(t, cb.location(), popupOrigin+"/dashboard")
	})
	t.Run("relays an OAuth error to the opener instead of redirecting", func(t *testing.T) {
		in := popupInst(t)
		c := in.client()
		s := c.get(startURL)
		state := queryParam(t, s.location(), "state")
		cb := c.get(popupOrigin + "/api/auth/callback/test?state=" + url.QueryEscape(state) + "&error=access_denied")
		mustEqual(t, cb.Status, 200)
		mustContain(t, string(cb.Body), DataElementID)
		mustContain(t, string(cb.Body), "access_denied")
	})
	t.Run("relays a start-stage error (unknown provider) to the opener", func(t *testing.T) {
		in := popupInst(t)
		res := in.client().get(popupOrigin + "/api/auth/oauth-popup/start?provider=nope&popupOrigin=" + url.QueryEscape(popupOrigin) + "&popupNonce=n1")
		mustEqual(t, res.Status, 200)
		mustContain(t, string(res.Body), DataElementID)
		mustContain(t, string(res.Body), "provider_not_found")
	})
	t.Run("keeps internal state keys out of additionalData when storing state", func(t *testing.T) {
		in := popupInst(t)
		ad := url.QueryEscape(`{"link":{"email":"popup@test.com","userId":"some-user-id"},"tenant":"acme"}`)
		res := in.client().get(startURL + "&additionalData=" + ad)
		if res.location() == "" {
			t.Fatalf("no location: %d %s", res.Status, res.Body)
		}
		recs, err := in.ctx().Adapter.FindMany(context.Background(), adapter.FindManyInput{Model: "verification"})
		if err != nil {
			t.Fatal(err)
		}
		var stored map[string]any
		for _, r := range recs {
			v, _ := r["value"].(string)
			if !strings.HasPrefix(v, "{") {
				continue
			}
			m := decodeJSON(t, v)
			if m["tenant"] == "acme" {
				stored = m
			}
		}
		if stored == nil {
			t.Fatal("state not stored")
		}
		if _, ok := stored["link"]; ok {
			t.Fatal("link leaked into state")
		}
	})
	t.Run("rejects an untrusted callbackURL at start", func(t *testing.T) {
		in := popupInst(t)
		res := in.client().get(popupOrigin + "/api/auth/oauth-popup/start?provider=test&popupOrigin=" + url.QueryEscape(popupOrigin) +
			"&popupNonce=n1&callbackURL=" + url.QueryEscape("https://evil.example.com"))
		mustEqual(t, res.Status, 200)
		mustContain(t, string(res.Body), "invalid_callback_url")
	})
	t.Run("rejects an untrusted popup origin", func(t *testing.T) {
		in := popupInst(t)
		res := in.client().get(popupOrigin + "/api/auth/oauth-popup/start?provider=test&popupOrigin=" + url.QueryEscape("https://evil.example.com") + "&popupNonce=n1")
		mustEqual(t, res.Status, 403)
	})
}

func TestOAuthPopupClientTests(t *testing.T) {
	t.Skip("oauth-popup.client.test.ts covers the browser client plugin (signIn.popup message gate, bearer fetch plugin with localStorage); TS-only")
}
