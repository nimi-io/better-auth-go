package oauthprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/plugins/bearer"
	"github.com/nimi-io/better-auth-go/plugins/genericoauth"
)

// Helpers for port_oauth_test.go (oauth.test.ts): a relying party built from a second
// betterauth instance with the generic-oauth plugin, reachable at http://localhost:5000
// through the swapped HTTP clients.

const (
	oaRPBase       = "http://localhost:5000"
	oaRPHost       = "localhost:5000"
	oaProviderID   = "test"
	oaRedirectURI  = oaRPBase + "/api/auth/callback/" + oaProviderID
	oaAuthorizeURL = testBaseURL + "/api/auth/oauth2/authorize"
)

// oaJar is a cookie jar (cookieSetter equivalent).
type oaJar struct {
	order []string
	m     map[string]string
}

func oaNewJar() *oaJar { return &oaJar{m: map[string]string{}} }

func (j *oaJar) apply(h http.Header) {
	if j == nil {
		return
	}
	for _, sc := range h.Values("Set-Cookie") {
		n, v, a := betterauth.ParseSetCookie(sc)
		if ma, ok := a["max-age"]; ok && (ma == "0" || strings.HasPrefix(ma, "-")) {
			delete(j.m, n)
			continue
		}
		if _, ok := j.m[n]; !ok {
			j.order = append(j.order, n)
		}
		j.m[n] = v
	}
}

func (j *oaJar) cookie() string {
	if j == nil {
		return ""
	}
	var parts []string
	seen := map[string]bool{}
	for _, k := range j.order {
		if v, ok := j.m[k]; ok && !seen[k] {
			seen[k] = true
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, "; ")
}

// header returns request headers carrying the jar cookies.
func (j *oaJar) header() http.Header {
	h := http.Header{}
	if c := j.cookie(); c != "" {
		h.Set("Cookie", c)
	}
	return h
}

// oaFetch sends a request through the test network (AS at localhost:3000, RP at
// localhost:5000). target is absolute or relative to the AS /api/auth.
func oaFetch(t *testing.T, env *testEnv, method, target string, body any, jar *oaJar, extra http.Header) *response {
	t.Helper()
	if !strings.HasPrefix(target, "http") {
		target = testAuthBase + target
	}
	var rd io.Reader
	ct := ""
	switch b := body.(type) {
	case nil:
	case url.Values:
		rd = strings.NewReader(b.Encode())
		ct = "application/x-www-form-urlencoded"
	default:
		raw, _ := json.Marshal(b)
		rd = bytes.NewReader(raw)
		ct = "application/json"
	}
	req, err := http.NewRequest(method, target, rd)
	if err != nil {
		t.Fatal(err)
	}
	if c := jar.cookie(); c != "" {
		req.Header.Set("Cookie", c)
	}
	for k, vs := range extra {
		req.Header.Del(k)
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if ct != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", ct)
	}
	if method != http.MethodGet && req.Header.Get("Origin") == "" {
		req.Header.Set("Origin", req.URL.Scheme+"://"+req.URL.Host)
	}
	res, err := env.RoundTrip(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return &response{status: res.StatusCode, header: res.Header, body: b}
}

// oaSearch returns the query string (with "?") of a possibly relative URL.
func oaSearch(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if u.RawQuery == "" {
		return ""
	}
	return "?" + u.RawQuery
}

// oaWithQuery mirrors the oauthProviderClient fetch plugin: it adds the signed query of
// window.location.search to the body.
func oaWithQuery(body map[string]any, search string) map[string]any {
	if body == nil {
		body = map[string]any{}
	}
	if _, ok := body["oauth_query"]; ok {
		return body
	}
	if search != "" {
		if q := BuildSignedOAuthQuery(search); q != "" {
			body["oauth_query"] = q
		}
	}
	return body
}

// oaRouteOAuth2 routes oauth2.HTTPClient (used by the RP) through the test network.
func oaRouteOAuth2(t *testing.T, env *testEnv) {
	prev := oauth2.HTTPClient
	oauth2.HTTPClient = &http.Client{Transport: env, CheckRedirect: prev.CheckRedirect}
	t.Cleanup(func() { oauth2.HTTPClient = prev })
}

// oaServeDiscovery serves /.well-known/openid-configuration at the AS root (like the
// listhen server upstream) and everything else through the AS handler.
func oaServeDiscovery(env *testEnv) {
	h := env.auth.Handler()
	env.serveHost("localhost:3000", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			res, err := env.auth.API.Call(context.Background(), "getOpenIdConfig", betterauth.CallInput{})
			if err != nil {
				w.WriteHeader(500)
				return
			}
			m := decodeMap(env.t, res)
			raw, _ := json.Marshal(m)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(raw)
			return
		}
		h.ServeHTTP(w, r)
	}))
}

// oaRP is the relying party (createTestInstance with genericOAuth).
type oaRP struct {
	auth *betterauth.Auth
}

// oaNewRP builds the RP and registers it at localhost:5000. cfg carries the optional
// fields (Scopes, Prompt, DiscoveryURL, TokenURLParams).
func oaNewRP(t *testing.T, env *testEnv, clientID, clientSecret string, cfg genericoauth.Config) *oaRP {
	t.Helper()
	if cfg.Scopes == nil {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	if cfg.AccountSubject == nil {
		cfg.AccountSubject = func(_ context.Context, _ *oauth2.Tokens, profile map[string]any) (any, error) {
			if s, ok := profile["sub"].(string); ok {
				return s, nil
			}
			return "", nil
		}
	}
	cfg.ProviderID = oaProviderID
	cfg.RedirectURI = oaRedirectURI
	if cfg.DiscoveryURL == "" {
		cfg.AuthorizationURL = testBaseURL + "/api/auth/oauth2/authorize"
		cfg.TokenURL = testBaseURL + "/api/auth/oauth2/token"
		cfg.UserInfoURL = testBaseURL + "/api/auth/oauth2/userinfo"
	}
	cfg.ClientID = clientID
	cfg.ClientSecret = clientSecret
	pk := true
	cfg.PKCE = &pk
	a, err := betterauth.New(betterauth.Config{
		BaseURL:          oaRPBase,
		Secret:           "better-auth.secret-for-tests-1234567890abcdef",
		Database:         memory.New(),
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true},
		Logger:           betterauth.NopLogger{},
		RateLimit:        &betterauth.RateLimitConfig{Enabled: betterauth.Bool(false)},
		Account: &betterauth.AccountConfig{AccountLinking: &betterauth.AccountLinkingConfig{
			TrustedProviders: []string{oaProviderID},
		}},
		Plugins: []*betterauth.Plugin{genericoauth.New(genericoauth.Options{Config: []genericoauth.Config{cfg}}), bearer.New()},
	})
	if err != nil {
		t.Fatalf("rp: %v", err)
	}
	env.serveHost(oaRPHost, a.Handler())
	return &oaRP{auth: a}
}

// signInSocial is client.signIn.social({provider, callbackURL: "/success"}); it returns
// the authorization URL.
func (rp *oaRP) signInSocial(t *testing.T, env *testEnv, jar *oaJar) string {
	t.Helper()
	res := oaFetch(t, env, "POST", oaRPBase+"/api/auth/sign-in/social",
		map[string]any{"provider": oaProviderID, "callbackURL": "/success"}, jar, nil)
	if res.status != 200 {
		t.Fatalf("sign-in/social: %d %s", res.status, res.body)
	}
	jar.apply(res.header)
	u, _ := res.json()["url"].(string)
	if u == "" {
		t.Fatalf("missing authorization URL: %s", res.body)
	}
	return u
}

// oaAuthorize GETs the authorization URL at the AS and returns the redirect location.
func oaAuthorize(t *testing.T, env *testEnv, authURL string, jar *oaJar) (string, *response) {
	t.Helper()
	res := oaFetch(t, env, "GET", authURL, nil, jar, nil)
	return res.location(), res
}

// oaRedirectResult decodes a {redirect, url} JSON body.
func oaRedirectResult(t *testing.T, res *response) (bool, string) {
	t.Helper()
	m := res.json()
	if m == nil {
		t.Fatalf("expected JSON redirect, got %d %q %s", res.status, res.location(), res.body)
	}
	r, _ := m["redirect"].(bool)
	u, _ := m["url"].(string)
	return r, u
}

func oaContains(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Fatalf("expected %q to contain %q", s, sub)
	}
}

func oaNotContains(t *testing.T, s, sub string) {
	t.Helper()
	if strings.Contains(s, sub) {
		t.Fatalf("expected %q not to contain %q", s, sub)
	}
}

func oaStr(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func jsonUnmarshalOa(b []byte, v any) error { return json.Unmarshal(b, v) }
