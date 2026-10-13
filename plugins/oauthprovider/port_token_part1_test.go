package oauthprovider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Port of token.test.ts (part 1): authorization_code, refresh_token and reuse interval.

const tkValidResource = "https://myapi.example.com"

func tkStdClientBody(redirectURI string) map[string]any {
	return map[string]any{
		"token_endpoint_auth_method": "client_secret_post",
		"grant_types":                []any{"authorization_code", "client_credentials", "refresh_token"},
		"redirect_uris":              []any{redirectURI},
		"application_type":           "native",
		"skip_consent":               true,
	}
}

func tkResourceOpts(resources ...string) Options {
	rs := make([]ResourceInput, len(resources))
	for i, r := range resources {
		rs[i] = ResourceInput{Identifier: r}
	}
	f := false
	return Options{Resources: rs, EnforcePerClientResources: &f}
}

// tkIDTokenBasics asserts the id_token verifies and carries no profile/email claims.
func tkIDTokenBasics(t *testing.T, e *tkEnv, idToken string) *jsonx.Object {
	t.Helper()
	p := tkVerify(t, idToken, e.jwks(), "", "")
	if tkGet(p, "sub") == nil || tkGet(p, "name") != nil || tkGet(p, "email") != nil {
		t.Fatalf("id token claims: %v", p)
	}
	return p
}

func TestTk_OauthTokenAuthorizationCode(t *testing.T) {
	e := tkNewEnv(t, tkResourceOpts(tkValidResource))
	redirectURI := tkRPBase + "/api/auth/callback/test"
	state := "123"
	oc := e.admin(tkStdClientBody(redirectURI))
	clientID, secret := tkStr(oc, "client_id"), tkStr(oc, "client_secret")
	if clientID == "" || secret == "" || oc["user_id"] == nil {
		t.Fatalf("client: %v", oc)
	}
	if ru, _ := oc["redirect_uris"].([]any); len(ru) != 1 || ru[0] != redirectURI {
		t.Fatalf("redirect_uris: %v", oc["redirect_uris"])
	}
	authCode := func(t *testing.T, scopes []string) (string, string) {
		t.Helper()
		v := tkVerifier()
		loc := e.authorize(clientID, redirectURI, state, scopes, v)
		if !strings.Contains(loc, redirectURI) || !strings.Contains(loc, "code=") || !strings.Contains(loc, "state=123") {
			t.Fatalf("callback: %q", loc)
		}
		return tkCode(t, loc), v
	}
	exchange := func(code, verifier string, resources ...string) *response {
		return e.token(tkCodeForm(code, verifier, redirectURI, clientID, secret, resources...), nil)
	}

	scopeCase := func(name string, scopes []string, wantRefresh bool) {
		t.Run(name, func(t *testing.T) {
			code, v := authCode(t, scopes)
			m := tkOK(t, exchange(code, v))
			if tkStr(m, "access_token") == "" || tkStr(m, "id_token") == "" {
				t.Fatalf("tokens: %v", m)
			}
			if (m["refresh_token"] != nil) != wantRefresh {
				t.Fatalf("refresh_token presence: %v", m)
			}
			if m["scope"] != strings.Join(scopes, " ") {
				t.Fatalf("scope: %v", m["scope"])
			}
			tkIDTokenBasics(t, e, tkStr(m, "id_token"))
		})
	}
	scopeCase("scope openid should provide access_token and id_token", []string{"openid"}, false)

	t.Run("should exchange a PKCE authorization code when state is omitted", func(t *testing.T) {
		v := tkVerifier()
		loc := e.authorize(clientID, redirectURI, "", []string{"openid"}, v)
		if !strings.Contains(loc, redirectURI) || !strings.Contains(loc, "code=") || strings.Contains(loc, "state=") {
			t.Fatalf("callback: %q", loc)
		}
		m := tkOK(t, exchange(tkCode(t, loc), v))
		if m["access_token"] == nil || m["id_token"] == nil || m["scope"] != "openid" {
			t.Fatalf("tokens: %v", m)
		}
	})
	scopeCase("scope openid+profile should provide access_token and id_token", []string{"openid", "profile"}, false)
	scopeCase("scope openid+email should provide access_token and id_token", []string{"openid", "email"}, false)
	scopeCase("scope openid+offline_access should provide opaque access_token, id_token, and refresh_token", []string{"openid", "offline_access"}, true)

	t.Run("scope openid+offline_access & specified resource should provide JWT access_token, id_token, and refresh_token", func(t *testing.T) {
		scopes := []string{"openid", "offline_access"}
		code, v := authCode(t, scopes)
		m := tkOK(t, exchange(code, v, tkValidResource))
		if m["access_token"] == nil || m["id_token"] == nil || m["refresh_token"] == nil || m["scope"] != "openid offline_access" {
			t.Fatalf("tokens: %v", m)
		}
		tkIDTokenBasics(t, e, tkStr(m, "id_token"))
		at := tkVerify(t, tkStr(m, "access_token"), e.jwks(), tkValidResource, testBaseURL)
		if tkGet(at, "azp") != clientID || tkGet(at, "sub") == nil || tkGet(at, "iat") == nil ||
			tkNum(tkGet(at, "exp")) != tkNum(m["expires_at"]) || tkGet(at, "scope") != "openid offline_access" {
			t.Fatalf("access token: %v / %v", at, m)
		}
	})

	t.Run("rejects concurrent redemption of the same authorization code", func(t *testing.T) {
		code, v := authCode(t, []string{"openid", "offline_access"})
		var wg sync.WaitGroup
		results := make([]*response, 2)
		for i := range results {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results[i] = exchange(code, v)
			}(i)
		}
		wg.Wait()
		var ok, fail []*response
		for _, r := range results {
			if r.status == 200 {
				ok = append(ok, r)
			} else {
				fail = append(fail, r)
			}
		}
		if len(ok) != 1 || len(fail) != 1 {
			t.Fatalf("expected one success and one failure: %d %s / %d %s", results[0].status, results[0].body, results[1].status, results[1].body)
		}
		if ok[0].json()["access_token"] == nil || ok[0].json()["id_token"] == nil {
			t.Fatalf("winner: %s", ok[0].body)
		}
		if fail[0].json()["error"] != "invalid_grant" {
			t.Fatalf("loser: %s", fail[0].body)
		}
	})

	t.Run("rejects authorization code replay with invalid_grant and revokes issued tokens", func(t *testing.T) {
		code, v := authCode(t, []string{"openid"})
		m := tkOK(t, exchange(code, v))
		if m["access_token"] == nil {
			t.Fatalf("tokens: %v", m)
		}
		tkExpectErr(t, exchange(code, v), 400, "invalid_grant")
		ui := e.do("GET", "/oauth2/userinfo", nil, http.Header{"Authorization": {"Bearer " + tkStr(m, "access_token")}})
		if ui.status != 401 {
			t.Fatalf("userinfo: %d %s", ui.status, ui.body)
		}
	})

	t.Run("rejects authorization code replay with invalid_grant and still attempts refresh-token cleanup when access-token cleanup fails", func(t *testing.T) {
		code, v := authCode(t, []string{"openid", "offline_access"})
		m := tkOK(t, exchange(code, v))
		if m["access_token"] == nil || m["refresh_token"] == nil {
			t.Fatalf("tokens: %v", m)
		}
		e.hooks.mu.Lock()
		e.hooks.deleteManyCalls = nil
		e.hooks.failDeleteMany = errors.New("cleanup failed")
		e.hooks.mu.Unlock()
		tkExpectErr(t, exchange(code, v), 400, "invalid_grant")
		if !e.logs.has("authorization code replay cleanup failed") {
			t.Fatalf("expected cleanup error log, got %v", e.logs.errors)
		}
		e.hooks.mu.Lock()
		calls := append([]string(nil), e.hooks.deleteManyCalls...)
		e.hooks.mu.Unlock()
		if len(calls) < 2 || calls[0] != "oauthAccessToken" || calls[1] != "oauthRefreshToken" {
			t.Fatalf("deleteMany calls: %v", calls)
		}
		tkExpectErr(t, e.token(tkRefreshForm(tkStr(m, "refresh_token"), clientID, secret, ""), nil), 400, "invalid_grant")
	})

	t.Run("redirect_uri conditional (RFC 6749 §4.1.3)", func(t *testing.T) {
		mintHeadless := func(t *testing.T) (string, string) {
			t.Helper()
			sess := e.mustCall("getSession", betterauth.CallInput{Headers: e.h})
			user, _ := sess["user"].(map[string]any)
			session, _ := sess["session"].(map[string]any)
			code := tkVerifier()
			verifier := tkVerifier() + "abcdefghijk"
			now := time.Now()
			id, _ := storeToken(&resolved{}, code, TokenTypeAuthorizationCode)
			raw, _ := json.Marshal(map[string]any{
				"type": "authorization_code",
				"query": map[string]any{
					"client_id":             clientID,
					"scope":                 "openid",
					"code_challenge":        challengeFor(verifier),
					"code_challenge_method": "S256",
				},
				"userId":    user["id"],
				"sessionId": session["id"],
				"authTime":  now.UnixMilli(),
			})
			if _, err := e.auth.Context().InternalAdapter.CreateVerificationValue(context.Background(), id, string(raw), now.Add(600*time.Second), nil); err != nil {
				t.Fatal(err)
			}
			return code, verifier
		}
		mintBound := func(t *testing.T) string {
			t.Helper()
			return tkCode(t, e.authorize(clientID, redirectURI, state, []string{"openid", "profile", "email", "offline_access"}, tkVerifier()))
		}
		t.Run("exchanges a headless code that omits redirect_uri", func(t *testing.T) {
			code, v := mintHeadless(t)
			f := tkCodeForm(code, v, "", clientID, secret)
			f.Del("redirect_uri")
			m := tkOK(t, e.token(f, nil))
			if m["access_token"] == nil {
				t.Fatalf("tokens: %v", m)
			}
		})
		t.Run("rejects a redirect_uri supplied against a headless code with invalid_grant", func(t *testing.T) {
			code, v := mintHeadless(t)
			m := tkExpectErr(t, e.token(tkCodeForm(code, v, redirectURI, clientID, secret), nil), 0, "invalid_grant")
			if m["access_token"] != nil {
				t.Fatal(m)
			}
		})
		t.Run("requires redirect_uri when the code was bound to one", func(t *testing.T) {
			code := mintBound(t)
			f := tkCodeForm(code, "", "", clientID, secret)
			f.Del("redirect_uri")
			tkExpectErr(t, e.token(f, nil), 0, "invalid_request")
		})
		t.Run("rejects a mismatched redirect_uri with invalid_grant", func(t *testing.T) {
			code := mintBound(t)
			tkExpectErr(t, e.token(tkCodeForm(code, "", "https://attacker.example/callback", clientID, secret), nil), 0, "invalid_grant")
		})
	})
}

// tkRefreshFixture is the shared setup of the refresh_token describes.
type tkRefreshFixture struct {
	e           *tkEnv
	redirectURI string
	clientID    string
	secret      string
}

func (f *tkRefreshFixture) authorizeForRefreshToken(t *testing.T, scopes []string, checkID bool) map[string]any {
	t.Helper()
	v := tkVerifier()
	loc := f.e.authorize(f.clientID, f.redirectURI, "123", scopes, v)
	if !strings.Contains(loc, f.redirectURI) || !strings.Contains(loc, "code=") || !strings.Contains(loc, "state=123") {
		t.Fatalf("callback: %q", loc)
	}
	m := tkOK(t, f.e.token(tkCodeForm(tkCode(t, loc), v, f.redirectURI, f.clientID, f.secret), nil))
	if m["refresh_token"] == nil {
		t.Fatalf("tokens: %v", m)
	}
	if checkID {
		if m["access_token"] == nil || m["id_token"] == nil || m["scope"] != strings.Join(scopes, " ") {
			t.Fatalf("tokens: %v", m)
		}
		tkIDTokenBasics(t, f.e, tkStr(m, "id_token"))
	}
	return m
}

func (f *tkRefreshFixture) refresh(refreshToken, scope string, resources ...string) *response {
	return f.e.token(tkRefreshForm(refreshToken, f.clientID, f.secret, scope, resources...), nil)
}

func TestTk_OauthTokenRefreshToken(t *testing.T) {
	e := tkNewEnv(t, tkResourceOpts(tkValidResource))
	redirectURI := tkRPBase + "/api/auth/callback/test"
	oc := e.admin(tkStdClientBody(redirectURI))
	f := &tkRefreshFixture{e: e, redirectURI: redirectURI, clientID: tkStr(oc, "client_id"), secret: tkStr(oc, "client_secret")}
	if f.clientID == "" || f.secret == "" || oc["user_id"] == nil {
		t.Fatalf("client: %v", oc)
	}
	scopes := []string{"openid", "profile", "offline_access"}
	joined := strings.Join(scopes, " ")

	t.Run("returns invalid_request when refresh_token omits client_id", func(t *testing.T) {
		r := e.token(map[string][]string{"grant_type": {"refresh_token"}, "refresh_token": {"not-used"}}, nil)
		tkExpectErr(t, r, 400, "invalid_request")
	})
	t.Run("returns invalid_request when refresh_token is omitted", func(t *testing.T) {
		r := e.token(map[string][]string{"grant_type": {"refresh_token"}, "client_id": {f.clientID}, "client_secret": {f.secret}}, nil)
		tkExpectErr(t, r, 400, "invalid_request")
	})
	t.Run("should refresh token with same scopes, opaque access token", func(t *testing.T) {
		tokens := f.authorizeForRefreshToken(t, scopes, true)
		m := tkOK(t, f.refresh(tkStr(tokens, "refresh_token"), joined))
		if m["access_token"] == nil || m["id_token"] == nil || m["refresh_token"] == nil || m["scope"] != joined ||
			m["refresh_token"] == tokens["refresh_token"] {
			t.Fatalf("refresh: %v", m)
		}
	})
	t.Run("rejects refresh token use by a different client with invalid_grant", func(t *testing.T) {
		tokens := f.authorizeForRefreshToken(t, scopes, true)
		otherRedirect := tkRPBase + "/api/auth/callback/other"
		other := e.admin(map[string]any{
			"grant_types":      []any{"authorization_code", "refresh_token"},
			"redirect_uris":    []any{otherRedirect},
			"application_type": "native",
			"skip_consent":     true,
		})
		if other["client_id"] == nil || other["client_secret"] == nil {
			t.Fatalf("other client: %v", other)
		}
		r := e.token(tkRefreshForm(tkStr(tokens, "refresh_token"), tkStr(other, "client_id"), tkStr(other, "client_secret"), joined), nil)
		m := tkExpectErr(t, r, 0, "invalid_grant")
		if m["error_description"] != "invalid refresh token" {
			t.Fatalf("description: %v", m)
		}
	})
	t.Run("should preserve auth_time in id_token after refresh (OIDC Core 1.0 Section 12.2)", func(t *testing.T) {
		tokens := f.authorizeForRefreshToken(t, scopes, true)
		orig := decodeJWTPayload(t, tkStr(tokens, "id_token"))
		if orig["auth_time"] == nil {
			t.Fatalf("auth_time missing: %v", orig)
		}
		m := tkOK(t, f.refresh(tkStr(tokens, "refresh_token"), joined))
		if m["id_token"] == nil {
			t.Fatalf("refresh: %v", m)
		}
		if got := decodeJWTPayload(t, tkStr(m, "id_token"))["auth_time"]; got != orig["auth_time"] {
			t.Fatalf("auth_time %v != %v", got, orig["auth_time"])
		}
	})
	jwtCase := func(name string, newScopes []string, resource bool) {
		t.Run(name, func(t *testing.T) {
			tokens := f.authorizeForRefreshToken(t, scopes, true)
			var res []string
			if resource {
				res = []string{tkValidResource}
			}
			m := tkOK(t, f.refresh(tkStr(tokens, "refresh_token"), strings.Join(newScopes, " "), res...))
			if m["access_token"] == nil || m["id_token"] == nil || m["refresh_token"] == nil ||
				m["scope"] != strings.Join(newScopes, " ") || m["refresh_token"] == tokens["refresh_token"] {
				t.Fatalf("refresh: %v", m)
			}
			if resource {
				at := tkVerify(t, tkStr(m, "access_token"), e.jwks(), tkValidResource, testBaseURL)
				if tkGet(at, "azp") != f.clientID || tkGet(at, "sub") == nil || tkGet(at, "iat") == nil ||
					tkNum(tkGet(at, "exp")) != tkNum(m["expires_at"]) || tkGet(at, "scope") != strings.Join(newScopes, " ") {
					t.Fatalf("access token: %v", at)
				}
			}
		})
	}
	jwtCase("should refresh token with same scopes, JWT access token", scopes, true)
	jwtCase("should refresh token with lesser scopes, opaque access token", []string{"openid", "offline_access"}, false)
	jwtCase("should refresh token with lesser scopes, JWT access token", []string{"openid", "offline_access"}, true)
	jwtCase("should refresh token even when removing offline_scope", []string{"openid"}, false)

	t.Run("should not refresh token with more scopes", func(t *testing.T) {
		tokens := f.authorizeForRefreshToken(t, scopes, true)
		tkExpectErr(t, f.refresh(tkStr(tokens, "refresh_token"), "openid email offline_access"), 0, "")
	})
	t.Run("should prevent replay attacks", func(t *testing.T) {
		tokens := f.authorizeForRefreshToken(t, scopes, true)
		form := tkRefreshForm(tkStr(tokens, "refresh_token"), f.clientID, f.secret, "")
		m := tkOK(t, e.token(form, nil))
		if m["access_token"] == nil || m["id_token"] == nil || m["refresh_token"] == nil || m["scope"] != joined {
			t.Fatalf("refresh: %v", m)
		}
		tkExpectErr(t, e.token(form, nil), 0, "")
		tkExpectErr(t, f.refresh(tkStr(m, "refresh_token"), ""), 0, "")
	})
	concurrent := func(fns ...func() *response) []*response {
		out := make([]*response, len(fns))
		var wg sync.WaitGroup
		for i, fn := range fns {
			wg.Add(1)
			go func(i int, fn func() *response) {
				defer wg.Done()
				out[i] = fn()
			}(i, fn)
		}
		wg.Wait()
		return out
	}
	t.Run("rejects concurrent rotation of the same refresh token", func(t *testing.T) {
		tokens := f.authorizeForRefreshToken(t, scopes, true)
		rt := tkStr(tokens, "refresh_token")
		rs := concurrent(func() *response { return f.refresh(rt, "") }, func() *response { return f.refresh(rt, "") })
		var ok, fail []*response
		for _, r := range rs {
			if r.status == 200 {
				ok = append(ok, r)
			} else {
				fail = append(fail, r)
			}
		}
		if len(ok) != 1 || len(fail) != 1 {
			t.Fatalf("results: %d %s / %d %s", rs[0].status, rs[0].body, rs[1].status, rs[1].body)
		}
		if ok[0].json()["refresh_token"] == nil || fail[0].json()["error"] != "invalid_grant" {
			t.Fatalf("results: %s / %s", ok[0].body, fail[0].body)
		}
		tkExpectErr(t, f.refresh(rt, ""), 0, "invalid_grant")
	})
	t.Run("winner's child token is usable for a subsequent rotation", func(t *testing.T) {
		tokens := f.authorizeForRefreshToken(t, scopes, true)
		rt := tkStr(tokens, "refresh_token")
		rs := concurrent(func() *response { return f.refresh(rt, "") }, func() *response { return f.refresh(rt, "") })
		var winner map[string]any
		for _, r := range rs {
			if r.status == 200 {
				winner = r.json()
				break
			}
		}
		if winner == nil || winner["refresh_token"] == nil {
			t.Fatalf("no winner: %s / %s", rs[0].body, rs[1].body)
		}
		next := tkOK(t, f.refresh(tkStr(winner, "refresh_token"), ""))
		if next["refresh_token"] == nil || next["refresh_token"] == winner["refresh_token"] {
			t.Fatalf("next: %v", next)
		}
	})
	revoke := func(token string) *response {
		return e.do("POST", "/oauth2/revoke", url.Values{"token": {token}, "token_type_hint": {"refresh_token"},
			"client_id": {f.clientID}, "client_secret": {f.secret}}, nil)
	}
	t.Run("revoke endpoint marks the refresh row revoked and blocks reuse", func(t *testing.T) {
		tokens := f.authorizeForRefreshToken(t, scopes, true)
		rt := tkStr(tokens, "refresh_token")
		if r := revoke(rt); r.status != 200 {
			t.Fatalf("revoke: %d %s", r.status, r.body)
		}
		rows := e.findMany("oauthRefreshToken", eq("clientId", f.clientID))
		if len(rows) < 1 {
			t.Fatal("no refresh rows")
		}
		anyRevoked := false
		for _, r := range rows {
			if r["revoked"] != nil {
				anyRevoked = true
			}
		}
		if !anyRevoked {
			t.Fatalf("no revoked row: %v", rows)
		}
		tkExpectErr(t, f.refresh(rt, ""), 0, "invalid_grant")
	})
	t.Run("concurrent revoke + rotate against the same refresh token: exactly one wins", func(t *testing.T) {
		tokens := f.authorizeForRefreshToken(t, scopes, true)
		rt := tkStr(tokens, "refresh_token")
		rs := concurrent(func() *response { return f.refresh(rt, "") }, func() *response { return revoke(rt) })
		// Upstream's single-threaded event loop lets the revoke (which starts first) win the
		// race, so it asserts a successful revoke. With real concurrency either request can win
		// the atomic revoked-is-null update; exactly one must win. When the rotation wins,
		// upstream's revoke answers 400 "refresh token revoked" (APIError name is "APIError").
		refreshWon := rs[0].status == 200
		revokeWon := rs[1].status == 200
		if refreshWon == revokeWon {
			t.Fatalf("expected exactly one winner: refresh %d %s / revoke %d %s", rs[0].status, rs[0].body, rs[1].status, rs[1].body)
		}
		if refreshWon {
			if rs[0].json()["refresh_token"] == nil {
				t.Fatalf("refresh: %s", rs[0].body)
			}
			tkExpectErr(t, rs[1], 400, "invalid_request")
		} else if rs[0].json()["error"] != "invalid_grant" {
			t.Fatalf("refresh: %s", rs[0].body)
		}
		tkExpectErr(t, f.refresh(rt, ""), 0, "invalid_grant")
	})
}

func TestTk_OauthTokenRefreshTokenReuseInterval(t *testing.T) {
	validAudience := "https://reuse-api.example.com"
	otherAudience := "https://other-reuse-api.example.com"
	var calls int
	var callsMu sync.Mutex
	opts := tkResourceOpts(validAudience, otherAudience)
	opts.RefreshTokenReuseInterval = 30
	opts.CustomTokenResponseFields = func(in TokenResponseFieldsInput) (*jsonx.Object, error) {
		if in.GrantType != "refresh_token" {
			return jsonx.NewObject(), nil
		}
		callsMu.Lock()
		defer callsMu.Unlock()
		calls++
		return jsonx.O("refresh_call", strconv.Itoa(calls)), nil
	}
	e := tkNewEnv(t, opts)
	redirectURI := tkRPBase + "/api/auth/oauth2/callback/test"
	f := &tkRefreshFixture{e: e, redirectURI: redirectURI}
	newClient := func(t *testing.T) {
		oc := e.admin(tkStdClientBody(redirectURI))
		f.clientID, f.secret = tkStr(oc, "client_id"), tkStr(oc, "client_secret")
		if f.clientID == "" || f.secret == "" {
			t.Fatalf("client: %v", oc)
		}
	}
	resetCalls := func() { callsMu.Lock(); calls = 0; callsMu.Unlock() }
	getCalls := func() int { callsMu.Lock(); defer callsMu.Unlock(); return calls }
	scopes := []string{"openid", "profile", "offline_access"}
	matchReplay := func(t *testing.T, replay, first map[string]any, refreshCall string) {
		t.Helper()
		for _, k := range []string{"access_token", "expires_at", "token_type", "refresh_token", "scope", "id_token"} {
			if replay[k] != first[k] {
				t.Fatalf("replay %s: %v != %v", k, replay[k], first[k])
			}
		}
		if refreshCall != "" && replay["refresh_call"] != refreshCall {
			t.Fatalf("refresh_call: %v", replay["refresh_call"])
		}
	}

	t.Run("replays the same response inside the refresh token reuse interval", func(t *testing.T) {
		newClient(t)
		resetCalls()
		tokens := f.authorizeForRefreshToken(t, scopes, false)
		first := tkOK(t, f.refresh(tkStr(tokens, "refresh_token"), ""))
		if first["refresh_token"] == nil || first["refresh_call"] != "1" {
			t.Fatalf("first: %v", first)
		}
		replay := tkOK(t, f.refresh(tkStr(tokens, "refresh_token"), ""))
		matchReplay(t, replay, first, "1")
		if tkNum(replay["expires_in"]) > tkNum(first["expires_in"]) {
			t.Fatalf("expires_in: %v > %v", replay["expires_in"], first["expires_in"])
		}
		if getCalls() != 1 {
			t.Fatalf("calls: %d", getCalls())
		}
		next := tkOK(t, f.refresh(tkStr(first, "refresh_token"), ""))
		if next["refresh_token"] == nil || next["refresh_token"] == first["refresh_token"] {
			t.Fatalf("next: %v", next)
		}
	})
	t.Run("replays equivalent requests when scope and resource order differ", func(t *testing.T) {
		newClient(t)
		resetCalls()
		tokens := f.authorizeForRefreshToken(t, scopes, false)
		first := tkOK(t, f.refresh(tkStr(tokens, "refresh_token"), "profile openid offline_access", validAudience, otherAudience))
		if first["refresh_token"] == nil || first["refresh_call"] != "1" {
			t.Fatalf("first: %v", first)
		}
		replay := tkOK(t, f.refresh(tkStr(tokens, "refresh_token"), "offline_access profile openid", otherAudience, validAudience))
		matchReplay(t, replay, first, "1")
		if getCalls() != 1 {
			t.Fatalf("calls: %d", getCalls())
		}
	})
	t.Run("returns the rotated token response when storing the replay cache fails", func(t *testing.T) {
		newClient(t)
		resetCalls()
		tokens := f.authorizeForRefreshToken(t, scopes, false)
		e.hooks.mu.Lock()
		e.hooks.updateHook = func(model string, update adapter.Record) error {
			if model == "oauthRefreshToken" {
				if _, ok := update["rotationReplayResponse"]; ok {
					return errors.New("replay cache unavailable")
				}
			}
			return nil
		}
		e.hooks.mu.Unlock()
		defer func() { e.hooks.mu.Lock(); e.hooks.updateHook = nil; e.hooks.mu.Unlock() }()
		first := tkOK(t, f.refresh(tkStr(tokens, "refresh_token"), ""))
		if first["refresh_token"] == nil || first["refresh_call"] != "1" {
			t.Fatalf("first: %v", first)
		}
		if !e.logs.has("failed to store refresh token rotation replay") {
			t.Fatalf("expected log, got %v", e.logs.errors)
		}
		next := tkOK(t, f.refresh(tkStr(first, "refresh_token"), ""))
		if next["refresh_token"] == nil || next["refresh_call"] != "2" {
			t.Fatalf("next: %v", next)
		}
	})
	t.Run("does not replay a cached response for a different resource", func(t *testing.T) {
		newClient(t)
		tokens := f.authorizeForRefreshToken(t, scopes, false)
		first := tkOK(t, f.refresh(tkStr(tokens, "refresh_token"), "", validAudience))
		if first["refresh_token"] == nil {
			t.Fatalf("first: %v", first)
		}
		tkExpectErr(t, f.refresh(tkStr(tokens, "refresh_token"), "", otherAudience), 0, "invalid_grant")
		next := tkOK(t, f.refresh(tkStr(first, "refresh_token"), ""))
		if next["refresh_token"] == nil {
			t.Fatalf("next: %v", next)
		}
	})
	t.Run("invalidates the family after the reuse interval expires", func(t *testing.T) {
		newClient(t)
		tokens := f.authorizeForRefreshToken(t, scopes, false)
		first := tkOK(t, f.refresh(tkStr(tokens, "refresh_token"), ""))
		if first["refresh_token"] == nil {
			t.Fatalf("first: %v", first)
		}
		var rotatedID any
		for _, r := range e.findMany("oauthRefreshToken", eq("clientId", f.clientID)) {
			if s, _ := r["rotationReplayResponse"].(string); s != "" {
				rotatedID = r["id"]
			}
		}
		if rotatedID == nil {
			t.Fatal("no rotated row")
		}
		e.update("oauthRefreshToken", adapter.Record{"rotationReplayExpiresAt": time.Unix(0, 0)}, eq("id", rotatedID))
		tkExpectErr(t, f.refresh(tkStr(tokens, "refresh_token"), ""), 0, "invalid_grant")
		tkExpectErr(t, f.refresh(tkStr(first, "refresh_token"), ""), 0, "invalid_grant")
	})
}
