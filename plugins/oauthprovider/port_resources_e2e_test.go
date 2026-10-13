package oauthprovider

import (
	"context"
	"math"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
)

// Port of resources-e2e.test.ts.

// rsBootProvider mirrors bootProvider (enforcePerClientResources defaults to false).
func rsBootProvider(t *testing.T, opts Options, eo ...envOptions) (*testEnv, *resolved) {
	t.Helper()
	if opts.EnforcePerClientResources == nil {
		opts.EnforcePerClientResources = rsBool(false)
	}
	var e envOptions
	if len(eo) > 0 {
		e = eo[0]
	}
	env := newEnv(t, opts, e)
	ResetSeedStateForTests(env.plugin)
	ac := env.auth.Context()
	o, err := pluginOptions(ac)
	if err != nil {
		t.Fatal(err)
	}
	if err := seedResourcesOnce(context.Background(), ac, o); err != nil {
		t.Fatal(err)
	}
	return env, o
}

func rsFakeCtx(env *testEnv) *betterauth.EndpointContext {
	return &betterauth.EndpointContext{Auth: env.auth.Context(), Body: map[string]any{}}
}

type rsHarness struct {
	env         *testEnv
	h           http.Header
	clientID    string
	secret      string
	redirectURI string
}

type rsFlowResult struct {
	redirected string
	code       string
	tokens     *response
}

func rsBootCodeFlowHarness(t *testing.T, opts Options, logger *rsLogger) *rsHarness {
	t.Helper()
	eo := envOptions{jwt: &jwt.Options{JWT: &jwt.JWTOptions{Issuer: testBaseURL}}}
	if logger != nil {
		eo.mutate = func(c *betterauth.Config) { c.Logger = logger }
	}
	env, _ := rsBootProvider(t, opts, eo)
	h := env.signInWithTestUser()
	redirectURI := "https://rp.example.com/api/auth/oauth2/callback/test"
	c := env.adminCreateClient(h, map[string]any{
		"redirect_uris":              []any{redirectURI},
		"token_endpoint_auth_method": "client_secret_post",
		"scope":                      "openid profile email offline_access",
		"skip_consent":               true,
	})
	id, _ := c["client_id"].(string)
	secret, _ := c["client_secret"].(string)
	if id == "" || secret == "" {
		t.Fatalf("admin client creation failed: %v", c)
	}
	return &rsHarness{env: env, h: h, clientID: id, secret: secret, redirectURI: redirectURI}
}

func (hs *rsHarness) exchangeCode(code, verifier string, resources []string) *response {
	f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {hs.redirectURI},
		"client_id": {hs.clientID}, "client_secret": {hs.secret}}
	if verifier != "" {
		f.Set("code_verifier", verifier)
	}
	for _, r := range resources {
		f.Add("resource", r)
	}
	return hs.env.token(f, hs.h)
}

func (hs *rsHarness) runCodeFlow(authorizeResource, tokenResource []string, scopes ...string) rsFlowResult {
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email", "offline_access"}
	}
	verifier, challenge := pkcePair()
	kv := []string{"response_type", "code", "client_id", hs.clientID, "state", "state-123", "scope", strings.Join(scopes, " "),
		"redirect_uri", hs.redirectURI, "code_challenge", challenge, "code_challenge_method", "S256"}
	for _, r := range authorizeResource {
		kv = append(kv, "resource", r)
	}
	res := hs.env.do("GET", authorizeURL(kv...), nil, hs.h)
	loc := res.location()
	u, _ := url.Parse(loc)
	code := ""
	if u != nil {
		code = u.Query().Get("code")
	}
	if code == "" {
		return rsFlowResult{redirected: loc}
	}
	return rsFlowResult{redirected: loc, code: code, tokens: hs.exchangeCode(code, verifier, tokenResource)}
}

func (hs *rsHarness) introspect(token string) map[string]any {
	return hs.env.do("POST", "/oauth2/introspect", url.Values{"client_id": {hs.clientID}, "client_secret": {hs.secret},
		"token": {token}, "token_type_hint": {"access_token"}}, http.Header{"Accept": {"application/json"}}).json()
}

func (hs *rsHarness) refreshRows(t *testing.T) []adapter.Record {
	return hs.env.findMany(modelRefreshToken, eq("clientId", hs.clientID))
}

func rsAccessToken(t *testing.T, r *response) string {
	t.Helper()
	if r == nil {
		t.Fatal("no token response")
	}
	at, _ := r.json()["access_token"].(string)
	if at == "" {
		t.Fatalf("no access_token: %d %s", r.status, r.body)
	}
	return at
}

func rsAud(t *testing.T, token string) []string {
	return rsAudValues(decodeJWTPayload(t, token)["aud"])
}

func rsRowWithResources(rows []adapter.Record, ids ...string) adapter.Record {
	for _, r := range rows {
		res := recStrings(r, "resources")
		ok := true
		for _, id := range ids {
			if !rsContains(res, id) {
				ok = false
			}
		}
		if ok {
			return r
		}
	}
	return nil
}

func rsTTLSeconds(r adapter.Record) float64 {
	exp, _ := r["expiresAt"].(time.Time)
	created, _ := r["createdAt"].(time.Time)
	return exp.Sub(created).Seconds()
}

func rsResourceRow(identifier string, ttl any, disabled bool) adapter.Record {
	now := time.Now()
	return adapter.Record{"identifier": identifier, "name": identifier, "accessTokenTtl": ttl, "refreshTokenTtl": nil,
		"signingAlgorithm": nil, "signingKeyId": nil, "allowedScopes": nil, "customClaims": nil, "disabled": disabled,
		"policyVersion": 1, "metadata": nil, "createdAt": now, "updatedAt": now}
}

func TestRs_IntrospectionResourceTokens(t *testing.T) {
	t.Run("introspects a JWT whose `aud` is an oauthResource identifier as active", func(t *testing.T) {
		res := "https://api.example.com/bug-1"
		hs := rsBootCodeFlowHarness(t, Options{Resources: []ResourceInput{{Identifier: res}}}, nil)
		r := hs.runCodeFlow([]string{res}, []string{res})
		at := rsAccessToken(t, r.tokens)
		in := hs.introspect(at)
		if in["active"] != true || in["client_id"] != hs.clientID {
			t.Fatal(in)
		}
		if !rsContains(rsAud(t, at), res) {
			t.Fatal(rsAud(t, at))
		}
	})
	t.Run("hard-rejects a JWT whose resource row was deleted (introspection inactive)", func(t *testing.T) {
		res := "https://api.example.com/bug-1-delete"
		hs := rsBootCodeFlowHarness(t, Options{Resources: []ResourceInput{{Identifier: res}}}, nil)
		at := rsAccessToken(t, hs.runCodeFlow([]string{res}, []string{res}).tokens)
		if in := hs.introspect(at); in["active"] != true {
			t.Fatal(in)
		}
		if err := hs.env.db.Delete(context.Background(), modelResource, []adapter.Where{eq("identifier", res)}); err != nil {
			t.Fatal(err)
		}
		if in := hs.introspect(at); in["active"] != false {
			t.Fatal(in)
		}
	})
	t.Run("continues to verify a JWT whose resource row was disabled (block new issuance only)", func(t *testing.T) {
		res := "https://api.example.com/bug-1-disabled"
		hs := rsBootCodeFlowHarness(t, Options{Resources: []ResourceInput{{Identifier: res}}}, nil)
		at := rsAccessToken(t, hs.runCodeFlow([]string{res}, []string{res}).tokens)
		hs.env.update(modelResource, adapter.Record{"disabled": true}, eq("identifier", res))
		if in := hs.introspect(at); in["active"] != true {
			t.Fatal(in)
		}
	})
	t.Run("blocks NEW issuance against a disabled resource (resolveResourcePolicy rejects)", func(t *testing.T) {
		res := "https://api.example.com/bug-1-disabled-mint"
		hs := rsBootCodeFlowHarness(t, Options{Resources: []ResourceInput{{Identifier: res}}}, nil)
		hs.env.update(modelResource, adapter.Record{"disabled": true}, eq("identifier", res))
		r := hs.runCodeFlow([]string{res}, []string{res})
		if r.code != "" || !strings.Contains(r.redirected, "invalid_target") {
			t.Fatal(r.code, r.redirected)
		}
	})
}

func TestRs_CodeGrantBindsAuthorizeResource(t *testing.T) {
	t.Run("reissues against the authorize-time resource when /token omits it", func(t *testing.T) {
		res := "https://api.example.com/bug-2-omit"
		hs := rsBootCodeFlowHarness(t, Options{Resources: []ResourceInput{{Identifier: res}}}, nil)
		at := rsAccessToken(t, hs.runCodeFlow([]string{res}, nil).tokens)
		if !rsContains(rsAud(t, at), res) {
			t.Fatal(rsAud(t, at))
		}
	})
	t.Run("rejects with invalid_target when /token widens the resource set", func(t *testing.T) {
		a, b := "https://api.example.com/bug-2-widen-a", "https://api.example.com/bug-2-widen-b"
		hs := rsBootCodeFlowHarness(t, Options{Resources: []ResourceInput{{Identifier: a}, {Identifier: b}}}, nil)
		r := hs.runCodeFlow([]string{a}, []string{b})
		if r.tokens == nil || r.tokens.json()["error"] != "invalid_target" {
			t.Fatal(r.tokens)
		}
	})
	t.Run("accepts /token resource when it equals the authorize-time resource", func(t *testing.T) {
		res := "https://api.example.com/bug-2-match"
		hs := rsBootCodeFlowHarness(t, Options{Resources: []ResourceInput{{Identifier: res}}}, nil)
		at := rsAccessToken(t, hs.runCodeFlow([]string{res}, []string{res}).tokens)
		if !rsContains(rsAud(t, at), res) {
			t.Fatal(rsAud(t, at))
		}
	})
}

func TestRs_RefreshPreservesResource(t *testing.T) {
	t.Run("persists `resource` on the oauthRefreshToken row at issuance", func(t *testing.T) {
		res := "https://api.example.com/bug-3-persist"
		hs := rsBootCodeFlowHarness(t, Options{Resources: []ResourceInput{{Identifier: res}}}, nil)
		r := hs.runCodeFlow([]string{res}, []string{res})
		if r.tokens.json()["refresh_token"] == nil {
			t.Fatal(string(r.tokens.body))
		}
		rows := hs.refreshRows(t)
		if len(rows) == 0 || rsRowWithResources(rows, res) == nil {
			t.Fatal(rows)
		}
	})
	t.Run("re-applies the original resource on refresh when /token omits resource", func(t *testing.T) {
		res := "https://api.example.com/bug-3-rebind"
		hs := rsBootCodeFlowHarness(t, Options{Resources: []ResourceInput{{Identifier: res}}}, nil)
		initial := hs.runCodeFlow([]string{res}, []string{res})
		rt, _ := initial.tokens.json()["refresh_token"].(string)
		refreshed := hs.env.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt},
			"client_id": {hs.clientID}, "client_secret": {hs.secret}}, hs.h)
		at := rsAccessToken(t, refreshed)
		if !rsContains(rsAud(t, at), res) {
			t.Fatal(rsAud(t, at))
		}
	})
	t.Run("rejects refresh that widens the resource beyond the persisted set", func(t *testing.T) {
		a, b := "https://api.example.com/bug-3-widen-a", "https://api.example.com/bug-3-widen-b"
		hs := rsBootCodeFlowHarness(t, Options{Resources: []ResourceInput{{Identifier: a}, {Identifier: b}}}, nil)
		initial := hs.runCodeFlow([]string{a}, []string{a})
		rt, _ := initial.tokens.json()["refresh_token"].(string)
		refreshed := hs.env.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt},
			"client_id": {hs.clientID}, "client_secret": {hs.secret}, "resource": {b}}, hs.h)
		if refreshed.json()["error"] != "invalid_target" {
			t.Fatalf("%d %s", refreshed.status, refreshed.body)
		}
	})
}

func TestRs_DBOnlyResources(t *testing.T) {
	t.Run("looks up a DB row even when resources config is absent", func(t *testing.T) {
		env, o := rsBootProvider(t, Options{})
		id := "https://api.example.com/bug-4-db-only"
		if _, err := env.db.Create(context.Background(), adapter.CreateInput{Model: modelResource, Data: rsResourceRow(id, 120, false)}); err != nil {
			t.Fatal(err)
		}
		p, err := resolveResourcePolicy(rsFakeCtx(env), o, id, "client-x", []string{"read"})
		if err != nil {
			t.Fatal(err)
		}
		if len(p.audience) != 1 || p.audience[0] != id || p.accessTokenTTL == nil || *p.accessTokenTTL != 120 {
			t.Fatal(p.audience, p.accessTokenTTL)
		}
	})
	t.Run("rejects an unknown identifier with invalid_target when no config and no DB row", func(t *testing.T) {
		env, o := rsBootProvider(t, Options{})
		_, err := resolveResourcePolicy(rsFakeCtx(env), o, "https://api.example.com/bug-4-nope", "client-x", []string{})
		e, _ := betterauth.AsAPIError(err)
		rsExpectBodyError(t, e, "invalid_target")
	})
	t.Run("rejects a disabled DB row with invalid_target even without legacy config", func(t *testing.T) {
		env, o := rsBootProvider(t, Options{})
		id := "https://api.example.com/bug-4-disabled"
		if _, err := env.db.Create(context.Background(), adapter.CreateInput{Model: modelResource, Data: rsResourceRow(id, nil, true)}); err != nil {
			t.Fatal(err)
		}
		_, err := resolveResourcePolicy(rsFakeCtx(env), o, id, "client-x", []string{})
		e, _ := betterauth.AsAPIError(err)
		rsExpectBodyError(t, e, "invalid_target")
	})
}

func TestRs_RefreshTokenTTLFromResource(t *testing.T) {
	t.Run("uses the resource refreshTokenTtl when shorter than plugin default", func(t *testing.T) {
		id := "https://api.example.com/bug-7-short"
		hs := rsBootCodeFlowHarness(t, Options{Resources: []ResourceInput{{Identifier: id, RefreshTokenTTL: rsIntPtr(60)}},
			RefreshTokenExpiresIn: 86400}, nil)
		r := hs.runCodeFlow([]string{id}, []string{id})
		if r.tokens.json()["refresh_token"] == nil {
			t.Fatal(string(r.tokens.body))
		}
		row := rsRowWithResources(hs.refreshRows(t), id)
		if row == nil {
			t.Fatal("no row")
		}
		if ttl := rsTTLSeconds(row); math.Abs(ttl-60) >= 5 {
			t.Fatal(ttl)
		}
	})
	t.Run("policy.refreshTokenTtl reflects resource override (unit-level)", func(t *testing.T) {
		id := "https://api.example.com/bug-7-policy"
		env, o := rsBootProvider(t, Options{Resources: []ResourceInput{{Identifier: id, RefreshTokenTTL: rsIntPtr(300)}}})
		p, err := resolveResourcePolicy(rsFakeCtx(env), o, id, "client-x", []string{})
		if err != nil || p.refreshTokenTTL == nil || *p.refreshTokenTTL != 300 {
			t.Fatal(p, err)
		}
	})
	t.Run("policy.refreshTokenTtl picks the minimum across multi-resource requests", func(t *testing.T) {
		a, b := "https://api.example.com/bug-7-multi-a", "https://api.example.com/bug-7-multi-b"
		env, o := rsBootProvider(t, Options{Resources: []ResourceInput{{Identifier: a, RefreshTokenTTL: rsIntPtr(600)},
			{Identifier: b, RefreshTokenTTL: rsIntPtr(120)}}})
		p, err := resolveResourcePolicy(rsFakeCtx(env), o, []string{a, b}, "client-x", []string{})
		if err != nil || p.refreshTokenTTL == nil || *p.refreshTokenTTL != 120 {
			t.Fatal(p, err)
		}
	})
	t.Run("caps resource refreshTokenTtl against the plugin default (lowest wins)", func(t *testing.T) {
		id := "https://api.example.com/bug-7-cap"
		hs := rsBootCodeFlowHarness(t, Options{Resources: []ResourceInput{{Identifier: id, RefreshTokenTTL: rsIntPtr(3600)}},
			RefreshTokenExpiresIn: 60}, nil)
		r := hs.runCodeFlow([]string{id}, []string{id})
		if r.tokens.json()["refresh_token"] == nil {
			t.Fatal(string(r.tokens.body))
		}
		row := rsRowWithResources(hs.refreshRows(t), id)
		if row == nil {
			t.Fatal("no row")
		}
		ttl := rsTTLSeconds(row)
		if math.Abs(ttl-60) >= 5 || ttl >= 3600 {
			t.Fatal(ttl)
		}
	})
}

func TestRs_RepeatedResourceParameter(t *testing.T) {
	t.Run("JWT audience carries every requested resource (auth code grant)", func(t *testing.T) {
		a, b := "https://api.example.com/bug-10-a", "https://api.example.com/bug-10-b"
		hs := rsBootCodeFlowHarness(t, Options{Resources: []ResourceInput{{Identifier: a}, {Identifier: b}}}, nil)
		at := rsAccessToken(t, hs.runCodeFlow([]string{a, b}, []string{a, b}).tokens)
		aud := rsAud(t, at)
		if !rsContains(aud, a) || !rsContains(aud, b) {
			t.Fatal(aud)
		}
	})
	t.Run("refresh-token row persists every requested resource", func(t *testing.T) {
		a, b := "https://api.example.com/bug-10-refresh-a", "https://api.example.com/bug-10-refresh-b"
		hs := rsBootCodeFlowHarness(t, Options{Resources: []ResourceInput{{Identifier: a}, {Identifier: b}}}, nil)
		r := hs.runCodeFlow([]string{a, b}, []string{a, b})
		if r.tokens.json()["refresh_token"] == nil {
			t.Fatal(string(r.tokens.body))
		}
		if rsRowWithResources(hs.refreshRows(t), a, b) == nil {
			t.Fatal("no row with both resources")
		}
	})
	t.Run("single-value `resource` form continues to work unchanged", func(t *testing.T) {
		res := "https://api.example.com/bug-10-single"
		hs := rsBootCodeFlowHarness(t, Options{Resources: []ResourceInput{{Identifier: res}}}, nil)
		at := rsAccessToken(t, hs.runCodeFlow([]string{res}, []string{res}).tokens)
		if !rsContains(rsAud(t, at), res) {
			t.Fatal(rsAud(t, at))
		}
	})
}

func TestRs_ResourcePolicyDownscopes(t *testing.T) {
	t.Run("reports the effective scope after allowedScopes narrows the grant", func(t *testing.T) {
		id := "https://api.example.com/downscope-response"
		hs := rsBootCodeFlowHarness(t, Options{Resources: []ResourceInput{{Identifier: id, AllowedScopes: []string{"email"}}}}, nil)
		r := hs.runCodeFlow([]string{id}, []string{id}, "profile", "email")
		at := rsAccessToken(t, r.tokens)
		if r.tokens.json()["scope"] != "email" {
			t.Fatal(string(r.tokens.body))
		}
		if s := decodeJWTPayload(t, at)["scope"]; s != "email" {
			t.Fatal(s)
		}
	})
}

func TestRs_JWTClientIDClaim(t *testing.T) {
	t.Run("emits both `client_id` and `azp` on a JWT access token", func(t *testing.T) {
		id := "https://api.example.com/bug-8"
		hs := rsBootCodeFlowHarness(t, Options{Resources: []ResourceInput{{Identifier: id}}}, nil)
		at := rsAccessToken(t, hs.runCodeFlow([]string{id}, []string{id}).tokens)
		p := decodeJWTPayload(t, at)
		if decodeJWTHeader(t, at)["typ"] != "at+jwt" || p["client_id"] != hs.clientID || p["azp"] != hs.clientID {
			t.Fatal(decodeJWTHeader(t, at), p)
		}
	})
	t.Run("uses the client identifier as sub for client_credentials JWT access tokens", func(t *testing.T) {
		res := "https://api.example.com/m2m-sub"
		env, _ := rsBootProvider(t, Options{Scopes: []string{"read"}, Resources: []ResourceInput{{Identifier: res}},
			ClientPrivileges: func(PrivilegeContext) (bool, error) { return true, nil }},
			envOptions{jwt: &jwt.Options{JWT: &jwt.JWTOptions{Issuer: testBaseURL}}})
		h := env.signInWithTestUser()
		c := env.adminCreateClient(h, map[string]any{"scope": "read", "grant_types": []any{"client_credentials"},
			"token_endpoint_auth_method": "client_secret_basic", "client_credentials_scopes": []any{"read"},
			"redirect_uris": []any{"https://client.example.com/callback"}})
		cid, _ := c["client_id"].(string)
		sec, _ := c["client_secret"].(string)
		tr := env.token(url.Values{"grant_type": {"client_credentials"}, "scope": {"read"}, "resource": {res}}, basicAuth(cid, sec))
		at := rsAccessToken(t, tr)
		p := decodeJWTPayload(t, at)
		if decodeJWTHeader(t, at)["typ"] != "at+jwt" || p["sub"] != cid || p["client_id"] != cid {
			t.Fatal(p)
		}
	})
	t.Run("strips `client_id` from per-resource customClaims (AS owns it)", func(t *testing.T) {
		id := "https://api.example.com/bug-8-strip"
		hs := rsBootCodeFlowHarness(t, Options{Resources: []ResourceInput{{Identifier: id,
			CustomClaims: jsonx.O("client_id", "attacker-owned-value", "department", "ok-claim")}}}, &rsLogger{})
		at := rsAccessToken(t, hs.runCodeFlow([]string{id}, []string{id}).tokens)
		p := decodeJWTPayload(t, at)
		if p["client_id"] != hs.clientID || p["department"] != "ok-claim" {
			t.Fatal(p)
		}
	})
}

func TestRs_SeedIdentifierValidation(t *testing.T) {
	bootLogged := func(t *testing.T, opts Options) (*testEnv, *rsLogger) {
		logger := &rsLogger{}
		env, _ := rsBootProvider(t, opts, envOptions{mutate: func(c *betterauth.Config) { c.Logger = logger }})
		return env, logger
	}
	t.Run("skips invalid identifiers without throwing during seed", func(t *testing.T) {
		good := "https://api.example.com/bug-9-good"
		env, _ := bootLogged(t, Options{Resources: []ResourceInput{{Identifier: good}, {Identifier: "not a uri"}}})
		if r := rsReadResource(env, good); r == nil || r["identifier"] != good {
			t.Fatal(r)
		}
		if r := rsReadResource(env, "not a uri"); r != nil {
			t.Fatal(r)
		}
	})
	t.Run("skips identifiers with URI fragments (RFC 8707 §2)", func(t *testing.T) {
		good := "https://api.example.com/bug-9-frag-good"
		frag := "https://api.example.com/bug-9#fragment"
		env, _ := bootLogged(t, Options{Resources: []ResourceInput{{Identifier: good}, {Identifier: frag}}})
		if r := rsReadResource(env, good); r == nil {
			t.Fatal("missing good row")
		}
		if r := rsReadResource(env, frag); r != nil {
			t.Fatal(r)
		}
	})
	t.Run("honors a custom identifierValidator that rejects entries", func(t *testing.T) {
		good, blocked := "https://allowed.example.com/bug-9", "https://blocked.example.com/bug-9"
		env, _ := bootLogged(t, Options{IdentifierValidator: func(id string) (bool, error) {
			return !strings.Contains(id, "blocked.example.com"), nil
		}, Resources: []ResourceInput{{Identifier: good}, {Identifier: blocked}}})
		if r := rsReadResource(env, good); r == nil {
			t.Fatal("missing good row")
		}
		if r := rsReadResource(env, blocked); r != nil {
			t.Fatal(r)
		}
	})
	t.Run("strips unsupported signingAlgorithm values from seed config and warns", func(t *testing.T) {
		id := "https://api.example.com/bug-5-seed-alg"
		env, logger := bootLogged(t, Options{Resources: []ResourceInput{{Identifier: id, SigningAlgorithm: rsStrPtr("HS256")}}})
		r := rsReadResource(env, id)
		if r == nil || r["identifier"] != id || r["signingAlgorithm"] != nil {
			t.Fatal(r)
		}
		found := false
		for _, m := range logger.get("warn") {
			if strings.Contains(m, `dropping unsupported signingAlgorithm "HS256"`) && strings.Contains(m, id) {
				found = true
			}
		}
		if !found {
			t.Fatal(logger.get("warn"))
		}
	})
}
