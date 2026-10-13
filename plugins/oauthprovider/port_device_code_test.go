package oauthprovider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/internal/testdb"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/deviceauthorization"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
	"github.com/nimi-io/better-auth-go/plugins/openapi"
)

// Port of packages/oauth-provider/src/device-code.test.ts.

const dxDeviceGrant = DeviceCodeGrantType

func dxJwtIssuer(issuer string) *jwt.Options {
	return &jwt.Options{JWT: &jwt.JWTOptions{Issuer: issuer}}
}

// dxBind points env helpers at the current (sub)test so failures are reported there.
func dxBind(env *testEnv, t *testing.T) func() {
	prev := env.t
	env.t = t
	return func() { env.t = prev }
}

func dxFormHeaders(h http.Header) http.Header {
	out := http.Header{}
	for k, vs := range h {
		out[k] = append([]string(nil), vs...)
	}
	out.Set("Content-Type", "application/x-www-form-urlencoded")
	return out
}

// dxForm builds url-encoded form data preserving the given pair order.
func dxForm(kv ...string) string {
	var parts []string
	for i := 0; i+1 < len(kv); i += 2 {
		parts = append(parts, url.QueryEscape(kv[i])+"="+url.QueryEscape(kv[i+1]))
	}
	return strings.Join(parts, "&")
}

func dxErr(r *response) string {
	s, _ := r.json()["error"].(string)
	return s
}

func dxExpectStatusErr(t *testing.T, r *response, status int, code string) {
	t.Helper()
	if r.status != status || dxErr(r) != code {
		t.Fatalf("expected %d %s, got %d %s", status, code, r.status, r.body)
	}
}

func dxExpectOK(t *testing.T, r *response) map[string]any {
	t.Helper()
	if r.status != 200 {
		t.Fatalf("expected 200, got %d %s", r.status, r.body)
	}
	return r.json()
}

func dxStr(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func dxCreateClient(env *testEnv, body map[string]any) map[string]any {
	env.t.Helper()
	return env.adminCreateClient(env.signInWithTestUser(), body)
}

func dxCreateDeviceClient(env *testEnv, grantTypes ...string) string {
	env.t.Helper()
	if len(grantTypes) == 0 {
		grantTypes = []string{dxDeviceGrant}
	}
	gt := make([]any, len(grantTypes))
	for i, g := range grantTypes {
		gt[i] = g
	}
	c := dxCreateClient(env, map[string]any{
		"token_endpoint_auth_method": "none",
		"grant_types":                gt,
		"scope":                      "openid profile email",
		"application_type":           "native",
	})
	return dxStr(c, "client_id")
}

func dxConfidential(env *testEnv, method, redirect string, grantTypes ...string) (string, string) {
	env.t.Helper()
	if len(grantTypes) == 0 {
		grantTypes = []string{dxDeviceGrant}
	}
	gt := make([]any, len(grantTypes))
	for i, g := range grantTypes {
		gt[i] = g
	}
	body := map[string]any{
		"token_endpoint_auth_method": method,
		"grant_types":                gt,
		"scope":                      "openid",
		"application_type":           "web",
	}
	if redirect != "" {
		body["redirect_uris"] = []any{redirect}
	}
	c := dxCreateClient(env, body)
	id, secret := dxStr(c, "client_id"), dxStr(c, "client_secret")
	if id == "" || secret == "" {
		env.t.Fatalf("confidential OAuth client was not created: %v", c)
	}
	return id, secret
}

func dxVerify(env *testEnv, userCode string, headers http.Header) map[string]any {
	env.t.Helper()
	return env.mustCall("deviceVerify", betterauth.CallInput{Query: map[string]any{"user_code": userCode}, Headers: headers})
}

func dxApprove(env *testEnv, userCode string, headers http.Header) {
	env.t.Helper()
	env.mustCall("deviceApprove", betterauth.CallInput{Body: map[string]any{"userCode": userCode}, Headers: headers})
}

func dxDeviceCode(env *testEnv, body map[string]any) (string, string) {
	env.t.Helper()
	m := env.mustCall("deviceCode", betterauth.CallInput{Body: body})
	return dxStr(m, "device_code"), dxStr(m, "user_code")
}

func dxApprovedDeviceCode(env *testEnv, clientID, scope string, resource any) string {
	env.t.Helper()
	if scope == "" {
		scope = "openid profile email"
	}
	headers := env.signInWithTestUser()
	body := map[string]any{"client_id": clientID, "scope": scope}
	if resource != nil {
		body["resource"] = resource
	}
	dc, uc := dxDeviceCode(env, body)
	v := dxVerify(env, uc, headers)
	if resource != nil {
		got, _ := json.Marshal(v["resource"])
		want, _ := json.Marshal(resource)
		if string(got) != string(want) {
			env.t.Fatalf("verification resource %s, want %s", got, want)
		}
	}
	dxApprove(env, uc, headers)
	return dc
}

func dxPoll(env *testEnv, kv ...string) *response {
	return env.do("POST", "/oauth2/token", dxForm(kv...), nil)
}

func dxDeviceCodeHTTP(env *testEnv, body any, headers http.Header) *response {
	return env.do("POST", "/device/code", body, headers)
}

func TestDx_DeviceCodeComposition(t *testing.T) {
	t.Run("registers Device Authorization and its OAuth grant from one plugin", func(t *testing.T) {
		env := newEnv(t, Options{}, envOptions{plugins: []*betterauth.Plugin{OAuthDeviceAuthorization(deviceauthorization.Options{})}})
		md := env.mustCall("getOAuthServerConfig", betterauth.CallInput{})
		if md["device_authorization_endpoint"] != testBaseURL+"/api/auth/device/code" {
			t.Fatalf("device_authorization_endpoint: %v", md["device_authorization_endpoint"])
		}
		if !dxContainsAny(md["grant_types_supported"], dxDeviceGrant) {
			t.Fatalf("grant_types_supported: %v", md["grant_types_supported"])
		}
	})
	t.Run("explains when OAuth Provider is missing", func(t *testing.T) {
		t.Setenv("NODE_ENV", "test")
		_, err := betterauth.New(dxBareConfig(t, OAuthDeviceAuthorization(deviceauthorization.Options{})))
		if err == nil || !strings.Contains(err.Error(), "oauthDeviceAuthorization() requires oauthProvider() or mcp().") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("rejects a second Device Authorization plugin", func(t *testing.T) {
		env := newEnv(t, Options{}, envOptions{
			before:          []*betterauth.Plugin{deviceauthorization.New(deviceauthorization.Options{})},
			plugins:         []*betterauth.Plugin{OAuthDeviceAuthorization(deviceauthorization.Options{})},
			expectInitError: true,
		})
		if env.initErr == nil || !strings.Contains(env.initErr.Error(), "oauthDeviceAuthorization() cannot be combined with another Device Authorization plugin.") {
			t.Fatalf("err = %v", env.initErr)
		}
	})
	t.Run("composes before OAuth Provider in the plugin list", func(t *testing.T) {
		env := newEnv(t, Options{}, envOptions{noJwt: true, before: []*betterauth.Plugin{
			jwt.New(jwt.Options{}), OAuthDeviceAuthorization(deviceauthorization.Options{}),
		}})
		md := env.mustCall("getOAuthServerConfig", betterauth.CallInput{})
		if !dxContainsAny(md["grant_types_supported"], dxDeviceGrant) {
			t.Fatalf("grant_types_supported: %v", md["grant_types_supported"])
		}
	})
	t.Run("exposes OAuth contracts only in composed installations", func(t *testing.T) {
		// The expectTypeOf assertions on the client types are TS-only; the OpenAPI document
		// assertions are ported.
		t.Setenv("NODE_ENV", "test")
		standalone, err := betterauth.New(dxBareConfig(t, deviceauthorization.New(deviceauthorization.Options{}), openapi.New(openapi.Options{})))
		if err != nil {
			t.Fatal(err)
		}
		composed := newEnv(t, Options{}, envOptions{plugins: []*betterauth.Plugin{
			OAuthDeviceAuthorization(deviceauthorization.Options{}), openapi.New(openapi.Options{}),
		}})
		docOf := func(a *betterauth.Auth) map[string]any {
			res, err := a.API.Call(context.Background(), "generateOpenAPISchema", betterauth.CallInput{})
			if err != nil {
				t.Fatal(err)
			}
			return decodeMap(t, res)
		}
		op := func(doc map[string]any) map[string]any {
			return dxPath(doc, "paths", "/device/code", "post")
		}
		props := func(doc map[string]any) map[string]any {
			return dxPath(op(doc), "requestBody", "content", "application/json", "schema", "properties")
		}
		sd, cd := docOf(standalone), docOf(composed.auth)
		for _, f := range []string{"resource", "client_secret", "client_assertion", "client_assertion_type"} {
			if _, ok := props(sd)[f]; ok {
				t.Fatalf("standalone has %s", f)
			}
			if _, ok := props(cd)[f]; !ok {
				t.Fatalf("composed lacks %s: %v", f, props(cd))
			}
		}
		if _, ok := dxPath(op(sd), "responses", "401", "headers")["WWW-Authenticate"]; ok {
			t.Fatal("standalone documents WWW-Authenticate")
		}
		u := dxPath(op(cd), "responses", "401")
		if s := dxPath(u, "headers", "WWW-Authenticate", "schema"); s["type"] != "string" || s["example"] != "Basic" {
			t.Fatalf("401 header schema: %v", u)
		}
		enum, _ := dxPath(u, "content", "application/json", "schema", "properties", "error")["enum"].([]any)
		if len(enum) != 1 || enum[0] != "invalid_client" {
			t.Fatalf("401 error enum: %v", u)
		}
	})
}

func dxBareConfig(t *testing.T, plugins ...*betterauth.Plugin) betterauth.Config {
	return betterauth.Config{
		BaseURL:          testBaseURL,
		Secret:           "better-auth.secret-for-tests-1234567890abcdef",
		Database:         dxMemoryDB(t),
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true},
		Logger:           betterauth.NopLogger{},
		RateLimit:        &betterauth.RateLimitConfig{Enabled: betterauth.Bool(false)},
		TrustedOrigins:   []string{testBaseURL},
		Plugins:          plugins,
	}
}

func dxMemoryDB(t *testing.T) adapter.Factory {
	return sqladapter.New(testdb.SQLite(t), sqladapter.Config{})
}

func dxPath(m map[string]any, keys ...string) map[string]any {
	cur := m
	for _, k := range keys {
		next, _ := cur[k].(map[string]any)
		if next == nil {
			return map[string]any{}
		}
		cur = next
	}
	return cur
}

func dxContainsAny(v any, s string) bool {
	arr, _ := v.([]any)
	for _, x := range arr {
		if x == s {
			return true
		}
	}
	return false
}

func TestDx_DeviceCodeGrant(t *testing.T) {
	resource := "https://api.example.com"
	secondResource := "https://files.example.com"
	var onDeviceAuthCalls atomic.Int32
	env := newEnv(t, Options{
		Resources:                      []ResourceInput{{Identifier: resource}, {Identifier: secondResource}},
		EnforcePerClientResources:      betterauth.Bool(false),
		AllowDynamicClientRegistration: true,
		Scopes:                         []string{"openid", "profile", "email", "offline_access"},
	}, envOptions{
		jwt: dxJwtIssuer(testBaseURL),
		plugins: []*betterauth.Plugin{OAuthDeviceAuthorization(deviceauthorization.Options{
			ExpiresIn: "5min",
			Interval:  "2s",
			OnDeviceAuthRequest: func(context.Context, string, *string) error {
				onDeviceAuthCalls.Add(1)
				return nil
			},
		})},
	})
	userRec := env.findOne("user", eq("email", testUserEmail))
	userID, _ := userRec["id"].(string)

	run := func(name string, f func(t *testing.T)) {
		t.Run(name, func(t *testing.T) {
			defer dxBind(env, t)()
			f(t)
		})
	}

	run("adds OAuth fields only when the device grant is composed", func(t *testing.T) {
		fieldsOf := func(p *betterauth.Plugin) map[string]bool {
			out := map[string]bool{}
			for _, tbl := range p.Schema {
				if tbl.Key == "deviceCode" {
					for _, f := range tbl.Fields {
						out[f.Name] = true
					}
				}
			}
			return out
		}
		standalone := fieldsOf(deviceauthorization.New(deviceauthorization.Options{}))
		plugin := OAuthDeviceAuthorization(deviceauthorization.Options{})
		oauth := fieldsOf(plugin)
		for _, f := range []string{"resource", "resources", "oauthClientId"} {
			if standalone[f] {
				t.Fatalf("standalone has %s", f)
			}
		}
		if !oauth["resources"] || !oauth["oauthClientId"] {
			t.Fatalf("oauth fields: %v", oauth)
		}
		// error schema accepts invalid_target (the documented 400 error enum).
		var ep *betterauth.Endpoint
		for _, e := range plugin.Endpoints {
			if e.Key == "deviceCode" {
				ep = e
			}
		}
		raw, _ := jsonx.Marshal(ep.Metadata["openapi"])
		var oa map[string]any
		_ = json.Unmarshal(raw, &oa)
		enum, _ := dxPath(oa, "responses", "400", "content", "application/json", "schema", "properties", "error")["enum"].([]any)
		found := false
		for _, e := range enum {
			if e == "invalid_target" {
				found = true
			}
		}
		if !found {
			t.Fatalf("400 error enum lacks invalid_target: %v", enum)
		}
	})

	run("accepts a confidential client authenticated with Basic without body client_id", func(t *testing.T) {
		headers := env.signInWithTestUser()
		id, secret := dxConfidential(env, "client_secret_basic", "https://client.example.com/callback")
		r := dxDeviceCodeHTTP(env, url.Values{"scope": {"openid"}}, basicAuth(id, secret))
		m := dxExpectOK(t, r)
		if dxStr(m, "device_code") == "" || dxStr(m, "user_code") == "" {
			t.Fatalf("response: %s", r.body)
		}
		if v := dxVerify(env, dxStr(m, "user_code"), headers); v["client_id"] != id {
			t.Fatalf("verify: %v", v)
		}
	})

	run("accepts a confidential client authenticated with client_secret_post", func(t *testing.T) {
		headers := env.signInWithTestUser()
		id, secret := dxConfidential(env, "client_secret_post", "https://post.example.com/callback")
		r := dxDeviceCodeHTTP(env, url.Values{"client_id": {id}, "client_secret": {secret}, "scope": {"openid"}}, nil)
		m := dxExpectOK(t, r)
		if dxStr(m, "device_code") == "" || dxStr(m, "user_code") == "" {
			t.Fatalf("response: %s", r.body)
		}
		if v := dxVerify(env, dxStr(m, "user_code"), headers); v["client_id"] != id {
			t.Fatalf("verify: %v", v)
		}
	})

	run("accepts client_secret_post through the in-process API contract", func(t *testing.T) {
		id, secret := dxConfidential(env, "client_secret_post", "https://post-api.example.com/callback")
		dc, uc := dxDeviceCode(env, map[string]any{"client_id": id, "client_secret": secret, "scope": "openid"})
		if dc == "" || uc == "" {
			t.Fatal("missing codes")
		}
	})

	run("authenticates an assertion whose client ID is supplied intrinsically", func(t *testing.T) {
		assertionMethod := "https://example.com/device-assertion"
		assertionValue := "valid-device-assertion"
		assertionClientID := "intrinsic-assertion-client"
		aenv := newEnv(t, Options{
			Extensions: []*Extension{{ClientAuthentication: []ClientAuthenticationStrategy{{
				Method:         assertionMethod,
				AssertionTypes: []string{assertionMethod},
				Authenticate: func(in ClientAuthenticationInput) (*ClientAuthenticationResult, error) {
					if in.Assertion != assertionValue {
						return nil, betterauth.NewAPIError("UNAUTHORIZED", jsonx.O("error", "invalid_client", "error_description", "invalid assertion"))
					}
					return &ClientAuthenticationResult{ClientID: assertionClientID}, nil
				},
			}}}},
			GenerateClientID: func() string { return assertionClientID },
			Scopes:           []string{"openid"},
		}, envOptions{jwt: dxJwtIssuer(testBaseURL), plugins: []*betterauth.Plugin{OAuthDeviceAuthorization(deviceauthorization.Options{})}})
		headers := aenv.signInWithTestUser()
		created := aenv.adminCreateClient(headers, map[string]any{
			"token_endpoint_auth_method": assertionMethod,
			"grant_types":                []any{dxDeviceGrant},
			"scope":                      "openid",
			"application_type":           "native",
		})
		if created["client_id"] != assertionClientID {
			t.Fatalf("created: %v", created)
		}
		r := aenv.do("POST", "/device/code", url.Values{
			"client_assertion_type": {assertionMethod}, "client_assertion": {assertionValue}, "scope": {"openid"},
		}, nil)
		m := dxExpectOK(t, r)
		if v := dxVerify(aenv, dxStr(m, "user_code"), headers); v["client_id"] != assertionClientID {
			t.Fatalf("verify: %v", v)
		}
	})

	run("rejects multiple client authentication methods and repeated authentication parameters", func(t *testing.T) {
		id, secret := dxConfidential(env, "client_secret_basic", "https://cardinality.example.com/callback", "client_credentials", dxDeviceGrant)
		basic := basicAuth(id, secret)
		r := env.token(url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}, "scope": {"openid"}}, basic)
		dxExpectStatusErr(t, r, 400, "invalid_request")
		r = dxDeviceCodeHTTP(env, url.Values{"client_id": {id}, "client_secret": {secret}, "scope": {"openid"}}, basic)
		dxExpectStatusErr(t, r, 400, "invalid_request")
		bearer := http.Header{"Authorization": {"Bearer unsupported"}}
		r = env.token(url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}, "scope": {"openid"}}, bearer)
		dxExpectStatusErr(t, r, 400, "invalid_request")
		r = dxDeviceCodeHTTP(env, dxForm("client_id", id, "client_secret", "", "scope", "openid"), basic)
		if m := dxExpectOK(t, r); dxStr(m, "device_code") == "" {
			t.Fatalf("empty basic: %s", r.body)
		}
		pid, psecret := dxConfidential(env, "client_secret_post", "https://cardinality-post.example.com/callback")
		r = dxDeviceCodeHTTP(env, dxForm("client_id", pid, "client_secret", "", "client_secret", psecret, "scope", "openid"), nil)
		if m := dxExpectOK(t, r); dxStr(m, "device_code") == "" {
			t.Fatalf("one effective secret: %s", r.body)
		}
		publicID := dxCreateDeviceClient(env)
		r = dxDeviceCodeHTTP(env, url.Values{"client_id": {publicID}, "scope": {"openid"}}, bearer)
		dxExpectStatusErr(t, r, 401, "invalid_client")
		if got := r.header.Get("WWW-Authenticate"); got != "Bearer" {
			t.Fatalf("challenge = %q", got)
		}
		for _, field := range []string{"client_secret", "client_assertion", "client_assertion_type"} {
			r = dxDeviceCodeHTTP(env, map[string]any{"client_id": publicID, "scope": "openid", field: 42}, nil)
			dxExpectStatusErr(t, r, 400, "invalid_request")
		}
		for _, field := range []string{"client_secret", "client_assertion", "client_assertion_type"} {
			r = dxDeviceCodeHTTP(env, dxForm("client_id", publicID, "scope", "openid", field, "first", field, "second"), nil)
			dxExpectStatusErr(t, r, 400, "invalid_request")
		}
		r = dxDeviceCodeHTTP(env, dxForm("client_id", publicID, "scope", "openid", "resource", resource, "resource", secondResource), nil)
		if m := dxExpectOK(t, r); dxStr(m, "device_code") == "" {
			t.Fatalf("repeated resource: %s", r.body)
		}
	})

	run("rejects an unknown client in composed mode without explicit standalone validation", func(t *testing.T) {
		r := dxDeviceCodeHTTP(env, url.Values{"client_id": {"unknown-composed-client"}, "scope": {"openid"}}, nil)
		dxExpectStatusErr(t, r, 400, "invalid_client")
	})

	run("returns an RFC invalid_request envelope for duplicate base parameters", func(t *testing.T) {
		r := dxDeviceCodeHTTP(env, dxForm("client_id", "duplicate-parameter-client", "scope", "openid", "scope", "email"), nil)
		dxExpectStatusErr(t, r, 400, "invalid_request")
		if !strings.Contains(dxStr(r.json(), "error_description"), "scope") {
			t.Fatalf("description: %s", r.body)
		}
	})

	run("returns an RFC invalid_request envelope for malformed base parameters", func(t *testing.T) {
		r := dxDeviceCodeHTTP(env, map[string]any{"client_id": []any{"malformed-client"}, "scope": "openid"}, nil)
		dxExpectStatusErr(t, r, 400, "invalid_request")
		if !strings.Contains(dxStr(r.json(), "error_description"), "client_id") {
			t.Fatalf("description: %s", r.body)
		}
	})

	run("returns invalid_request when an unauthenticated request omits client_id", func(t *testing.T) {
		r := dxDeviceCodeHTTP(env, url.Values{"scope": {"openid"}}, nil)
		dxExpectStatusErr(t, r, 400, "invalid_request")
		if !strings.Contains(dxStr(r.json(), "error_description"), "client_id") {
			t.Fatalf("description: %s", r.body)
		}
	})

	run("returns invalid_client when Basic auth and body client_id identify different clients", func(t *testing.T) {
		id, secret := dxConfidential(env, "client_secret_basic", "https://authenticated.example.com/callback")
		bodyClient := dxCreateDeviceClient(env)
		r := dxDeviceCodeHTTP(env, url.Values{"client_id": {bodyClient}, "scope": {"openid"}}, basicAuth(id, secret))
		dxExpectStatusErr(t, r, 400, "invalid_client")
	})

	validatedEnv := func(t *testing.T, result bool, calls *atomic.Int32) *testEnv {
		return newEnv(t, Options{Scopes: []string{"openid"}}, envOptions{
			jwt: dxJwtIssuer(testBaseURL),
			plugins: []*betterauth.Plugin{OAuthDeviceAuthorization(deviceauthorization.Options{
				ValidateClient: func(context.Context, string) (bool, error) {
					calls.Add(1)
					return result, nil
				},
			})},
		})
	}

	run("treats an empty body client_id as omitted for authenticated requests", func(t *testing.T) {
		var calls atomic.Int32
		venv := validatedEnv(t, false, &calls)
		id, secret := dxConfidential(venv, "client_secret_basic", "https://empty-id.example.com/callback")
		r := venv.do("POST", "/device/code", dxForm("client_id", "", "client_id", id, "scope", "openid"), basicAuth(id, secret))
		if m := dxExpectOK(t, r); dxStr(m, "device_code") == "" {
			t.Fatalf("response: %s", r.body)
		}
		if calls.Load() != 0 {
			t.Fatalf("validateClient called %d times", calls.Load())
		}
	})

	run("does not route an authenticated unknown body client through standalone validation", func(t *testing.T) {
		var calls atomic.Int32
		venv := validatedEnv(t, true, &calls)
		id, secret := dxConfidential(venv, "client_secret_basic", "https://unknown-id.example.com/callback")
		r := venv.do("POST", "/device/code", url.Values{"client_id": {"unknown-standalone-id"}, "scope": {"openid"}}, basicAuth(id, secret))
		dxExpectStatusErr(t, r, 400, "invalid_client")
		if calls.Load() != 0 {
			t.Fatalf("validateClient called %d times", calls.Load())
		}
	})

	run("advertises device_authorization_endpoint in discovery metadata", func(t *testing.T) {
		as := env.mustCall("getOAuthServerConfig", betterauth.CallInput{})
		expected := strings.Replace(dxStr(as, "token_endpoint"), "/oauth2/token", "/device/code", 1)
		if as["device_authorization_endpoint"] != expected {
			t.Fatalf("as: %v vs %s", as["device_authorization_endpoint"], expected)
		}
		oid := env.mustCall("getOpenIdConfig", betterauth.CallInput{})
		if oid["device_authorization_endpoint"] != expected {
			t.Fatalf("openid: %v", oid["device_authorization_endpoint"])
		}
	})

	run("advertises the device_code grant in supported grant types", func(t *testing.T) {
		as := env.mustCall("getOAuthServerConfig", betterauth.CallInput{})
		if !dxContainsAny(as["grant_types_supported"], dxDeviceGrant) {
			t.Fatalf("grant types: %v", as["grant_types_supported"])
		}
	})

	run("issues a real OAuth token for an approved device code", func(t *testing.T) {
		clientID := dxCreateDeviceClient(env)
		dc := dxApprovedDeviceCode(env, clientID, "", resource)
		r := dxPoll(env, "grant_type", dxDeviceGrant, "device_code", dc, "client_id", clientID, "resource", resource)
		m := dxExpectOK(t, r)
		if m["token_type"] != "Bearer" || m["scope"] != "openid profile email" {
			t.Fatalf("token: %s", r.body)
		}
		at := decodeJWTPayload(t, dxStr(m, "access_token"))
		if at["sub"] != userID || at["client_id"] != clientID {
			t.Fatalf("access token: %v", at)
		}
		if !dxAudContains(at["aud"], resource) {
			t.Fatalf("aud: %v", at["aud"])
		}
		if !strings.Contains(" "+dxStr(at, "scope")+" ", " openid ") {
			t.Fatalf("scope: %v", at["scope"])
		}
		idt := decodeJWTPayload(t, dxStr(m, "id_token"))
		if idt["sub"] != userID || idt["aud"] != clientID {
			t.Fatalf("id token: %v", idt)
		}
	})

	run("returns invalid_request when device-code polling omits client_id", func(t *testing.T) {
		clientID := dxCreateDeviceClient(env)
		dc := dxApprovedDeviceCode(env, clientID, "", nil)
		r := dxPoll(env, "grant_type", dxDeviceGrant, "device_code", dc)
		dxExpectStatusErr(t, r, 400, "invalid_request")
	})

	run("treats empty token client ID occurrences as omitted regardless of order", func(t *testing.T) {
		clientID := dxCreateDeviceClient(env)
		for _, ids := range [][2]string{{"", clientID}, {clientID, ""}} {
			dc := dxApprovedDeviceCode(env, clientID, "", nil)
			r := dxPoll(env, "grant_type", dxDeviceGrant, "device_code", dc, "client_id", ids[0], "client_id", ids[1])
			if m := dxExpectOK(t, r); dxStr(m, "access_token") == "" {
				t.Fatalf("token: %s", r.body)
			}
		}
	})

	run("returns an HTTP Basic challenge when client authentication fails", func(t *testing.T) {
		clientID := dxCreateDeviceClient(env)
		dc := dxApprovedDeviceCode(env, clientID, "", nil)
		r := env.do("POST", "/oauth2/token", dxForm("grant_type", dxDeviceGrant, "device_code", dc), basicAuth(clientID, "wrong-secret"))
		dxExpectStatusErr(t, r, 401, "invalid_client")
		if got := r.header.Get("WWW-Authenticate"); got != "Basic" {
			t.Fatalf("WWW-Authenticate = %q", got)
		}
	})

	run("normalizes whitespace in approved scopes", func(t *testing.T) {
		clientID := dxCreateDeviceClient(env)
		dc := dxApprovedDeviceCode(env, clientID, "  openid\tprofile  email  ", resource)
		r := dxPoll(env, "grant_type", dxDeviceGrant, "device_code", dc, "client_id", clientID, "resource", resource)
		m := dxExpectOK(t, r)
		if m["scope"] != "openid profile email" {
			t.Fatalf("scope: %v", m["scope"])
		}
		if at := decodeJWTPayload(t, dxStr(m, "access_token")); at["scope"] != "openid profile email" {
			t.Fatalf("at scope: %v", at["scope"])
		}
	})

	run("rejects resources outside the provider policy", func(t *testing.T) {
		clientID := dxCreateDeviceClient(env)
		onDeviceAuthCalls.Store(0)
		_, err := env.call("deviceCode", betterauth.CallInput{Body: map[string]any{
			"client_id": clientID, "scope": "openid", "resource": "https://unregistered.example.com",
		}})
		expectOAuthError(t, err, "invalid_target", "")
		if onDeviceAuthCalls.Load() != 0 {
			t.Fatal("onDeviceAuthRequest was called")
		}
	})

	run("treats an empty form resource as omitted within the OAuth flow", func(t *testing.T) {
		clientID := dxCreateDeviceClient(env)
		r := dxDeviceCodeHTTP(env, url.Values{"client_id": {clientID}, "scope": {"openid"}, "resource": {""}}, nil)
		m := dxExpectOK(t, r)
		headers := env.signInWithTestUser()
		v := dxVerify(env, dxStr(m, "user_code"), headers)
		if _, ok := v["resource"]; ok {
			t.Fatalf("verification resource: %v", v["resource"])
		}
		dxApprove(env, dxStr(m, "user_code"), headers)
		tr := dxPoll(env, "grant_type", dxDeviceGrant, "device_code", dxStr(m, "device_code"), "client_id", clientID)
		dxExpectOK(t, tr)
	})

	run("keeps base validation when resource and client_id are both invalid", func(t *testing.T) {
		r := env.do("POST", "/device/code", `{"client_id":42,"resource":"/api"}`, http.Header{"Content-Type": {"application/json"}})
		dxExpectStatusErr(t, r, 400, "invalid_request")
	})

	for _, tc := range []struct {
		label    string
		resource any
	}{
		{"malformed", "https://[invalid"},
		{"relative", "/api"},
		{"fragmented", resource + "#fragment"},
		{"dangerous-scheme", "javascript:alert(1)"},
		{"wrong-type", 42},
		{"array-item", []any{resource, "/api"}},
	} {
		run("returns invalid_target for "+tc.label+" RFC 8707 resource indicators at the HTTP boundary", func(t *testing.T) {
			clientID := dxCreateDeviceClient(env)
			r := dxDeviceCodeHTTP(env, map[string]any{"client_id": clientID, "resource": tc.resource}, nil)
			dxExpectStatusErr(t, r, 400, "invalid_target")
		})
	}

	run("binds repeated form-encoded resources at the device endpoint", func(t *testing.T) {
		clientID := dxCreateDeviceClient(env)
		r := dxDeviceCodeHTTP(env, dxForm("client_id", clientID, "scope", "openid", "resource", resource, "resource", secondResource), nil)
		m := dxExpectOK(t, r)
		v := dxVerify(env, dxStr(m, "user_code"), env.signInWithTestUser())
		got, _ := json.Marshal(v["resource"])
		if string(got) != `["`+resource+`","`+secondResource+`"]` {
			t.Fatalf("resource: %s", got)
		}
	})

	run("validates every repeated form-encoded resource", func(t *testing.T) {
		clientID := dxCreateDeviceClient(env)
		r := dxDeviceCodeHTTP(env, dxForm("client_id", clientID, "scope", "openid", "resource", "/relative", "resource", resource), nil)
		dxExpectStatusErr(t, r, 400, "invalid_target")
		if d := dxStr(r.json(), "error_description"); d != "Invalid resource indicator" {
			t.Fatalf("description: %q", d)
		}
	})

	run("rejects a resource added after approval without consuming the code", func(t *testing.T) {
		clientID := dxCreateDeviceClient(env)
		dc := dxApprovedDeviceCode(env, clientID, "openid", nil)
		r := dxPoll(env, "grant_type", dxDeviceGrant, "device_code", dc, "client_id", clientID, "resource", resource)
		dxExpectStatusErr(t, r, 400, "invalid_target")
		if rec := env.findOne("deviceCode", eq("deviceCode", dc)); rec == nil {
			t.Fatal("device code consumed")
		}
	})

	run("single-uses the device code (second exchange fails)", func(t *testing.T) {
		clientID := dxCreateDeviceClient(env)
		dc := dxApprovedDeviceCode(env, clientID, "", nil)
		dxExpectOK(t, dxPoll(env, "grant_type", dxDeviceGrant, "device_code", dc, "client_id", clientID))
		r := dxPoll(env, "grant_type", dxDeviceGrant, "device_code", dc, "client_id", clientID)
		dxExpectStatusErr(t, r, 400, "invalid_grant")
	})

	run("preserves an approved code when user lookup fails before OAuth issuance", func(t *testing.T) {
		clientID := dxCreateDeviceClient(env)
		dc := dxApprovedDeviceCode(env, clientID, "", nil)
		env.update("deviceCode", adapter.Record{"userId": "missing-user"}, eq("deviceCode", dc))
		r := dxPoll(env, "grant_type", dxDeviceGrant, "device_code", dc, "client_id", clientID)
		dxExpectStatusErr(t, r, 500, "server_error")
		if rec := env.findOne("deviceCode", eq("deviceCode", dc)); rec == nil {
			t.Fatal("device code consumed")
		}
	})

	run("returns authorization_pending before approval", func(t *testing.T) {
		clientID := dxCreateDeviceClient(env)
		dc, _ := dxDeviceCode(env, map[string]any{"client_id": clientID, "scope": "openid"})
		r := dxPoll(env, "grant_type", dxDeviceGrant, "device_code", dc, "client_id", clientID)
		dxExpectStatusErr(t, r, 400, "authorization_pending")
	})

	run("returns slow_down when polling faster than the interval", func(t *testing.T) {
		clientID := dxCreateDeviceClient(env)
		dc, _ := dxDeviceCode(env, map[string]any{"client_id": clientID, "scope": "openid"})
		dxPoll(env, "grant_type", dxDeviceGrant, "device_code", dc, "client_id", clientID)
		r := dxPoll(env, "grant_type", dxDeviceGrant, "device_code", dc, "client_id", clientID)
		dxExpectStatusErr(t, r, 400, "slow_down")
	})

	run("returns access_denied when the user denies the request", func(t *testing.T) {
		clientID := dxCreateDeviceClient(env)
		headers := env.signInWithTestUser()
		dc, uc := dxDeviceCode(env, map[string]any{"client_id": clientID, "scope": "openid"})
		dxVerify(env, uc, headers)
		env.mustCall("deviceDeny", betterauth.CallInput{Body: map[string]any{"userCode": uc}, Headers: headers})
		r := dxPoll(env, "grant_type", dxDeviceGrant, "device_code", dc, "client_id", clientID)
		dxExpectStatusErr(t, r, 400, "access_denied")
	})

	run("rejects an unknown device code", func(t *testing.T) {
		clientID := dxCreateDeviceClient(env)
		r := dxPoll(env, "grant_type", dxDeviceGrant, "device_code", "does-not-exist", "client_id", clientID)
		dxExpectStatusErr(t, r, 400, "invalid_grant")
	})

	run("rejects a device code presented by a different client", func(t *testing.T) {
		clientID := dxCreateDeviceClient(env)
		other := dxCreateDeviceClient(env)
		dc := dxApprovedDeviceCode(env, clientID, "", nil)
		r := dxPoll(env, "grant_type", dxDeviceGrant, "device_code", dc, "client_id", other)
		dxExpectStatusErr(t, r, 400, "invalid_grant")
	})

	run("returns invalid_grant (not invalid_scope) when a narrower-scoped client replays a code", func(t *testing.T) {
		victim := dxCreateDeviceClient(env)
		dc := dxApprovedDeviceCode(env, victim, "openid profile email", nil)
		attacker := dxCreateClient(env, map[string]any{
			"token_endpoint_auth_method": "none",
			"grant_types":                []any{dxDeviceGrant},
			"scope":                      "openid",
			"application_type":           "native",
		})
		r := dxPoll(env, "grant_type", dxDeviceGrant, "device_code", dc, "client_id", dxStr(attacker, "client_id"))
		dxExpectStatusErr(t, r, 400, "invalid_grant")
	})

	run("does not reveal device-code scopes to a confidential client", func(t *testing.T) {
		victim := dxCreateDeviceClient(env)
		dc := dxApprovedDeviceCode(env, victim, "openid profile email", nil)
		attacker := dxCreateClient(env, map[string]any{
			"token_endpoint_auth_method": "client_secret_basic",
			"grant_types":                []any{dxDeviceGrant},
			"scope":                      "openid",
			"application_type":           "web",
		})
		r := env.do("POST", "/oauth2/token", dxForm("grant_type", dxDeviceGrant, "device_code", dc),
			basicAuth(dxStr(attacker, "client_id"), dxStr(attacker, "client_secret")))
		dxExpectStatusErr(t, r, 400, "invalid_grant")
	})

	run("blocks redeeming an OAuth-client device code at the first-party /device/token", func(t *testing.T) {
		clientID := dxCreateDeviceClient(env)
		dc := dxApprovedDeviceCode(env, clientID, "", nil)
		r := env.do("POST", "/device/token", map[string]any{"grant_type": dxDeviceGrant, "device_code": dc, "client_id": clientID}, nil)
		dxExpectStatusErr(t, r, 400, "invalid_grant")
		if !strings.Contains(dxStr(r.json(), "error_description"), "/oauth2/token") {
			t.Fatalf("description: %s", r.body)
		}
	})

	run("keeps minted OAuth codes out of the session flow after client deletion", func(t *testing.T) {
		clientID := dxCreateDeviceClient(env)
		dc := dxApprovedDeviceCode(env, clientID, "", nil)
		if err := env.db.Delete(context.Background(), "oauthClient", []adapter.Where{eq("clientId", clientID)}); err != nil {
			t.Fatal(err)
		}
		r := env.do("POST", "/device/token", map[string]any{"grant_type": dxDeviceGrant, "device_code": dc, "client_id": clientID}, nil)
		dxExpectStatusErr(t, r, 400, "invalid_grant")
		if rec := env.findOne("deviceCode", eq("deviceCode", dc)); rec == nil {
			t.Fatal("device code consumed")
		}
	})

	run("still issues a first-party session token for a non-OAuth client at /device/token", func(t *testing.T) {
		firstParty := "first-party-cli"
		senv := dxStandaloneEnv(t, deviceauthorization.New(deviceauthorization.Options{}))
		headers := senv.signInWithTestUser()
		dc, uc := dxDeviceCode(senv, map[string]any{"client_id": firstParty})
		dxVerify(senv, uc, headers)
		dxApprove(senv, uc, headers)
		r := senv.do("POST", "/device/token", map[string]any{"grant_type": dxDeviceGrant, "device_code": dc, "client_id": firstParty}, nil)
		m := dxExpectOK(t, r)
		if m["access_token"] == nil || m["token_type"] != "Bearer" {
			t.Fatalf("token: %s", r.body)
		}
	})
}

func dxAudContains(aud any, s string) bool {
	switch v := aud.(type) {
	case string:
		return v == s
	case []any:
		for _, x := range v {
			if x == s {
				return true
			}
		}
	}
	return false
}

// dxStandaloneEnv builds an auth instance without the oauth-provider plugin (a testEnv
// so the HTTP / call helpers work).
func dxStandaloneEnv(t *testing.T, plugins ...*betterauth.Plugin) *testEnv {
	t.Helper()
	t.Setenv("NODE_ENV", "test")
	env := &testEnv{t: t, hosts: map[string]http.Handler{}}
	cfg := dxBareConfig(t, plugins...)
	inner := cfg.Database
	cfg.Database = func(ao adapter.Options) (adapter.Adapter, error) {
		a, err := inner(ao)
		env.db = a
		return a, err
	}
	a, err := betterauth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RunMigrations(context.Background()); err != nil {
		t.Fatal(err)
	}
	env.auth = a
	env.mustCall("signUpEmail", betterauth.CallInput{Body: map[string]any{"email": testUserEmail, "password": testUserPassword, "name": testUserName}})
	return env
}

func TestDx_DeviceCodeImmutableRouting(t *testing.T) {
	firstParty := "late-registered-oauth-client"
	env := newEnv(t, Options{
		GenerateClientID: func() string { return firstParty },
		Scopes:           []string{"openid"},
	}, envOptions{jwt: dxJwtIssuer(testBaseURL), plugins: []*betterauth.Plugin{OAuthDeviceAuthorization(deviceauthorization.Options{
		ValidateClient: func(_ context.Context, id string) (bool, error) { return id == firstParty, nil },
	})}})
	t.Run("keeps a standalone code in the session flow after its client id is registered", func(t *testing.T) {
		defer dxBind(env, t)()
		headers := env.signInWithTestUser()
		dc, uc := dxDeviceCode(env, map[string]any{"client_id": firstParty})
		dxVerify(env, uc, headers)
		dxApprove(env, uc, headers)
		reg := env.adminCreateClient(headers, map[string]any{
			"token_endpoint_auth_method": "none",
			"grant_types":                []any{dxDeviceGrant},
			"scope":                      "openid",
			"application_type":           "native",
		})
		if reg["client_id"] != firstParty {
			t.Fatalf("registered: %v", reg)
		}
		r := dxPoll(env, "grant_type", dxDeviceGrant, "device_code", dc, "client_id", firstParty)
		dxExpectStatusErr(t, r, 400, "invalid_grant")
		r = env.do("POST", "/device/token", map[string]any{"grant_type": dxDeviceGrant, "device_code": dc, "client_id": firstParty}, nil)
		if m := dxExpectOK(t, r); m["access_token"] == nil {
			t.Fatalf("token: %s", r.body)
		}
	})
}

func TestDx_DeviceCodeGrantExpiry(t *testing.T) {
	env := newEnv(t, Options{
		AllowDynamicClientRegistration: true,
		Scopes:                         []string{"openid", "profile", "email"},
	}, envOptions{jwt: dxJwtIssuer(testBaseURL), plugins: []*betterauth.Plugin{OAuthDeviceAuthorization(deviceauthorization.Options{
		ExpiresIn: "1s", Interval: "1s",
	})}})
	t.Run("returns expired_token once the device code has expired", func(t *testing.T) {
		defer dxBind(env, t)()
		created := env.adminCreateClient(env.signInWithTestUser(), map[string]any{
			"token_endpoint_auth_method": "none",
			"grant_types":                []any{dxDeviceGrant},
			"scope":                      "openid",
			"application_type":           "native",
		})
		clientID := dxStr(created, "client_id")
		dc, _ := dxDeviceCode(env, map[string]any{"client_id": clientID, "scope": "openid"})
		time.Sleep(1200 * time.Millisecond)
		r := dxPoll(env, "grant_type", dxDeviceGrant, "device_code", dc, "client_id", clientID)
		dxExpectStatusErr(t, r, 400, "expired_token")
	})
}

func TestDx_DeviceCodeGrantReuse(t *testing.T) {
	discovered := "discovered-device-client"
	shared := OAuthDeviceAuthorization(deviceauthorization.Options{})
	first := newEnv(t, Options{
		Scopes: []string{"openid"},
		Extensions: []*Extension{{ClientDiscovery: []*ClientDiscovery{{
			ID:      "device-code-reuse-test",
			Matches: func(id string) bool { return id == discovered },
			Resolve: func(_ *betterauth.EndpointContext, id string, _ *SchemaClient) (*SchemaClient, error) {
				return &SchemaClient{ClientID: id, TokenEndpointAuthMethod: "none", GrantTypes: []string{dxDeviceGrant}, Scopes: []string{"openid"}}, nil
			},
		}}}},
	}, envOptions{jwt: dxJwtIssuer(testBaseURL), plugins: []*betterauth.Plugin{shared}})
	_ = newEnv(t, Options{Scopes: []string{"openid"}}, envOptions{
		jwt:     dxJwtIssuer("http://localhost:3001"),
		mutate:  func(c *betterauth.Config) { c.BaseURL = "http://localhost:3001" },
		plugins: []*betterauth.Plugin{shared},
	})
	t.Run("keeps each auth instance bound to its own provider options", func(t *testing.T) {
		defer dxBind(first, t)()
		headers := first.signInWithTestUser()
		dc, uc := dxDeviceCode(first, map[string]any{"client_id": discovered, "scope": "openid"})
		dxVerify(first, uc, headers)
		dxApprove(first, uc, headers)
		r := first.do("POST", "/device/token", map[string]any{"grant_type": dxDeviceGrant, "device_code": dc, "client_id": discovered}, nil)
		dxExpectStatusErr(t, r, 400, "invalid_grant")
	})
}
