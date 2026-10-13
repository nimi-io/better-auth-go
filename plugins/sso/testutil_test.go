package sso

// Test helpers: the Go equivalent of getTestInstance (memory database, default test user
// test@test.com / test123456), HTTP/direct-API clients, a mock OIDC provider (the
// oauth2-mock-server used upstream) and a mock SAML identity provider (the express +
// samlify IdP used upstream).

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/sso/internal/samlify"
)

const (
	testEmail    = "test@test.com"
	testPassword = "test123456"
	testName     = "test user"
)

type testEnv struct {
	t      *testing.T
	auth   *betterauth.Auth
	db     *memory.DB
	server *httptest.Server
	plugin *betterauth.Plugin
	// baseURL is the auth base URL (server URL + /api/auth).
	baseURL string
}

type envConfig struct {
	mutate       func(c *betterauth.Config)
	extraPlugins []*betterauth.Plugin
	noTestUser   bool
	// before adds plugins registered before sso.
	before []*betterauth.Plugin
}

// newEnv builds an auth instance with the sso plugin on an httptest server.
func newEnv(t *testing.T, opts Options, cfgs ...envConfig) *testEnv {
	t.Helper()
	t.Setenv("NODE_ENV", "test")
	var ec envConfig
	if len(cfgs) > 0 {
		ec = cfgs[0]
	}
	e := &testEnv{t: t, db: memory.NewDB()}
	mux := http.NewServeMux()
	e.server = httptest.NewServer(mux)
	t.Cleanup(e.server.Close)
	e.baseURL = e.server.URL + "/api/auth"
	e.plugin = New(opts)
	plugins := append(append([]*betterauth.Plugin{}, ec.before...), e.plugin)
	plugins = append(plugins, ec.extraPlugins...)
	cfg := betterauth.Config{
		BaseURL:          e.server.URL,
		Secret:           "better-auth-secret-that-is-long-enough-for-validation-test",
		Database:         memory.New(e.db),
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true},
		Logger:           betterauth.NopLogger{},
		RateLimit:        &betterauth.RateLimitConfig{Enabled: betterauth.Bool(false)},
		Plugins:          plugins,
	}
	if ec.mutate != nil {
		ec.mutate(&cfg)
	}
	a, err := betterauth.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.auth = a
	mux.Handle("/api/auth/", a.Handler())
	if !ec.noTestUser {
		e.signUp(testEmail, testPassword, testName)
	}
	return e
}

// ---- results ----

type result struct {
	Status  int
	Data    any
	Raw     []byte
	Headers http.Header
	Err     *betterauth.APIError
}

func (r *result) m() map[string]any {
	m, _ := r.Data.(map[string]any)
	return m
}

func (r *result) code() string {
	if r.Err == nil {
		return ""
	}
	return r.Err.Code()
}

func (r *result) message() string {
	if r.Err == nil {
		return ""
	}
	return r.Err.Message()
}

func (r *result) location() string { return r.Headers.Get("Location") }

// locURL parses the Location header.
func (r *result) locURL(t *testing.T) *url.URL {
	t.Helper()
	u, err := url.Parse(r.location())
	if err != nil {
		t.Fatalf("bad location %q", r.location())
	}
	return u
}

// api calls an endpoint directly (auth.api.X).
func (e *testEnv) api(key string, headers http.Header, body any, query map[string]any) *result {
	e.t.Helper()
	return e.apiIn(key, betterauth.CallInput{Headers: headers, Body: body, Query: query})
}

func (e *testEnv) apiIn(key string, in betterauth.CallInput) *result {
	e.t.Helper()
	res, err := e.auth.API.Call(context.Background(), key, in)
	out := &result{}
	if err != nil {
		apiErr, ok := betterauth.AsAPIError(err)
		if !ok {
			e.t.Fatalf("%s: %v", key, err)
		}
		out.Err = apiErr
		out.Status = apiErr.StatusCode
		out.Headers = apiErr.Headers
		return out
	}
	out.Status, out.Headers = res.Status, res.Headers
	if raw, ok := res.Data.(*betterauth.Response); ok {
		out.Raw = raw.Body
		return out
	}
	b, jerr := res.JSON()
	if jerr != nil {
		e.t.Fatalf("%s: encode: %v", key, jerr)
	}
	out.Raw = b
	if len(b) > 0 {
		_ = json.Unmarshal(b, &out.Data)
	}
	return out
}

func (e *testEnv) mustAPI(key string, headers http.Header, body any, query map[string]any) *result {
	e.t.Helper()
	r := e.api(key, headers, body, query)
	if r.Err != nil {
		e.t.Fatalf("%s: %d %s %s", key, r.Status, r.code(), r.message())
	}
	return r
}

var noRedirectClient = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// do performs a JSON HTTP request against the auth handler without following redirects.
// path is relative to /api/auth (or an absolute URL).
func (e *testEnv) do(method, path string, headers http.Header, body any) *result {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	u := path
	if !strings.HasPrefix(path, "http") {
		u = e.baseURL + path
	}
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if req.Header.Get("Origin") == "" {
		req.Header.Set("Origin", e.server.URL)
	}
	return e.send(req)
}

// postForm submits an x-www-form-urlencoded POST (an IdP posting to the ACS).
func (e *testEnv) postForm(path string, headers http.Header, form url.Values) *result {
	e.t.Helper()
	u := path
	if !strings.HasPrefix(path, "http") {
		u = e.baseURL + path
	}
	req, err := http.NewRequest("POST", u, strings.NewReader(form.Encode()))
	if err != nil {
		e.t.Fatal(err)
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return e.send(req)
}

func (e *testEnv) send(req *http.Request) *result {
	e.t.Helper()
	res, err := noRedirectClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	out := &result{Status: res.StatusCode, Headers: res.Header, Raw: b}
	if len(b) > 0 {
		_ = json.Unmarshal(b, &out.Data)
	}
	if res.StatusCode >= 400 {
		m, _ := out.Data.(map[string]any)
		apiErr := betterauth.NewAPIErrorCode(res.StatusCode, nil)
		if m != nil {
			o := jsonx.NewObject()
			for k, v := range m {
				o.Set(k, v)
			}
			apiErr = betterauth.NewAPIErrorCode(res.StatusCode, o)
		}
		out.Err = apiErr
	}
	return out
}

// ---- cookies & sessions ----

// cookieHeaders converts Set-Cookie response headers into request headers with Cookie.
func cookieHeaders(h http.Header) http.Header {
	return mergeCookies(http.Header{}, h)
}

// mergeCookies applies Set-Cookie headers from h onto the Cookie header of base.
func mergeCookies(base http.Header, h http.Header) http.Header {
	jar := map[string]string{}
	var order []string
	for _, part := range strings.Split(base.Get("Cookie"), ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		if _, ok := jar[k]; !ok {
			order = append(order, k)
		}
		jar[k] = v
	}
	for _, sc := range h.Values("Set-Cookie") {
		name, value, attrs := betterauth.ParseSetCookie(sc)
		if ma, ok := attrs["max-age"]; ok && (ma == "0" || strings.HasPrefix(ma, "-")) || value == "" {
			delete(jar, name)
			continue
		}
		if _, ok := jar[name]; !ok {
			order = append(order, name)
		}
		jar[name] = value
	}
	var parts []string
	for _, k := range order {
		if v, ok := jar[k]; ok {
			parts = append(parts, k+"="+v)
		}
	}
	out := base.Clone()
	if out == nil {
		out = http.Header{}
	}
	if len(parts) > 0 {
		out.Set("Cookie", strings.Join(parts, "; "))
	} else {
		out.Del("Cookie")
	}
	return out
}

// signUp creates a user and returns its session headers.
func (e *testEnv) signUp(email, password, name string) http.Header {
	e.t.Helper()
	res, err := e.auth.API.Call(context.Background(), "signUpEmail", betterauth.CallInput{
		Body: map[string]any{"email": email, "password": password, "name": name}})
	if err != nil {
		e.t.Fatalf("sign up %s: %v", email, err)
	}
	return cookieHeaders(res.Headers)
}

// signIn signs in and returns session headers.
func (e *testEnv) signIn(email, password string) http.Header {
	e.t.Helper()
	res, err := e.auth.API.Call(context.Background(), "signInEmail", betterauth.CallInput{
		Body: map[string]any{"email": email, "password": password}})
	if err != nil {
		e.t.Fatalf("sign in %s: %v", email, err)
	}
	return cookieHeaders(res.Headers)
}

// signInTestUser is signInWithTestUser.
func (e *testEnv) signInTestUser() http.Header { return e.signIn(testEmail, testPassword) }

// session returns the session of headers (nil when signed out).
func (e *testEnv) session(headers http.Header) *betterauth.SessionWithUser {
	e.t.Helper()
	s, err := e.auth.API.GetSession(context.Background(), headers)
	if err != nil {
		e.t.Fatalf("getSession: %v", err)
	}
	return s
}

// rows returns the stored rows of a model.
func (e *testEnv) rows(model string) []map[string]any {
	e.t.Helper()
	recs, err := e.auth.Context().Adapter.FindMany(context.Background(), adapterFindAll(model))
	if err != nil {
		e.t.Fatal(err)
	}
	out := make([]map[string]any, len(recs))
	for i, r := range recs {
		out[i] = r
	}
	return out
}

// ---- mock OIDC provider (oauth2-mock-server) ----

type mockResponse struct {
	StatusCode int
	Body       any
}

type mockOIDC struct {
	t      *testing.T
	server *httptest.Server
	// URL is the issuer ("http://localhost:<port>").
	URL   string
	Key   *rsa.PrivateKey
	KeyID string

	mu sync.Mutex
	// BeforeTokenSigning customises id token claims.
	BeforeTokenSigning func(payload map[string]any, r *http.Request)
	// BeforeResponse customises the token response.
	BeforeResponse func(resp *mockResponse, r *http.Request)
	// BeforeUserinfo customises the userinfo response.
	BeforeUserinfo func(resp *mockResponse, r *http.Request)
	// Discovery customises the discovery document.
	Discovery func(doc map[string]any)
	// TokenRequests records token request forms.
	TokenRequests []url.Values
	// TokenHeaders records token request headers.
	TokenHeaders []http.Header
	nonces       map[string]string
}

// newMockOIDC starts a mock OpenID provider on localhost.
func newMockOIDC(t *testing.T) *mockOIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m := &mockOIDC{t: t, Key: key, KeyID: "mock-key", nonces: map[string]string{}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m.server = httptest.NewUnstartedServer(http.HandlerFunc(m.serve))
	m.server.Listener = ln
	m.server.Start()
	t.Cleanup(m.server.Close)
	m.URL = "http://localhost:" + fmt.Sprint(ln.Addr().(*net.TCPAddr).Port)
	return m
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (m *mockOIDC) discoveryDoc() map[string]any {
	doc := map[string]any{
		"issuer":                                m.URL,
		"authorization_endpoint":                m.URL + "/authorize",
		"token_endpoint":                        m.URL + "/token",
		"userinfo_endpoint":                     m.URL + "/userinfo",
		"jwks_uri":                              m.URL + "/jwks",
		"end_session_endpoint":                  m.URL + "/endsession",
		"introspection_endpoint":                m.URL + "/introspect",
		"revocation_endpoint":                   m.URL + "/revoke",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic", "client_secret_post", "private_key_jwt"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"subject_types_supported":               []string{"public"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"code_challenge_methods_supported":      []string{"plain", "S256"},
	}
	if m.Discovery != nil {
		m.Discovery(doc)
	}
	return doc
}

func (m *mockOIDC) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		writeJSON(w, 200, m.discoveryDoc())
	case "/jwks":
		j, _ := jose.JWKFromPublicKey(&m.Key.PublicKey)
		j.Kid, j.Alg, j.Use = m.KeyID, "RS256", "sig"
		writeJSON(w, 200, jose.JWKS{Keys: []jose.JWK{j}})
	case "/authorize":
		q := r.URL.Query()
		code := bacrypto.RandomString(16)
		m.mu.Lock()
		m.nonces[code] = q.Get("nonce")
		m.mu.Unlock()
		target, _ := url.Parse(q.Get("redirect_uri"))
		tq := target.Query()
		tq.Set("code", code)
		if s := q.Get("state"); s != "" {
			tq.Set("state", s)
		}
		target.RawQuery = tq.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
	case "/token":
		_ = r.ParseForm()
		m.mu.Lock()
		m.TokenRequests = append(m.TokenRequests, r.PostForm)
		m.TokenHeaders = append(m.TokenHeaders, r.Header.Clone())
		nonce := m.nonces[r.PostForm.Get("code")]
		m.mu.Unlock()
		clientID := r.PostForm.Get("client_id")
		if u, _, ok := r.BasicAuth(); ok {
			clientID, _ = url.QueryUnescape(u)
		}
		now := time.Now().Unix()
		payload := map[string]any{"iss": m.URL, "sub": "johndoe", "aud": clientID, "iat": now, "exp": now + 3600, "nbf": now - 10}
		if nonce != "" {
			payload["nonce"] = nonce
		}
		if m.BeforeTokenSigning != nil {
			m.BeforeTokenSigning(payload, r)
		}
		resp := &mockResponse{StatusCode: 200, Body: map[string]any{
			"access_token":  "mock-access-token-" + bacrypto.RandomString(8),
			"token_type":    "Bearer",
			"expires_in":    3600,
			"scope":         "openid email profile",
			"refresh_token": "mock-refresh-token",
			"id_token":      m.IDToken(payload),
		}}
		if m.BeforeResponse != nil {
			m.BeforeResponse(resp, r)
		}
		writeJSON(w, resp.StatusCode, resp.Body)
	case "/userinfo":
		resp := &mockResponse{StatusCode: 200, Body: map[string]any{"sub": "johndoe"}}
		if m.BeforeUserinfo != nil {
			m.BeforeUserinfo(resp, r)
		}
		writeJSON(w, resp.StatusCode, resp.Body)
	default:
		http.NotFound(w, r)
	}
}

// IDToken signs claims with the mock key.
func (m *mockOIDC) IDToken(claims map[string]any) string {
	p := jsonx.NewObject()
	for k, v := range claims {
		switch t := v.(type) {
		case int64:
			p.Set(k, float64(t))
		case int:
			p.Set(k, float64(t))
		default:
			p.Set(k, v)
		}
	}
	tok, err := jose.SignJWT(jsonx.O("alg", "RS256", "kid", m.KeyID, "typ", "JWT"), p, m.Key)
	if err != nil {
		panic(err)
	}
	return tok
}

// oidcFlowResult is the outcome of simulateOAuthFlow.
type oidcFlowResult struct {
	// CallbackURL is the Location returned by the SSO callback.
	CallbackURL string
	// Headers carry the cookies set by the callback.
	Headers http.Header
	Status  int
}

// simulateOAuthFlow follows the provider authorization URL (which redirects back with a
// code) and calls the callback with headers (state cookies included).
func (e *testEnv) simulateOAuthFlow(authURL string, headers http.Header) oidcFlowResult {
	e.t.Helper()
	res, err := noRedirectClient.Get(authURL)
	if err != nil {
		e.t.Fatal(err)
	}
	res.Body.Close()
	loc := res.Header.Get("Location")
	if loc == "" {
		e.t.Fatalf("no redirect location from %s (status %d)", authURL, res.StatusCode)
	}
	cb := e.do("GET", loc, headers, nil)
	return oidcFlowResult{CallbackURL: cb.location(), Headers: cookieHeaders(cb.Headers), Status: cb.Status}
}

// ---- mock SAML identity provider ----

// samlIdPMetadataFor rewrites the upstream IdP metadata fixture (localhost:8081) to url.
func samlFixtureFor(xml, base string) string {
	return strings.ReplaceAll(xml, "http://localhost:8081", base)
}

// mockSAMLIdP mirrors createMockSAMLIdP.
type mockSAMLIdP struct {
	t                       *testing.T
	server                  *httptest.Server
	URL                     string
	MetadataXML             string
	SPMetadataXML           string
	IsAssertionEncrypted    bool
	WantAuthnRequestsSigned bool
}

type mockSAMLOptions struct {
	idpMetadataXML          string
	spMetadataXML           string
	isAssertionEncrypted    bool
	wantAuthnRequestsSigned bool
}

// mockSAMLTemplate is the login response template of the upstream mock IdP.
const mockSAMLTemplate = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status><saml:Assertion ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}" InResponseTo="{InResponseTo}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{AttributeStatement}</saml:Assertion></samlp:Response>`

var mockSAMLAttributes = []samlify.TemplateAttribute{
	{Name: "firstName", ValueTag: "firstName", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", ValueXsiType: "xs:string"},
	{Name: "lastName", ValueTag: "lastName", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", ValueXsiType: "xs:string"},
	{Name: "email", ValueTag: "email", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", ValueXsiType: "xs:string"},
}

// samlTemplateOverrides mirror MockSAMLTemplateOverrides.
type samlTemplateOverrides struct {
	Audience         string
	Destination      string
	InResponseTo     *string
	SubjectRecipient string
}

// newMockSAMLIdP starts the mock IdP; its URL replaces localhost:8081 in the fixtures.
func newMockSAMLIdP(t *testing.T, o mockSAMLOptions) *mockSAMLIdP {
	t.Helper()
	m := &mockSAMLIdP{t: t, IsAssertionEncrypted: o.isAssertionEncrypted, WantAuthnRequestsSigned: o.wantAuthnRequestsSigned}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m.server = httptest.NewUnstartedServer(http.HandlerFunc(m.serve))
	m.server.Listener = ln
	m.server.Start()
	t.Cleanup(m.server.Close)
	m.URL = "http://localhost:" + fmt.Sprint(ln.Addr().(*net.TCPAddr).Port)
	m.MetadataXML = samlFixtureFor(or(o.idpMetadataXML, idpMetadata), m.URL)
	m.SPMetadataXML = or(o.spMetadataXML, spMetadata)
	return m
}

func (m *mockSAMLIdP) idp() *samlify.Entity {
	idp, err := samlify.IdentityProvider(samlify.Setting{Metadata: m.MetadataXML, PrivateKey: idPk, PrivateKeyPass: "jXmKf9By6ruLnUdRo90G",
		IsAssertionEncrypted: m.IsAssertionEncrypted, LoginResponseTemplate: &samlify.LoginResponseTemplate{Context: mockSAMLTemplate, Attributes: mockSAMLAttributes}})
	if err != nil {
		m.t.Fatal(err)
	}
	return idp
}

func (m *mockSAMLIdP) sp(spXML string) *samlify.Entity {
	sp, err := samlify.ServiceProvider(samlify.Setting{Metadata: or(spXML, m.SPMetadataXML)})
	if err != nil {
		m.t.Fatal(err)
	}
	return sp
}

// LoginResponse builds a base64 SAMLResponse for email (createLoginResponse with the
// upstream template callback).
func (m *mockSAMLIdP) LoginResponse(spXML, email string, ov samlTemplateOverrides) string {
	idp, sp := m.idp(), m.sp(spXML)
	acs, _ := sp.Meta.GetAssertionConsumerService("post")
	nameIDFormat := ""
	if f := idp.Setting.NameIDFormat; len(f) > 0 {
		nameIDFormat = f[0]
	}
	_, resp, err := idp.CreateLoginResponse(sp, "", samlify.LoginResponseUser{Email: email}, func(tpl string) (string, string) {
		id := "_" + bacrypto.RandomUUID()
		now := time.Now()
		later := now.Add(5 * time.Minute)
		irt := "null"
		if ov.InResponseTo != nil {
			irt = *ov.InResponseTo
		}
		return id, samlify.ReplaceTagsByValue(tpl, []samlify.Tag{
			samlify.T("ID", id), samlify.T("AssertionID", "_"+bacrypto.RandomUUID()), samlify.T("Destination", or(ov.Destination, acs)),
			samlify.T("Audience", or(ov.Audience, sp.Meta.GetEntityID())), samlify.T("EntityID", sp.Meta.GetEntityID()),
			samlify.T("SubjectRecipient", or(ov.SubjectRecipient, acs)), samlify.T("Issuer", idp.Meta.GetEntityID()),
			samlify.T("IssueInstant", samlify.ISOTime(now)), samlify.T("AssertionConsumerServiceURL", acs),
			samlify.T("StatusCode", SAMLStatusSuccess), samlify.T("ConditionsNotBefore", samlify.ISOTime(now)),
			samlify.T("ConditionsNotOnOrAfter", samlify.ISOTime(later)), samlify.T("SubjectConfirmationDataNotOnOrAfter", samlify.ISOTime(later)),
			samlify.T("NameIDFormat", nameIDFormat), samlify.T("NameID", email), samlify.T("InResponseTo", irt), samlify.T("AuthnStatement", ""),
			samlify.T("attrFirstName", "Test"), samlify.T("attrLastName", "User"), samlify.T("attrEmail", "test@email.com"),
		})
	})
	if err != nil {
		m.t.Fatal(err)
	}
	return resp
}

func (m *mockSAMLIdP) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/sso/saml2/idp/post", "/api/sso/saml2/idp/redirect":
		q := r.URL.Query()
		if m.WantAuthnRequestsSigned {
			if q.Get("SAMLRequest") == "" || q.Get("SigAlg") == "" || q.Get("Signature") == "" {
				writeJSON(w, 400, map[string]any{"error": "Missing required signature parameters"})
				return
			}
			if q.Get("SigAlg") != samlify.SignatureRSASHA256 {
				writeJSON(w, 400, map[string]any{"error": "Unsupported signature algorithm: " + q.Get("SigAlg")})
				return
			}
			if !verifyRedirectSignature(r.URL.RawQuery, idPk, "jXmKf9By6ruLnUdRo90G") {
				writeJSON(w, 400, map[string]any{"error": "Invalid AuthnRequest signature"})
				return
			}
		}
		email := "test@email.com"
		if q.Get("emailCase") == "mixed" {
			email = "TestUser@Example.com"
		}
		idpInitiated := q.Get("idpInitiated") == "true"
		irt := "null"
		if idpInitiated {
			irt = ""
		} else if !m.WantAuthnRequestsSigned && q.Get("SAMLRequest") != "" {
			if parsed, err := m.idp().ParseLoginRequest(q.Get("SAMLRequest")); err == nil && parsed.ID != "" {
				irt = parsed.ID
			}
		}
		resp := m.LoginResponse("", email, samlTemplateOverrides{Audience: q.Get("audience"), Destination: q.Get("destination"),
			SubjectRecipient: q.Get("recipient"), InResponseTo: &irt})
		writeJSON(w, 200, map[string]any{"samlResponse": resp, "entityEndpoint": "http://localhost:3001/api/sso/saml2/sp/acs"})
	case "/api/sso/saml2/idp/metadata":
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(m.MetadataXML))
	default:
		http.NotFound(w, r)
	}
}

// verifyRedirectSignature verifies a redirect-binding signature over the raw query.
func verifyRedirectSignature(rawQuery, keyPEM, pass string) bool {
	idx := strings.Index(rawQuery, "&Signature=")
	if idx < 0 {
		return false
	}
	signed := rawQuery[:idx]
	sig, err := url.QueryUnescape(rawQuery[idx+len("&Signature="):])
	if err != nil {
		return false
	}
	signer, err := samlify.ParsePrivateKey(keyPEM, pass)
	if err != nil {
		return false
	}
	key, ok := signer.(*rsa.PrivateKey)
	if !ok {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	sum := sha256.Sum256([]byte(signed))
	return rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], raw) == nil
}

// fetchSAMLResponse calls the mock IdP sign-in URL and returns the SAMLResponse.
func fetchSAMLResponse(t *testing.T, signInURL string) (string, int, map[string]any) {
	t.Helper()
	res, err := http.Get(signInURL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	s, _ := body["samlResponse"].(string)
	return s, res.StatusCode, body
}

func adapterFindAll(model string) adapter.FindManyInput { return adapter.FindManyInput{Model: model} }
