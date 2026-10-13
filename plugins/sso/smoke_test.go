package sso

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
)

func TestSmokeOIDCFlow(t *testing.T) {
	idp := newMockOIDC(t)
	idp.BeforeTokenSigning = func(p map[string]any, _ *http.Request) {
		p["sub"] = "oauth2"
		p["email"] = "sso-user@localhost.com"
		p["email_verified"] = true
		p["name"] = "Test User"
	}
	idp.BeforeUserinfo = func(r *mockResponse, _ *http.Request) {
		r.Body = map[string]any{"sub": "oauth2", "email": "sso-user@localhost.com", "email_verified": true, "name": "OAuth2 Test"}
	}
	env := newEnv(t, Options{}, envConfig{mutate: func(c *betterauth.Config) { c.TrustedOrigins = []string{idp.URL} }})
	h := env.signInTestUser()
	reg := env.mustAPI("registerSSOProvider", h, map[string]any{
		"issuer": idp.URL, "domain": "localhost.com", "providerId": "test",
		"oidcConfig": map[string]any{"clientId": "test", "clientSecret": "test"},
	}, nil)
	if reg.m()["redirectURI"] != env.baseURL+"/sso/callback/test" {
		t.Fatalf("register: %s", reg.Raw)
	}
	res := env.do("POST", "/sign-in/sso", nil, map[string]any{"email": "my-email@localhost.com", "callbackURL": "/dashboard"})
	if res.Err != nil {
		t.Fatalf("signin: %s", res.Raw)
	}
	authURL, _ := res.m()["url"].(string)
	if !strings.HasPrefix(authURL, idp.URL+"/authorize") {
		t.Fatalf("url %s", authURL)
	}
	flow := env.simulateOAuthFlow(authURL, cookieHeaders(res.Headers))
	if flow.CallbackURL != "/dashboard" {
		t.Fatalf("callback %d %q", flow.Status, flow.CallbackURL)
	}
	s := env.session(flow.Headers)
	if s == nil || s.User.Email != "sso-user@localhost.com" {
		t.Fatalf("session %+v", s)
	}
}

func TestSmokeSAMLFlow(t *testing.T) {
	idp := newMockSAMLIdP(t, mockSAMLOptions{})
	env := newEnv(t, Options{SAML: &SAMLOptions{EnableInResponseToValidation: betterauth.Bool(false)}})
	h := env.signInTestUser()
	reg := env.api("registerSSOProvider", h, map[string]any{
		"providerId": "saml-provider-1", "issuer": idp.URL, "domain": "localhost.com",
		"samlConfig": map[string]any{
			"entryPoint":           idp.URL + "/api/sso/saml2/idp/post",
			"cert":                 certificate,
			"callbackUrl":          "http://localhost:3000/dashboard",
			"wantAssertionsSigned": false, "signatureAlgorithm": "sha256", "digestAlgorithm": "sha256",
			"idpMetadata":      map[string]any{"metadata": idp.MetadataXML},
			"spMetadata":       map[string]any{"metadata": spMetadata},
			"identifierFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		},
	}, nil)
	if reg.Err != nil {
		t.Fatalf("register: %d %s", reg.Status, reg.Raw)
	}
	res := env.do("POST", "/sign-in/sso", nil, map[string]any{"providerId": "saml-provider-1", "callbackURL": "http://localhost:3000/dashboard"})
	if res.Err != nil {
		t.Fatalf("signin: %s", res.Raw)
	}
	signInURL, _ := res.m()["url"].(string)
	samlResp, status, body := fetchSAMLResponse(t, signInURL)
	if status != 200 {
		t.Fatalf("idp: %d %v", status, body)
	}
	u, _ := url.Parse(signInURL)
	acs := env.postForm("/sso/saml2/sp/acs/saml-provider-1", nil, url.Values{"SAMLResponse": {samlResp}, "RelayState": {u.Query().Get("RelayState")}})
	if acs.Status != 302 {
		t.Fatalf("acs: %d %s", acs.Status, acs.Raw)
	}
	t.Log("location", acs.location())
	s := env.session(cookieHeaders(acs.Headers))
	if s == nil || s.User.Email != "test@email.com" {
		t.Fatalf("session %+v location=%s", s, acs.location())
	}
}
