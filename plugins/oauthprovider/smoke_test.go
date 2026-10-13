package oauthprovider

import (
	"net/url"
	"strings"
	"testing"
)

// End-to-end smoke test of the authorization code flow with PKCE, refresh, userinfo,
// introspection and revocation (Go-specific; the ported upstream suites cover details).
func TestSmokeAuthorizationCodeFlow(t *testing.T) {
	env := newEnv(t, Options{AllowDynamicClientRegistration: true})
	h := env.signInWithTestUser()
	client := env.createClient(h, map[string]any{
		"redirect_uris": []any{"https://rp.example.com/callback"},
		"skip_consent":  true,
	})
	clientID, _ := client["client_id"].(string)
	secret, _ := client["client_secret"].(string)
	if clientID == "" || secret == "" {
		t.Fatalf("client: %v", client)
	}
	verifier, challenge := pkcePair()
	// consent required (create-client ignores skip_consent): expect redirect to consent page.
	res := env.do("GET", authorizeURL("response_type", "code", "client_id", clientID, "redirect_uri",
		"https://rp.example.com/callback", "scope", "openid profile email offline_access", "state", "abc",
		"code_challenge", challenge, "code_challenge_method", "S256"), nil, h)
	if res.status != 302 || !strings.HasPrefix(res.location(), "/consent?") {
		t.Fatalf("authorize: %d %q %s", res.status, res.location(), res.body)
	}
	q := strings.TrimPrefix(res.location(), "/consent?")
	consentRes := env.do("POST", "/oauth2/consent", map[string]any{"accept": true, "oauth_query": q}, h)
	cm := consentRes.json()
	if consentRes.status != 200 {
		t.Fatalf("consent: %d %s", consentRes.status, consentRes.body)
	}
	u, _ := url.Parse(cm["url"].(string))
	code := u.Query().Get("code")
	if code == "" || u.Query().Get("state") != "abc" || u.Query().Get("iss") != testAuthBase {
		t.Fatalf("consent result: %v", cm)
	}
	tok := env.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"redirect_uri": {"https://rp.example.com/callback"}}, basicAuth(clientID, secret))
	if tok.status != 200 {
		t.Fatalf("token: %d %s", tok.status, tok.body)
	}
	tm := tok.json()
	for _, k := range []string{"access_token", "refresh_token", "id_token"} {
		if tm[k] == nil {
			t.Fatalf("missing %s: %s", k, tok.body)
		}
	}
	idc := decodeJWTPayload(t, tm["id_token"].(string))
	if idc["aud"] != clientID || idc["iss"] != testAuthBase {
		t.Fatalf("id token claims: %v", idc)
	}
	ui := env.do("GET", "/oauth2/userinfo", nil, map[string][]string{"Authorization": {"Bearer " + tm["access_token"].(string)}})
	if ui.status != 200 || ui.json()["email"] != testUserEmail {
		t.Fatalf("userinfo: %d %s", ui.status, ui.body)
	}
	in := env.do("POST", "/oauth2/introspect", url.Values{"token": {tm["access_token"].(string)}}, basicAuth(clientID, secret))
	if in.status != 200 || in.json()["active"] != true {
		t.Fatalf("introspect: %d %s", in.status, in.body)
	}
	rt := env.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tm["refresh_token"].(string)}}, basicAuth(clientID, secret))
	if rt.status != 200 {
		t.Fatalf("refresh: %d %s", rt.status, rt.body)
	}
	rv := env.do("POST", "/oauth2/revoke", url.Values{"token": {rt.json()["access_token"].(string)}}, basicAuth(clientID, secret))
	if rv.status != 200 {
		t.Fatalf("revoke: %d %s", rv.status, rv.body)
	}
	in2 := env.do("POST", "/oauth2/introspect", url.Values{"token": {rt.json()["access_token"].(string)}}, basicAuth(clientID, secret))
	if in2.json()["active"] != false {
		t.Fatalf("introspect after revoke: %s", in2.body)
	}
	md := env.do("GET", testBaseURL+"/api/auth/.well-known/openid-configuration", nil, nil)
	if md.status != 200 || md.json()["issuer"] != testAuthBase {
		t.Fatalf("discovery: %d %s", md.status, md.body)
	}
}
