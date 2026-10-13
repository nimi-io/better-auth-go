package line

import (
	"context"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

var ctx = context.Background()

func opts() Options {
	return Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "line-channel", ClientSecret: "line-secret"}}
}

func TestIdentity(t *testing.T) {
	p := New(opts())
	if p.ID() != "line" || p.Name() != "LINE" {
		t.Fatalf("%q %q", p.ID(), p.Name())
	}
	if !oauth2.SupportsIDTokenSignIn(p) {
		t.Fatal("id token sign-in should be supported")
	}
	if _, ok := oauth2.AsRefresher(p); !ok {
		t.Fatal("refresh should be supported")
	}
}

func TestAuthorizationURL(t *testing.T) {
	o := opts()
	o.Scope = []string{"extra"}
	o.Prompt = "consent"
	u, err := New(o).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{
		State: "st", CodeVerifier: "verifier", RedirectURI: "https://app/cb", Scopes: []string{"more"},
		LoginHint: "U123", IDTokenNonce: "n1", AdditionalParams: map[string]string{"bot_prompt": "aggressive", "nonce": "attacker"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme+"://"+u.Host+u.Path != AuthorizationEndpoint {
		t.Fatalf("endpoint %s", u)
	}
	q := u.Query()
	want := map[string]string{"response_type": "code", "client_id": "line-channel", "state": "st", "redirect_uri": "https://app/cb",
		"scope": "openid profile email extra more", "login_hint": "U123", "code_challenge_method": "S256",
		"code_challenge": oauth2.GenerateCodeChallenge("verifier"), "bot_prompt": "aggressive"}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	// upstream sends neither a nonce nor the configured prompt
	for _, k := range []string{"nonce", "prompt"} {
		if q.Has(k) {
			t.Errorf("unexpected %s", k)
		}
	}
	o = opts()
	o.DisableDefaultScope = true
	o.RedirectURI = "https://override/cb"
	u, _ = New(o).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{State: "s", RedirectURI: "r"})
	if u.Query().Has("scope") || u.Query().Get("redirect_uri") != "https://override/cb" {
		t.Fatalf("query %v", u.Query())
	}
}

func TestValidateAuthorizationCode(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST api.line.me/oauth2/v2.1/token", 200, map[string]any{"access_token": "at", "refresh_token": "rt", "id_token": "idt", "expires_in": 2592000, "scope": "openid profile", "token_type": "Bearer"})
	tokens, err := New(opts()).ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "c", CodeVerifier: "verifier", RedirectURI: "https://app/cb"})
	if err != nil || tokens.AccessToken != "at" || tokens.IDToken != "idt" || len(tokens.Scopes) != 2 {
		t.Fatalf("%+v %v", tokens, err)
	}
	r := m.Last("api.line.me/oauth2/v2.1/token")
	want := map[string]string{"grant_type": "authorization_code", "code": "c", "code_verifier": "verifier", "redirect_uri": "https://app/cb", "client_id": "line-channel", "client_secret": "line-secret"}
	if len(r.Form) != len(want) {
		t.Fatalf("form %v", r.Form)
	}
	for k, v := range want {
		if r.Form.Get(k) != v {
			t.Errorf("%s = %q", k, r.Form.Get(k))
		}
	}
}

func TestRefreshAccessToken(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST api.line.me/oauth2/v2.1/token", 200, map[string]any{"access_token": "new-at", "refresh_token": "new-rt"})
	tokens, err := New(opts()).RefreshAccessToken(ctx, "old-rt", nil)
	if err != nil || tokens.AccessToken != "new-at" {
		t.Fatalf("%+v %v", tokens, err)
	}
	r := m.Last("api.line.me/oauth2/v2.1/token")
	if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "old-rt" || r.Form.Get("client_id") != "line-channel" || r.Form.Get("client_secret") != "line-secret" {
		t.Fatalf("form %v", r.Form)
	}
	o := opts()
	o.RefreshAccessToken = func(context.Context, string) (*oauth2.Tokens, error) {
		return &oauth2.Tokens{AccessToken: "custom"}, nil
	}
	if tk, _ := New(o).RefreshAccessToken(ctx, "x", nil); tk.AccessToken != "custom" {
		t.Fatal("override ignored")
	}
}

func TestVerifyIDToken(t *testing.T) {
	m := oauth2test.New(t)
	p := New(opts())
	m.JSON("POST api.line.me/oauth2/v2.1/verify", 200, map[string]any{"iss": "https://access.line.me", "sub": "U1", "aud": "line-channel", "nonce": "n1"})
	if ok, err := p.VerifyIDToken(ctx, "the-id-token", "n1"); !ok || err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	r := m.Last("api.line.me/oauth2/v2.1/verify")
	if r.Method != "POST" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" ||
		r.Body != "id_token=the-id-token&client_id=line-channel&nonce=n1" {
		t.Fatalf("request %s %v %q", r.Method, r.Header, r.Body)
	}
	// response nonce mismatch
	if ok, _ := p.VerifyIDToken(ctx, "the-id-token", "other"); ok {
		t.Fatal("nonce mismatch accepted")
	}
	// response nonce present but none expected
	if ok, _ := p.VerifyIDToken(ctx, "the-id-token", ""); ok {
		t.Fatal("unexpected nonce accepted")
	}
	if !m.Last("api.line.me/oauth2/v2.1/verify").Form.Has("id_token") || m.Last("api.line.me/oauth2/v2.1/verify").Form.Has("nonce") {
		t.Fatal("nonce must be omitted when empty")
	}
	// no nonce in response: accepted regardless of expected nonce
	m.JSON("POST api.line.me/oauth2/v2.1/verify", 200, map[string]any{"sub": "U1", "aud": "line-channel"})
	if ok, _ := p.VerifyIDToken(ctx, "t", "n1"); !ok {
		t.Fatal("token without nonce rejected")
	}
	// audience mismatch
	m.JSON("POST api.line.me/oauth2/v2.1/verify", 200, map[string]any{"sub": "U1", "aud": "other-channel"})
	if ok, _ := p.VerifyIDToken(ctx, "t", ""); ok {
		t.Fatal("audience mismatch accepted")
	}
	// verify endpoint error
	m.JSON("POST api.line.me/oauth2/v2.1/verify", 400, map[string]any{"error": "invalid_request", "error_description": "Invalid IdToken."})
	if ok, err := p.VerifyIDToken(ctx, "t", ""); ok || err != nil {
		t.Fatalf("error response: %v %v", ok, err)
	}
	// overrides
	o := opts()
	o.VerifyIDToken = func(context.Context, string, string) (bool, error) { return true, nil }
	if ok, _ := New(o).VerifyIDToken(ctx, "t", ""); !ok {
		t.Fatal("verifyIdToken override ignored")
	}
	o = opts()
	o.DisableIDTokenSignIn = true
	if oauth2.SupportsIDTokenSignIn(New(o)) {
		t.Fatal("disableIdTokenSignIn ignored")
	}
}

func TestGetUserInfoFromIDToken(t *testing.T) {
	m := oauth2test.New(t)
	idt := m.IDToken(map[string]any{"iss": "https://access.line.me", "sub": "U1", "aud": "line-channel", "name": "Line User", "picture": "https://profile.line-scdn.net/a", "email": "line@example.com"})
	p := New(opts())
	res, err := p.GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at", IDToken: idt}})
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	if res.User.Name != "Line User" || res.User.Email != "line@example.com" || res.User.Image != "https://profile.line-scdn.net/a" || res.User.EmailVerified {
		t.Fatalf("user %+v", res.User)
	}
	if len(m.Requests) != 0 {
		t.Fatal("userinfo endpoint must not be called when the id token decodes")
	}
	if sub, _ := p.AccountSubject(ctx, nil, res.Data); sub != "U1" {
		t.Fatalf("subject %q", sub)
	}
}

func TestGetUserInfoFallsBackToUserInfoEndpoint(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.line.me/oauth2/v2.1/userinfo", 200, map[string]any{"sub": "U2", "picture": "https://pic"})
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at", IDToken: "not-a-jwt"}})
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	if res.User.Name != "" || res.User.Email != "" || res.User.Image != "https://pic" {
		t.Fatalf("user %+v", res.User)
	}
	if got := m.Last("api.line.me/oauth2/v2.1/userinfo").Header.Get("Authorization"); got != "Bearer at" {
		t.Fatalf("authorization %q", got)
	}
	m.JSON("GET api.line.me/oauth2/v2.1/userinfo", 401, map[string]any{"error": "invalid_token"})
	res, err = New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "bad"}})
	if err != nil || res != nil {
		t.Fatalf("%v %v", res, err)
	}
}

func TestMapProfileToUserAndGetUserInfoOverride(t *testing.T) {
	m := oauth2test.New(t)
	idt := m.IDToken(map[string]any{"sub": "U1", "name": "Line User", "amr": []any{"linesso"}})
	o := opts()
	o.MapProfileToUser = func(p map[string]any) (map[string]any, error) {
		return map[string]any{"email": "U1@line.example", "emailVerified": true, "amr": p["amr"]}, nil
	}
	res, err := New(o).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: idt}})
	if err != nil || res.User.Email != "U1@line.example" || !res.User.EmailVerified || res.User.Name != "Line User" || res.User.Extra["amr"] == nil {
		t.Fatalf("%+v %v", res, err)
	}
	o = opts()
	o.GetUserInfo = func(context.Context, *oauth2.Tokens) (*oauth2.UserInfoResult, error) {
		return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: "custom"}}, nil
	}
	if res, _ := New(o).GetUserInfo(ctx, oauth2.UserInfoParams{}); res == nil || res.User.Name != "custom" {
		t.Fatal("override ignored")
	}
}
