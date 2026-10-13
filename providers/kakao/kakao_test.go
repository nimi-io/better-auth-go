package kakao

import (
	"context"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

const (
	callback = "https://app.example/callback"
	state    = "state-xyz"
)

var verifier = strings.Repeat("v", 64)

func newProvider(mut ...func(*Options)) *oauth2.GenericProvider {
	o := Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "client-123", ClientSecret: "secret-abc"}}
	for _, m := range mut {
		m(&o)
	}
	return New(o)
}

func TestIdentity(t *testing.T) {
	p := newProvider()
	if p.ID() != "kakao" || p.Name() != "Kakao" {
		t.Fatalf("got %q %q", p.ID(), p.Name())
	}
	if p.S.Subject == nil {
		t.Fatal("kakao must declare a stable account subject")
	}
	if !p.SupportsRefresh() || p.SupportsIDToken() {
		t.Fatal("capabilities mismatch")
	}
}

func TestAuthorizationURL(t *testing.T) {
	p := newProvider(func(o *Options) { o.Prompt = "consent" })
	u, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{
		State: state, CodeVerifier: verifier, RedirectURI: callback, LoginHint: "hint",
		Scopes: []string{"talk_message"}, AdditionalParams: map[string]string{"custom": "value", "state": "attacker"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != AuthorizationEndpoint {
		t.Fatalf("endpoint %s", got)
	}
	q := u.Query()
	want := map[string]string{
		"response_type": "code", "client_id": "client-123", "state": state, "redirect_uri": callback,
		"scope": "account_email profile_image profile_nickname talk_message", "custom": "value",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	// upstream forwards neither PKCE, login hint nor prompt
	for _, k := range []string{"code_challenge", "code_challenge_method", "login_hint", "prompt"} {
		if q.Has(k) {
			t.Errorf("unexpected %s", k)
		}
	}
	wantRaw := "response_type=code&client_id=client-123&state=state-xyz&scope=account_email+profile_image+profile_nickname+talk_message&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&custom=value"
	if u.RawQuery != wantRaw {
		t.Errorf("raw query\n got %s\nwant %s", u.RawQuery, wantRaw)
	}
}

func TestAuthorizationURLOptions(t *testing.T) {
	p := newProvider(func(o *Options) {
		o.DisableDefaultScope = true
		o.Scope = []string{"friends"}
		o.RedirectURI = "https://override.example/cb"
		o.AuthorizationEndpoint = "https://proxy.example/authorize"
	})
	u, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, RedirectURI: callback})
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "proxy.example" || u.Query().Get("scope") != "friends" || u.Query().Get("redirect_uri") != "https://override.example/cb" {
		t.Fatalf("got %s", u)
	}
	p = newProvider(func(o *Options) { o.DisableDefaultScope = true })
	u, _ = p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, RedirectURI: callback})
	if u.Query().Has("scope") {
		t.Fatal("empty scopes must omit scope")
	}
	_, err = New(Options{}).CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, RedirectURI: callback})
	if err == nil || err.Error() != "OAuth provider requires clientId" {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateAuthorizationCode(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST kauth.kakao.com/oauth/token", 200, map[string]any{
		"access_token": "at", "refresh_token": "rt", "token_type": "bearer", "expires_in": 21599,
		"refresh_token_expires_in": 5183999, "scope": "account_email profile_nickname",
	})
	p := newProvider(func(o *Options) { o.ClientKey = "ck" })
	tok, err := p.ValidateAuthorizationCode(context.Background(), oauth2.CodeParams{Code: "auth-code", CodeVerifier: verifier, RedirectURI: callback, DeviceID: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "at" || tok.RefreshToken != "rt" || tok.AccessTokenExpiresAt == nil || tok.RefreshTokenExpiresAt == nil || len(tok.Scopes) != 2 {
		t.Fatalf("tokens %+v", tok)
	}
	r := m.Last("kauth.kakao.com/oauth/token")
	f := r.Form
	if f.Get("grant_type") != "authorization_code" || f.Get("code") != "auth-code" || f.Get("redirect_uri") != callback ||
		f.Get("client_id") != "client-123" || f.Get("client_secret") != "secret-abc" || f.Get("client_key") != "ck" {
		t.Fatalf("form %v", f)
	}
	if f.Has("code_verifier") || f.Has("device_id") {
		t.Fatalf("kakao does not forward code_verifier/device_id: %v", f)
	}
	if r.Header.Get("Authorization") != "" {
		t.Fatal("client_secret_post expected")
	}

	// options.redirectURI wins
	p = newProvider(func(o *Options) { o.RedirectURI = "https://override.example/cb" })
	_, _ = p.ValidateAuthorizationCode(context.Background(), oauth2.CodeParams{Code: "c", RedirectURI: callback})
	if got := m.Last("kauth.kakao.com/oauth/token").Form.Get("redirect_uri"); got != "https://override.example/cb" {
		t.Fatalf("redirect_uri %s", got)
	}
}

func TestValidateAuthorizationCodeError(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("kauth.kakao.com/oauth/token", 400, map[string]any{"error": "invalid_grant", "error_description": "bad code"})
	if _, err := newProvider().ValidateAuthorizationCode(context.Background(), oauth2.CodeParams{Code: "c", RedirectURI: callback}); err == nil {
		t.Fatal("expected error")
	}
}

var profile = map[string]any{
	"id":           float64(1234567890),
	"connected_at": "2024-01-01T00:00:00Z",
	"kakao_account": map[string]any{
		"profile": map[string]any{
			"nickname": "Nick", "thumbnail_image_url": "https://img/thumb.jpg", "profile_image_url": "https://img/full.jpg",
		},
		"name": "Real Name", "email": "user@kakao.com", "is_email_valid": true, "is_email_verified": true,
	},
}

func TestGetUserInfo(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET kapi.kakao.com/v2/user/me", 200, profile)
	p := newProvider()
	res, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || res == nil {
		t.Fatalf("res=%v err=%v", res, err)
	}
	if h := m.Last("kapi.kakao.com/v2/user/me").Header.Get("Authorization"); h != "Bearer at" {
		t.Fatalf("auth header %q", h)
	}
	u := res.User
	if u.Name != "Nick" || u.Email != "user@kakao.com" || u.Image != "https://img/full.jpg" || !u.EmailVerified {
		t.Fatalf("user %+v", u)
	}
	sub, err := p.AccountSubject(context.Background(), nil, res.Data)
	if err != nil || sub != "1234567890" {
		t.Fatalf("subject %q %v", sub, err)
	}
}

func TestGetUserInfoFallbacks(t *testing.T) {
	m := oauth2test.New(t)
	cases := []struct {
		account  map[string]any
		name     string
		image    string
		verified bool
	}{
		{map[string]any{"name": "Real", "profile": map[string]any{"thumbnail_image_url": "t"}, "is_email_valid": true}, "Real", "t", false},
		{map[string]any{"is_email_verified": true, "is_email_valid": false}, "", "", false},
		{nil, "", "", false},
	}
	for i, c := range cases {
		body := map[string]any{"id": float64(1)}
		if c.account != nil {
			body["kakao_account"] = c.account
		}
		m.JSON("kapi.kakao.com/v2/user/me", 200, body)
		res, err := newProvider().GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
		if err != nil || res == nil {
			t.Fatalf("%d: %v %v", i, res, err)
		}
		if res.User.Name != c.name || res.User.Image != c.image || res.User.EmailVerified != c.verified || res.User.Email != "" {
			t.Errorf("%d: %+v", i, res.User)
		}
	}
}

func TestGetUserInfoError(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("kapi.kakao.com/v2/user/me", 401, map[string]any{"msg": "this access token does not exist", "code": -401})
	res, err := newProvider().GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "x"}})
	if res != nil || err != nil {
		t.Fatalf("expected null, got %v %v", res, err)
	}
}

func TestMapProfileToUser(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("kapi.kakao.com/v2/user/me", 200, profile)
	p := newProvider(func(o *Options) {
		o.MapProfileToUser = func(pr map[string]any) (map[string]any, error) {
			return map[string]any{"name": "Mapped", "emailVerified": false, "kakaoId": pr["id"], "id": "ignored"}, nil
		}
	})
	res, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.User.Name != "Mapped" || res.User.EmailVerified || res.User.Email != "user@kakao.com" || res.User.Extra["kakaoId"] != float64(1234567890) {
		t.Fatalf("user %+v", res.User)
	}
	if _, ok := res.User.Extra["id"]; ok {
		t.Fatal("id must not be mapped")
	}
}

func TestGetUserInfoOverride(t *testing.T) {
	oauth2test.New(t)
	p := newProvider(func(o *Options) {
		o.GetUserInfo = func(_ context.Context, tok *oauth2.Tokens) (*oauth2.UserInfoResult, error) {
			return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: tok.AccessToken}, Data: map[string]any{"id": "custom"}}, nil
		}
	})
	res, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "custom-at"}})
	if err != nil || res.User.Name != "custom-at" {
		t.Fatalf("%v %v", res, err)
	}
}

func TestRefreshAccessToken(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST kauth.kakao.com/oauth/token", 200, map[string]any{"access_token": "new-at", "refresh_token": "new-rt", "token_type": "bearer", "expires_in": 3600})
	p := newProvider(func(o *Options) { o.ClientKey = "ck" })
	tok, err := p.RefreshAccessToken(context.Background(), "old-rt", nil)
	if err != nil || tok.AccessToken != "new-at" || tok.RefreshToken != "new-rt" || tok.AccessTokenExpiresAt == nil {
		t.Fatalf("%+v %v", tok, err)
	}
	f := m.Last("kauth.kakao.com/oauth/token").Form
	if f.Get("grant_type") != "refresh_token" || f.Get("refresh_token") != "old-rt" || f.Get("client_id") != "client-123" ||
		f.Get("client_secret") != "secret-abc" || f.Has("client_key") {
		t.Fatalf("form %v", f)
	}

	called := false
	p = newProvider(func(o *Options) {
		o.RefreshAccessToken = func(_ context.Context, rt string) (*oauth2.Tokens, error) {
			called = true
			return &oauth2.Tokens{AccessToken: "custom-" + rt}, nil
		}
	})
	tok, _ = p.RefreshAccessToken(context.Background(), "rt", nil)
	if !called || tok.AccessToken != "custom-rt" {
		t.Fatal("override not used")
	}
}
