package wechat

import (
	"context"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

var ctx = context.Background()

func opts() Options {
	return Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "wx-app", ClientSecret: "wx-secret"}}
}

func withOpenID(openid string) oauth2.UserInfoParams {
	return oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "access-token", Raw: map[string]any{"openid": openid}}}
}

func TestIdentity(t *testing.T) {
	p := New(opts())
	if p.ID() != "wechat" || p.Name() != "WeChat" {
		t.Fatalf("%q %q", p.ID(), p.Name())
	}
	if oauth2.SupportsIDTokenSignIn(p) {
		t.Fatal("no id token sign-in")
	}
}

// social-providers.test.ts: "preserves the manual authorize URL shape with appid and wechat_redirect fragment"
func TestAuthorizationURLShape(t *testing.T) {
	p := New(Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "wx-app-1", ClientSecret: "secret"}})
	u, err := p.CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{State: "state-xyz", CodeVerifier: strings.Repeat("v", 64), RedirectURI: "https://app.example/callback"})
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme+"://"+u.Host+u.Path != AuthorizationEndpoint {
		t.Fatalf("endpoint %s", u)
	}
	q := u.Query()
	want := map[string]string{"appid": "wx-app-1", "response_type": "code", "scope": "snsapi_login", "lang": "cn", "state": "state-xyz", "redirect_uri": "https://app.example/callback"}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if u.Fragment != "wechat_redirect" || !strings.HasSuffix(u.String(), "#wechat_redirect") {
		t.Fatalf("fragment %s", u)
	}
	for _, k := range []string{"client_id", "code_challenge"} {
		if q.Has(k) {
			t.Errorf("unexpected %s", k)
		}
	}
}

// social-providers.test.ts: "forwards additionalParams but drops reserved keys and appid"
func TestAuthorizationURLAdditionalParams(t *testing.T) {
	p := New(Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "wx-app-1", ClientSecret: "secret"}})
	u, _ := p.CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{State: "state-xyz", RedirectURI: "r",
		AdditionalParams: map[string]string{"custom": "value", "state": "attacker", "appid": "attacker-app"}})
	q := u.Query()
	if q.Get("custom") != "value" || q.Get("state") != "state-xyz" || q.Get("appid") != "wx-app-1" {
		t.Fatalf("query %v", q)
	}
}

func TestAuthorizationURLLangScopesRedirect(t *testing.T) {
	o := opts()
	o.Lang = "en"
	o.Scope = []string{"snsapi_userinfo"}
	o.RedirectURI = "https://override/cb"
	u, _ := New(o).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{State: "s", RedirectURI: "r"})
	q := u.Query()
	if q.Get("lang") != "en" || q.Get("scope") != "snsapi_login,snsapi_userinfo" || q.Get("redirect_uri") != "https://override/cb" {
		t.Fatalf("query %v", q)
	}
}

func TestValidateAuthorizationCode(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.weixin.qq.com/sns/oauth2/access_token", 200, map[string]any{
		"access_token": "at", "expires_in": 7200, "refresh_token": "rt", "openid": "open-1", "scope": "snsapi_login,snsapi_userinfo", "unionid": "union-1",
	})
	tokens, err := New(opts()).ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "the-code", CodeVerifier: "v", RedirectURI: "r"})
	if err != nil {
		t.Fatal(err)
	}
	if tokens.TokenType != "Bearer" || tokens.AccessToken != "at" || tokens.RefreshToken != "rt" || tokens.AccessTokenExpiresAt == nil ||
		strings.Join(tokens.Scopes, " ") != "snsapi_login snsapi_userinfo" || tokens.Raw["openid"] != "open-1" || tokens.Raw["unionid"] != "union-1" {
		t.Fatalf("tokens %+v", tokens)
	}
	r := m.Last("api.weixin.qq.com/sns/oauth2/access_token")
	if r.Method != "GET" || r.URL.RawQuery != "appid=wx-app&secret=wx-secret&code=the-code&grant_type=authorization_code" {
		t.Fatalf("request %s %s", r.Method, r.URL.RawQuery)
	}

	m.JSON("GET api.weixin.qq.com/sns/oauth2/access_token", 200, map[string]any{"errcode": 40029, "errmsg": "invalid code"})
	_, err = New(opts()).ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "bad"})
	if err == nil || err.Error() != "Failed to validate authorization code: invalid code" {
		t.Fatalf("err %v", err)
	}
	m.JSON("GET api.weixin.qq.com/sns/oauth2/access_token", 500, map[string]any{})
	_, err = New(opts()).ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "bad"})
	if err == nil || err.Error() != "Failed to validate authorization code: Unknown error" {
		t.Fatalf("err %v", err)
	}
}

func TestRefreshAccessToken(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.weixin.qq.com/sns/oauth2/refresh_token", 200, map[string]any{
		"access_token": "new-at", "expires_in": 7200, "refresh_token": "new-rt", "openid": "open-1", "scope": "snsapi_login",
	})
	tokens, err := New(opts()).RefreshAccessToken(ctx, "old-rt", nil)
	if err != nil || tokens.AccessToken != "new-at" || tokens.RefreshToken != "new-rt" || tokens.TokenType != "Bearer" || tokens.Scopes[0] != "snsapi_login" {
		t.Fatalf("%+v %v", tokens, err)
	}
	r := m.Last("api.weixin.qq.com/sns/oauth2/refresh_token")
	if r.URL.RawQuery != "appid=wx-app&grant_type=refresh_token&refresh_token=old-rt" {
		t.Fatalf("query %s", r.URL.RawQuery)
	}
	m.JSON("GET api.weixin.qq.com/sns/oauth2/refresh_token", 200, map[string]any{"errcode": 42002, "errmsg": "refresh_token expired"})
	if _, err := New(opts()).RefreshAccessToken(ctx, "x", nil); err == nil || err.Error() != "Failed to refresh access token: refresh_token expired" {
		t.Fatalf("err %v", err)
	}
	o := opts()
	o.RefreshAccessToken = func(context.Context, string) (*oauth2.Tokens, error) {
		return &oauth2.Tokens{AccessToken: "custom"}, nil
	}
	if tk, _ := New(o).RefreshAccessToken(ctx, "x", nil); tk.AccessToken != "custom" {
		t.Fatal("override ignored")
	}
}

// wechat.test.ts: "creates a non-routable placeholder email keyed to unionid"
func TestGetUserInfoPlaceholderUnionID(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.weixin.qq.com/sns/userinfo", 200, map[string]any{"openid": "open-123", "unionid": "union-abc", "nickname": "WeChat User", "headimgurl": "https://example.com/avatar.png"})
	p := New(opts())
	res, err := p.GetUserInfo(ctx, withOpenID("open-123"))
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	if res.User.Email != "union-abc@wechat.placeholder.invalid" || res.User.EmailVerified || res.User.Name != "WeChat User" || res.User.Image != "https://example.com/avatar.png" {
		t.Fatalf("user %+v", res.User)
	}
	if _, ok := res.User.Extra["id"]; ok {
		t.Fatal("user must not carry id")
	}
	sub, err := p.AccountSubject(ctx, &oauth2.Tokens{AccessToken: "access-token"}, res.Data)
	if err != nil || sub != "union-abc" {
		t.Fatalf("subject %q %v", sub, err)
	}
	r := m.Last("api.weixin.qq.com/sns/userinfo")
	if r.URL.RawQuery != "access_token=access-token&openid=open-123&lang=zh_CN" {
		t.Fatalf("query %s", r.URL.RawQuery)
	}
}

// wechat.test.ts: "falls back to openid for the placeholder when unionid is absent"
func TestGetUserInfoPlaceholderOpenID(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.weixin.qq.com/sns/userinfo", 200, map[string]any{"openid": "open-456", "nickname": "No Union", "headimgurl": "https://example.com/avatar.png"})
	p := New(opts())
	res, err := p.GetUserInfo(ctx, withOpenID("open-456"))
	if err != nil || res == nil || res.User.Email != "open-456@wechat.placeholder.invalid" || res.User.EmailVerified {
		t.Fatalf("%+v %v", res, err)
	}
	if sub, _ := p.AccountSubject(ctx, nil, res.Data); sub != "open-456" {
		t.Fatalf("subject %q", sub)
	}
}

// wechat.test.ts: "lets mapProfileToUser supply a real email"
func TestGetUserInfoMapProfileToUser(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.weixin.qq.com/sns/userinfo", 200, map[string]any{"openid": "open-789", "unionid": "union-xyz", "nickname": "Mapped User", "headimgurl": "https://example.com/avatar.png"})
	o := opts()
	o.MapProfileToUser = func(map[string]any) (map[string]any, error) { return map[string]any{"email": "real@example.com"}, nil }
	res, err := New(o).GetUserInfo(ctx, withOpenID("open-789"))
	if err != nil || res == nil || res.User.Email != "real@example.com" {
		t.Fatalf("%+v %v", res, err)
	}
}

// wechat.test.ts: "returns null when the token carries no openid"
func TestGetUserInfoWithoutOpenID(t *testing.T) {
	m := oauth2test.New(t)
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "access-token"}})
	if err != nil || res != nil {
		t.Fatalf("%v %v", res, err)
	}
	if len(m.Requests) != 0 {
		t.Fatal("no request expected")
	}
}

func TestGetUserInfoErrcodeAndOverride(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.weixin.qq.com/sns/userinfo", 200, map[string]any{"errcode": 40003, "errmsg": "invalid openid"})
	res, err := New(opts()).GetUserInfo(ctx, withOpenID("x"))
	if err != nil || res != nil {
		t.Fatalf("%v %v", res, err)
	}
	o := opts()
	o.GetUserInfo = func(context.Context, *oauth2.Tokens) (*oauth2.UserInfoResult, error) {
		return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: "custom"}}, nil
	}
	res, _ = New(o).GetUserInfo(ctx, oauth2.UserInfoParams{})
	if res == nil || res.User.Name != "custom" {
		t.Fatal("override ignored")
	}
}

func TestFullFlowCarriesOpenID(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.weixin.qq.com/sns/oauth2/access_token", 200, map[string]any{"access_token": "at", "expires_in": 7200, "refresh_token": "rt", "openid": "open-9", "scope": "snsapi_login"})
	m.JSON("GET api.weixin.qq.com/sns/userinfo", 200, map[string]any{"openid": "open-9", "nickname": "Flow"})
	p := New(opts())
	tokens, err := p.ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "c"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := p.GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: *tokens})
	if err != nil || res == nil || res.User.Name != "Flow" {
		t.Fatalf("%+v %v", res, err)
	}
}
