package facebook

import (
	"context"
	"errors"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

var ctx = context.Background()

func opts() Options {
	return Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "fb-app", ClientSecret: "fb-secret"}}
}

func fbProfile(id string) map[string]any {
	return map[string]any{
		"id": id, "name": "User " + id, "email": id + "@example.com",
		"picture": map[string]any{"data": map[string]any{"url": "https://x", "height": 100, "width": 100, "is_silhouette": false}},
	}
}

func debugToken(m *oauth2test.Server, data map[string]any) {
	m.JSON("GET graph.facebook.com/debug_token", 200, map[string]any{"data": data})
}

func countRequests(m *oauth2test.Server, hostPath string) int {
	n := 0
	for _, r := range m.Requests {
		if r.URL.Host+r.URL.Path == hostPath {
			n++
		}
	}
	return n
}

func TestIdentity(t *testing.T) {
	p := New(opts())
	if p.ID() != "facebook" || p.Name() != "Facebook" {
		t.Fatalf("id/name %q %q", p.ID(), p.Name())
	}
	if _, ok := oauth2.AsRefresher(p); !ok {
		t.Fatal("refresh should be supported")
	}
	if !oauth2.SupportsIDTokenSignIn(p) {
		t.Fatal("id token sign-in should be supported")
	}
}

func TestAuthorizationURL(t *testing.T) {
	o := opts()
	o.ConfigID = "cfg-1"
	o.Scope = []string{"user_birthday"}
	o.Prompt = "consent"
	p := New(o)
	u, err := p.CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{
		State: "st", CodeVerifier: "verifier", RedirectURI: "https://app.example/callback/facebook",
		Scopes: []string{"user_friends"}, LoginHint: "user@example.com",
		AdditionalParams: map[string]string{"auth_type": "rerequest", "state": "attacker"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme+"://"+u.Host+u.Path != AuthorizationEndpoint {
		t.Fatalf("endpoint %s", u)
	}
	q := u.Query()
	want := map[string]string{
		"response_type": "code", "client_id": "fb-app", "state": "st",
		"scope":        "email public_profile user_birthday user_friends",
		"redirect_uri": "https://app.example/callback/facebook", "login_hint": "user@example.com",
		"config_id": "cfg-1", "auth_type": "rerequest",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	// Facebook does not send PKCE or the configured prompt.
	for _, k := range []string{"code_challenge", "code_challenge_method", "prompt"} {
		if q.Has(k) {
			t.Errorf("unexpected %s", k)
		}
	}
}

func TestAuthorizationURLOverridesAndDisableDefaultScope(t *testing.T) {
	o := opts()
	o.DisableDefaultScope = true
	o.Scope = []string{"email"}
	o.RedirectURI = "https://override/cb"
	o.ConfigID = "cfg-1"
	p := New(o)
	u, err := p.CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{
		State: "st", RedirectURI: "https://app/cb", AdditionalParams: map[string]string{"config_id": "call-time"},
	})
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("scope") != "email" || q.Get("redirect_uri") != "https://override/cb" || q.Get("config_id") != "call-time" {
		t.Fatalf("query %v", q)
	}
}

func TestAuthorizationURLRequiresCredentials(t *testing.T) {
	for _, o := range []oauth2.ProviderOptions{{ClientID: "fb-app"}, {ClientSecret: "s"}} {
		_, err := New(Options{ProviderOptions: o}).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{State: "s", RedirectURI: "r"})
		if err == nil || err.Error() != "CLIENT_ID_AND_SECRET_REQUIRED" {
			t.Fatalf("err %v", err)
		}
	}
	// a clientId array satisfies the requirement
	u, err := New(Options{ProviderOptions: oauth2.ProviderOptions{ClientIDs: []string{"a", "b"}, ClientSecret: "s"}}).
		CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{State: "s", RedirectURI: "r"})
	if err != nil || u.Query().Get("client_id") != "a" {
		t.Fatalf("%v %v", u, err)
	}
}

func TestValidateAuthorizationCode(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST graph.facebook.com/v24.0/oauth/access_token", 200, map[string]any{"access_token": "at", "token_type": "bearer", "expires_in": 5183944})
	tokens, err := New(opts()).ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "the-code", CodeVerifier: "verifier", RedirectURI: "https://app/cb"})
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken != "at" || tokens.AccessTokenExpiresAt == nil {
		t.Fatalf("tokens %+v", tokens)
	}
	r := m.Last("graph.facebook.com/v24.0/oauth/access_token")
	want := map[string]string{"grant_type": "authorization_code", "code": "the-code", "redirect_uri": "https://app/cb", "client_id": "fb-app", "client_secret": "fb-secret"}
	for k, v := range want {
		if r.Form.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, r.Form.Get(k), v)
		}
	}
	if r.Form.Has("code_verifier") {
		t.Error("code_verifier must not be sent")
	}
}

func TestRefreshAccessToken(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST graph.facebook.com/v24.0/oauth/access_token", 200, map[string]any{"access_token": "new-at", "refresh_token": "new-rt"})
	tokens, err := New(opts()).RefreshAccessToken(ctx, "old-rt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken != "new-at" || tokens.RefreshToken != "new-rt" {
		t.Fatalf("tokens %+v", tokens)
	}
	r := m.Last("graph.facebook.com/v24.0/oauth/access_token")
	if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "old-rt" || r.Form.Get("client_id") != "fb-app" || r.Form.Get("client_secret") != "fb-secret" {
		t.Fatalf("form %v", r.Form)
	}

	o := opts()
	o.RefreshAccessToken = func(_ context.Context, rt string) (*oauth2.Tokens, error) {
		return &oauth2.Tokens{AccessToken: "custom-" + rt}, nil
	}
	tokens, err = New(o).RefreshAccessToken(ctx, "rt", nil)
	if err != nil || tokens.AccessToken != "custom-rt" {
		t.Fatalf("%+v %v", tokens, err)
	}
}

// facebook.test.ts: "returns the profile for a token bound to the configured app"
func TestGetUserInfoOpaqueTokenBoundToApp(t *testing.T) {
	m := oauth2test.New(t)
	debugToken(m, map[string]any{"is_valid": true, "app_id": "fb-app", "user_id": "u1"})
	m.JSON("GET graph.facebook.com/me", 200, fbProfile("u1"))
	p := New(opts())
	res, err := p.GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "opaque-access-token"}})
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	if res.User.Email != "u1@example.com" || res.User.Name != "User u1" || res.User.Image != "https://x" || res.User.EmailVerified {
		t.Fatalf("user %+v", res.User)
	}
	if _, ok := res.User.Extra["id"]; ok {
		t.Fatal("user must not carry id")
	}
	sub, err := p.AccountSubject(ctx, &oauth2.Tokens{AccessToken: "opaque-access-token"}, res.Data)
	if err != nil || sub != "u1" {
		t.Fatalf("subject %q %v", sub, err)
	}
	dbg := m.Last("graph.facebook.com/debug_token")
	if dbg.URL.Query().Get("input_token") != "opaque-access-token" || dbg.URL.Query().Get("access_token") != "fb-app|fb-secret" {
		t.Fatalf("debug_token query %v", dbg.URL.RawQuery)
	}
	me := m.Last("graph.facebook.com/me")
	if me.URL.Query().Get("fields") != "id,name,email,picture" || me.Header.Get("Authorization") != "Bearer opaque-access-token" {
		t.Fatalf("me request %s %v", me.URL, me.Header)
	}
	if countRequests(m, "graph.facebook.com/debug_token") != 1 || countRequests(m, "graph.facebook.com/me") != 1 {
		t.Fatal("expected exactly one debug_token and one /me request")
	}
}

// facebook.test.ts: "rejects a token issued to a different app (token substitution)"
func TestGetUserInfoRejectsForeignAppToken(t *testing.T) {
	m := oauth2test.New(t)
	debugToken(m, map[string]any{"is_valid": true, "app_id": "someone-elses-app", "user_id": "other-user"})
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "foreign-app-token"}})
	if err != nil || res != nil {
		t.Fatalf("%v %v", res, err)
	}
	if countRequests(m, "graph.facebook.com/me") != 0 || countRequests(m, "graph.facebook.com/debug_token") != 1 {
		t.Fatal("unexpected requests")
	}
}

// facebook.test.ts: "rejects when the profile id does not match the validated token"
func TestGetUserInfoRejectsProfileMismatch(t *testing.T) {
	m := oauth2test.New(t)
	debugToken(m, map[string]any{"is_valid": true, "app_id": "fb-app", "user_id": "u1"})
	m.JSON("GET graph.facebook.com/me", 200, fbProfile("a-different-user"))
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "opaque-access-token"}})
	if err != nil || res != nil {
		t.Fatalf("%v %v", res, err)
	}
}

// facebook.test.ts: "rejects when no access token is supplied"
func TestGetUserInfoRejectsMissingAccessToken(t *testing.T) {
	m := oauth2test.New(t)
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{})
	if err != nil || res != nil {
		t.Fatalf("%v %v", res, err)
	}
	if len(m.Requests) != 0 {
		t.Fatalf("unexpected requests %d", len(m.Requests))
	}
}

func TestGetUserInfoRejectsInvalidDebugToken(t *testing.T) {
	cases := []map[string]any{
		{"is_valid": false, "app_id": "fb-app", "user_id": "u1"},
		{"is_valid": true, "app_id": "fb-app"},
		{"is_valid": true, "user_id": "u1"},
		{"is_valid": "true", "app_id": "fb-app", "user_id": "u1"},
	}
	for _, c := range cases {
		m := oauth2test.New(t)
		debugToken(m, c)
		m.JSON("GET graph.facebook.com/me", 200, fbProfile("u1"))
		res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "t"}})
		if err != nil || res != nil {
			t.Fatalf("%v: %v %v", c, res, err)
		}
	}
	// debug_token failure
	m := oauth2test.New(t)
	m.JSON("GET graph.facebook.com/debug_token", 400, map[string]any{"error": map[string]any{"message": "bad"}})
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "t"}})
	if err != nil || res != nil {
		t.Fatalf("%v %v", res, err)
	}
	// no client secret: the token cannot be validated
	res, err = New(Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "fb-app"}}).
		GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "t"}})
	if err != nil || res != nil {
		t.Fatalf("%v %v", res, err)
	}
}

func TestGetUserInfoAcceptsSecondaryClientID(t *testing.T) {
	m := oauth2test.New(t)
	debugToken(m, map[string]any{"is_valid": true, "app_id": "ios-app", "user_id": "u1"})
	m.JSON("GET graph.facebook.com/me", 200, fbProfile("u1"))
	o := Options{ProviderOptions: oauth2.ProviderOptions{ClientIDs: []string{"web-app", "ios-app"}, ClientSecret: "fb-secret"}}
	res, err := New(o).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "t"}})
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	if got := m.Last("graph.facebook.com/debug_token").URL.Query().Get("access_token"); got != "web-app|fb-secret" {
		t.Fatalf("app access token %q", got)
	}
}

func TestGetUserInfoExtraFieldsAndEmailVerified(t *testing.T) {
	m := oauth2test.New(t)
	debugToken(m, map[string]any{"is_valid": true, "app_id": "fb-app", "user_id": "u1"})
	prof := fbProfile("u1")
	prof["email_verified"] = true
	prof["birthday"] = "01/01/1990"
	m.JSON("GET graph.facebook.com/me", 200, prof)
	o := opts()
	o.Fields = []string{"birthday", "gender"}
	o.MapProfileToUser = func(profile map[string]any) (map[string]any, error) {
		return map[string]any{"name": "Mapped", "birthday": profile["birthday"], "id": "ignored"}, nil
	}
	res, err := New(o).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "t"}})
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	if got := m.Last("graph.facebook.com/me").URL.Query().Get("fields"); got != "id,name,email,picture,birthday,gender" {
		t.Fatalf("fields %q", got)
	}
	if !res.User.EmailVerified || res.User.Name != "Mapped" || res.User.Extra["birthday"] != "01/01/1990" {
		t.Fatalf("user %+v", res.User)
	}
	if _, ok := res.User.Extra["id"]; ok {
		t.Fatal("mapped id must be ignored")
	}
}

func TestGetUserInfoLimitedLoginIDToken(t *testing.T) {
	m := oauth2test.New(t)
	idt := m.IDToken(map[string]any{"sub": "fb-user-1", "email": "limited@example.com", "name": "Limited User", "picture": "https://pic", "iss": Issuer, "aud": "fb-app"})
	p := New(opts())
	res, err := p.GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: idt, AccessToken: "ignored"}})
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	if res.User.Email != "limited@example.com" || res.User.Name != "Limited User" || res.User.Image != "https://pic" || res.User.EmailVerified {
		t.Fatalf("user %+v", res.User)
	}
	if len(m.Requests) != 0 {
		t.Fatal("limited login must not call the Graph API")
	}
	sub, _ := p.AccountSubject(ctx, nil, res.Data)
	if sub != "fb-user-1" {
		t.Fatalf("subject %q", sub)
	}

	o := opts()
	o.MapProfileToUser = func(map[string]any) (map[string]any, error) {
		return map[string]any{"emailVerified": true, "image": "https://mapped"}, nil
	}
	res, err = New(o).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: idt}})
	if err != nil || !res.User.EmailVerified || res.User.Image != "https://mapped" {
		t.Fatalf("%+v %v", res, err)
	}

	// a non-JWT id token falls back to the access-token path
	res, err = New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: "opaque"}})
	if err != nil || res != nil {
		t.Fatalf("%v %v", res, err)
	}
}

func TestMapProfileToUserError(t *testing.T) {
	m := oauth2test.New(t)
	idt := m.IDToken(map[string]any{"sub": "x"})
	o := opts()
	o.MapProfileToUser = func(map[string]any) (map[string]any, error) { return nil, errors.New("boom") }
	if _, err := New(o).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{IDToken: idt}}); err == nil {
		t.Fatal("expected mapper error")
	}
}

func TestGetUserInfoOverride(t *testing.T) {
	o := opts()
	o.GetUserInfo = func(_ context.Context, tk *oauth2.Tokens) (*oauth2.UserInfoResult, error) {
		return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: "custom " + tk.AccessToken}, Data: map[string]any{"id": "c1"}}, nil
	}
	res, err := New(o).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || res.User.Name != "custom at" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestVerifyIDToken(t *testing.T) {
	m := oauth2test.New(t)
	m.ServeJWKS("GET limited.facebook.com/.well-known/oauth/openid/jwks/")
	p := New(opts())
	good := m.IDToken(map[string]any{"sub": "u1", "iss": Issuer, "aud": "fb-app", "nonce": "n1"})
	if ok, err := p.VerifyIDToken(ctx, good, "n1"); !ok || err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if ok, _ := p.VerifyIDToken(ctx, good, "other-nonce"); ok {
		t.Fatal("nonce mismatch accepted")
	}
	for _, claims := range []map[string]any{
		{"sub": "u1", "iss": "https://evil", "aud": "fb-app"},
		{"sub": "u1", "iss": Issuer, "aud": "other-app"},
	} {
		if ok, _ := p.VerifyIDToken(ctx, m.IDToken(claims), ""); ok {
			t.Fatalf("token accepted: %v", claims)
		}
	}
	// opaque Graph access tokens are accepted (identity resolved via getUserInfo)
	if ok, err := p.VerifyIDToken(ctx, "EAAopaque", "n1"); !ok || err != nil {
		t.Fatal("opaque token rejected")
	}
	o := opts()
	o.DisableIDTokenSignIn = true
	if oauth2.SupportsIDTokenSignIn(New(o)) {
		t.Fatal("disableIdTokenSignIn ignored")
	}
	o = opts()
	o.VerifyIDToken = func(context.Context, string, string) (bool, error) { return false, nil }
	if ok, _ := New(o).VerifyIDToken(ctx, good, ""); ok {
		t.Fatal("verifyIdToken override ignored")
	}
}

func TestAccountSubject(t *testing.T) {
	p := New(opts())
	if s, _ := p.AccountSubject(ctx, nil, map[string]any{"id": "graph-id"}); s != "graph-id" {
		t.Fatalf("subject %q", s)
	}
	if s, _ := p.AccountSubject(ctx, nil, map[string]any{"sub": "jwt-sub", "id": "graph-id"}); s != "jwt-sub" {
		t.Fatalf("subject %q", s)
	}
}
