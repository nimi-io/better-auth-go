package discord

import (
	"context"
	"net/http"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

const (
	callback = "https://app.example/callback"
	state    = "state-xyz"
)

var verifier = func() string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = 'v'
	}
	return string(b)
}()

func creds() oauth2.ProviderOptions {
	return oauth2.ProviderOptions{ClientID: "client-123", ClientSecret: "secret-abc"}
}

func baseInput() oauth2.AuthorizationURLParams {
	return oauth2.AuthorizationURLParams{State: state, CodeVerifier: verifier, RedirectURI: callback}
}

func TestIdentity(t *testing.T) {
	p := New(Options{ProviderOptions: creds()})
	if p.ID() != "discord" || p.Name() != "Discord" {
		t.Fatalf("id/name %s %s", p.ID(), p.Name())
	}
	if _, ok := oauth2.AsRefresher(p); !ok {
		t.Fatal("refresh should be supported")
	}
	if oauth2.SupportsIDTokenSignIn(p) {
		t.Fatal("discord has no id-token sign-in")
	}
}

// upstream: "preserves the authorize URL shape after the shared-helper refactor"
func TestAuthorizationURLShape(t *testing.T) {
	p := New(Options{ProviderOptions: creds()})
	u, err := p.CreateAuthorizationURL(context.Background(), baseInput())
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme+"://"+u.Host+u.Path != AuthorizationEndpoint {
		t.Fatalf("endpoint %s", u)
	}
	if q.Get("client_id") != "client-123" || q.Get("state") != state || q.Get("redirect_uri") != callback ||
		q.Get("response_type") != "code" || q.Get("scope") != "identify email" || q.Get("prompt") != "none" {
		t.Fatalf("query %v", q)
	}
	if q.Has("permissions") || q.Has("code_challenge") || q.Has("login_hint") {
		t.Fatalf("unexpected params %v", q)
	}
	want := "https://discord.com/api/oauth2/authorize?response_type=code&client_id=client-123&state=state-xyz&scope=identify+email&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&prompt=none"
	if u.String() != want {
		t.Fatalf("url\n got %s\nwant %s", u, want)
	}
}

// upstream: "appends permissions when bot scope is requested with options.permissions"
func TestAuthorizationURLPermissions(t *testing.T) {
	perm := int64(8)
	p := New(Options{ProviderOptions: creds(), Permissions: &perm})
	in := baseInput()
	in.Scopes = []string{"bot"}
	u, _ := p.CreateAuthorizationURL(context.Background(), in)
	if u.Query().Get("permissions") != "8" || u.Query().Get("scope") != "identify email bot" {
		t.Fatalf("query %v", u.Query())
	}
	// no bot scope -> no permissions
	u, _ = p.CreateAuthorizationURL(context.Background(), baseInput())
	if u.Query().Has("permissions") {
		t.Fatalf("permissions without bot scope: %v", u.Query())
	}
	// bot via options.scope, permissions 0 is still sent
	zero := int64(0)
	o := creds()
	o.Scope = []string{"bot"}
	p = New(Options{ProviderOptions: o, Permissions: &zero})
	u, _ = p.CreateAuthorizationURL(context.Background(), baseInput())
	if u.Query().Get("permissions") != "0" {
		t.Fatalf("query %v", u.Query())
	}
	// bot without permissions option
	p = New(Options{ProviderOptions: o})
	u, _ = p.CreateAuthorizationURL(context.Background(), baseInput())
	if u.Query().Has("permissions") {
		t.Fatalf("query %v", u.Query())
	}
	// call-time additionalParams override permissions
	p = New(Options{ProviderOptions: creds(), Permissions: &perm})
	in.AdditionalParams = map[string]string{"permissions": "16"}
	u, _ = p.CreateAuthorizationURL(context.Background(), in)
	if u.Query().Get("permissions") != "16" {
		t.Fatalf("query %v", u.Query())
	}
}

// upstream: "forwards additionalParams while dropping reserved keys"
func TestAuthorizationURLAdditionalParams(t *testing.T) {
	p := New(Options{ProviderOptions: creds()})
	in := baseInput()
	in.AdditionalParams = map[string]string{"custom": "value", "state": "attacker"}
	u, _ := p.CreateAuthorizationURL(context.Background(), in)
	if u.Query().Get("custom") != "value" || u.Query().Get("state") != state {
		t.Fatalf("query %v", u.Query())
	}
}

func TestAuthorizationURLOptions(t *testing.T) {
	o := creds()
	o.Scope = []string{"guilds"}
	o.Prompt = "consent"
	o.RedirectURI = "https://override.example/cb"
	o.AuthorizationEndpoint = "https://proxy.example/authorize?x=1"
	p := New(Options{ProviderOptions: o})
	in := baseInput()
	in.Scopes = []string{"connections"}
	in.LoginHint = "ignored@example.com"
	u, _ := p.CreateAuthorizationURL(context.Background(), in)
	q := u.Query()
	// scope order upstream: defaults, request scopes, options.scope
	if q.Get("scope") != "identify email connections guilds" || q.Get("prompt") != "consent" ||
		q.Get("redirect_uri") != "https://override.example/cb" || u.Host != "proxy.example" || q.Get("x") != "1" || q.Has("login_hint") {
		t.Fatalf("url %s", u)
	}
	o.DisableDefaultScope = true
	p = New(Options{ProviderOptions: o})
	u, _ = p.CreateAuthorizationURL(context.Background(), in)
	if u.Query().Get("scope") != "connections guilds" {
		t.Fatalf("scope %s", u.Query().Get("scope"))
	}
	// clientId required
	p = New(Options{})
	if _, err := p.CreateAuthorizationURL(context.Background(), baseInput()); err == nil || err.Error() != "OAuth provider requires clientId" {
		t.Fatalf("err %v", err)
	}
}

func TestValidateAuthorizationCode(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST discord.com/api/oauth2/token", 200, map[string]any{
		"access_token": "discord-access-token", "refresh_token": "discord-refresh-token",
		"token_type": "Bearer", "expires_in": 3600, "scope": "identify email",
	})
	p := New(Options{ProviderOptions: creds()})
	tok, err := p.ValidateAuthorizationCode(context.Background(), oauth2.CodeParams{Code: "auth-code", RedirectURI: callback, CodeVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "discord-access-token" || tok.RefreshToken != "discord-refresh-token" || tok.AccessTokenExpiresAt == nil ||
		len(tok.Scopes) != 2 || tok.Scopes[0] != "identify" {
		t.Fatalf("tokens %+v", tok)
	}
	r := m.Last("discord.com/api/oauth2/token")
	f := r.Form
	if f.Get("grant_type") != "authorization_code" || f.Get("code") != "auth-code" || f.Get("redirect_uri") != callback ||
		f.Get("client_id") != "client-123" || f.Get("client_secret") != "secret-abc" || f.Has("code_verifier") {
		t.Fatalf("form %v", f)
	}
	if r.Body != "grant_type=authorization_code&code=auth-code&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&client_id=client-123&client_secret=secret-abc" {
		t.Fatalf("body %s", r.Body)
	}
	// options.redirectURI wins
	o := creds()
	o.RedirectURI = "https://override.example/cb"
	_, _ = New(Options{ProviderOptions: o}).ValidateAuthorizationCode(context.Background(), oauth2.CodeParams{Code: "c", RedirectURI: callback})
	if got := m.Last("discord.com/api/oauth2/token").Form.Get("redirect_uri"); got != "https://override.example/cb" {
		t.Fatalf("redirect_uri %s", got)
	}
	// errors are thrown
	m.JSON("POST discord.com/api/oauth2/token", 400, map[string]any{"error": "invalid_grant"})
	if _, err := p.ValidateAuthorizationCode(context.Background(), oauth2.CodeParams{Code: "c", RedirectURI: callback}); err == nil {
		t.Fatal("expected error")
	}
}

func TestRefresh(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST discord.com/api/oauth2/token", 200, map[string]any{"access_token": "new-at", "refresh_token": "new-rt", "token_type": "Bearer", "expires_in": 604800})
	o := creds()
	o.ClientKey = "ck"
	p := New(Options{ProviderOptions: o})
	tok, err := p.RefreshAccessToken(context.Background(), "old-rt", nil)
	if err != nil || tok.AccessToken != "new-at" || tok.RefreshToken != "new-rt" {
		t.Fatalf("refresh %+v %v", tok, err)
	}
	f := m.Last("discord.com/api/oauth2/token").Form
	if f.Get("grant_type") != "refresh_token" || f.Get("refresh_token") != "old-rt" || f.Get("client_id") != "client-123" || f.Get("client_secret") != "secret-abc" {
		t.Fatalf("form %v", f)
	}
	// options.refreshAccessToken override
	o.RefreshAccessToken = func(_ context.Context, rt string) (*oauth2.Tokens, error) {
		return &oauth2.Tokens{AccessToken: "custom-" + rt}, nil
	}
	tok, _ = New(Options{ProviderOptions: o}).RefreshAccessToken(context.Background(), "x", nil)
	if tok.AccessToken != "custom-x" {
		t.Fatalf("custom refresh %+v", tok)
	}
}

func discordProfile(overrides map[string]any) map[string]any {
	p := map[string]any{
		"id": "920138789012345000", "username": "mapped-id", "discriminator": "0", "global_name": "Mapped",
		"avatar": nil, "mfa_enabled": false, "banner": nil, "accent_color": nil, "locale": "en-US",
		"verified": true, "email": "mapped-id@example.com", "flags": 0, "premium_type": 0, "public_flags": 0,
		"display_name": "mapped-id", "avatar_decoration": nil, "banner_color": nil,
	}
	for k, v := range overrides {
		if v == "<delete>" {
			delete(p, k)
			continue
		}
		p[k] = v
	}
	return p
}

func getUser(t *testing.T, o Options, profile map[string]any) (*oauth2.UserInfoResult, error) {
	t.Helper()
	m := oauth2test.New(t)
	m.JSON("GET discord.com/api/users/@me", 200, profile)
	res, err := New(o).GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "discord-access-token"}})
	if r := m.Last("discord.com/api/users/@me"); r == nil || r.Header.Get("Authorization") != "Bearer discord-access-token" {
		t.Fatalf("user request %+v", r)
	}
	return res, err
}

func TestGetUserInfoMapping(t *testing.T) {
	res, err := getUser(t, Options{ProviderOptions: creds()}, discordProfile(nil))
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	u := res.User
	// (920138789012345000 >> 22) % 6
	if u.Name != "Mapped" || u.Email != "mapped-id@example.com" || !u.EmailVerified ||
		u.Image != "https://cdn.discordapp.com/embed/avatars/0.png" {
		t.Fatalf("user %+v", u)
	}
	if res.Data["image_url"] != u.Image || res.Data["id"] != "920138789012345000" {
		t.Fatalf("data %v", res.Data)
	}
	sub, err := New(Options{ProviderOptions: creds()}).AccountSubject(context.Background(), nil, res.Data)
	if err != nil || sub != "920138789012345000" {
		t.Fatalf("subject %q %v", sub, err)
	}
}

func TestAvatarURL(t *testing.T) {
	cases := []struct {
		name    string
		profile map[string]any
		want    string
	}{
		// expected values computed with node: Number(BigInt(id) >> 22n) % 6, parseInt(d) % 5
		{"new username default", map[string]any{"id": "80351110224678912", "discriminator": "0", "avatar": nil}, "https://cdn.discordapp.com/embed/avatars/5.png"},
		{"legacy discriminator", map[string]any{"id": "1", "discriminator": "1337", "avatar": nil}, "https://cdn.discordapp.com/embed/avatars/2.png"},
		{"legacy discriminator 0005", map[string]any{"id": "1", "discriminator": "0005", "avatar": nil}, "https://cdn.discordapp.com/embed/avatars/0.png"},
		{"missing discriminator", map[string]any{"id": "1", "avatar": nil}, "https://cdn.discordapp.com/embed/avatars/NaN.png"},
		{"static avatar", map[string]any{"id": "42", "discriminator": "0", "avatar": "abc123"}, "https://cdn.discordapp.com/avatars/42/abc123.png"},
		{"animated avatar", map[string]any{"id": "42", "discriminator": "0", "avatar": "a_abc123"}, "https://cdn.discordapp.com/avatars/42/a_abc123.gif"},
	}
	for _, c := range cases {
		got, err := AvatarURL(c.profile)
		if err != nil || got != c.want {
			t.Errorf("%s: got %q %v want %q", c.name, got, err, c.want)
		}
	}
	// upstream throws when avatar is undefined or the snowflake is not a BigInt
	if _, err := AvatarURL(map[string]any{"id": "1", "discriminator": "0"}); err == nil {
		t.Error("expected error for missing avatar")
	}
	if _, err := AvatarURL(map[string]any{"id": "not-a-number", "discriminator": "0", "avatar": nil}); err == nil {
		t.Error("expected error for invalid snowflake")
	}
}

func TestGetUserInfoNameFallbacks(t *testing.T) {
	res, _ := getUser(t, Options{ProviderOptions: creds()}, discordProfile(map[string]any{"global_name": nil}))
	if res.User.Name != "mapped-id" {
		t.Fatalf("name %q", res.User.Name)
	}
	res, _ = getUser(t, Options{ProviderOptions: creds()}, discordProfile(map[string]any{"global_name": "", "username": ""}))
	if res.User.Name != "" {
		t.Fatalf("name %q", res.User.Name)
	}
	// providers without email (#9124)
	res, _ = getUser(t, Options{ProviderOptions: creds()}, discordProfile(map[string]any{"email": nil, "verified": false}))
	if res.User.Email != "" || res.User.EmailVerified {
		t.Fatalf("user %+v", res.User)
	}
}

// link-account.test.ts: mapProfileToUser cannot redefine the provider identity.
func TestMapProfileToUser(t *testing.T) {
	o := creds()
	o.MapProfileToUser = func(p map[string]any) (map[string]any, error) {
		return map[string]any{"id": "mapped-profile-id", "name": "Custom " + p["username"].(string), "emailVerified": false, "locale": p["locale"]}, nil
	}
	res, err := getUser(t, Options{ProviderOptions: o}, discordProfile(nil))
	if err != nil {
		t.Fatal(err)
	}
	if res.User.Name != "Custom mapped-id" || res.User.EmailVerified || res.User.Extra["locale"] != "en-US" || res.User.Email != "mapped-id@example.com" {
		t.Fatalf("user %+v", res.User)
	}
	sub, _ := New(Options{ProviderOptions: o}).AccountSubject(context.Background(), nil, res.Data)
	if sub != "920138789012345000" {
		t.Fatalf("subject %q", sub)
	}
}

func TestGetUserInfoErrorAndOverride(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET discord.com/api/users/@me", http.StatusUnauthorized, map[string]any{"message": "401: Unauthorized"})
	res, err := New(Options{ProviderOptions: creds()}).GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "bad"}})
	if res != nil || err != nil {
		t.Fatalf("expected null, got %v %v", res, err)
	}
	o := creds()
	o.GetUserInfo = func(_ context.Context, tok *oauth2.Tokens) (*oauth2.UserInfoResult, error) {
		return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: "custom"}, Data: map[string]any{"id": tok.AccessToken}}, nil
	}
	res, err = New(Options{ProviderOptions: o}).GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || res.User.Name != "custom" || res.Data["id"] != "at" {
		t.Fatalf("override %v %v", res, err)
	}
}
