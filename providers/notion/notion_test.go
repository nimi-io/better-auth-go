package notion

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

var ctx = context.Background()

func opts() Options {
	return Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "notion-client", ClientSecret: "notion-secret"}}
}

func TestIdentity(t *testing.T) {
	p := New(opts())
	if p.ID() != "notion" || p.Name() != "Notion" {
		t.Fatalf("id/name = %s/%s", p.ID(), p.Name())
	}
	sub, err := p.AccountSubject(ctx, &oauth2.Tokens{}, map[string]any{"object": "user", "id": "u-1"})
	if err != nil || sub != "u-1" {
		t.Fatalf("subject = %q %v", sub, err)
	}
}

func TestAuthorizationURL(t *testing.T) {
	u, err := New(opts()).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{
		State: "st", CodeVerifier: "v", RedirectURI: "https://app/cb", LoginHint: "a@b.c",
		AdditionalParams: map[string]string{"owner": "workspace", "custom": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme+"://"+u.Host+u.Path != AuthorizationEndpoint {
		t.Fatalf("url = %s", u)
	}
	q := u.Query()
	want := map[string]string{"response_type": "code", "client_id": "notion-client", "state": "st",
		"redirect_uri": "https://app/cb", "login_hint": "a@b.c", "owner": "user", "custom": "1"}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q want %q", k, q.Get(k), v)
		}
	}
	if q.Has("scope") || q.Has("code_challenge") {
		t.Errorf("query = %v", q)
	}

	o := opts()
	o.Scope = []string{"read"}
	u, _ = New(o).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{State: "s", RedirectURI: "r", Scopes: []string{"write"}})
	if u.Query().Get("scope") != "read write" || u.Query().Get("owner") != "user" {
		t.Fatalf("url = %s", u)
	}
}

func TestExchangeBasicAuth(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST api.notion.com/v1/oauth/token", 200, map[string]any{
		"access_token": "at", "refresh_token": "rt", "token_type": "bearer", "bot_id": "b", "workspace_id": "w",
	})
	tok, err := New(opts()).ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "code", CodeVerifier: "ignored", RedirectURI: "https://app/cb"})
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "at" || tok.RefreshToken != "rt" || tok.Raw["workspace_id"] != "w" {
		t.Fatalf("tokens = %+v", tok)
	}
	r := m.Last("api.notion.com/v1/oauth/token")
	if r.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("notion-client:notion-secret")) {
		t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
	}
	if r.Body != "grant_type=authorization_code&code=code&redirect_uri=https%3A%2F%2Fapp%2Fcb" {
		t.Fatalf("body = %s", r.Body)
	}
}

func TestRefresh(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST api.notion.com/v1/oauth/token", 200, map[string]any{"access_token": "new", "refresh_token": "rt2"})
	tok, err := New(opts()).RefreshAccessToken(ctx, "rt", nil)
	if err != nil || tok.AccessToken != "new" || tok.RefreshToken != "rt2" {
		t.Fatalf("tok = %+v %v", tok, err)
	}
	r := m.Last("api.notion.com/v1/oauth/token")
	// refresh uses the default client authentication (client_secret_post)
	if r.Body != "grant_type=refresh_token&refresh_token=rt&client_id=notion-client&client_secret=notion-secret" || r.Header.Get("Authorization") != "" {
		t.Fatalf("body = %s headers = %v", r.Body, r.Header)
	}
}

func notionMe(user map[string]any) map[string]any {
	return map[string]any{"object": "user", "id": "bot-1", "type": "bot", "bot": map[string]any{"owner": map[string]any{"type": "user", "user": user}}}
}

func TestUserInfo(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.notion.com/v1/users/me", 200, notionMe(map[string]any{
		"object": "user", "id": "u-1", "type": "person", "name": "Ada", "avatar_url": "https://notion/ada.png",
		"person": map[string]any{"email": "ada@example.com"},
	}))
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || res == nil {
		t.Fatal(res, err)
	}
	u := res.User
	if u.Name != "Ada" || u.Email != "ada@example.com" || u.Image != "https://notion/ada.png" || u.EmailVerified {
		t.Fatalf("user = %+v", u)
	}
	if res.Data["id"] != "u-1" {
		t.Fatalf("data must be the owner user profile: %v", res.Data)
	}
	r := m.Last("api.notion.com/v1/users/me")
	if r.Header.Get("Authorization") != "Bearer at" || r.Header.Get("Notion-Version") != "2022-06-28" {
		t.Fatalf("headers = %v", r.Header)
	}
}

func TestUserInfoMissingFields(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.notion.com/v1/users/me", 200, notionMe(map[string]any{"object": "user", "id": "u-2", "type": "person"}))
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || res == nil || res.User.Name != "" || res.User.Email != "" {
		t.Fatalf("res = %+v %v", res, err)
	}
}

func TestUserInfoNoOwnerUser(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.notion.com/v1/users/me", 200, map[string]any{"object": "user", "id": "bot-1", "bot": map[string]any{"owner": map[string]any{"type": "workspace", "workspace": true}}})
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if res != nil || err != nil {
		t.Fatalf("res = %+v err = %v", res, err)
	}
}

func TestUserInfoMapProfileToUser(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.notion.com/v1/users/me", 200, notionMe(map[string]any{"object": "user", "id": "u-3", "type": "person", "name": "Bob"}))
	o := opts()
	o.MapProfileToUser = func(p map[string]any) (map[string]any, error) {
		return map[string]any{"email": "bob@example.com", "emailVerified": true, "notionType": p["type"]}, nil
	}
	res, err := New(o).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || res.User.Email != "bob@example.com" || !res.User.EmailVerified || res.User.Extra["notionType"] != "person" || res.User.Name != "Bob" {
		t.Fatalf("res = %+v %v", res, err)
	}
}

func TestUserInfoError(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.notion.com/v1/users/me", 401, map[string]any{"object": "error", "code": "unauthorized"})
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if res != nil || err != nil {
		t.Fatalf("res = %+v err = %v", res, err)
	}
}
