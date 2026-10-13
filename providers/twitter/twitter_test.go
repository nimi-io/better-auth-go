package twitter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

var ctx = context.Background()

func opts() Options {
	return Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "twitter-app", ClientSecret: "twitter-secret"}}
}

// mockUsersMe routes /2/users/me by its user.fields query.
func mockUsersMe(m *oauth2test.Server, profileStatus int, profile any, emailStatus int, email any) {
	m.Handle("GET api.x.com/2/users/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("user.fields") {
		case "profile_image_url":
			w.WriteHeader(profileStatus)
			_ = json.NewEncoder(w).Encode(profile)
		case "confirmed_email":
			w.WriteHeader(emailStatus)
			_ = json.NewEncoder(w).Encode(email)
		default:
			w.WriteHeader(404)
		}
	})
}

var baseProfile = map[string]any{"data": map[string]any{"id": "twitter-user-1", "name": "Twitter User", "username": "twitter-user", "profile_image_url": "https://pbs.twimg.com/a.png"}}

func TestIdentity(t *testing.T) {
	p := New(opts())
	if p.ID() != "twitter" || p.Name() != "Twitter" {
		t.Fatalf("%q %q", p.ID(), p.Name())
	}
	if oauth2.SupportsIDTokenSignIn(p) {
		t.Fatal("twitter has no id token sign-in")
	}
	if _, ok := oauth2.AsRefresher(p); !ok {
		t.Fatal("refresh should be supported")
	}
}

func TestAuthorizationURL(t *testing.T) {
	o := opts()
	o.Scope = []string{"like.read"}
	o.Prompt = "consent"
	u, err := New(o).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{
		State: "st", CodeVerifier: "verifier", RedirectURI: "https://app/cb", Scopes: []string{"follows.read"},
		LoginHint: "ignored", AdditionalParams: map[string]string{"custom": "v", "client_id": "attacker"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme+"://"+u.Host+u.Path != AuthorizationEndpoint {
		t.Fatalf("endpoint %s", u)
	}
	q := u.Query()
	want := map[string]string{
		"response_type": "code", "client_id": "twitter-app", "state": "st", "redirect_uri": "https://app/cb",
		"scope":                 "users.read tweet.read offline.access users.email like.read follows.read",
		"code_challenge_method": "S256", "code_challenge": oauth2.GenerateCodeChallenge("verifier"), "custom": "v",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	for _, k := range []string{"login_hint", "prompt"} {
		if q.Has(k) {
			t.Errorf("unexpected %s", k)
		}
	}

	o = opts()
	o.DisableDefaultScope = true
	u, _ = New(o).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{State: "s", RedirectURI: "r"})
	if u.Query().Has("scope") {
		t.Fatal("scope should be omitted when empty")
	}
	if _, err := New(Options{}).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{State: "s"}); err == nil {
		t.Fatal("expected clientId error")
	}
}

func basic(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))
}

func TestValidateAuthorizationCodeUsesBasicAuthAndPKCE(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST api.x.com/2/oauth2/token", 200, map[string]any{"access_token": "at", "refresh_token": "rt", "expires_in": 7200, "scope": "users.read tweet.read", "token_type": "bearer"})
	tokens, err := New(opts()).ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "c", CodeVerifier: "verifier", RedirectURI: "https://app/cb"})
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken != "at" || tokens.RefreshToken != "rt" || len(tokens.Scopes) != 2 {
		t.Fatalf("tokens %+v", tokens)
	}
	r := m.Last("api.x.com/2/oauth2/token")
	if r.Header.Get("Authorization") != basic("twitter-app", "twitter-secret") {
		t.Fatalf("authorization %q", r.Header.Get("Authorization"))
	}
	want := map[string]string{"grant_type": "authorization_code", "code": "c", "code_verifier": "verifier", "redirect_uri": "https://app/cb"}
	if len(r.Form) != len(want) {
		t.Fatalf("form %v", r.Form)
	}
	for k, v := range want {
		if r.Form.Get(k) != v {
			t.Errorf("%s = %q", k, r.Form.Get(k))
		}
	}

	m.JSON("POST api.x.com/2/oauth2/token", 400, map[string]any{"error": "invalid_request", "error_description": "Value passed for the authorization code was invalid."})
	if _, err := New(opts()).ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "bad", RedirectURI: "r"}); err == nil {
		t.Fatal("expected token error")
	}
}

func TestRefreshAccessTokenUsesBasicAuth(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST api.x.com/2/oauth2/token", 200, map[string]any{"access_token": "new-at", "refresh_token": "new-rt"})
	tokens, err := New(opts()).RefreshAccessToken(ctx, "old-rt", nil)
	if err != nil || tokens.AccessToken != "new-at" || tokens.RefreshToken != "new-rt" {
		t.Fatalf("%+v %v", tokens, err)
	}
	r := m.Last("api.x.com/2/oauth2/token")
	if r.Header.Get("Authorization") != basic("twitter-app", "twitter-secret") || r.Form.Has("client_secret") ||
		r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "old-rt" {
		t.Fatalf("request %v %v", r.Header, r.Form)
	}
	o := opts()
	o.RefreshAccessToken = func(context.Context, string) (*oauth2.Tokens, error) {
		return &oauth2.Tokens{AccessToken: "custom"}, nil
	}
	tokens, _ = New(o).RefreshAccessToken(ctx, "x", nil)
	if tokens.AccessToken != "custom" {
		t.Fatal("override ignored")
	}
}

// twitter.test.ts: "uses the user id for the placeholder when no confirmed email exists"
func TestGetUserInfoPlaceholderEmail(t *testing.T) {
	m := oauth2test.New(t)
	mockUsersMe(m, 200, baseProfile, 403, map[string]any{"title": "Email unavailable"})
	p := New(opts())
	res, err := p.GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "access-token"}})
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	if res.User.Email != "twitter-user-1@twitter.placeholder.invalid" || res.User.EmailVerified {
		t.Fatalf("user %+v", res.User)
	}
	if res.User.Name != "Twitter User" || res.User.Image != "https://pbs.twimg.com/a.png" {
		t.Fatalf("user %+v", res.User)
	}
	if got := m.Last("api.x.com/2/users/me").Header.Get("Authorization"); got != "Bearer access-token" {
		t.Fatalf("authorization %q", got)
	}
	sub, err := p.AccountSubject(ctx, nil, res.Data)
	if err != nil || sub != "twitter-user-1" {
		t.Fatalf("subject %q %v", sub, err)
	}
}

// twitter.test.ts: "keeps a confirmed email"
func TestGetUserInfoConfirmedEmail(t *testing.T) {
	m := oauth2test.New(t)
	mockUsersMe(m, 200, map[string]any{"data": map[string]any{"id": "twitter-user-1", "name": "Twitter User", "username": "twitter-user"}},
		200, map[string]any{"data": map[string]any{"confirmed_email": "user@example.com"}})
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "access-token"}})
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	if res.User.Email != "user@example.com" || !res.User.EmailVerified {
		t.Fatalf("user %+v", res.User)
	}
	// the confirmed email is written back into the raw profile
	if oauth2.Path(res.Data, "data", "email") != "user@example.com" {
		t.Fatalf("profile %v", res.Data)
	}
}

func TestGetUserInfoProfileErrorReturnsNil(t *testing.T) {
	m := oauth2test.New(t)
	mockUsersMe(m, 401, map[string]any{"title": "Unauthorized"}, 200, map[string]any{})
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "bad"}})
	if err != nil || res != nil {
		t.Fatalf("%v %v", res, err)
	}
}

func TestMapProfileToUserAndGetUserInfoOverride(t *testing.T) {
	m := oauth2test.New(t)
	mockUsersMe(m, 200, baseProfile, 200, map[string]any{"data": map[string]any{"confirmed_email": "user@example.com"}})
	o := opts()
	o.MapProfileToUser = func(profile map[string]any) (map[string]any, error) {
		return map[string]any{"name": oauth2.Path(profile, "data", "username"), "emailVerified": false, "handle": oauth2.Path(profile, "data", "username")}, nil
	}
	res, err := New(o).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || res.User.Name != "twitter-user" || res.User.EmailVerified || res.User.Extra["handle"] != "twitter-user" || res.User.Email != "user@example.com" {
		t.Fatalf("%+v %v", res, err)
	}

	o = opts()
	o.GetUserInfo = func(context.Context, *oauth2.Tokens) (*oauth2.UserInfoResult, error) {
		return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: "custom"}, Data: map[string]any{"data": map[string]any{"id": "c"}}}, nil
	}
	n := len(m.Requests)
	res, err = New(o).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || res.User.Name != "custom" || len(m.Requests) != n {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestAccountSubjectRequiresData(t *testing.T) {
	if _, err := New(opts()).AccountSubject(ctx, nil, map[string]any{"id": "x"}); err == nil {
		t.Fatal("expected error for profile without data")
	}
}
