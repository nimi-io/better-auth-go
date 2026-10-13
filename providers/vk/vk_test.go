package vk

import (
	"context"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

var ctx = context.Background()

func opts() Options {
	return Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "vk-app", ClientSecret: "vk-secret"}}
}

func TestIdentity(t *testing.T) {
	p := New(opts())
	if p.ID() != "vk" || p.Name() != "VK" {
		t.Fatalf("id/name = %s/%s", p.ID(), p.Name())
	}
	sub, err := p.AccountSubject(ctx, &oauth2.Tokens{}, map[string]any{"user": map[string]any{"user_id": float64(1234567)}})
	if err != nil || sub != "1234567" {
		t.Fatalf("subject = %q %v", sub, err)
	}
}

func TestAuthorizationURL(t *testing.T) {
	u, err := New(opts()).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{
		State: "st", CodeVerifier: "verifier", RedirectURI: "https://app/cb", Scopes: []string{"wall"},
		AdditionalParams: map[string]string{"lang_id": "3", "client_id": "attacker"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme+"://"+u.Host+u.Path != AuthorizationEndpoint {
		t.Fatalf("url = %s", u)
	}
	q := u.Query()
	want := map[string]string{"response_type": "code", "client_id": "vk-app", "state": "st", "scope": "email phone wall",
		"redirect_uri": "https://app/cb", "code_challenge_method": "S256", "code_challenge": oauth2.GenerateCodeChallenge("verifier"), "lang_id": "3"}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q want %q", k, q.Get(k), v)
		}
	}
	o := opts()
	o.DisableDefaultScope = true
	o.Scope = []string{"vkid.personal_info"}
	u, _ = New(o).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{State: "s", RedirectURI: "r"})
	if u.Query().Get("scope") != "vkid.personal_info" || u.Query().Has("code_challenge") {
		t.Fatalf("url = %s", u)
	}
}

func TestExchangeSendsDeviceID(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST id.vk.com/oauth2/auth", 200, map[string]any{
		"access_token": "at", "refresh_token": "rt", "id_token": "idt", "expires_in": 3600, "user_id": 1, "scope": "email phone",
	})
	o := opts()
	o.ClientKey = "ck"
	tok, err := New(o).ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "code", CodeVerifier: "ver", RedirectURI: "https://app/cb", DeviceID: "dev-1"})
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "at" || tok.RefreshToken != "rt" || tok.IDToken != "idt" || tok.AccessTokenExpiresAt == nil {
		t.Fatalf("tokens = %+v", tok)
	}
	want := "grant_type=authorization_code&code=code&code_verifier=ver&client_key=ck&device_id=dev-1&redirect_uri=https%3A%2F%2Fapp%2Fcb&client_id=vk-app&client_secret=vk-secret"
	if b := m.Last("id.vk.com/oauth2/auth").Body; b != want {
		t.Fatalf("body = %s", b)
	}
}

func TestRefresh(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST id.vk.com/oauth2/auth", 200, map[string]any{"access_token": "new", "refresh_token": "rt2"})
	tok, err := New(opts()).RefreshAccessToken(ctx, "rt", nil)
	if err != nil || tok.AccessToken != "new" || tok.RefreshToken != "rt2" {
		t.Fatalf("tok = %+v %v", tok, err)
	}
	if b := m.Last("id.vk.com/oauth2/auth").Body; b != "grant_type=refresh_token&refresh_token=rt&client_id=vk-app&client_secret=vk-secret" {
		t.Fatalf("body = %s", b)
	}
}

func vkProfile() map[string]any {
	return map[string]any{"user": map[string]any{
		"user_id": "1234567", "first_name": "Ivan", "last_name": "Petrov", "email": "ivan@example.com",
		"phone": float64(79991234567), "avatar": "https://vk/avatar.jpg", "sex": float64(2), "verified": false, "birthday": "01.01.1990",
	}}
}

func TestUserInfo(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST id.vk.com/oauth2/user_info", 200, vkProfile())
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "a t"}})
	if err != nil || res == nil {
		t.Fatal(res, err)
	}
	u := res.User
	if u.Name != "Ivan Petrov" || u.Email != "ivan@example.com" || u.Image != "https://vk/avatar.jpg" || u.EmailVerified {
		t.Fatalf("user = %+v", u)
	}
	if u.Extra["first_name"] != "Ivan" || u.Extra["last_name"] != "Petrov" || u.Extra["birthday"] != "01.01.1990" || u.Extra["sex"] != float64(2) {
		t.Fatalf("extra = %v", u.Extra)
	}
	r := m.Last("id.vk.com/oauth2/user_info")
	if r.Method != "POST" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Body != "access_token=a+t&client_id=vk-app" {
		t.Fatalf("request = %s %v %s", r.Method, r.Header, r.Body)
	}
	if r.Header.Get("Authorization") != "" {
		t.Error("vk user_info uses the form body, not a bearer header")
	}
}

func TestUserInfoWithoutEmail(t *testing.T) {
	m := oauth2test.New(t)
	p := vkProfile()
	delete(p["user"].(map[string]any), "email")
	m.JSON("POST id.vk.com/oauth2/user_info", 200, p)
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "t"}})
	if res != nil || err != nil {
		t.Fatalf("no email must yield null: %+v %v", res, err)
	}

	// mapProfileToUser can supply the email
	o := opts()
	o.MapProfileToUser = func(p map[string]any) (map[string]any, error) {
		return map[string]any{"email": "mapped@example.com", "sex": "male"}, nil
	}
	res, err = New(o).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "t"}})
	if err != nil || res == nil {
		t.Fatal(res, err)
	}
	if res.User.Email != "mapped@example.com" || res.User.Extra["sex"] != "male" || res.User.Name != "Ivan Petrov" {
		t.Fatalf("user = %+v", res.User)
	}
}

func TestUserInfoMapperCalledOnce(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST id.vk.com/oauth2/user_info", 200, vkProfile())
	calls := 0
	o := opts()
	o.MapProfileToUser = func(map[string]any) (map[string]any, error) { calls++; return map[string]any{"name": "N"}, nil }
	res, _ := New(o).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "t"}})
	if calls != 1 || res.User.Name != "N" {
		t.Fatalf("calls = %d user = %+v", calls, res.User)
	}
}

func TestUserInfoNoAccessToken(t *testing.T) {
	oauth2test.New(t)
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{})
	if res != nil || err != nil {
		t.Fatalf("res = %+v err = %v", res, err)
	}
}

func TestUserInfoError(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST id.vk.com/oauth2/user_info", 400, map[string]any{"error": "invalid_token"})
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "t"}})
	if res != nil || err != nil {
		t.Fatalf("res = %+v err = %v", res, err)
	}
}
