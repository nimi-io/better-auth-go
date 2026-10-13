package salesforce

import (
	"context"
	"errors"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

var ctx = context.Background()

func opts() Options {
	return Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "sf-client", ClientSecret: "sf-secret"}}
}

func TestIdentity(t *testing.T) {
	p := New(opts())
	if p.ID() != "salesforce" || p.Name() != "Salesforce" {
		t.Fatalf("id/name = %s/%s", p.ID(), p.Name())
	}
	sub, err := p.AccountSubject(ctx, &oauth2.Tokens{}, map[string]any{"sub": "https://login.salesforce.com/id/00D/005", "user_id": "005"})
	if err != nil || sub != "005" {
		t.Fatalf("subject = %q %v", sub, err)
	}
}

func TestEndpoints(t *testing.T) {
	cases := []struct {
		o    Options
		host string
	}{
		{Options{}, "login.salesforce.com"},
		{Options{Environment: "production"}, "login.salesforce.com"},
		{Options{Environment: "sandbox"}, "test.salesforce.com"},
		{Options{Environment: "sandbox", LoginURL: "acme.my.salesforce.com"}, "acme.my.salesforce.com"},
	}
	for _, c := range cases {
		a, tk, u := c.o.Endpoints()
		base := "https://" + c.host + "/services/oauth2/"
		if a != base+"authorize" || tk != base+"token" || u != base+"userinfo" {
			t.Errorf("%+v: %s %s %s", c.o, a, tk, u)
		}
	}
}

func TestAuthorizationURL(t *testing.T) {
	u, err := New(opts()).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{
		State: "st", CodeVerifier: "verifier", RedirectURI: "https://app/cb", Scopes: []string{"api"},
		AdditionalParams: map[string]string{"display": "popup"},
	})
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Host != "login.salesforce.com" || u.Path != "/services/oauth2/authorize" {
		t.Fatalf("url = %s", u)
	}
	want := map[string]string{"response_type": "code", "client_id": "sf-client", "state": "st", "scope": "openid email profile api",
		"redirect_uri": "https://app/cb", "code_challenge_method": "S256", "code_challenge": oauth2.GenerateCodeChallenge("verifier"), "display": "popup"}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q want %q", k, q.Get(k), v)
		}
	}

	o := opts()
	o.Environment = "sandbox"
	o.RedirectURI = "https://override/cb"
	o.DisableDefaultScope = true
	u, _ = New(o).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{State: "s", CodeVerifier: "v", RedirectURI: "https://app/cb"})
	if u.Host != "test.salesforce.com" || u.Query().Get("redirect_uri") != "https://override/cb" || u.Query().Has("scope") {
		t.Fatalf("url = %s", u)
	}
}

func TestAuthorizationURLRequirements(t *testing.T) {
	_, err := New(Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "c"}}).CreateAuthorizationURL(ctx,
		oauth2.AuthorizationURLParams{State: "s", CodeVerifier: "v", RedirectURI: "r"})
	if err == nil || err.Error() != "CLIENT_ID_AND_SECRET_REQUIRED" {
		t.Fatalf("err = %v", err)
	}
	_, err = New(opts()).CreateAuthorizationURL(ctx, oauth2.AuthorizationURLParams{State: "s", RedirectURI: "r"})
	if err == nil || err.Error() != "codeVerifier is required for Salesforce" {
		t.Fatalf("err = %v", err)
	}
}

func TestExchange(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST acme.my.salesforce.com/services/oauth2/token", 200, map[string]any{
		"access_token": "at", "refresh_token": "rt", "id_token": "idt", "token_type": "Bearer", "scope": "openid email",
	})
	o := opts()
	o.LoginURL = "acme.my.salesforce.com"
	o.RedirectURI = "https://override/cb"
	tok, err := New(o).ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "code", CodeVerifier: "ver", RedirectURI: "https://app/cb"})
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "at" || tok.RefreshToken != "rt" || tok.IDToken != "idt" {
		t.Fatalf("tokens = %+v", tok)
	}
	r := m.Last("acme.my.salesforce.com/services/oauth2/token")
	want := "grant_type=authorization_code&code=code&code_verifier=ver&redirect_uri=https%3A%2F%2Foverride%2Fcb&client_id=sf-client&client_secret=sf-secret"
	if r.Body != want {
		t.Fatalf("body = %s", r.Body)
	}
}

func TestRefresh(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST login.salesforce.com/services/oauth2/token", 200, map[string]any{"access_token": "new"})
	o := opts()
	o.ClientKey = "ignored"
	tok, err := New(o).RefreshAccessToken(ctx, "rt", nil)
	if err != nil || tok.AccessToken != "new" {
		t.Fatalf("tok = %+v %v", tok, err)
	}
	if b := m.Last("login.salesforce.com/services/oauth2/token").Body; b != "grant_type=refresh_token&refresh_token=rt&client_id=sf-client&client_secret=sf-secret" {
		t.Fatalf("body = %s", b)
	}
}

func profile() map[string]any {
	return map[string]any{
		"sub": "https://login.salesforce.com/id/00D/005", "user_id": "005", "organization_id": "00D",
		"email": "user@example.com", "email_verified": true, "name": "Jane Doe",
		"photos": map[string]any{"picture": "https://sf/pic", "thumbnail": "https://sf/thumb"},
	}
}

func TestUserInfo(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET login.salesforce.com/services/oauth2/userinfo", 200, profile())
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || res == nil {
		t.Fatal(res, err)
	}
	u := res.User
	if u.Name != "Jane Doe" || u.Email != "user@example.com" || u.Image != "https://sf/pic" || !u.EmailVerified {
		t.Fatalf("user = %+v", u)
	}
	if got := m.Last("login.salesforce.com/services/oauth2/userinfo").Header.Get("Authorization"); got != "Bearer at" {
		t.Fatalf("authorization = %q", got)
	}

	p := profile()
	p["photos"] = map[string]any{"thumbnail": "https://sf/thumb"}
	delete(p, "email_verified")
	m.JSON("GET login.salesforce.com/services/oauth2/userinfo", 200, p)
	res, _ = New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if res.User.Image != "https://sf/thumb" || res.User.EmailVerified {
		t.Fatalf("user = %+v", res.User)
	}
}

func TestUserInfoMapProfileToUser(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET login.salesforce.com/services/oauth2/userinfo", 200, profile())
	o := opts()
	o.MapProfileToUser = func(p map[string]any) (map[string]any, error) {
		return map[string]any{"name": "Mapped", "orgId": p["organization_id"]}, nil
	}
	res, err := New(o).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || res.User.Name != "Mapped" || res.User.Extra["orgId"] != "00D" || res.User.Email != "user@example.com" {
		t.Fatalf("res = %+v %v", res, err)
	}

	// errors inside getUserInfo (including the mapper) are swallowed and yield null
	o.MapProfileToUser = func(map[string]any) (map[string]any, error) { return nil, errors.New("boom") }
	res, err = New(o).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if res != nil || err != nil {
		t.Fatalf("res = %+v err = %v", res, err)
	}
}

func TestUserInfoError(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET login.salesforce.com/services/oauth2/userinfo", 403, map[string]any{"error": "forbidden"})
	res, err := New(opts()).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if res != nil || err != nil {
		t.Fatalf("res = %+v err = %v", res, err)
	}
}
