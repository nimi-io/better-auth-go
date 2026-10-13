package zoom

import (
	"context"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/oauth2/oauth2test"
)

var ctx = context.Background()

const (
	baseCallback = "https://app.example/callback"
	baseState    = "state-xyz"
)

var baseVerifier = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"

func opts(pkce *bool) Options {
	return Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "client-123", ClientSecret: "secret-abc"}, PKCE: pkce}
}

var off = new(bool)

func base() oauth2.AuthorizationURLParams {
	return oauth2.AuthorizationURLParams{State: baseState, CodeVerifier: baseVerifier, RedirectURI: baseCallback}
}

func TestIdentity(t *testing.T) {
	p := New(opts(nil))
	if p.ID() != "zoom" || p.Name() != "Zoom" {
		t.Fatalf("id/name = %s/%s", p.ID(), p.Name())
	}
	sub, err := p.AccountSubject(ctx, &oauth2.Tokens{}, map[string]any{"id": "zJKyaiAyTNC-MWjiWC18KQ", "account_id": "acc"})
	if err != nil || sub != "zJKyaiAyTNC-MWjiWC18KQ" {
		t.Fatalf("subject = %q %v", sub, err)
	}
}

// preserves the authorize URL shape after the shared-helper refactor
func TestAuthorizationURLShape(t *testing.T) {
	u, err := New(opts(off)).CreateAuthorizationURL(ctx, base())
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme+"://"+u.Host+u.Path != "https://zoom.us/oauth/authorize" {
		t.Fatalf("url = %s", u)
	}
	if q.Get("client_id") != "client-123" || q.Get("response_type") != "code" || q.Get("redirect_uri") != baseCallback {
		t.Fatalf("query = %v", q)
	}
	if q.Has("scope") || q.Has("code_challenge") {
		t.Fatalf("query = %v", q)
	}
}

// adds PKCE challenge by default
func TestAuthorizationURLPKCEDefault(t *testing.T) {
	u, _ := New(opts(nil)).CreateAuthorizationURL(ctx, base())
	if u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("code_challenge") != oauth2.GenerateCodeChallenge(baseVerifier) {
		t.Fatalf("query = %v", u.Query())
	}
}

// forwards additionalParams while dropping reserved keys
func TestAuthorizationURLAdditionalParams(t *testing.T) {
	p := base()
	p.AdditionalParams = map[string]string{"custom": "value", "redirect_uri": "https://attacker"}
	u, _ := New(opts(off)).CreateAuthorizationURL(ctx, p)
	if u.Query().Get("custom") != "value" || u.Query().Get("redirect_uri") != baseCallback {
		t.Fatalf("query = %v", u.Query())
	}
}

func TestAuthorizationURLIgnoresScopes(t *testing.T) {
	o := opts(nil)
	o.Scope = []string{"user:read"}
	p := base()
	p.Scopes = []string{"meeting:read"}
	u, _ := New(o).CreateAuthorizationURL(ctx, p)
	if u.Query().Has("scope") {
		t.Fatalf("query = %v", u.Query())
	}
}

func TestExchange(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST zoom.us/oauth/token", 200, map[string]any{
		"access_token": "at", "refresh_token": "rt", "token_type": "bearer", "expires_in": 3599, "scope": "user:read:admin",
	})
	tok, err := New(opts(off)).ValidateAuthorizationCode(ctx, oauth2.CodeParams{Code: "code", CodeVerifier: "ver", RedirectURI: baseCallback})
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "at" || tok.RefreshToken != "rt" || tok.AccessTokenExpiresAt == nil || tok.Scopes[0] != "user:read:admin" {
		t.Fatalf("tokens = %+v", tok)
	}
	want := "grant_type=authorization_code&code=code&code_verifier=ver&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&client_id=client-123&client_secret=secret-abc"
	if b := m.Last("zoom.us/oauth/token").Body; b != want {
		t.Fatalf("body = %s", b)
	}
}

func TestRefresh(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST zoom.us/oauth/token", 200, map[string]any{"access_token": "new", "refresh_token": "rt2", "expires_in": 3599})
	tok, err := New(opts(nil)).RefreshAccessToken(ctx, "rt", nil)
	if err != nil || tok.AccessToken != "new" || tok.RefreshToken != "rt2" || tok.AccessTokenExpiresAt == nil {
		t.Fatalf("tok = %+v %v", tok, err)
	}
	if b := m.Last("zoom.us/oauth/token").Body; b != "grant_type=refresh_token&refresh_token=rt&client_id=client-123&client_secret=secret-abc" {
		t.Fatalf("body = %s", b)
	}
}

func zoomProfile(verified any) map[string]any {
	return map[string]any{
		"id": "zJKyaiAyTNC-MWjiWC18KQ", "account_id": "q6gBJVO5TzexKYTb_I2rpg", "display_name": "Jill Chill",
		"email": "jchill@example.com", "first_name": "Jill", "last_name": "Chill", "pic_url": "https://zoom/pic", "verified": verified,
	}
}

func TestUserInfo(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.zoom.us/v2/users/me", 200, zoomProfile(1))
	res, err := New(opts(nil)).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || res == nil {
		t.Fatal(res, err)
	}
	u := res.User
	if u.Name != "Jill Chill" || u.Email != "jchill@example.com" || u.Image != "https://zoom/pic" || !u.EmailVerified {
		t.Fatalf("user = %+v", u)
	}
	if res.Data["account_id"] != "q6gBJVO5TzexKYTb_I2rpg" {
		t.Fatalf("data = %v", res.Data)
	}
	if got := m.Last("api.zoom.us/v2/users/me").Header.Get("Authorization"); got != "Bearer at" {
		t.Fatalf("authorization = %q", got)
	}

	m.JSON("GET api.zoom.us/v2/users/me", 200, zoomProfile(0))
	res, _ = New(opts(nil)).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if res.User.EmailVerified {
		t.Fatal("verified: 0 must not be verified")
	}
}

func TestUserInfoMapProfileToUser(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.zoom.us/v2/users/me", 200, zoomProfile(1))
	o := opts(nil)
	o.MapProfileToUser = func(p map[string]any) (map[string]any, error) {
		return map[string]any{"name": oauth2.JoinName(oauth2.String(p, "first_name"), oauth2.String(p, "last_name")) + "!", "emailVerified": false, "accountId": p["account_id"]}, nil
	}
	res, err := New(o).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || res.User.Name != "Jill Chill!" || res.User.EmailVerified || res.User.Extra["accountId"] != "q6gBJVO5TzexKYTb_I2rpg" {
		t.Fatalf("res = %+v %v", res, err)
	}
}

func TestUserInfoError(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("GET api.zoom.us/v2/users/me", 401, map[string]any{"code": 124, "message": "Invalid access token."})
	res, err := New(opts(nil)).GetUserInfo(ctx, oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if res != nil || err != nil {
		t.Fatalf("res = %+v err = %v", res, err)
	}
}
