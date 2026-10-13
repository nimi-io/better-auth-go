package linear

import (
	"context"
	"encoding/json"
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
	if p.ID() != "linear" || p.Name() != "Linear" {
		t.Fatalf("got %q %q", p.ID(), p.Name())
	}
	if p.S.Subject == nil || !p.SupportsRefresh() || p.SupportsIDToken() {
		t.Fatal("capabilities mismatch")
	}
}

func TestAuthorizationURL(t *testing.T) {
	p := newProvider(func(o *Options) { o.Prompt = "consent" })
	u, err := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{
		State: state, CodeVerifier: verifier, RedirectURI: callback, LoginHint: "user@example.com",
		AdditionalParams: map[string]string{"actor": "app", "redirect_uri": "https://attacker"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != AuthorizationEndpoint {
		t.Fatalf("endpoint %s", got)
	}
	// login hint forwarded; PKCE and prompt are not
	wantRaw := "response_type=code&client_id=client-123&state=state-xyz&scope=read&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&login_hint=user%40example.com&actor=app"
	if u.RawQuery != wantRaw {
		t.Fatalf("raw query\n got %s\nwant %s", u.RawQuery, wantRaw)
	}
}

func TestAuthorizationURLOptions(t *testing.T) {
	p := newProvider(func(o *Options) {
		o.Scope = []string{"write"}
		o.RedirectURI = "https://override.example/cb"
		o.AuthorizationEndpoint = "https://proxy.example/authorize"
	})
	u, _ := p.CreateAuthorizationURL(context.Background(), oauth2.AuthorizationURLParams{State: state, RedirectURI: callback, Scopes: []string{"issues:create"}})
	q := u.Query()
	if u.Host != "proxy.example" || q.Get("scope") != "read write issues:create" || q.Get("redirect_uri") != "https://override.example/cb" || q.Has("login_hint") {
		t.Fatalf("got %s", u)
	}
	u, _ = newProvider(func(o *Options) { o.DisableDefaultScope = true }).CreateAuthorizationURL(context.Background(),
		oauth2.AuthorizationURLParams{State: state, RedirectURI: callback})
	if u.Query().Has("scope") {
		t.Fatal("scope must be omitted")
	}
}

func TestValidateAuthorizationCode(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST api.linear.app/oauth/token", 200, map[string]any{
		"access_token": "at", "refresh_token": "rt", "token_type": "Bearer", "expires_in": 86399, "scope": []any{"read", "write"},
	})
	tok, err := newProvider().ValidateAuthorizationCode(context.Background(), oauth2.CodeParams{Code: "auth-code", CodeVerifier: verifier, RedirectURI: callback})
	if err != nil || tok.AccessToken != "at" || tok.RefreshToken != "rt" || tok.AccessTokenExpiresAt == nil || len(tok.Scopes) != 2 {
		t.Fatalf("%+v %v", tok, err)
	}
	f := m.Last("api.linear.app/oauth/token").Form
	if f.Get("grant_type") != "authorization_code" || f.Get("code") != "auth-code" || f.Get("redirect_uri") != callback ||
		f.Get("client_id") != "client-123" || f.Get("client_secret") != "secret-abc" || f.Has("code_verifier") {
		t.Fatalf("form %v", f)
	}
}

var viewer = map[string]any{
	"id": "lin-user-1", "name": "Linus", "email": "linus@linear.app", "avatarUrl": "https://img/a.png",
	"active": true, "createdAt": "2024-01-01T00:00:00.000Z", "updatedAt": "2024-02-01T00:00:00.000Z",
}

func TestGetUserInfo(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST api.linear.app/graphql", 200, map[string]any{"data": map[string]any{"viewer": viewer}})
	p := newProvider()
	res, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	r := m.Last("api.linear.app/graphql")
	if r.Header.Get("Authorization") != "Bearer at" || r.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("headers %v", r.Header)
	}
	// body is byte-identical to JSON.stringify({ query: `...` }) upstream
	wantBody := `{"query":"\n\t\t\t\t\t\t\tquery {\n\t\t\t\t\t\t\t\tviewer {\n\t\t\t\t\t\t\t\t\tid\n\t\t\t\t\t\t\t\t\tname\n\t\t\t\t\t\t\t\t\temail\n\t\t\t\t\t\t\t\t\tavatarUrl\n\t\t\t\t\t\t\t\t\tactive\n\t\t\t\t\t\t\t\t\tcreatedAt\n\t\t\t\t\t\t\t\t\tupdatedAt\n\t\t\t\t\t\t\t\t}\n\t\t\t\t\t\t\t}\n\t\t\t\t\t\t"}`
	if r.Body != wantBody {
		t.Fatalf("body\n got %s\nwant %s", r.Body, wantBody)
	}
	var parsed map[string]string
	if err := json.Unmarshal([]byte(r.Body), &parsed); err != nil || !strings.Contains(parsed["query"], "viewer {") {
		t.Fatalf("body %s", r.Body)
	}
	u := res.User
	if u.Name != "Linus" || u.Email != "linus@linear.app" || u.Image != "https://img/a.png" || u.EmailVerified {
		t.Fatalf("user %+v", u)
	}
	if res.Data["id"] != "lin-user-1" || res.Data["data"] != nil {
		t.Fatalf("data must be the viewer: %v", res.Data)
	}
	sub, err := p.AccountSubject(context.Background(), nil, res.Data)
	if err != nil || sub != "lin-user-1" {
		t.Fatalf("subject %q %v", sub, err)
	}
}

func TestGetUserInfoFailures(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("api.linear.app/graphql", 200, map[string]any{"errors": []any{map[string]any{"message": "Authentication required"}}})
	if res, err := newProvider().GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "x"}}); res != nil || err != nil {
		t.Fatalf("missing viewer must yield null: %v %v", res, err)
	}
	m.JSON("api.linear.app/graphql", 400, map[string]any{"errors": []any{}})
	if res, err := newProvider().GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "x"}}); res != nil || err != nil {
		t.Fatalf("HTTP error must yield null: %v %v", res, err)
	}
}

func TestMapProfileToUser(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("api.linear.app/graphql", 200, map[string]any{"data": map[string]any{"viewer": viewer}})
	var got map[string]any
	p := newProvider(func(o *Options) {
		o.MapProfileToUser = func(pr map[string]any) (map[string]any, error) {
			got = pr
			return map[string]any{"emailVerified": true, "active": pr["active"]}, nil
		}
	})
	res, err := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{Tokens: oauth2.Tokens{AccessToken: "at"}})
	if err != nil || !res.User.EmailVerified || res.User.Extra["active"] != true || res.User.Name != "Linus" {
		t.Fatalf("%+v %v", res, err)
	}
	if got["id"] != "lin-user-1" {
		t.Fatal("mapper must receive the viewer object")
	}
}

func TestGetUserInfoOverride(t *testing.T) {
	oauth2test.New(t)
	p := newProvider(func(o *Options) {
		o.GetUserInfo = func(context.Context, *oauth2.Tokens) (*oauth2.UserInfoResult, error) {
			return &oauth2.UserInfoResult{User: oauth2.UserInfo{Name: "custom"}}, nil
		}
	})
	if res, _ := p.GetUserInfo(context.Background(), oauth2.UserInfoParams{}); res.User.Name != "custom" {
		t.Fatal("override not used")
	}
}

func TestRefreshAccessToken(t *testing.T) {
	m := oauth2test.New(t)
	m.JSON("POST api.linear.app/oauth/token", 200, map[string]any{"access_token": "new-at", "refresh_token": "new-rt", "expires_in": 86399})
	tok, err := newProvider().RefreshAccessToken(context.Background(), "old-rt", nil)
	if err != nil || tok.AccessToken != "new-at" || tok.RefreshToken != "new-rt" {
		t.Fatalf("%+v %v", tok, err)
	}
	f := m.Last("api.linear.app/oauth/token").Form
	if f.Get("grant_type") != "refresh_token" || f.Get("refresh_token") != "old-rt" || f.Get("client_id") != "client-123" || f.Get("client_secret") != "secret-abc" {
		t.Fatalf("form %v", f)
	}
	p := newProvider(func(o *Options) {
		o.RefreshAccessToken = func(_ context.Context, rt string) (*oauth2.Tokens, error) {
			return &oauth2.Tokens{AccessToken: "custom-" + rt}, nil
		}
	})
	if tok, _ := p.RefreshAccessToken(context.Background(), "rt", nil); tok.AccessToken != "custom-rt" {
		t.Fatal("override not used")
	}
}
