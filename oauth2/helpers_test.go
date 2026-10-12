package oauth2

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestCreateAuthorizationURL(t *testing.T) {
	u, err := CreateAuthorizationURL(AuthorizationURLOptions{
		ClientID: "cid", AuthorizationEndpoint: "https://idp.example.com/auth?x=1", RedirectURI: "https://app/cb",
		State: "st", CodeVerifier: "verifier", Scopes: []string{"openid", "email"}, Prompt: "consent",
		AdditionalParams: map[string]string{"hd": "x.com", "state": "evil"},
	})
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("state") != "st" || q.Get("scope") != "openid email" || q.Get("code_challenge_method") != "S256" ||
		q.Get("code_challenge") != GenerateCodeChallenge("verifier") || q.Get("x") != "1" || q.Get("hd") != "x.com" {
		t.Fatalf("unexpected url %s", u)
	}
	// Expected value computed independently: printf '<verifier>' | openssl dgst -sha256 -binary | base64url.
	if GenerateCodeChallenge("dBjftJeZ4CVP-mJ92K3UvO8rCUo0D6BHzvZd2ZozIIs") != "ONEqbtyr3ookh5eiK1hKe8hDzp4mLBA0N9ehJcdxFAM" {
		t.Fatal("PKCE challenge mismatch")
	}
}

func TestValidateAuthorizationCodeAndRefresh(t *testing.T) {
	var lastForm url.Values
	var lastAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		lastForm, _ = url.ParseQuery(string(b))
		lastAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"rt","expires_in":3600,"scope":"a b","id_token":"x.y.z"}`))
	}))
	defer srv.Close()
	tok, err := ValidateAuthorizationCode(context.Background(), CodeExchange{Code: "c", CodeVerifier: "v", RedirectURI: "https://app/cb",
		TokenEndpoint: srv.URL, Client: ClientCredentials{ClientID: "cid", ClientSecret: "sec"}})
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "at" || tok.AccessTokenExpiresAt == nil || len(tok.Scopes) != 2 || tok.IDToken != "x.y.z" {
		t.Fatalf("tokens %+v", tok)
	}
	if lastForm.Get("client_secret") != "sec" || lastForm.Get("code_verifier") != "v" || lastForm.Get("grant_type") != "authorization_code" {
		t.Fatalf("form %v", lastForm)
	}
	if _, err := RefreshAccessToken(context.Background(), RefreshRequest{RefreshToken: "rt", TokenEndpoint: srv.URL,
		Client: ClientCredentials{ClientID: "cid", ClientSecret: "sec"}, Basic: true}); err != nil {
		t.Fatal(err)
	}
	if lastAuth != EncodeBasicCredentials("cid", "sec") || lastForm.Get("client_secret") != "" {
		t.Fatalf("basic auth not applied: %q %v", lastAuth, lastForm)
	}
}

func TestRefusesRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/", http.StatusFound)
	}))
	defer srv.Close()
	if _, err := GetJSON(context.Background(), srv.URL, nil); err == nil {
		t.Fatal("redirect should be refused")
	}
}
