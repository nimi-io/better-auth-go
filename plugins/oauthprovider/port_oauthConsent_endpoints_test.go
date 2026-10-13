package oauthprovider

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
)

// Port of oauthConsent/endpoints.test.ts.

// mxConsentTesterPlugin is the createConsentTester plugin: a server-only endpoint that
// inserts an oauthConsent row.
func mxConsentTesterPlugin() *betterauth.Plugin {
	return &betterauth.Plugin{ID: "createConsentTester", Endpoints: []*betterauth.Endpoint{{
		Key: "testerCreateConsent", Path: "/server/oauth2/consent", Methods: []string{"POST"}, ServerOnly: true,
		Use: []betterauth.Middleware{betterauth.SessionMiddleware},
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			iat := time.Unix(time.Now().Unix(), 0)
			data := adapter.Record{"createdAt": iat, "updatedAt": iat}
			for k, v := range bodyMap(ctx) {
				data[k] = v
			}
			return ctx.Auth.Adapter.Create(ctx.Context(), adapter.CreateInput{Model: "oauthConsent", Data: data})
		},
	}}}
}

// mxMatchObject asserts every key of want equals the same key of got (JSON compare).
func mxMatchObject(t *testing.T, got, want any) {
	t.Helper()
	g, _ := mxJSON(t, got).(map[string]any)
	w, _ := mxJSON(t, want).(map[string]any)
	for k, v := range w {
		mxExpectJSON(t, map[string]any{k: g[k]}, map[string]any{k: v})
	}
}

func TestMx_OAuthConsent(t *testing.T) {
	redirectURI := "http://localhost:5000/api/auth/callback/test"
	env := newEnv(t, Options{}, envOptions{noJwt: true, plugins: []*betterauth.Plugin{
		jwt.New(jwt.Options{}), mxConsentTesterPlugin(),
	}})
	h := env.signInWithTestUser()
	userID := recStr(env.findOne("user", eq("email", testUserEmail)), "id")
	client1Scopes := []any{"profile"}
	client2Scopes := []any{"openid", "profile"}
	c1 := env.adminCreateClient(h, map[string]any{"redirect_uris": []any{redirectURI}, "application_type": "native"})
	if c1["client_id"] == nil || c1["user_id"] == nil || c1["client_secret"] == nil {
		t.Fatalf("client1: %v", c1)
	}
	c2 := env.adminCreateClient(h, map[string]any{"redirect_uris": []any{redirectURI}, "application_type": "native",
		"scope": "openid profile"})
	if c2["client_id"] == nil || c2["user_id"] == nil || c2["client_secret"] == nil || c2["scope"] != "openid profile" {
		t.Fatalf("client2: %v", c2)
	}
	createConsent := func(t *testing.T, clientID any, uid string, scopes []any) map[string]any {
		t.Helper()
		return env.mustCall("testerCreateConsent", betterauth.CallInput{Headers: h,
			Body: map[string]any{"clientId": clientID, "userId": uid, "scopes": scopes}})
	}
	var consent1, consent2 map[string]any

	t.Run("should create a tester consents", func(t *testing.T) {
		consent1 = createConsent(t, c1["client_id"], userID, client1Scopes)
		if consent1["clientId"] != c1["client_id"] || consent1["userId"] != userID {
			t.Fatalf("consent1: %v", consent1)
		}
		mxExpectJSON(t, consent1["scopes"], client1Scopes)
		consent2 = createConsent(t, c2["client_id"], userID, client2Scopes)
		if consent2["clientId"] != c2["client_id"] || consent2["userId"] != userID {
			t.Fatalf("consent2: %v", consent2)
		}
		mxExpectJSON(t, consent2["scopes"], client2Scopes)
	})
	t.Run("should get a specific consent", func(t *testing.T) {
		res := env.do("GET", "/oauth2/get-consent?id="+url.QueryEscape(consent1["id"].(string)), nil, h)
		if res.status != 200 {
			t.Fatalf("get-consent: %d %s", res.status, res.body)
		}
		mxMatchObject(t, res.json(), consent1)
	})
	t.Run("should get user's consents", func(t *testing.T) {
		res := env.do("GET", "/oauth2/get-consents", nil, h)
		var list []any
		if l, ok := mxJSON(t, mxJSONRaw(res.body)).([]any); ok {
			list = l
		}
		if res.status != 200 || len(list) != 2 {
			t.Fatalf("get-consents: %d %s", res.status, res.body)
		}
		mxExpectJSON(t, list, []any{consent1, consent2})
	})
	t.Run("should not allow updates to scopes not granted to client", func(t *testing.T) {
		res := env.do("POST", "/oauth2/update-consent", map[string]any{"id": consent2["id"],
			"update": map[string]any{"scopes": []any{"email"}}}, h)
		if res.status != 400 {
			t.Fatalf("update-consent: %d %s", res.status, res.body)
		}
	})
	t.Run("should allow scopes change to client", func(t *testing.T) {
		res := env.do("POST", "/oauth2/update-consent", map[string]any{"id": consent1["id"],
			"update": map[string]any{"scopes": []any{"email"}}}, h)
		if res.status != 200 {
			t.Fatalf("update-consent: %d %s", res.status, res.body)
		}
		mxExpectJSON(t, res.json()["scopes"], []any{"email"})
		consent1 = res.json()
	})
	t.Run("should reject updates to a consent owned by another user", func(t *testing.T) {
		other := env.mustCall("signUpEmail", betterauth.CallInput{Body: map[string]any{
			"email": "other-consent-owner@test.com", "password": "password123", "name": "Other Consent Owner"}})
		otherUser, _ := other["user"].(map[string]any)
		otherConsent := createConsent(t, c1["client_id"], otherUser["id"].(string), client1Scopes)
		res := env.do("POST", "/oauth2/update-consent", map[string]any{"id": otherConsent["id"],
			"update": map[string]any{"scopes": client1Scopes}}, h)
		if res.status != 401 {
			t.Fatalf("update-consent: %d %s", res.status, res.body)
		}
	})
	t.Run("should delete the consent", func(t *testing.T) {
		res := env.do("POST", "/oauth2/delete-consent", map[string]any{"id": consent1["id"]}, h)
		body := strings.TrimSpace(string(res.body))
		if res.status >= 300 || (body != "" && body != "null") {
			t.Fatalf("delete-consent: %d %s", res.status, res.body)
		}
	})
}

// mxJSONRaw wraps raw JSON bytes for mxJSON.
type mxJSONRaw []byte

func (j mxJSONRaw) MarshalJSON() ([]byte, error) { return j, nil }
