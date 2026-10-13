package adaptertest

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/db"
)

// callJSON calls an endpoint and decodes the JSON result.
func callJSON(h *H, auth *betterauth.Auth, key string, in betterauth.CallInput) (map[string]any, *betterauth.CallResult, error) {
	res, err := auth.API.Call(h.Ctx, key, in)
	if err != nil {
		return nil, res, err
	}
	b, err := res.JSON()
	if err != nil {
		return nil, res, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, res, err
	}
	return m, res, nil
}

func mustCallJSON(h *H, auth *betterauth.Auth, key string, in betterauth.CallInput) (map[string]any, *betterauth.CallResult) {
	h.Helper()
	m, res, err := callJSON(h, auth, key, in)
	if err != nil {
		h.Fatalf("%s: %v", key, err)
	}
	return m, res
}

// setCookieToHeader copies the Set-Cookie values of a response into a Cookie header.
func setCookieToHeader(headers http.Header, res *betterauth.CallResult) {
	var parts []string
	if existing := headers.Get("Cookie"); existing != "" {
		parts = append(parts, existing)
	}
	for _, sc := range res.Headers.Values("Set-Cookie") {
		name, value, _ := betterauth.ParseSetCookie(sc)
		if name != "" {
			parts = append(parts, name+"="+value)
		}
	}
	headers.Set("Cookie", strings.Join(parts, "; "))
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func randomUUID() string { return bacrypto.RandomUUID() }

// AuthFlowSuite is authFlowTestSuite.
var AuthFlowSuite = CreateTestSuite("auth-flow", SuiteConfig{
	DefaultOptions: func(c *betterauth.Config) {
		c.EmailAndPassword = &betterauth.EmailAndPasswordConfig{
			Enabled: true,
			Password: &betterauth.PasswordConfig{
				Hash:   func(password string) (string, error) { return password, nil },
				Verify: func(hash, password string) (bool, error) { return hash == password, nil },
			},
		}
	},
}, func() []Test {
	signUpBody := func(user R, password string) map[string]any {
		image, _ := user["image"].(string)
		return map[string]any{"email": user["email"], "password": password, "name": user["name"], "image": image}
	}
	return []Test{
		{Name: "should successfully sign up", Fn: func(h *H) {
			auth := h.GetAuth()
			user := h.Generate("user")
			start := time.Now()
			result, _ := mustCallJSON(h, auth, "signUpEmail", betterauth.CallInput{Body: signUpBody(user, randomUUID())})
			h.Logf("signUpEmail took %dms (without hashing)", time.Since(start).Milliseconds())
			u := obj(result["user"])
			h.True(u != nil, "result.user defined")
			h.Equal(u["email"], user["email"])
			h.Equal(u["name"], user["name"])
			image, _ := user["image"].(string)
			h.Equal(u["image"], image)
			h.Equal(u["emailVerified"], false)
			h.True(u["createdAt"] != nil, "createdAt defined")
			h.True(u["updatedAt"] != nil, "updatedAt defined")
		}},
		{Name: "should successfully sign in", Fn: func(h *H) {
			auth := h.GetAuth()
			user := h.Generate("user")
			password := randomUUID()
			signUp, _ := mustCallJSON(h, auth, "signUpEmail", betterauth.CallInput{Body: signUpBody(user, password)})
			start := time.Now()
			result, _ := mustCallJSON(h, auth, "signInEmail", betterauth.CallInput{Body: map[string]any{"email": user["email"], "password": password}})
			h.Logf("signInEmail took %dms (without hashing)", time.Since(start).Milliseconds())
			h.True(obj(result["user"]) != nil, "result.user defined")
			h.Equal(obj(result["user"])["id"], obj(signUp["user"])["id"])
		}},
		{Name: "should reset password with a single-use token", Fn: func(h *H) {
			var mu sync.Mutex
			resetToken := ""
			h.ModifyOptions(func(c *betterauth.Config) {
				if c.EmailAndPassword == nil {
					c.EmailAndPassword = &betterauth.EmailAndPasswordConfig{}
				}
				c.EmailAndPassword.Enabled = true
				c.EmailAndPassword.SendResetPassword = func(_ context.Context, data betterauth.EmailData, _ *http.Request) error {
					mu.Lock()
					resetToken = data.Token
					mu.Unlock()
					return nil
				}
			}, false)
			auth := h.GetAuth()
			user := h.Generate("user")
			originalPassword := randomUUID()
			newPassword := randomUUID() + "-new"
			signUp, _ := mustCallJSON(h, auth, "signUpEmail", betterauth.CallInput{Body: signUpBody(user, originalPassword)})
			mustCallJSON(h, auth, "requestPasswordReset", betterauth.CallInput{Body: map[string]any{
				"email": user["email"], "redirectTo": "http://localhost:3000/reset-password"}})
			mu.Lock()
			token := resetToken
			mu.Unlock()
			h.True(len(token) > 10, "reset token captured, got %q", token)
			resetResult, _ := mustCallJSON(h, auth, "resetPassword", betterauth.CallInput{Body: map[string]any{"token": token, "newPassword": newPassword}})
			h.Equal(resetResult["status"], true)
			oldData, _, oldErr := callJSON(h, auth, "signInEmail", betterauth.CallInput{Body: map[string]any{"email": user["email"], "password": originalPassword}})
			h.True(oldData == nil, "old password data should be null")
			h.True(oldErr != nil, "old password sign-in should fail")
			newResult, _ := mustCallJSON(h, auth, "signInEmail", betterauth.CallInput{Body: map[string]any{"email": user["email"], "password": newPassword}})
			h.Equal(obj(newResult["user"])["id"], obj(signUp["user"])["id"])
			replayData, _, replayErr := callJSON(h, auth, "resetPassword", betterauth.CallInput{Body: map[string]any{
				"token": token, "newPassword": randomUUID() + "-replay"}})
			h.True(replayData == nil, "replay data should be null")
			h.True(replayErr != nil, "replaying the reset token should fail")
		}},
		{Name: "should successfully get session", Fn: func(h *H) {
			auth := h.GetAuth()
			user := h.Generate("user")
			password := randomUUID()
			signUp, response := mustCallJSON(h, auth, "signUpEmail", betterauth.CallInput{Body: signUpBody(user, password)})
			headers := http.Header{}
			setCookieToHeader(headers, response)
			start := time.Now()
			result, _ := mustCallJSON(h, auth, "getSession", betterauth.CallInput{Headers: headers})
			h.Logf("getSession took %dms", time.Since(start).Milliseconds())
			h.True(result != nil && obj(result["user"]) != nil, "result.user defined")
			h.Equal(obj(result["user"]), obj(signUp["user"]))
			h.True(obj(result["session"]) != nil, "result.session defined")
		}},
		{Name: "should not sign in with invalid email", Fn: func(h *H) {
			auth := h.GetAuth()
			user := h.Generate("user")
			data, _, err := callJSON(h, auth, "signInEmail", betterauth.CallInput{Body: map[string]any{"email": user["email"], "password": randomUUID()}})
			h.True(data == nil, "data should be null")
			h.True(err != nil, "error should be defined")
		}},
		{Name: "should store and retrieve timestamps correctly across timezones", Fn: func(h *H) {
			// Upstream switches process.env.TZ between the calls. Go time values carry their
			// own location and time.Local is process-global, so the round trip is checked
			// through the ISO serialisation only.
			auth := h.GetAuth()
			user := h.Generate("user")
			password := randomUUID()
			signUp, _ := mustCallJSON(h, auth, "signUpEmail", betterauth.CallInput{Body: signUpBody(user, password)})
			signIn, _ := mustCallJSON(h, auth, "signInEmail", betterauth.CallInput{Body: map[string]any{"email": user["email"], "password": password}})
			a, _ := obj(signUp["user"])["createdAt"].(string)
			b, _ := obj(signIn["user"])["createdAt"].(string)
			ta, okA := parseISO(a)
			tb, okB := parseISO(b)
			h.True(okA && okB, "createdAt should be ISO dates: %q %q", a, b)
			h.Equal(ta.UTC().Format("2006-01-02T15:04:05.000Z"), tb.UTC().Format("2006-01-02T15:04:05.000Z"))
		}},
		{Name: "should sign up with additional fields", Fn: func(h *H) {
			h.ModifyOptions(func(c *betterauth.Config) {
				ensureUser(c).AdditionalFields = append(ensureUser(c).AdditionalFields, db.Field{Name: "dateField", Type: db.TypeDate})
			}, true)
			auth := h.GetAuth()
			user := h.Generate("user")
			dateField := jsNow()
			_, response := mustCallJSON(h, auth, "signUpEmail", betterauth.CallInput{Body: map[string]any{
				"email": user["email"], "name": user["name"], "password": randomUUID(),
				// using iso string to simulate client to server communication (this should be converted back to Date)
				"dateField": dateField.Format("2006-01-02T15:04:05.000Z"),
			}})
			headers := http.Header{}
			setCookieToHeader(headers, response)
			result, err := auth.API.GetSession(h.Ctx, headers)
			if err != nil {
				h.Fatalf("getSession: %v", err)
			}
			h.True(result != nil && result.User != nil, "session should be defined")
			h.Equal(result.User.Get("dateField"), dateField)
		}},
	}
})

func parseISO(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}
