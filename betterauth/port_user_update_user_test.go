package betterauth

// Port of packages/better-auth/src/api/routes/update-user.test.ts (v1.7.7).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/db"
)

func (p *puInst) dbUpdate(model string, where []adapter.Where, upd adapter.Record) adapter.Record {
	p.t.Helper()
	r, err := p.auth.Context().Adapter.Update(p.ctx(), model, where, upd)
	if err != nil {
		p.t.Fatalf("db.update: %v", err)
	}
	return r
}

func (p *puInst) dbFindMany(model string, where []adapter.Where) []adapter.Record {
	p.t.Helper()
	r, err := p.auth.Context().Adapter.FindMany(p.ctx(), adapter.FindManyInput{Model: model, Where: where})
	if err != nil {
		p.t.Fatalf("db.findMany: %v", err)
	}
	return r
}

func puTime(t *testing.T, v any) time.Time {
	t.Helper()
	switch x := v.(type) {
	case time.Time:
		return x
	case string:
		tt, err := time.Parse(time.RFC3339Nano, x)
		if err != nil {
			t.Fatal(err)
		}
		return tt
	}
	t.Fatalf("unexpected time value %T %v", v, v)
	return time.Time{}
}

func puWithSecondaryStorage(store *puStore, more func(c *Config)) func(c *Config) {
	return func(c *Config) {
		c.SecondaryStorage = store
		if more != nil {
			more(c)
		}
	}
}

// ---- describe("updateUser") ----

func TestPortUserUpdateUserName(t *testing.T) {
	p := puInstance(t, nil, puOpts{})
	headers, _ := p.signInWithTestUser()
	updated := p.post("/update-user", map[string]any{"name": "newName", "image": "https://example.com/image.jpg"}, headers)
	s := p.getSession(headers)
	if updated.Status != 200 || updated.JSON(t)["status"] != true {
		t.Fatalf("update: %d %s", updated.Status, updated.Body)
	}
	if puGet(s, "user", "name") != "newName" {
		t.Fatalf("name = %v", puGet(s, "user", "name"))
	}
}

func TestPortUserUpdateUserUnsetImage(t *testing.T) {
	p := puInstance(t, nil, puOpts{TestUser: &puUser{Image: "https://example.com/image.jpg"}})
	headers, _ := p.signInWithTestUser()
	p.post("/update-user", map[string]any{"image": nil}, headers)
	s := p.getSession(headers)
	user, _ := s["user"].(map[string]any)
	if user == nil {
		t.Fatalf("no session: %v", s)
	}
	if v, ok := user["image"]; !ok || v != nil {
		t.Fatalf("image = %v (present %v), want null", v, ok)
	}
}

func TestPortUserUpdateUserChangeEmailBothAddresses(t *testing.T) {
	var mu sync.Mutex
	var confirmationToken, verificationToken string
	var confirmCalls []ChangeEmailData
	var confirmReqs []*http.Request
	verifyCalls := 0
	p := puInstance(t, func(c *Config) {
		c.EmailVerification = &EmailVerificationConfig{SendVerificationEmail: func(_ context.Context, d EmailData, _ *http.Request) error {
			mu.Lock()
			defer mu.Unlock()
			verifyCalls++
			verificationToken = d.Token
			return nil
		}}
		c.User = &UserConfig{ChangeEmail: &ChangeEmailConfig{Enabled: true,
			SendChangeEmailConfirmation: func(_ context.Context, d ChangeEmailData, r *http.Request) error {
				mu.Lock()
				defer mu.Unlock()
				confirmCalls = append(confirmCalls, d)
				confirmReqs = append(confirmReqs, r)
				confirmationToken = d.Token
				return nil
			}}}
	}, puOpts{})
	headers, _ := p.signInWithTestUser()
	p.dbUpdate("user", []adapter.Where{{Field: "email", Value: p.testUser.Email}}, adapter.Record{"emailVerified": true})

	newEmail := "new-email@email.com"
	p.post("/change-email", map[string]any{"newEmail": newEmail}, headers)
	s := p.getSession(headers)
	if puGet(s, "user", "email") == newEmail || puGet(s, "user", "email") != p.testUser.Email {
		t.Fatalf("email changed too early: %v", puGet(s, "user", "email"))
	}
	if len(confirmCalls) != 1 {
		t.Fatalf("sendChangeEmailConfirmation called %d times", len(confirmCalls))
	}
	if confirmCalls[0].User.Email != p.testUser.Email || confirmCalls[0].NewEmail != newEmail || confirmReqs[0] == nil {
		t.Fatalf("unexpected confirmation call %+v", confirmCalls[0])
	}
	if confirmationToken == "" {
		t.Fatal("empty confirmation token")
	}

	res := p.verifyEmail(url.Values{"token": {confirmationToken}}, headers)
	if res.Status != 200 || res.JSON(t)["status"] != true {
		t.Fatalf("confirmation verify: %d %s", res.Status, res.Body)
	}
	if verifyCalls != 1 {
		t.Fatalf("sendVerificationEmail called %d times", verifyCalls)
	}
	if verificationToken == "" {
		t.Fatal("empty verification token")
	}
	s = p.getSession(headers)
	if puGet(s, "user", "email") != p.testUser.Email {
		t.Fatalf("email after confirmation = %v", puGet(s, "user", "email"))
	}
	res2 := p.verifyEmail(url.Values{"token": {verificationToken}}, headers)
	if res2.Status != 200 || res2.JSON(t)["status"] != true {
		t.Fatalf("verification verify: %d %s", res2.Status, res2.Body)
	}
	s = p.getSession(headers)
	if puGet(s, "user", "email") != newEmail || puGet(s, "user", "emailVerified") != true {
		t.Fatalf("after verification user = %v", s["user"])
	}
}

func TestPortUserUpdateUserPassword(t *testing.T) {
	p := puInstance(t, nil, puOpts{})
	headers, _ := p.signInWithTestUser()
	updated := p.post("/change-password", map[string]any{"newPassword": "newPassword", "currentPassword": p.testUser.Password, "revokeOtherSessions": true}, headers)
	if updated.Status != 200 {
		t.Fatalf("change-password: %d %s", updated.Status, updated.Body)
	}
	if _, ok := updated.JSON(t)["token"].(string); !ok {
		t.Fatalf("token not a string: %s", updated.Body)
	}
	if r := p.signIn(p.testUser.Email, "newPassword"); r.Status != 200 || r.JSON(t)["user"] == nil {
		t.Fatalf("sign-in with new password: %d %s", r.Status, r.Body)
	}
	if r := p.signIn(p.testUser.Email, p.testUser.Password); r.Status == 200 {
		t.Fatalf("sign-in with old password should fail: %s", r.Body)
	}
}

func TestPortUserUpdateUserAccountUpdatedAtOnPasswordChange(t *testing.T) {
	p := puInstance(t, nil, puOpts{})
	newHeaders := http.Header{}
	su := p.signUp("test-updated-at@email.com", "originalPassword", "Test User")
	puSessionSetter(newHeaders, su)
	s := p.getSession(newHeaders)
	if s == nil {
		t.Fatal("expected session")
	}
	userID, _ := puGet(s, "user", "id").(string)
	where := []adapter.Where{{Field: "userId", Value: userID}, {Field: "providerId", Value: "credential"}}
	initial := p.dbFindMany("account", where)
	if len(initial) != 1 {
		t.Fatalf("accounts = %d", len(initial))
	}
	initialUpdatedAt := puTime(t, initial[0]["updatedAt"])
	time.Sleep(100 * time.Millisecond)
	updated := p.post("/change-password", map[string]any{"newPassword": "newPassword123", "currentPassword": "originalPassword"}, newHeaders)
	if updated.Status != 200 {
		t.Fatalf("change-password: %d %s", updated.Status, updated.Body)
	}
	after := p.dbFindMany("account", where)
	if len(after) != 1 {
		t.Fatalf("accounts = %d", len(after))
	}
	newUpdatedAt := puTime(t, after[0]["updatedAt"])
	if newUpdatedAt.Equal(initialUpdatedAt) || !newUpdatedAt.After(initialUpdatedAt) {
		t.Fatalf("updatedAt not refreshed: %v -> %v", initialUpdatedAt, newUpdatedAt)
	}
}

func TestPortUserUpdateUserWrongCurrentPassword(t *testing.T) {
	p := puInstance(t, nil, puOpts{})
	newHeaders := http.Header{}
	puSessionSetter(newHeaders, p.signUp("new-email-2@email.com", "password", "name"))
	res := p.post("/change-password", map[string]any{"newPassword": "newPassword", "currentPassword": "wrongPassword"}, newHeaders)
	if res.Status == 200 {
		t.Fatalf("expected error, got %s", res.Body)
	}
	if r := p.signIn("new-email-2@email.com", "newPassword"); r.Status == 200 {
		t.Fatalf("sign-in with new password should fail: %s", r.Body)
	}
}

func TestPortUserUpdateUserRevokeOtherSessions(t *testing.T) {
	p := puInstance(t, nil, puOpts{})
	headers, _ := p.signInWithTestUser()
	newHeaders := http.Header{}
	res := p.post("/change-password", map[string]any{"newPassword": "newPassword", "currentPassword": p.testUser.Password, "revokeOtherSessions": true}, headers)
	if res.Status == 200 {
		puSessionSetter(newHeaders, res)
	}
	if newHeaders.Get("Cookie") == headers.Get("Cookie") {
		t.Fatal("cookie not replaced")
	}
	if s := p.getSession(headers); s != nil {
		t.Fatalf("old session should be revoked: %v", s)
	}
}

// @see https://github.com/better-auth/better-auth/pull/10390#discussion_r3585595438
func TestPortUserUpdateUserPreserveReplacementSessionSecondaryStorage(t *testing.T) {
	store := newPuStore()
	p := puInstance(t, puWithSecondaryStorage(store, nil), puOpts{})
	previous, signedIn := p.signInWithTestUser()
	userID, _ := puGet(signedIn, "user", "id").(string)
	replacement := http.Header{}
	res := p.post("/change-password", map[string]any{"newPassword": "new-secondary-storage-password", "currentPassword": p.testUser.Password, "revokeOtherSessions": true}, previous)
	if res.Status != 200 {
		t.Fatalf("change-password: %d %s", res.Status, res.Body)
	}
	puSessionSetter(replacement, res)
	token, _ := res.JSON(t)["token"].(string)
	if token == "" {
		t.Fatalf("token undefined: %s", res.Body)
	}
	if s := p.getSession(previous); s != nil {
		t.Fatalf("previous session should be null: %v", s)
	}
	rs := p.getSession(replacement)
	if rs == nil {
		t.Fatal("Replacement session was not created")
	}
	if puGet(rs, "user", "id") != userID {
		t.Fatalf("user id = %v", puGet(rs, "user", "id"))
	}
	if puGet(rs, "session", "token") != token {
		t.Fatalf("session token = %v, want %v", puGet(rs, "session", "token"), token)
	}
	raw, ok := store.get("active-sessions-" + userID)
	if !ok {
		raw = "[]"
	}
	var active []map[string]any
	if err := json.Unmarshal([]byte(raw), &active); err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0]["token"] != token {
		t.Fatalf("active sessions = %s, want only %s", raw, token)
	}
}

func TestPortUserUpdateUserShouldNotPassDefaults(t *testing.T) {
	p := puInstance(t, func(c *Config) {
		c.User = &UserConfig{ModelConfig: ModelConfig{AdditionalFields: []db.Field{{Name: "newField", Type: db.TypeString, DefaultValue: "default"}}}}
	}, puOpts{DisableTestUser: true})
	headers := http.Header{}
	puSessionSetter(headers, p.signUp("new-email@emial.com", "password", "name"))
	r := p.dbUpdate("user", []adapter.Where{{Field: "email", Value: "new-email@emial.com"}}, adapter.Record{"newField": "new"})
	if r["newField"] != "new" {
		t.Fatalf("db update newField = %v", r["newField"])
	}
	p.post("/update-user", map[string]any{"name": "newName"}, headers)
	s := p.getSession(headers)
	if puGet(s, "user", "newField") != "new" {
		t.Fatalf("newField = %v", puGet(s, "user", "newField"))
	}
}

func TestPortUserUpdateUserPropagateAcrossSessionsSecondaryStorage(t *testing.T) {
	store := newPuStore()
	p := puInstance(t, puWithSecondaryStorage(store, nil), puOpts{})
	h1, _ := p.signInWithTestUser()
	h2, _ := p.signInWithTestUser()
	p.post("/update-user", map[string]any{"name": "updatedName"}, h1)
	if s := p.getSession(h2); puGet(s, "user", "name") != "updatedName" {
		t.Fatalf("second session name = %v", puGet(s, "user", "name"))
	}
	if s := p.getSession(h1); puGet(s, "user", "name") != "updatedName" {
		t.Fatalf("first session name = %v", puGet(s, "user", "name"))
	}
}

func TestPortUserUpdateUserSingleSecondaryStorageWrite(t *testing.T) {
	store := newPuStore()
	p := puInstance(t, puWithSecondaryStorage(store, nil), puOpts{})
	store.clear()
	headers, _ := p.signInWithTestUser()
	var tokens []string
	for _, k := range store.keys() {
		if !strings.HasPrefix(k, "active-sessions-") {
			tokens = append(tokens, k)
		}
	}
	if len(tokens) != 1 {
		t.Fatalf("session keys = %v", tokens)
	}
	store.resetLog()
	if _, err := p.auth.API.Call(p.ctx(), "updateUser", CallInput{Body: map[string]any{"name": "updatedName"}, Headers: headers}); err != nil {
		t.Fatal(err)
	}
	if n := store.writes(tokens[0]); n != 1 {
		t.Fatalf("session token written %d times, want 1", n)
	}
}

func TestPortUserUpdateUserRejectInputFalseField(t *testing.T) {
	p := puInstance(t, func(c *Config) {
		c.User = &UserConfig{ModelConfig: ModelConfig{AdditionalFields: []db.Field{{Name: "newField", Type: db.TypeString, DefaultValue: "default", Input: Bool(false)}}}}
	}, puOpts{})
	headers, _ := p.signInWithTestUser()
	res := p.post("/update-user", map[string]any{"newField": "new"}, headers)
	if res.Status == 200 {
		t.Fatalf("expected error, got %s", res.Body)
	}
	if msg := res.JSON(t)["message"]; msg != "newField is not allowed to be set" {
		t.Fatalf("message = %v", msg)
	}
}

// ---- describe("delete user") ----

func TestPortUserDeleteUserDisabled(t *testing.T) {
	p := puInstance(t, func(c *Config) {
		c.User = &UserConfig{DeleteUser: &DeleteUserConfig{Enabled: false}}
	}, puOpts{})
	headers, _ := p.signInWithTestUser()
	res := p.post("/delete-user", map[string]any{}, headers)
	// Upstream only logs the response.
	t.Logf("delete-user (disabled): %d %s", res.Status, res.Body)
}

func TestPortUserDeleteUserFreshSession(t *testing.T) {
	p := puInstance(t, func(c *Config) {
		c.User = &UserConfig{DeleteUser: &DeleteUserConfig{Enabled: true}}
		c.Session = &SessionConfig{FreshAge: Duration(1000 * time.Second)}
	}, puOpts{})
	headers, _ := p.signInWithTestUser()
	res := p.post("/delete-user", map[string]any{}, headers)
	if res.Status != 200 || res.JSON(t)["success"] != true {
		t.Fatalf("delete-user: %d %s", res.Status, res.Body)
	}
	if s := p.getSession(headers); s != nil {
		t.Fatalf("session should be null: %v", s)
	}
}

// @see https://github.com/better-auth/better-auth/issues/8173
func TestPortUserDeleteUserRequiresPasswordWhenNotFresh(t *testing.T) {
	p := puInstance(t, func(c *Config) {
		c.User = &UserConfig{DeleteUser: &DeleteUserConfig{Enabled: true}}
		c.Session = &SessionConfig{FreshAge: Duration(1 * time.Second)}
	}, puOpts{})
	headers, _ := p.signInWithTestUser()
	s := p.getSession(headers)
	sessionID, _ := puGet(s, "session", "id").(string)
	if sessionID == "" {
		t.Fatal("session id undefined")
	}
	p.dbUpdate("session", []adapter.Where{{Field: "id", Value: sessionID}}, adapter.Record{"createdAt": time.Now().Add(-5 * time.Second)})
	res := p.post("/delete-user", map[string]any{}, headers)
	expectError(t, res, 400, "SESSION_EXPIRED")
}

func TestPortUserDeleteUserDeletesEverySession(t *testing.T) {
	store := newPuStore()
	p := puInstance(t, puWithSecondaryStorage(store, func(c *Config) {
		c.User = &UserConfig{DeleteUser: &DeleteUserConfig{Enabled: true}}
	}), puOpts{})
	headers, _ := p.signInWithTestUser()
	s := p.getSession(headers)
	userID, _ := puGet(s, "session", "userId").(string)
	raw, _ := store.get("active-sessions-" + userID)
	var sessions []map[string]any
	_ = json.Unmarshal([]byte(raw), &sessions)
	if len(sessions) != 2 {
		t.Fatalf("active sessions = %d (%s)", len(sessions), raw)
	}
	p.post("/delete-user", map[string]any{}, headers)
	if v, ok := store.get("active-sessions-" + userID); ok {
		t.Fatalf("active-sessions still present: %s", v)
	}
	if n := store.size(); n != 0 {
		t.Fatalf("store size = %d, keys %v", n, store.keys())
	}
}

func TestPortUserDeleteUserVerificationFlowAndPassword(t *testing.T) {
	var token string
	p := puInstance(t, func(c *Config) {
		c.User = &UserConfig{DeleteUser: &DeleteUserConfig{Enabled: true,
			SendDeleteAccountVerification: func(_ context.Context, d EmailData, _ *http.Request) error { token = d.Token; return nil }}}
	}, puOpts{})
	headers, _ := p.signInWithTestUser()
	res := p.post("/delete-user", map[string]any{"password": p.testUser.Password}, headers)
	if res.Status != 200 || res.JSON(t)["success"] != true {
		t.Fatalf("delete-user: %d %s", res.Status, res.Body)
	}
	if len(token) != 32 {
		t.Fatalf("token length = %d", len(token))
	}
	if r := p.get("/get-session", headers); r.Status != 200 {
		t.Fatalf("get-session: %d", r.Status)
	}
	cb := p.post("/delete-user", map[string]any{"token": token}, headers)
	if cb.Status != 200 || cb.JSON(t)["success"] != true {
		t.Fatalf("delete-user token: %d %s", cb.Status, cb.Body)
	}
	if s := p.getSession(headers); s != nil {
		t.Fatalf("session should be null: %v", s)
	}
}

func TestPortUserDeleteUserConcurrentTokenOnce(t *testing.T) {
	var token string
	var before, after atomic.Int32
	p := puInstance(t, func(c *Config) {
		c.User = &UserConfig{DeleteUser: &DeleteUserConfig{Enabled: true,
			SendDeleteAccountVerification: func(_ context.Context, d EmailData, _ *http.Request) error { token = d.Token; return nil },
			BeforeDelete: func(context.Context, *User, *http.Request) error {
				before.Add(1)
				time.Sleep(50 * time.Millisecond)
				return nil
			},
			AfterDelete: func(context.Context, *User, *http.Request) error { after.Add(1); return nil },
		}}
	}, puOpts{})
	headers, _ := p.signInWithTestUser()
	req := p.post("/delete-user", map[string]any{"password": p.testUser.Password}, headers)
	if req.Status != 200 || req.JSON(t)["success"] != true {
		t.Fatalf("delete-user: %d %s", req.Status, req.Body)
	}
	if len(token) != 32 {
		t.Fatalf("token length = %d", len(token))
	}
	results := make([]*testResponse, 2)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = p.post("/delete-user", map[string]any{"token": token}, headers)
		}(i)
	}
	wg.Wait()
	successes, failures := 0, 0
	for _, r := range results {
		if r.Status == 200 {
			var m map[string]any
			if json.Unmarshal(r.Body, &m) == nil && m["success"] == true {
				successes++
			}
		} else {
			failures++
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("successes=%d failures=%d (%d %s / %d %s)", successes, failures,
			results[0].Status, results[0].Body, results[1].Status, results[1].Body)
	}
	if before.Load() != 1 || after.Load() != 1 {
		t.Fatalf("beforeDelete=%d afterDelete=%d", before.Load(), after.Load())
	}
	if rem := p.dbFindMany("verification", []adapter.Where{{Field: "identifier", Value: "delete-account-" + token}}); len(rem) != 0 {
		t.Fatalf("verification rows remaining: %d", len(rem))
	}
}

func TestPortUserDeleteUserIgnoreCookieCacheForChangePassword(t *testing.T) {
	p := puInstance(t, func(c *Config) {
		c.Session = &SessionConfig{CookieCache: &CookieCacheConfig{Enabled: true, MaxAge: 60 * time.Second}}
	}, puOpts{DisableTestUser: true})
	email := "cache-test-" + time.Now().Format("150405.000000") + "@test.com"
	pw := "testPassword123"
	p.signUp(email, pw, "Cache Test User")
	cacheHeaders := http.Header{}
	if r := p.signIn(email, pw); r.Status == 200 {
		puSessionSetter(cacheHeaders, r)
	}
	if s := p.getSession(cacheHeaders); puGet(s, "user") == nil {
		t.Fatal("expected initial session user")
	}
	cp := p.post("/change-password", map[string]any{"newPassword": "newSecurePassword123", "currentPassword": pw, "revokeOtherSessions": true}, cacheHeaders)
	if cp.Status != 200 {
		t.Fatalf("change-password: %d %s", cp.Status, cp.Body)
	}
	if s := p.getSession(cacheHeaders); s != nil {
		t.Fatalf("session should be null after password change: %v", s)
	}
}

func TestPortUserDeleteUserCallbackRejectsRevokedBackingSession(t *testing.T) {
	var token string
	p := puInstance(t, func(c *Config) {
		c.Session = &SessionConfig{CookieCache: &CookieCacheConfig{Enabled: true, MaxAge: 60 * time.Second}}
		c.User = &UserConfig{DeleteUser: &DeleteUserConfig{Enabled: true,
			SendDeleteAccountVerification: func(_ context.Context, d EmailData, _ *http.Request) error { token = d.Token; return nil }}}
	}, puOpts{DisableTestUser: true})
	email := "delete-callback-" + time.Now().Format("150405.000000") + "@test.com"
	pw := "testPassword123"
	p.signUp(email, pw, "Delete Callback")
	headers := http.Header{}
	if r := p.signIn(email, pw); r.Status == 200 {
		puSessionSetter(headers, r)
	}
	s := p.getSession(headers)
	sessionToken, _ := puGet(s, "session", "token").(string)
	if sessionToken == "" {
		t.Fatal("expected an active session")
	}
	p.post("/delete-user", map[string]any{"password": pw}, headers)
	if len(token) != 32 {
		t.Fatalf("token length = %d", len(token))
	}
	if err := p.auth.Context().Adapter.Delete(p.ctx(), "session", []adapter.Where{{Field: "token", Value: sessionToken}}); err != nil {
		t.Fatal(err)
	}
	res := p.do("GET", "/delete-user/callback?token="+token, nil, http.Header{"Cookie": {headers.Get("Cookie")}})
	if res.Status != 404 {
		t.Fatalf("expected 404, got %d %s", res.Status, res.Body)
	}
}

// ---- describe("change-email enumeration protection") (shared instance) ----

func TestPortUserChangeEmailEnumerationProtection(t *testing.T) {
	p := puInstance(t, func(c *Config) {
		c.EmailVerification = &EmailVerificationConfig{SendVerificationEmail: func(context.Context, EmailData, *http.Request) error { return nil }}
		c.User = &UserConfig{ChangeEmail: &ChangeEmailConfig{Enabled: true}}
	}, puOpts{})
	t.Run("should return 200 when target email already exists", func(t *testing.T) {
		h2 := http.Header{}
		puSessionSetter(h2, p.signUp("other-user@test.com", "password123", "Other User"))
		headers, _ := p.signInWithTestUser()
		res := p.post("/change-email", map[string]any{"newEmail": "other-user@test.com"}, headers)
		if res.Status != 200 || res.JSON(t)["status"] != true {
			t.Fatalf("change-email: %d %s", res.Status, res.Body)
		}
	})
	t.Run("should not change the user's email", func(t *testing.T) {
		headers, _ := p.signInWithTestUser()
		if s := p.getSession(headers); puGet(s, "user", "email") != p.testUser.Email {
			t.Fatalf("email = %v", puGet(s, "user", "email"))
		}
	})
}

// ---- describe("change-email without sendVerificationEmail") ----

func TestPortUserChangeEmailWithoutSendVerificationEmail(t *testing.T) {
	p := puInstance(t, func(c *Config) {
		c.User = &UserConfig{ChangeEmail: &ChangeEmailConfig{Enabled: true}}
	}, puOpts{})
	h2 := http.Header{}
	puSessionSetter(h2, p.signUp("existing-no-verif@test.com", "password123", "Existing User"))
	headers, _ := p.signInWithTestUser()
	resExisting := p.post("/change-email", map[string]any{"newEmail": "existing-no-verif@test.com"}, headers)
	resNon := p.post("/change-email", map[string]any{"newEmail": "does-not-exist@test.com"}, headers)
	if resExisting.Status != 400 || resNon.Status != 400 {
		t.Fatalf("statuses %d %d", resExisting.Status, resNon.Status)
	}
	if resExisting.JSON(t)["message"] != resNon.JSON(t)["message"] {
		t.Fatalf("messages differ: %s vs %s", resExisting.Body, resNon.Body)
	}
}

// ---- describe("change-email callbackURL preservation") ----

func TestPortUserChangeEmailCallbackURLPreservation(t *testing.T) {
	var sent []string
	p := puInstance(t, func(c *Config) {
		c.EmailVerification = &EmailVerificationConfig{SendVerificationEmail: func(context.Context, EmailData, *http.Request) error { return nil }}
		c.User = &UserConfig{ChangeEmail: &ChangeEmailConfig{Enabled: true,
			SendChangeEmailConfirmation: func(_ context.Context, d ChangeEmailData, _ *http.Request) error {
				sent = append(sent, d.URL)
				return nil
			}}}
	}, puOpts{})
	p.dbUpdate("user", []adapter.Where{{Field: "email", Value: p.testUser.Email}}, adapter.Record{"emailVerified": true})
	headers, _ := p.signInWithTestUser()
	callback := "/dashboard?tab=settings&from=email"
	p.post("/change-email", map[string]any{"newEmail": "new-email@email.com", "callbackURL": callback}, headers)
	if len(sent) != 1 {
		t.Fatalf("sendChangeEmailConfirmation called %d times", len(sent))
	}
	u, err := url.Parse(sent[0])
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("callbackURL"); got != callback {
		t.Fatalf("callbackURL = %q (url %q)", got, sent[0])
	}
	if _, ok := u.Query()["from"]; ok {
		t.Fatalf("from leaked into outer URL: %q", sent[0])
	}
}

// ---- describe("change-email rejects confirmation-only config for verified users") ----

func TestPortUserChangeEmailRejectsConfirmationOnlyConfig(t *testing.T) {
	p := puInstance(t, func(c *Config) {
		c.User = &UserConfig{ChangeEmail: &ChangeEmailConfig{Enabled: true,
			SendChangeEmailConfirmation: func(context.Context, ChangeEmailData, *http.Request) error { return nil }}}
	}, puOpts{})
	p.dbUpdate("user", []adapter.Where{{Field: "email", Value: p.testUser.Email}}, adapter.Record{"emailVerified": true})
	headers, _ := p.signInWithTestUser()
	res := p.post("/change-email", map[string]any{"newEmail": "unreachable@email.com"}, headers)
	if res.Status != 400 {
		t.Fatalf("expected 400, got %d %s", res.Status, res.Body)
	}
}

// ---- describe("credential identity across email changes") ----

func TestPortUserCredentialIdentityAcrossEmailChange(t *testing.T) {
	p := puInstance(t, func(c *Config) {
		c.User = &UserConfig{ChangeEmail: &ChangeEmailConfig{Enabled: true, UpdateEmailWithoutVerification: true}}
	}, puOpts{DisableTestUser: true})
	original, changed, pw := "credential-email-change@example.com", "changed-credential-email@example.com", "credential-password"
	sessionHeaders := http.Header{}
	su := p.signUp(original, pw, "Credential Email Change")
	if su.Status != 200 {
		t.Fatalf("sign-up error: %d %s", su.Status, su.Body)
	}
	puSessionSetter(sessionHeaders, su)
	userID, _ := puGet(su.JSON(t), "user", "id").(string)
	before := p.dbFindMany("account", []adapter.Where{{Field: "userId", Value: userID}})
	if len(before) != 1 || before[0]["providerId"] != "credential" || before[0]["accountId"] != userID {
		t.Fatalf("accounts before: %v", before)
	}
	ce := p.post("/change-email", map[string]any{"newEmail": changed}, sessionHeaders)
	if ce.Status != 200 || ce.JSON(t)["status"] != true {
		t.Fatalf("change-email: %d %s", ce.Status, ce.Body)
	}
	if r := p.signIn(original, pw); r.Status == 200 {
		t.Fatalf("old email sign-in should fail: %s", r.Body)
	}
	r := p.signIn(changed, pw)
	if r.Status != 200 || puGet(r.JSON(t), "user", "id") != userID {
		t.Fatalf("changed email sign-in: %d %s", r.Status, r.Body)
	}
	after := p.dbFindMany("account", []adapter.Where{{Field: "userId", Value: userID}})
	if len(after) != 1 || after[0]["id"] != before[0]["id"] || after[0]["providerId"] != "credential" || after[0]["accountId"] != userID {
		t.Fatalf("accounts after: %v", after)
	}
}

// ---- describe("setPassword") ----

func TestPortUserSetPasswordOnPasswordlessCredentialAccount(t *testing.T) {
	p := puInstance(t, nil, puOpts{})
	ac := p.auth.Context()
	headers, data := p.signInWithTestUser()
	userID, _ := puGet(data, "user", "id").(string)
	cred, err := ac.InternalAdapter.FindCredentialAccount(p.ctx(), userID)
	if err != nil || cred == nil {
		t.Fatalf("credential account: %v %v", cred, err)
	}
	if _, err := ac.InternalAdapter.UpdateAccount(p.ctx(), cred.ID, adapter.Record{"password": nil}); err != nil {
		t.Fatal(err)
	}
	res, err := p.auth.API.SetPassword(p.ctx(), "new-password", headers)
	if err != nil {
		t.Fatalf("setPassword: %v", err)
	}
	var m map[string]any
	_ = res.Decode(&m)
	if m["status"] != true {
		t.Fatalf("setPassword result = %v", m)
	}
	accounts, err := ac.InternalAdapter.FindAccounts(p.ctx(), userID)
	if err != nil {
		t.Fatal(err)
	}
	var creds []*Account
	for _, a := range accounts {
		if a.ProviderID == "credential" {
			creds = append(creds, a)
		}
	}
	if len(creds) != 1 || creds[0].Password == nil {
		t.Fatalf("credential accounts = %d", len(creds))
	}
	ok, err := ac.Password.Verify(*creds[0].Password, "new-password")
	if err != nil || !ok {
		t.Fatalf("password verify = %v %v", ok, err)
	}
}

// ---- describe("password length on verify-only fields") (shared instance) ----
// @see https://github.com/better-auth/better-auth/issues/11323

func TestPortUserPasswordLengthOnVerifyOnlyFields(t *testing.T) {
	var hashCalls, verifyCalls atomic.Int32
	p := puInstance(t, func(c *Config) {
		c.EmailAndPassword = &EmailAndPasswordConfig{Password: &PasswordConfig{
			Hash: func(pw string) (string, error) { hashCalls.Add(1); return "hashed:" + pw, nil },
			Verify: func(hash, pw string) (bool, error) {
				verifyCalls.Add(1)
				return hash == "hashed:"+pw, nil
			},
		}}
		c.User = &UserConfig{DeleteUser: &DeleteUserConfig{Enabled: true}}
	}, puOpts{})
	expectTooLong := func(t *testing.T, err error) {
		t.Helper()
		e, ok := AsAPIError(err)
		if !ok {
			t.Fatalf("expected APIError, got %v", err)
		}
		if e.Status != "BAD_REQUEST" || e.Code() != "PASSWORD_TOO_LONG" {
			t.Fatalf("got %s %s", e.Status, e.Code())
		}
	}
	t.Run("change-password rejects long currentPassword before hashing", func(t *testing.T) {
		headers, _ := p.signInWithTestUser()
		hashCalls.Store(0)
		verifyCalls.Store(0)
		_, err := p.auth.API.Call(p.ctx(), "changePassword", CallInput{Body: map[string]any{"newPassword": "newPassword123", "currentPassword": strings.Repeat("x", 129)}, Headers: headers})
		expectTooLong(t, err)
		if hashCalls.Load() != 0 || verifyCalls.Load() != 0 {
			t.Fatalf("hash=%d verify=%d", hashCalls.Load(), verifyCalls.Load())
		}
	})
	t.Run("delete-user rejects long password before hashing", func(t *testing.T) {
		headers, _ := p.signInWithTestUser()
		hashCalls.Store(0)
		verifyCalls.Store(0)
		_, err := p.auth.API.Call(p.ctx(), "deleteUser", CallInput{Body: map[string]any{"password": strings.Repeat("x", 129)}, Headers: headers})
		expectTooLong(t, err)
		if hashCalls.Load() != 0 || verifyCalls.Load() != 0 {
			t.Fatalf("hash=%d verify=%d", hashCalls.Load(), verifyCalls.Load())
		}
	})
}
