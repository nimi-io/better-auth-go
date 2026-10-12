package betterauth

// Port of packages/better-auth/src/db/db.test.ts (v1.7.7).
//
// Upstream's getTestInstance always installs the bearer() plugin and the tests read the
// session with `Authorization: Bearer <token>`. The Go port has no bearer plugin yet, so
// the session is read with the cookie the sign-up response set (same session token).

import (
	"context"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
)

// pdTestUser signs up the default upstream test user (getTestInstance createTestUser).
func pdTestUser(t *testing.T, env *testEnv) {
	t.Helper()
	if _, err := env.auth.API.SignUpEmail(context.Background(), SignUpEmailInput{
		Email: "test@test.com", Password: "test123456", Name: "test user"}, nil); err != nil {
		t.Fatalf("create test user: %v", err)
	}
}

func TestPortDBDB_CustomModelNames(t *testing.T) {
	env := newTestEnv(t, func(c *Config) {
		c.User = &UserConfig{ModelConfig: ModelConfig{ModelName: "users"}}
		c.Session = &SessionConfig{ModelConfig: ModelConfig{ModelName: "sessions"}}
		c.Account = &AccountConfig{ModelConfig: ModelConfig{ModelName: "accounts"}}
	})
	pdTestUser(t, env)
	c := env.client()
	res := c.post("/sign-up/email", map[string]any{"email": "test@email2.com", "password": "password", "name": "Test User"})
	if res.Status != 200 {
		t.Fatalf("sign-up: %d %s", res.Status, res.Body)
	}
	ctx := context.Background()
	ad := env.auth.Context().Adapter
	for _, model := range []string{"user", "session", "account"} {
		rows, err := ad.FindMany(ctx, adapter.FindManyInput{Model: model})
		if err != nil {
			t.Fatalf("findMany %s: %v", model, err)
		}
		// including the user that was created in the test instance
		if len(rows) != 2 {
			t.Errorf("%s rows = %d, want 2", model, len(rows))
		}
	}
	for _, physical := range []string{"users", "sessions", "accounts"} {
		if n := len(env.db.Rows(physical)); n != 2 {
			t.Errorf("physical table %q rows = %d, want 2", physical, n)
		}
	}
}

func TestPortDBDB_DBHooks(t *testing.T) {
	callback := false
	env := newTestEnv(t, func(c *Config) {
		c.DatabaseHooks = &DatabaseHooks{User: DBModelHooks{Create: DBOperationHooks{
			Before: func(_ context.Context, user adapter.Record) (*DBHookResult, error) {
				return &DBHookResult{Data: mergeRecord(user, adapter.Record{"image": "test-image"})}, nil
			},
			After: func(context.Context, adapter.Record) error {
				callback = true
				return nil
			},
		}}}
	})
	c := env.client()
	c.signUp("test@email.com", "password", "test")
	s := c.session()
	user, _ := s["user"].(map[string]any)
	if user == nil || user["image"] != "test-image" {
		t.Fatalf("session user = %v", s)
	}
	if !callback {
		t.Fatal("after hook not called")
	}
}

// Upstream runs this against Postgres (testWith: "postgres"); the id handling under test
// lives in the adapter factory, so the memory adapter exercises the same path.
func TestPortDBDB_HooksPreserveForcedUUIDWhenGenerateIDIsUUID(t *testing.T) {
	const existingID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
	email := "forced-id-user@test.com"
	env := newTestEnv(t, func(c *Config) {
		c.Advanced.Database = &DatabaseAdvancedConfig{GenerateID: adapter.IDUUID}
		c.DatabaseHooks = &DatabaseHooks{User: DBModelHooks{Create: DBOperationHooks{
			Before: func(_ context.Context, user adapter.Record) (*DBHookResult, error) {
				return &DBHookResult{Data: mergeRecord(user, adapter.Record{"id": existingID})}, nil
			},
		}}}
	})
	res, err := env.auth.API.SignUpEmail(context.Background(), SignUpEmailInput{Email: email, Name: "forced-id-user", Password: "password"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := res.Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.User.ID != existingID {
		t.Fatalf("result user id = %q", out.User.ID)
	}
	created, err := env.auth.Context().Adapter.FindOne(context.Background(), adapter.FindOneInput{Model: "user",
		Where: []adapter.Where{{Field: "id", Value: existingID}}})
	if err != nil || created == nil {
		t.Fatalf("created = %v %v", created, err)
	}
	if created["id"] != existingID || created["email"] != email {
		t.Fatalf("created = %v", created)
	}
}

func TestPortDBDB_CustomFieldNames(t *testing.T) {
	env := newTestEnv(t, func(c *Config) {
		c.User = &UserConfig{ModelConfig: ModelConfig{Fields: map[string]string{"email": "email_address"}}}
	})
	c := env.client()
	c.signUp("test@email.com", "password", "Test User")
	s := c.session()
	user, _ := s["user"].(map[string]any)
	if user == nil || user["email"] != "test@email.com" {
		t.Fatalf("session = %v", s)
	}
}

func TestPortDBDB_DeleteHooks(t *testing.T) {
	var userBefore, userAfter, sessionBefore, sessionAfter pdCalls
	env := newTestEnv(t, func(c *Config) {
		c.Session = &SessionConfig{StoreSessionInDatabase: true}
		c.User = &UserConfig{DeleteUser: &DeleteUserConfig{Enabled: true}}
		c.DatabaseHooks = &DatabaseHooks{
			User: DBModelHooks{Delete: DBOperationHooks{
				Before: func(ctx context.Context, d adapter.Record) (*DBHookResult, error) {
					userBefore.record(ctx, d)
					return nil, nil
				},
				After: func(ctx context.Context, d adapter.Record) error {
					userAfter.record(ctx, d)
					return nil
				},
			}},
			Session: DBModelHooks{Delete: DBOperationHooks{
				Before: func(ctx context.Context, d adapter.Record) (*DBHookResult, error) {
					sessionBefore.record(ctx, d)
					return nil, nil
				},
				After: func(ctx context.Context, d adapter.Record) error {
					sessionAfter.record(ctx, d)
					return nil
				},
			}},
		}
	})
	pdTestUser(t, env)
	c := env.client()
	res := c.signUp("delete-test@email.com", "password", "Delete Test User")
	userID, _ := res.JSON(t)["user"].(map[string]any)["id"].(string)
	if del := c.post("/delete-user", map[string]any{}); del.Status != 200 {
		t.Fatalf("delete-user: %d %s", del.Status, del.Body)
	}
	for name, calls := range map[string]*pdCalls{"user.before": &userBefore, "user.after": &userAfter,
		"session.before": &sessionBefore, "session.after": &sessionAfter} {
		if calls.count() != 1 {
			t.Errorf("%s called %d times, want 1", name, calls.count())
		}
	}
	for name, calls := range map[string]*pdCalls{"user.before": &userBefore, "user.after": &userAfter} {
		if calls.count() == 0 {
			continue
		}
		d, ctx := calls.at(0)
		if d["id"] != userID || d["email"] != "delete-test@email.com" || d["name"] != "Delete Test User" {
			t.Errorf("%s data = %v", name, d)
		}
		if EndpointContextFrom(ctx) == nil {
			t.Errorf("%s: hook context has no endpoint context", name)
		}
	}
}

func TestPortDBDB_DeleteHooksAbort(t *testing.T) {
	var userBefore, userAfter pdCalls
	env := newTestEnv(t, func(c *Config) {
		c.User = &UserConfig{DeleteUser: &DeleteUserConfig{Enabled: true}}
		c.DatabaseHooks = &DatabaseHooks{User: DBModelHooks{Delete: DBOperationHooks{
			Before: func(ctx context.Context, d adapter.Record) (*DBHookResult, error) {
				userBefore.record(ctx, d)
				return &DBHookResult{Abort: true}, nil
			},
			After: func(ctx context.Context, d adapter.Record) error {
				userAfter.record(ctx, d)
				return nil
			},
		}}}
	})
	pdTestUser(t, env)
	c := env.client()
	res := c.signUp("abort-delete-test@email.com", "password", "Abort Delete Test User")
	userID, _ := res.JSON(t)["user"].(map[string]any)["id"].(string)
	_ = c.post("/delete-user", map[string]any{}) // expected to fail due to hook returning false
	if userBefore.count() != 1 {
		t.Fatalf("before called %d times", userBefore.count())
	}
	if userAfter.count() != 0 {
		t.Fatalf("after called %d times", userAfter.count())
	}
	d, ctx := userBefore.at(0)
	if d["id"] != userID || d["email"] != "abort-delete-test@email.com" || d["name"] != "Abort Delete Test User" {
		t.Errorf("before data = %v", d)
	}
	if EndpointContextFrom(ctx) == nil {
		t.Error("hook context has no endpoint context")
	}
}
