package betterauth

// Port of packages/better-auth/src/db/internal-adapter.test.ts (v1.7.7).
//
// Upstream runs these against node:sqlite (`new DatabaseSync(":memory:")` + migrations);
// the Go port uses the memory adapter. Where upstream relies on a SQLite primary-key
// constraint, pdUniqueIDFactory supplies it.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/memory"
)

// ---- shared "internal adapter test" fixture ----

type pdMainFixture struct {
	auth  *Auth
	ia    *InternalAdapter
	store *pdStorage
	db    *memory.DB

	hookUserCreateBefore, hookUserCreateAfter                 pdCalls
	hookVerificationCreateBefore, hookVerificationCreateAfter pdCalls
	hookVerificationDeleteBefore, hookVerificationDeleteAfter pdCalls
	pluginHookUserCreateBefore, pluginHookUserCreateAfter     pdCalls
}

func pdNewMainFixture(t *testing.T) *pdMainFixture {
	t.Helper()
	f := &pdMainFixture{store: newPDStorage(), db: memory.NewDB()}
	var idMu sync.Mutex
	id := 1
	cfg := Config{
		Database: memory.New(f.db),
		User: &UserConfig{ModelConfig: ModelConfig{Fields: map[string]string{
			"email":         "email_address",
			"emailVerified": "email_verified",
		}}},
		Verification:     &VerificationConfig{StoreInDatabase: true},
		SecondaryStorage: f.store,
		Advanced: &AdvancedConfig{Database: &DatabaseAdvancedConfig{
			GenerateIDFunc: func(string, int) (string, bool) {
				idMu.Lock()
				defer idMu.Unlock()
				v := strconv.Itoa(id)
				id++
				return v, true
			},
		}},
		DatabaseHooks: &DatabaseHooks{
			User: DBModelHooks{Create: DBOperationHooks{
				Before: func(ctx context.Context, d adapter.Record) (*DBHookResult, error) {
					f.hookUserCreateBefore.record(ctx, d)
					return &DBHookResult{Data: d}, nil
				},
				After: func(ctx context.Context, d adapter.Record) error {
					f.hookUserCreateAfter.record(ctx, d)
					return nil
				},
			}},
			Verification: DBModelHooks{
				Create: DBOperationHooks{
					Before: func(ctx context.Context, d adapter.Record) (*DBHookResult, error) {
						f.hookVerificationCreateBefore.record(ctx, d)
						return &DBHookResult{Data: d}, nil
					},
					After: func(ctx context.Context, d adapter.Record) error {
						f.hookVerificationCreateAfter.record(ctx, d)
						return nil
					},
				},
				Delete: DBOperationHooks{
					Before: func(ctx context.Context, d adapter.Record) (*DBHookResult, error) {
						f.hookVerificationDeleteBefore.record(ctx, d)
						return nil, nil
					},
					After: func(ctx context.Context, d adapter.Record) error {
						f.hookVerificationDeleteAfter.record(ctx, d)
						return nil
					},
				},
			},
		},
		Plugins: []*Plugin{{
			ID: "test-plugin",
			Init: func(*AuthContext) (*PluginInit, error) {
				return &PluginInit{DatabaseHooks: &DatabaseHooks{
					User: DBModelHooks{Create: DBOperationHooks{
						Before: func(ctx context.Context, d adapter.Record) (*DBHookResult, error) {
							f.pluginHookUserCreateBefore.record(ctx, d)
							return &DBHookResult{Data: d}, nil
						},
						After: func(ctx context.Context, d adapter.Record) error {
							f.pluginHookUserCreateAfter.record(ctx, d)
							return nil
						},
					}},
					Session: DBModelHooks{Create: DBOperationHooks{
						Before: func(_ context.Context, d adapter.Record) (*DBHookResult, error) {
							return &DBHookResult{Data: mergeRecord(d, adapter.Record{"activeOrganizationId": "1"})}, nil
						},
					}},
				}}, nil
			},
		}},
	}
	f.auth = pdNewAuth(t, cfg)
	f.ia = pdIA(f.auth)
	return f
}

func TestPortDBInternalAdapter_CreateOAuthUserWithCustomGenerateID(t *testing.T) {
	f := pdNewMainFixture(t)
	now := time.Now()
	u, acc, err := f.ia.CreateOAuthUser(context.Background(),
		adapter.Record{"email": "email@email.com", "name": "name", "emailVerified": false},
		adapter.Record{"providerId": "provider", "accountId": "account", "accessTokenExpiresAt": now,
			"refreshTokenExpiresAt": now, "createdAt": now, "updatedAt": now})
	if err != nil || u == nil || acc == nil {
		t.Fatalf("createOAuthUser: %v %v %v", u, acc, err)
	}
	if u.ID != "1" || u.Name != "name" || u.Email != "email@email.com" || u.EmailVerified || u.Image != nil ||
		u.CreatedAt.IsZero() || u.UpdatedAt.IsZero() {
		t.Errorf("user = %+v", u)
	}
	if acc.ID != "2" || acc.UserID == "" || acc.ProviderID != "provider" || acc.AccountID != "account" ||
		acc.AccessToken != nil || acc.RefreshToken != nil || acc.RefreshTokenExpiresAt == nil || acc.AccessTokenExpiresAt == nil {
		t.Errorf("account = %+v", acc)
	}
	if u.ID != acc.UserID {
		t.Errorf("user.id %q != account.userId %q", u.ID, acc.UserID)
	}
	for name, c := range map[string]*pdCalls{
		"pluginHookUserCreateAfter": &f.pluginHookUserCreateAfter, "pluginHookUserCreateBefore": &f.pluginHookUserCreateBefore,
		"hookUserCreateAfter": &f.hookUserCreateAfter, "hookUserCreateBefore": &f.hookUserCreateBefore,
	} {
		if c.count() != 1 {
			t.Errorf("%s called %d times, want 1", name, c.count())
		}
	}
}

func TestPortDBInternalAdapter_AbortOAuthAccountCreationWhenUserVetoed(t *testing.T) {
	store := newPDStorage()
	a := pdNewAuth(t, Config{
		User: &UserConfig{ModelConfig: ModelConfig{Fields: map[string]string{
			"email": "email_address", "emailVerified": "email_verified"}}},
		Verification:     &VerificationConfig{StoreInDatabase: true},
		SecondaryStorage: store,
		DatabaseHooks: &DatabaseHooks{User: DBModelHooks{Create: DBOperationHooks{
			Before: func(context.Context, adapter.Record) (*DBHookResult, error) { return &DBHookResult{Abort: true}, nil },
		}}},
	})
	now := time.Now()
	_, _, err := pdIA(a).CreateOAuthUser(context.Background(),
		adapter.Record{"email": "blocked@email.com", "name": "Blocked", "emailVerified": false},
		adapter.Record{"providerId": "provider", "accountId": "account", "accessTokenExpiresAt": now, "refreshTokenExpiresAt": now})
	if err == nil || !strings.Contains(err.Error(), "Failed to create user") {
		t.Fatalf("expected 'Failed to create user', got %v", err)
	}
}

func pdAPIErrorCode(t *testing.T, err error) string {
	t.Helper()
	e, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("expected *APIError, got %T %v", err, err)
	}
	return e.Code()
}

// @see https://github.com/better-auth/better-auth/pull/9864
func TestPortDBInternalAdapter_RejectsCreateUserOutsideEndpointContextWithValidateUserInfo(t *testing.T) {
	a := pdNewAuth(t, Config{User: &UserConfig{
		ValidateUserInfo: func(*EndpointContext, map[string]any, UserInfoSource) (*ValidateUserInfoResult, error) {
			return nil, nil
		}}})
	_, err := pdIA(a).CreateUser(context.Background(), adapter.Record{
		"email": "missing-context@example.com", "name": "Missing Context", "emailVerified": false}, pdTestSource)
	if err == nil {
		t.Fatal("expected rejection")
	}
	if code := pdAPIErrorCode(t, err); code != "validation_context_missing" {
		t.Fatalf("code = %q", code)
	}
}

// @see https://github.com/better-auth/better-auth/pull/9864
func TestPortDBInternalAdapter_RequiresProvisioningSourceWithValidateUserInfo(t *testing.T) {
	a := pdNewAuth(t, Config{User: &UserConfig{
		ValidateUserInfo: func(*EndpointContext, map[string]any, UserInfoSource) (*ValidateUserInfoResult, error) {
			return nil, nil
		}}})
	_, err := pdIA(a).CreateUser(pdWithEndpoint(a), adapter.Record{
		"email": "missing-source@example.com", "name": "Missing Source", "emailVerified": false}, UserInfoSource{})
	if err == nil {
		t.Fatal("expected rejection")
	}
	if code := pdAPIErrorCode(t, err); code != "validation_source_missing" {
		t.Fatalf("code = %q", code)
	}
}

// @see https://github.com/better-auth/better-auth/pull/9864
func TestPortDBInternalAdapter_ForcesCreateUserValidationAction(t *testing.T) {
	var captured string
	a := pdNewAuth(t, Config{User: &UserConfig{
		ValidateUserInfo: func(_ *EndpointContext, _ map[string]any, s UserInfoSource) (*ValidateUserInfoResult, error) {
			captured = s.Action
			return nil, nil
		}}})
	_, err := pdIA(a).CreateUser(pdWithEndpoint(a), adapter.Record{
		"email": "canonical-action@example.com", "name": "Canonical Action", "emailVerified": false},
		UserInfoSource{Method: "test", Action: "sign-in"})
	if err != nil {
		t.Fatal(err)
	}
	if captured != "create-user" {
		t.Fatalf("action = %q", captured)
	}
}

func TestPortDBInternalAdapter_FindSessionWithCustomUserID(t *testing.T) {
	env := newTestEnv(t, func(c *Config) {
		c.Session = &SessionConfig{ModelConfig: ModelConfig{Fields: map[string]string{"userId": "user_id"}}}
	})
	c := env.client()
	c.signUp("test@test.com", "test123456", "test user")
	c2 := env.client()
	if res := c2.post("/sign-in/email", map[string]any{"email": "test@test.com", "password": "test123456"}); res.Status != 200 {
		t.Fatalf("sign-in: %d %s", res.Status, res.Body)
	}
	s := c2.session()
	if s == nil || s["session"] == nil {
		t.Fatalf("session = %v", s)
	}
}

func TestPortDBInternalAdapter_DeleteExpiredVerificationValuesOnFind(t *testing.T) {
	f := pdNewMainFixture(t)
	ctx := context.Background()
	if _, err := f.ia.CreateVerificationValue(ctx, "test-id-1", "test-id-1", time.Now().Add(-time.Second), nil); err != nil {
		t.Fatal(err)
	}
	if f.hookVerificationCreateBefore.count() != 1 || f.hookVerificationCreateAfter.count() != 1 {
		t.Fatalf("create hooks: before=%d after=%d", f.hookVerificationCreateBefore.count(), f.hookVerificationCreateAfter.count())
	}
	v, err := f.ia.FindVerificationValue(ctx, "test-id-1")
	if err != nil || v == nil || v.Identifier != "test-id-1" {
		t.Fatalf("value = %+v %v", v, err)
	}
	if f.hookVerificationDeleteBefore.count() != 1 || f.hookVerificationDeleteAfter.count() != 1 {
		t.Fatalf("delete hooks: before=%d after=%d", f.hookVerificationDeleteBefore.count(), f.hookVerificationDeleteAfter.count())
	}
	v2, err := f.ia.FindVerificationValue(ctx, "test-id-1")
	if err != nil || v2 != nil {
		t.Fatalf("value2 = %+v %v", v2, err)
	}
	if _, err := f.ia.CreateVerificationValue(ctx, "test-id-1", "test-id-1", time.Now().Add(time.Second), nil); err != nil {
		t.Fatal(err)
	}
	for i := 3; i <= 4; i++ {
		v, err := f.ia.FindVerificationValue(ctx, "test-id-1")
		if err != nil || v == nil || v.Identifier != "test-id-1" {
			t.Fatalf("value%d = %+v %v", i, v, err)
		}
	}
}

func TestPortDBInternalAdapter_DeleteVerificationByValueWithHooks(t *testing.T) {
	f := pdNewMainFixture(t)
	ctx := context.Background()
	if _, err := f.ia.CreateVerificationValue(ctx, "test-id-1", "test-id-1", time.Now().Add(time.Second), nil); err != nil {
		t.Fatal(err)
	}
	if err := f.ia.DeleteVerificationByIdentifier(ctx, "test-id-1"); err != nil {
		t.Fatal(err)
	}
	if f.hookVerificationDeleteBefore.count() != 1 || f.hookVerificationDeleteAfter.count() != 1 {
		t.Fatalf("delete hooks: before=%d after=%d", f.hookVerificationDeleteBefore.count(), f.hookVerificationDeleteAfter.count())
	}
}

func TestPortDBInternalAdapter_DeleteVerificationByIdentifierWithHooks(t *testing.T) {
	f := pdNewMainFixture(t)
	ctx := context.Background()
	v, err := f.ia.CreateVerificationValue(ctx, "test-id-1", "test-id-1", time.Now().Add(time.Second), nil)
	if err != nil || v == nil {
		t.Fatal(v, err)
	}
	if err := f.ia.DeleteVerificationByIdentifier(ctx, v.Identifier); err != nil {
		t.Fatal(err)
	}
	if f.hookVerificationDeleteBefore.count() != 1 || f.hookVerificationDeleteAfter.count() != 1 {
		t.Fatalf("delete hooks: before=%d after=%d", f.hookVerificationDeleteBefore.count(), f.hookVerificationDeleteAfter.count())
	}
}

func TestPortDBInternalAdapter_NoAdapterDeleteForMissingVerificationRecord(t *testing.T) {
	f := pdNewMainFixture(t)
	ctx := context.Background()
	ac := f.auth.Context()
	v, err := f.ia.CreateVerificationValue(ctx, "missing-entity-test", "test-value", time.Now().Add(time.Minute), nil)
	if err != nil || v == nil {
		t.Fatal(v, err)
	}
	if _, err := ac.Adapter.DeleteMany(ctx, "verification", []adapter.Where{{Field: "identifier", Value: v.Identifier}}); err != nil {
		t.Fatal(err)
	}
	spy := &pdSpyAdapter{Adapter: ac.Adapter}
	orig := ac.Adapter
	ac.Adapter = spy
	defer func() { ac.Adapter = orig }()
	if err := f.ia.DeleteVerificationByIdentifier(ctx, "missing-entity-test"); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, m := range spy.deletes {
		if m == "verification" {
			n++
		}
	}
	if n != 0 {
		t.Fatalf("adapter.delete called %d times for verification", n)
	}
}

func TestPortDBInternalAdapter_VerificationTokenStorage(t *testing.T) {
	ctx := context.Background()
	t.Run("should hash identifier when storeIdentifier is 'hashed'", func(t *testing.T) {
		ia := pdIA(pdNewAuth(t, Config{Verification: &VerificationConfig{StoreIdentifier: &StoreIdentifier{Mode: "hashed"}}}))
		v, err := ia.CreateVerificationValue(ctx, "reset-password:my-token-123", "user-id-123", time.Now().Add(time.Minute), nil)
		if err != nil || v == nil {
			t.Fatal(v, err)
		}
		if v.Identifier == "reset-password:my-token-123" {
			t.Fatal("identifier stored in plain text")
		}
		found, err := ia.FindVerificationValue(ctx, "reset-password:my-token-123")
		if err != nil || found == nil || found.Value != "user-id-123" {
			t.Fatalf("found = %+v %v", found, err)
		}
		if err := ia.DeleteVerificationByIdentifier(ctx, "reset-password:my-token-123"); err != nil {
			t.Fatal(err)
		}
		deleted, err := ia.FindVerificationValue(ctx, "reset-password:my-token-123")
		if err != nil || deleted != nil {
			t.Fatalf("deleted = %+v %v", deleted, err)
		}
	})
	t.Run("should use overrides for specific prefixes", func(t *testing.T) {
		ia := pdIA(pdNewAuth(t, Config{Verification: &VerificationConfig{
			StoreIdentifier:          &StoreIdentifier{Mode: "plain"},
			StoreIdentifierOverrides: map[string]StoreIdentifier{"reset-password": {Mode: "hashed"}},
		}}))
		h, err := ia.CreateVerificationValue(ctx, "reset-password:token-abc", "user-1", time.Now().Add(time.Minute), nil)
		if err != nil || h == nil {
			t.Fatal(h, err)
		}
		if h.Identifier == "reset-password:token-abc" {
			t.Error("reset-password identifier should be hashed")
		}
		p, err := ia.CreateVerificationValue(ctx, "magic-link:token-xyz", "user-2", time.Now().Add(time.Minute), nil)
		if err != nil || p == nil {
			t.Fatal(p, err)
		}
		if p.Identifier != "magic-link:token-xyz" {
			t.Errorf("plain identifier = %q", p.Identifier)
		}
	})
	t.Run("should fallback to plain lookup for old tokens", func(t *testing.T) {
		db := memory.NewDB()
		plain := pdIA(pdNewAuth(t, Config{Database: memory.New(db), Verification: &VerificationConfig{StoreIdentifier: &StoreIdentifier{Mode: "plain"}}}))
		if _, err := plain.CreateVerificationValue(ctx, "old-token:abc123", "old-value", time.Now().Add(time.Minute), nil); err != nil {
			t.Fatal(err)
		}
		hashed := pdIA(pdNewAuth(t, Config{Database: memory.New(db), Verification: &VerificationConfig{StoreIdentifier: &StoreIdentifier{Mode: "hashed"}}}))
		found, err := hashed.FindVerificationValue(ctx, "old-token:abc123")
		if err != nil || found == nil || found.Value != "old-value" {
			t.Fatalf("found = %+v %v", found, err)
		}
	})
}

func TestPortDBInternalAdapter_RunsAfterHookAfterAddingUserToDB(t *testing.T) {
	db := memory.NewDB()
	var calls pdCalls
	a := pdNewAuth(t, Config{
		Database: memory.New(db),
		DatabaseHooks: &DatabaseHooks{User: DBModelHooks{Create: DBOperationHooks{
			After: func(ctx context.Context, user adapter.Record) error {
				calls.record(ctx, user)
				var row adapter.Record
				for _, r := range db.Rows("user") {
					if r["id"] == user["id"] {
						row = r
					}
				}
				if row == nil {
					t.Errorf("user %v not in database when after hook ran", user["id"])
					return nil
				}
				for _, k := range []string{"id", "name", "email", "image"} {
					if fmt.Sprint(user[k]) != fmt.Sprint(row[k]) {
						t.Errorf("%s: hook %v != db %v", k, user[k], row[k])
					}
				}
				if adapter.ToBool(user["emailVerified"]) != adapter.ToBool(row["emailVerified"]) {
					t.Errorf("emailVerified: hook %v != db %v", user["emailVerified"], row["emailVerified"])
				}
				for _, k := range []string{"createdAt", "updatedAt"} {
					ht, ok1 := adapter.ToTime(user[k])
					dt, ok2 := adapter.ToTime(row[k])
					if !ok1 || !ok2 || !ht.Equal(dt) {
						t.Errorf("%s: hook %v != db %v", k, user[k], row[k])
					}
				}
				return nil
			},
		}}},
	})
	if _, err := a.API.SignUpEmail(context.Background(), SignUpEmailInput{
		Name: "sample", Email: "sample@sampling.com", Password: "some-sample-password"}, nil); err != nil {
		t.Fatal(err)
	}
	if calls.count() != 1 {
		t.Fatalf("after hook called %d times", calls.count())
	}
}

func TestPortDBInternalAdapter_TTLMathFloorForSecondaryStorage(t *testing.T) {
	store := newPDStorage()
	a := pdNewAuth(t, Config{SecondaryStorage: store})
	ia := pdIA(a)
	ctx := context.Background()
	now := time.Now()
	testUser := adapter.Record{"id": "test-user-id", "name": "Test User", "email": "test@example.com",
		"emailVerified": true, "image": nil, "createdAt": now, "updatedAt": now}
	if _, err := ia.CreateUser(ctx, testUser, pdTestSource); err != nil {
		t.Fatal(err)
	}
	userJSON := fmt.Sprintf(`{"id":"test-user-id","name":"Test User","email":"test@example.com","emailVerified":true,"image":null,"createdAt":%q,"updatedAt":%q}`,
		pdISO(now), pdISO(now))
	seed := func(token string, expiresAt time.Time) {
		store.put("active-sessions-test-user-id", fmt.Sprintf(`[{"token":%q,"expiresAt":%d}]`, token, expiresAt.UnixMilli()))
		store.put(token, fmt.Sprintf(`{"session":{"userId":"test-user-id","token":%q,"expiresAt":%q,"ipAddress":"127.0.0.1","userAgent":"test-agent"},"user":%s}`,
			token, pdISO(expiresAt), userJSON))
	}

	// case 1: fractional seconds
	seed("test-token", time.Now().Add(3599500*time.Millisecond))
	expectedTTL := 3599
	if _, err := ia.UpdateUser(ctx, "test-user-id", adapter.Record{"name": "Updated Name"}); err != nil {
		t.Fatal(err)
	}
	last, ok := store.lastTTL()
	if !ok || last > expectedTTL || last < expectedTTL-1 {
		t.Errorf("case 1: last TTL = %d (ok=%v), want %d±1", last, ok, expectedTTL)
	}

	// case 2: < 1s rounds down to 0
	store.resetTTLLog()
	seed("almost-expired-token", time.Now().Add(500*time.Millisecond))
	if _, err := ia.UpdateUser(ctx, "test-user-id", adapter.Record{"name": "Updated Again"}); err != nil {
		t.Fatal(err)
	}
	if last, ok := store.lastTTL(); !ok || last != 0 {
		t.Errorf("case 2: last TTL = %d (ok=%v), want 0", last, ok)
	}

	// case 3: large TTL with fractional component
	store.resetTTLLog()
	seed("long-token", time.Now().Add(7199999*time.Millisecond))
	if _, err := ia.UpdateUser(ctx, "test-user-id", adapter.Record{"name": "Final Update"}); err != nil {
		t.Fatal(err)
	}
	if last, ok := store.lastTTL(); !ok || last > 7199 || last < 7198 {
		t.Errorf("case 3: last TTL = %d (ok=%v), want 7198..7199", last, ok)
	}
}

func TestPortDBInternalAdapter_CreateOnSecondaryStorage(t *testing.T) {
	f := pdNewMainFixture(t)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	user := pdCreateUser(t, f.ia, "test-user", "test@email.com")
	session := pdCreateSession(t, f.ia, user.ID)
	if session.ID == "" {
		t.Fatal("session id must be set even with secondary storage only")
	}
	list, ok := pdActiveList(t, f.store, user.ID)
	if !ok {
		t.Fatal("active-sessions list missing")
	}
	if len(list) != 1 || list[0].Token != session.Token {
		t.Fatalf("active list = %+v", list)
	}
	last := list[0]
	for _, r := range list {
		if r.ExpiresAt >= last.ExpiresAt {
			last = r
		}
	}
	actualExp, ok := f.store.ttlOf("active-sessions-" + user.ID)
	if !ok {
		t.Fatal("active-sessions ttl missing")
	}
	expectedExp := int((int64(last.ExpiresAt) - time.Now().UnixMilli()) / 1000)
	if d := actualExp - expectedExp; d > 1 || d < 0 {
		t.Errorf("active-sessions ttl = %d, expected %d", actualExp, expectedExp)
	}
	raw, ok := f.store.raw(session.Token)
	if !ok {
		t.Fatal("session not stored")
	}
	stored, _ := pdJSON(t, raw).(map[string]any)
	su, _ := stored["user"].(map[string]any)
	ss, _ := stored["session"].(map[string]any)
	pdMatchObject(t, "stored user", su, pdToMap(t, user))
	wantSession := pdToMap(t, session)
	wantSession["activeOrganizationId"] = "1"
	pdMatchObject(t, "stored session", ss, wantSession)
	actualTokenExp, ok := f.store.ttlOf(session.Token)
	if !ok {
		t.Fatal("token ttl missing")
	}
	expectedTokenExp := int((expiresAt.UnixMilli() - time.Now().UnixMilli()) / 1000)
	if d := actualTokenExp - expectedTokenExp; d > 1 || d < 0 {
		t.Errorf("token ttl = %d, expected %d", actualTokenExp, expectedTokenExp)
	}
}

func TestPortDBInternalAdapter_DeleteOnSecondaryStorage(t *testing.T) {
	f := pdNewMainFixture(t)
	ctx := context.Background()
	now := time.Now()
	userID := "test-user"
	key := "active-sessions-" + userID
	for i := -5; i < 5; i++ {
		expiresAt := now.Add(time.Duration(i) * 24 * time.Hour)
		if _, err := f.ia.CreateSession(ctx, userID, &CreateSessionOptions{
			Override: adapter.Record{"expiresAt": expiresAt}, OverrideAll: true}); err != nil {
			t.Fatal(err)
		}
		actualExp, has := f.store.ttlOf(key)
		if i > 0 {
			if !has {
				t.Errorf("i=%d: active-sessions ttl missing", i)
				continue
			}
			expectedExp := int((expiresAt.UnixMilli() - time.Now().UnixMilli()) / 1000)
			if d := actualExp - expectedExp; d > 1 || d < 0 {
				t.Errorf("i=%d: active-sessions ttl = %d, expected %d (override expiresAt ignored?)", i, actualExp, expectedExp)
			}
		} else if has {
			t.Errorf("i=%d: active-sessions ttl = %d, want undefined (session expired/expiring now)", i, actualExp)
		}
	}
	list, ok := pdActiveList(t, f.store, userID)
	if !ok {
		t.Fatal("active-sessions missing")
	}
	if len(list) != 4 {
		t.Fatalf("stored sessions = %d, want 4: %+v", len(list), list)
	}
	token := list[len(list)-1].Token
	if !f.store.has(token) {
		t.Fatal("token not stored")
	}
	if err := f.ia.DeleteSession(ctx, token); err != nil {
		t.Fatal(err)
	}
	after, ok := pdActiveList(t, f.store, userID)
	if !ok {
		t.Fatal("active-sessions missing after delete")
	}
	if len(after) != 3 {
		t.Fatalf("after delete = %d, want 3", len(after))
	}
	if f.store.has(token) {
		t.Fatal("deleted token still stored")
	}
	last := after[0]
	for _, r := range after {
		if r.ExpiresAt >= last.ExpiresAt {
			last = r
		}
	}
	actualExp, ok := f.store.ttlOf(key)
	if !ok {
		t.Fatal("ttl missing")
	}
	expectedExp := int((int64(last.ExpiresAt) - time.Now().UnixMilli()) / 1000)
	if d := actualExp - expectedExp; d > 1 || d < 0 {
		t.Errorf("ttl after delete = %d, expected %d", actualExp, expectedExp)
	}
}

func TestPortDBInternalAdapter_DeleteSingleAccount(t *testing.T) {
	f := pdNewMainFixture(t)
	ctx := context.Background()
	user := pdCreateUser(t, f.ia, "Account Delete User", "account.delete@example.com")
	acc, err := f.ia.CreateAccount(ctx, adapter.Record{"userId": user.ID, "providerId": "test-provider", "accountId": "test-account-id-1"})
	if err != nil || acc == nil {
		t.Fatal(acc, err)
	}
	found, err := f.ia.FindAccountByKey(ctx, acc.ProviderID, acc.AccountID)
	if err != nil || found == nil {
		t.Fatal(found, err)
	}
	if err := f.ia.DeleteAccount(ctx, acc.ID); err != nil {
		t.Fatal(err)
	}
	found, err = f.ia.FindAccountByKey(ctx, acc.ProviderID, acc.AccountID)
	if err != nil || found != nil {
		t.Fatalf("found after delete = %+v %v", found, err)
	}
}

func TestPortDBInternalAdapter_RejectsAmbiguousAccountKeys(t *testing.T) {
	for _, joins := range []bool{false, true} {
		t.Run(fmt.Sprintf("joins=%v", joins), func(t *testing.T) {
			ia := pdIA(pdNewAuth(t, Config{Advanced: &AdvancedConfig{Database: &DatabaseAdvancedConfig{Joins: joins}}}))
			ctx := context.Background()
			for _, name := range []string{"first", "second"} {
				u := pdCreateUser(t, ia, name, name+"@ambiguous-account.test")
				if _, err := ia.CreateAccount(ctx, adapter.Record{"userId": u.ID, "providerId": "tenant", "accountId": "shared-subject"}); err != nil {
					t.Fatal(err)
				}
			}
			want := `Multiple accounts match the same accountId for provider "tenant".`
			if _, err := ia.FindAccountByKey(ctx, "tenant", "shared-subject"); err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("findAccountByKey err = %v", err)
			}
			if _, err := ia.FindAccountOwnerByKey(ctx, "tenant", "shared-subject"); err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("findAccountOwnerByKey err = %v", err)
			}
		})
	}
}

func TestPortDBInternalAdapter_FindsAccountOwnerByExactKey(t *testing.T) {
	f := pdNewMainFixture(t)
	ctx := context.Background()
	first := pdCreateUser(t, f.ia, "First Account Key User", "first.account.key@example.com")
	second := pdCreateUser(t, f.ia, "Second Account Key User", "second.account.key@example.com")
	accountID := "shared-provider-subject"
	firstAcc, err := f.ia.CreateAccount(ctx, adapter.Record{"userId": first.ID, "providerId": "first-provider-configuration", "accountId": accountID})
	if err != nil {
		t.Fatal(err)
	}
	secondAcc, err := f.ia.CreateAccount(ctx, adapter.Record{"userId": second.ID, "providerId": "second-provider-configuration", "accountId": accountID})
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.ia.FindAccountByKey(ctx, firstAcc.ProviderID, accountID)
	if err != nil || got == nil || got.ID != firstAcc.ID {
		t.Errorf("findAccountByKey = %+v %v", got, err)
	}
	owner, err := f.ia.FindAccountOwnerByKey(ctx, secondAcc.ProviderID, accountID)
	if err != nil || owner == nil || owner.Kind != "owned" || owner.User == nil || owner.User.ID != second.ID ||
		owner.Account == nil || owner.Account.ID != secondAcc.ID || owner.Account.ProviderID != "second-provider-configuration" {
		t.Errorf("findAccountOwnerByKey = %+v %v", owner, err)
	}
	missing, err := f.ia.FindAccountOwnerByKey(ctx, "missing-provider-configuration", accountID)
	if err != nil || missing != nil {
		t.Errorf("missing = %+v %v", missing, err)
	}
}

func TestPortDBInternalAdapter_ReportsAccountWhoseOwnerIsMissing(t *testing.T) {
	// SQLite needs `PRAGMA foreign_keys = OFF`; the memory adapter has no FK constraints.
	f := pdNewMainFixture(t)
	ctx := context.Background()
	acc, err := f.ia.CreateAccount(ctx, adapter.Record{"userId": "missing-account-owner", "providerId": "orphaned-provider", "accountId": "orphaned-subject"})
	if err != nil || acc == nil {
		t.Fatal(acc, err)
	}
	owner, err := f.ia.FindAccountOwnerByKey(ctx, acc.ProviderID, acc.AccountID)
	if err != nil || owner == nil || owner.Kind != "orphaned" || owner.Account == nil ||
		owner.Account.ID != acc.ID || owner.Account.UserID != "missing-account-owner" {
		t.Fatalf("owner = %+v %v", owner, err)
	}
}

func TestPortDBInternalAdapter_FindsCredentialAccountAfterEmailChange(t *testing.T) {
	f := pdNewMainFixture(t)
	ctx := context.Background()
	user := pdCreateUser(t, f.ia, "Stable Credential User", "stable.credential@example.com")
	acc, err := f.ia.CreateAccount(ctx, adapter.Record{"userId": user.ID, "providerId": "credential", "accountId": user.ID, "password": "password-hash"})
	if err != nil {
		t.Fatal(err)
	}
	check := func(label string) {
		got, err := f.ia.FindCredentialAccount(ctx, user.ID)
		if err != nil || got == nil || got.ID != acc.ID || got.AccountID != user.ID {
			t.Errorf("%s: credential account = %+v %v", label, got, err)
		}
	}
	check("before")
	if _, err := f.ia.UpdateUser(ctx, user.ID, adapter.Record{"email": "changed.stable.credential@example.com"}); err != nil {
		t.Fatal(err)
	}
	check("after")
}

func TestPortDBInternalAdapter_DeleteMultipleAccountsForUser(t *testing.T) {
	f := pdNewMainFixture(t)
	ctx := context.Background()
	user := pdCreateUser(t, f.ia, "Accounts Delete User", "accounts.delete@example.com")
	for i, p := range []string{"test-provider-1", "test-provider-2"} {
		if _, err := f.ia.CreateAccount(ctx, adapter.Record{"userId": user.ID, "providerId": p, "accountId": fmt.Sprintf("test-account-id-%d", i+2)}); err != nil {
			t.Fatal(err)
		}
	}
	accs, err := f.ia.FindAccounts(ctx, user.ID)
	if err != nil || len(accs) != 2 {
		t.Fatalf("accounts = %d %v", len(accs), err)
	}
	if err := f.ia.DeleteAccounts(ctx, user.ID); err != nil {
		t.Fatal(err)
	}
	accs, err = f.ia.FindAccounts(ctx, user.ID)
	if err != nil || len(accs) != 0 {
		t.Fatalf("accounts after delete = %d %v", len(accs), err)
	}
}

// pdSecondaryOnly is `{ database: sqlite, secondaryStorage: createStringSecondaryStorage(map) }`.
func pdSecondaryOnly(t *testing.T, mutate func(c *Config)) (*Auth, *pdStorage) {
	t.Helper()
	store := newPDStorage()
	cfg := Config{SecondaryStorage: store}
	if mutate != nil {
		mutate(&cfg)
	}
	return pdNewAuth(t, cfg), store
}

func pdTokens(ss []*Session) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s.Token
	}
	sort.Strings(out)
	return out
}

func pdSorted(v ...string) []string {
	sort.Strings(v)
	return v
}

func TestPortDBInternalAdapter_ListSessionsSkipsMissingSessions(t *testing.T) {
	a, store := pdSecondaryOnly(t, nil)
	ia := pdIA(a)
	user := pdCreateUser(t, ia, "test-user-skip", "test-skip@email.com")
	s1, s2, s3 := pdCreateSession(t, ia, user.ID), pdCreateSession(t, ia, user.ID), pdCreateSession(t, ia, user.ID)
	ss, err := ia.ListSessions(context.Background(), user.ID, false)
	if err != nil || len(ss) != 3 {
		t.Fatalf("sessions = %d %v", len(ss), err)
	}
	store.del(s2.Token)
	ss, err = ia.ListSessions(context.Background(), user.ID, false)
	if err != nil || len(ss) != 2 {
		t.Fatalf("sessions = %d %v", len(ss), err)
	}
	if got, want := pdTokens(ss), pdSorted(s1.Token, s3.Token); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("tokens = %v, want %v", got, want)
	}
}

func TestPortDBInternalAdapter_DefersSecondarySessionDeletionUntilCommit(t *testing.T) {
	a, store := pdSecondaryOnly(t, nil)
	ia := pdIA(a)
	ac := a.Context()
	user := pdCreateUser(t, ia, "transactional-session-user", "transactional-session@example.com")
	session := pdCreateSession(t, ia, user.ID)
	rollback := errors.New("rollback")
	err := ac.RunWithTransaction(context.Background(), func(ctx context.Context) error {
		if err := ia.DeleteUserSessions(ctx, user.ID); err != nil {
			return err
		}
		if !store.has(session.Token) {
			t.Error("session deleted before commit")
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("err = %v", err)
	}
	if !store.has(session.Token) || !store.has("active-sessions-"+user.ID) {
		t.Fatal("rollback must keep the cached session")
	}
	err = ac.RunWithTransaction(context.Background(), func(ctx context.Context) error {
		if err := ia.DeleteUserSessions(ctx, user.ID); err != nil {
			return err
		}
		if !store.has(session.Token) {
			t.Error("session deleted before commit")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if store.has(session.Token) || store.has("active-sessions-"+user.ID) {
		t.Fatal("commit must delete the cached session")
	}
}

func TestPortDBInternalAdapter_DefersSecondarySessionCreationUntilCommit(t *testing.T) {
	a, store := pdSecondaryOnly(t, func(c *Config) { c.Session = &SessionConfig{StoreSessionInDatabase: true} })
	ia := pdIA(a)
	ac := a.Context()
	user := pdCreateUser(t, ia, "deferred-session-user", "deferred-session@example.com")
	var committed *Session
	err := ac.RunWithTransaction(context.Background(), func(ctx context.Context) error {
		s, err := ia.CreateSession(ctx, user.ID, &CreateSessionOptions{DeferSecondaryStorageWrites: true})
		if err != nil {
			return err
		}
		if store.has(s.Token) {
			t.Error("session written before commit")
		}
		committed = s
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !store.has(committed.Token) {
		t.Fatal("session not written after commit")
	}
	rolledBack := ""
	rollback := errors.New("rollback")
	err = ac.RunWithTransaction(context.Background(), func(ctx context.Context) error {
		s, err := ia.CreateSession(ctx, user.ID, &CreateSessionOptions{DeferSecondaryStorageWrites: true})
		if err != nil {
			return err
		}
		rolledBack = s.Token
		if store.has(s.Token) {
			t.Error("session written before commit")
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("err = %v", err)
	}
	if store.has(rolledBack) {
		t.Fatal("rolled back session written to secondary storage")
	}
}

// @see https://github.com/better-auth/better-auth/pull/10473#discussion_r3626724281
func TestPortDBInternalAdapter_RejectsDeferredSecondaryOnlySessionCreationWhenPersistenceFails(t *testing.T) {
	a, store := pdSecondaryOnly(t, nil)
	ia := pdIA(a)
	user := pdCreateUser(t, ia, "failed-deferred-session-user", "failed-deferred-session@example.com")
	store.failSet = errors.New("secondary storage unavailable")
	err := a.Context().RunWithTransaction(context.Background(), func(ctx context.Context) error {
		_, err := ia.CreateSession(ctx, user.ID, &CreateSessionOptions{DeferSecondaryStorageWrites: true})
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "secondary storage unavailable") {
		t.Fatalf("expected rejection with 'secondary storage unavailable', got %v", err)
	}
}

// @see https://github.com/better-auth/better-auth/pull/10390#discussion_r3585595438
func TestPortDBInternalAdapter_PreservesSessionsCreatedAfterDeletionRequested(t *testing.T) {
	a, store := pdSecondaryOnly(t, nil)
	ia := pdIA(a)
	user := pdCreateUser(t, ia, "replacement-session-user", "replacement-session@example.com")
	previous := pdCreateSession(t, ia, user.ID)
	var replacement *Session
	err := a.Context().RunWithTransaction(context.Background(), func(ctx context.Context) error {
		if err := ia.DeleteUserSessions(ctx, user.ID); err != nil {
			return err
		}
		s, err := ia.CreateSession(ctx, user.ID, nil)
		if err != nil {
			return err
		}
		if !store.has(previous.Token) || !store.has(s.Token) {
			t.Error("both sessions must exist inside the transaction")
		}
		replacement = s
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if store.has(previous.Token) {
		t.Error("previous session not deleted")
	}
	if !store.has(replacement.Token) {
		t.Error("replacement session deleted")
	}
	list, _ := pdActiveList(t, store, user.ID)
	if len(list) != 1 || list[0].Token != replacement.Token {
		t.Errorf("active list = %+v", list)
	}
}

// @see https://github.com/better-auth/better-auth/pull/10390
func TestPortDBInternalAdapter_KeepsStoredSessionsWhenRevocationSnapshotUnreadable(t *testing.T) {
	failActive := false
	a, store := pdSecondaryOnly(t, func(c *Config) { c.Session = &SessionConfig{StoreSessionInDatabase: true} })
	store.failGet = func(key string) error {
		if failActive && strings.HasPrefix(key, "active-sessions-") {
			return errors.New("secondary storage is unavailable")
		}
		return nil
	}
	ia := pdIA(a)
	user := pdCreateUser(t, ia, "snapshot-failure-user", "snapshot-failure@example.com")
	session := pdCreateSession(t, ia, user.ID)
	failActive = true
	err := ia.DeleteUserSessions(context.Background(), user.ID)
	if err == nil || !strings.Contains(err.Error(), "secondary storage is unavailable") {
		t.Errorf("deleteUserSessions should reject with 'secondary storage is unavailable', got %v", err)
	}
	failActive = false
	store.del(session.Token)
	stored, err := ia.FindSession(context.Background(), session.Token)
	if err != nil || stored == nil || stored.Session.Token != session.Token {
		t.Fatalf("stored session = %+v %v (database row must survive)", stored, err)
	}
}

func TestPortDBInternalAdapter_ListSessionsSkipsMalformedSessionData(t *testing.T) {
	a, store := pdSecondaryOnly(t, nil)
	ia := pdIA(a)
	user := pdCreateUser(t, ia, "test-user-malformed", "test-malformed@email.com")
	s1, s2, s3 := pdCreateSession(t, ia, user.ID), pdCreateSession(t, ia, user.ID), pdCreateSession(t, ia, user.ID)
	store.put(s2.Token, `{"session":null,"user":null}`)
	ss, err := ia.ListSessions(context.Background(), user.ID, false)
	if err != nil || len(ss) != 2 {
		t.Fatalf("sessions = %d %v", len(ss), err)
	}
	if got, want := pdTokens(ss), pdSorted(s1.Token, s3.Token); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("tokens = %v, want %v", got, want)
	}
}

func TestPortDBInternalAdapter_ListSessionsSkipsCorruptSessions(t *testing.T) {
	a, store := pdSecondaryOnly(t, nil)
	ia := pdIA(a)
	user := pdCreateUser(t, ia, "test-user-corrupt", "test-corrupt@email.com")
	s1, s2, s3 := pdCreateSession(t, ia, user.ID), pdCreateSession(t, ia, user.ID), pdCreateSession(t, ia, user.ID)
	store.put(s2.Token, "invalid-json{{{")
	ss, err := ia.ListSessions(context.Background(), user.ID, false)
	if err != nil || len(ss) != 2 {
		t.Fatalf("sessions = %d %v", len(ss), err)
	}
	if got, want := pdTokens(ss), pdSorted(s1.Token, s3.Token); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("tokens = %v, want %v", got, want)
	}
}

func TestPortDBInternalAdapter_ListSessionsEmptyWhenAllCorrupt(t *testing.T) {
	a, store := pdSecondaryOnly(t, nil)
	ia := pdIA(a)
	user := pdCreateUser(t, ia, "test-user-all-corrupt", "test-all-corrupt@email.com")
	s1, s2 := pdCreateSession(t, ia, user.ID), pdCreateSession(t, ia, user.ID)
	store.put(s1.Token, "invalid-json")
	store.put(s2.Token, "also-invalid")
	ss, err := ia.ListSessions(context.Background(), user.ID, false)
	if err != nil || len(ss) != 0 {
		t.Fatalf("sessions = %d %v", len(ss), err)
	}
}

func TestPortDBInternalAdapter_FindSessionsSkipsInvalidEntries(t *testing.T) {
	for _, tc := range []struct{ name, stored string }{
		{"malformed JSON sessions", "invalid-json{{{"},
		{"JSON null sessions", "null"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, store := pdSecondaryOnly(t, nil)
			ia := pdIA(a)
			user := pdCreateUser(t, ia, "test-user-find", "test-find@email.com")
			s1, s2, s3 := pdCreateSession(t, ia, user.ID), pdCreateSession(t, ia, user.ID), pdCreateSession(t, ia, user.ID)
			store.put(s2.Token, tc.stored)
			got, err := ia.FindSessions(context.Background(), []string{s1.Token, s2.Token, s3.Token}, false)
			if err != nil {
				t.Fatal(err)
			}
			var toks []string
			for _, s := range got {
				toks = append(toks, s.Session.Token)
			}
			if fmt.Sprint(toks) != fmt.Sprint([]string{s1.Token, s3.Token}) {
				t.Fatalf("tokens = %v, want [%s %s]", toks, s1.Token, s3.Token)
			}
		})
	}
}

func TestPortDBInternalAdapter_UpdateSessionAndActiveSessionsList(t *testing.T) {
	a, store := pdSecondaryOnly(t, nil)
	ia := pdIA(a)
	user := pdCreateUser(t, ia, "test-user-update", "test-update@email.com")
	session := pdCreateSession(t, ia, user.ID)
	raw, ok := store.raw(session.Token)
	if !ok {
		t.Fatal("session not stored")
	}
	stored := pdJSON(t, raw).(map[string]any)
	if ip := stored["session"].(map[string]any)["ipAddress"]; ip != "" {
		t.Fatalf("ipAddress = %#v, want \"\"", ip)
	}
	initial, ok := pdActiveList(t, store, user.ID)
	if !ok || len(initial) != 1 {
		t.Fatalf("initial list = %+v", initial)
	}
	newExpiresAt := time.UnixMilli(int64(initial[0].ExpiresAt) + 60*60*1000)
	if _, err := ia.UpdateSession(context.Background(), session.Token, adapter.Record{"ipAddress": "192.168.1.1", "expiresAt": newExpiresAt}); err != nil {
		t.Fatal(err)
	}
	raw, ok = store.raw(session.Token)
	if !ok {
		t.Fatal("session missing after update")
	}
	updated := pdJSON(t, raw).(map[string]any)
	if ip := updated["session"].(map[string]any)["ipAddress"]; ip != "192.168.1.1" {
		t.Errorf("updated ipAddress = %#v", ip)
	}
	if u, _ := updated["user"].(map[string]any); u == nil || u["id"] != user.ID {
		t.Errorf("user not intact: %v", updated["user"])
	}
	list, ok := pdActiveList(t, store, user.ID)
	if !ok || len(list) != 1 || list[0].Token != session.Token || int64(list[0].ExpiresAt) != newExpiresAt.UnixMilli() {
		t.Fatalf("updated list = %+v, want expiresAt %d", list, newExpiresAt.UnixMilli())
	}
	ttl, ok := store.ttlOf("active-sessions-" + user.ID)
	expected := int((newExpiresAt.UnixMilli() - time.Now().UnixMilli()) / 1000)
	if !ok || ttl-expected > 1 || ttl-expected < 0 {
		t.Errorf("ttl = %d (ok=%v), expected %d", ttl, ok, expected)
	}
}

func TestPortDBInternalAdapter_DeduplicatesActiveSessionsList(t *testing.T) {
	a, store := pdSecondaryOnly(t, nil)
	ia := pdIA(a)
	user := pdCreateUser(t, ia, "corrupt-sessions-test-user", "corrupt-sessions-test@example.com")
	session := pdCreateSession(t, ia, user.ID)
	list, _ := pdActiveList(t, store, user.ID)
	exp := session.ExpiresAt.UnixMilli()
	store.put("active-sessions-"+user.ID, fmt.Sprintf(`[{"token":%q,"expiresAt":%d},{"token":%q,"expiresAt":%d},{"token":%q,"expiresAt":%d}]`,
		list[0].Token, int64(list[0].ExpiresAt), session.Token, exp, session.Token, exp))
	if parsed, _ := pdActiveList(t, store, user.ID); len(parsed) != 3 {
		t.Fatalf("corrupted list = %d", len(parsed))
	}
	ss, err := ia.ListSessions(context.Background(), user.ID, false)
	if err != nil || len(ss) != 1 {
		t.Fatalf("sessions = %d %v", len(ss), err)
	}
}

func TestPortDBInternalAdapter_VerificationSecondaryStorage(t *testing.T) {
	ctx := context.Background()
	t.Run("should store verification in secondary storage by default", func(t *testing.T) {
		a, store := pdSecondaryOnly(t, nil)
		v, err := pdIA(a).CreateVerificationValue(ctx, "test-verification", "test-value", time.Now().Add(time.Minute), nil)
		if err != nil || v == nil {
			t.Fatal(v, err)
		}
		if !store.has("verification:" + v.Identifier) {
			t.Error("data missing")
		}
		if _, ok := store.ttlOf("verification:" + v.Identifier); !ok {
			t.Error("ttl missing")
		}
	})
	t.Run("should find verification from secondary storage", func(t *testing.T) {
		a, _ := pdSecondaryOnly(t, nil)
		ia := pdIA(a)
		if _, err := ia.CreateVerificationValue(ctx, "find-test", "find-value", time.Now().Add(time.Minute), nil); err != nil {
			t.Fatal(err)
		}
		found, err := ia.FindVerificationValue(ctx, "find-test")
		if err != nil || found == nil || found.Identifier != "find-test" || found.Value != "find-value" {
			t.Fatalf("found = %+v %v", found, err)
		}
	})
	t.Run("should NOT store in database when secondary-only mode", func(t *testing.T) {
		a, store := pdSecondaryOnly(t, nil)
		ia := pdIA(a)
		if _, err := ia.CreateVerificationValue(ctx, "secondary-only-test", "test-value", time.Now().Add(time.Minute), nil); err != nil {
			t.Fatal(err)
		}
		if !store.has("verification:secondary-only-test") {
			t.Fatal("not in secondary storage")
		}
		store.clear()
		found, err := ia.FindVerificationValue(ctx, "secondary-only-test")
		if err != nil || found != nil {
			t.Fatalf("found = %+v %v (database must not be used)", found, err)
		}
	})
	t.Run("should delete verification from secondary storage", func(t *testing.T) {
		a, store := pdSecondaryOnly(t, nil)
		ia := pdIA(a)
		if _, err := ia.CreateVerificationValue(ctx, "delete-test", "delete-value", time.Now().Add(time.Minute), nil); err != nil {
			t.Fatal(err)
		}
		if !store.has("verification:delete-test") {
			t.Fatal("not stored")
		}
		if err := ia.DeleteVerificationByIdentifier(ctx, "delete-test"); err != nil {
			t.Fatal(err)
		}
		if store.has("verification:delete-test") {
			t.Fatal("not deleted")
		}
	})
	for _, name := range []string{"should store in both when storeInDatabase is true", "should fallback to database when not in secondary storage"} {
		t.Run(name, func(t *testing.T) {
			a, store := pdSecondaryOnly(t, func(c *Config) { c.Verification = &VerificationConfig{StoreInDatabase: true} })
			ia := pdIA(a)
			if _, err := ia.CreateVerificationValue(ctx, "both-test", "both-value", time.Now().Add(time.Minute), nil); err != nil {
				t.Fatal(err)
			}
			if !store.has("verification:both-test") {
				t.Fatal("not in secondary storage")
			}
			store.clear()
			found, err := ia.FindVerificationValue(ctx, "both-test")
			if err != nil || found == nil || found.Value != "both-value" {
				t.Fatalf("found = %+v %v", found, err)
			}
		})
	}
	t.Run("should set correct TTL based on expiresAt", func(t *testing.T) {
		a, store := pdSecondaryOnly(t, nil)
		if _, err := pdIA(a).CreateVerificationValue(ctx, "ttl-test", "ttl-value", time.Now().Add(300*time.Second), nil); err != nil {
			t.Fatal(err)
		}
		ttl, ok := store.ttlOf("verification:ttl-test")
		if !ok || ttl < 298 || ttl > 300 {
			t.Fatalf("ttl = %d (ok=%v)", ttl, ok)
		}
	})
}

// "safeJSONParse date revival in secondary storage": upstream simulates a Redis client that
// returns pre-parsed objects from get(). The Go SecondaryStorage interface returns strings,
// so that shape cannot occur; the date-revival assertions are ported against JSON strings.
func TestPortDBInternalAdapter_DateRevivalInSecondaryStorage(t *testing.T) {
	ctx := context.Background()
	t.Run("returns time values from findVerificationValue", func(t *testing.T) {
		a, _ := pdSecondaryOnly(t, nil)
		ia := pdIA(a)
		if _, err := ia.CreateVerificationValue(ctx, "date-test", "test-value", time.Now().Add(time.Minute), nil); err != nil {
			t.Fatal(err)
		}
		found, err := ia.FindVerificationValue(ctx, "date-test")
		if err != nil || found == nil {
			t.Fatal(found, err)
		}
		if found.ExpiresAt.IsZero() || found.CreatedAt.IsZero() || found.UpdatedAt.IsZero() {
			t.Fatalf("dates not revived: %+v", found)
		}
	})
	t.Run("detects expiry correctly", func(t *testing.T) {
		a, _ := pdSecondaryOnly(t, nil)
		ia := pdIA(a)
		if _, err := ia.CreateVerificationValue(ctx, "expiry-check", "test-value", time.Now().Add(time.Minute), nil); err != nil {
			t.Fatal(err)
		}
		found, err := ia.FindVerificationValue(ctx, "expiry-check")
		if err != nil || found == nil {
			t.Fatal(found, err)
		}
		if !found.ExpiresAt.After(time.Now()) || !found.ExpiresAt.Before(time.Now().Add(120*time.Second)) {
			t.Fatalf("expiresAt = %v", found.ExpiresAt)
		}
	})
	t.Run("consistent across multiple reads", func(t *testing.T) {
		a, _ := pdSecondaryOnly(t, nil)
		ia := pdIA(a)
		if _, err := ia.CreateVerificationValue(ctx, "multi-read-test", "test-value", time.Now().Add(time.Minute), nil); err != nil {
			t.Fatal(err)
		}
		first, err := ia.FindVerificationValue(ctx, "multi-read-test")
		if err != nil || first == nil || first.ExpiresAt.IsZero() || first.CreatedAt.IsZero() || first.UpdatedAt.IsZero() {
			t.Fatal(first, err)
		}
		second, err := ia.FindVerificationValue(ctx, "multi-read-test")
		if err != nil || second == nil || !second.ExpiresAt.Equal(first.ExpiresAt) {
			t.Fatalf("second = %+v %v", second, err)
		}
	})
	t.Run("preserves non-date string fields", func(t *testing.T) {
		a, _ := pdSecondaryOnly(t, nil)
		ia := pdIA(a)
		if _, err := ia.CreateVerificationValue(ctx, "string-field-test", "my-token-value-123", time.Now().Add(time.Minute), nil); err != nil {
			t.Fatal(err)
		}
		found, err := ia.FindVerificationValue(ctx, "string-field-test")
		if err != nil || found == nil || found.Identifier != "string-field-test" || found.Value != "my-token-value-123" || found.ExpiresAt.IsZero() {
			t.Fatalf("found = %+v %v", found, err)
		}
	})
}

func TestPortDBInternalAdapter_ConsumeVerificationValue(t *testing.T) {
	ctx := context.Background()
	mk := func(t *testing.T, mutate func(c *Config)) *InternalAdapter {
		cfg := Config{}
		if mutate != nil {
			mutate(&cfg)
		}
		return pdIA(pdNewAuth(t, cfg))
	}
	create := func(t *testing.T, ia *InternalAdapter, id, value string, exp time.Time) {
		t.Helper()
		if _, err := ia.CreateVerificationValue(ctx, id, value, exp, nil); err != nil {
			t.Fatal(err)
		}
	}
	consumeAll := func(ia *InternalAdapter, id string, n int) []*Verification {
		out := make([]*Verification, n)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				out[i], _ = ia.ConsumeVerificationValue(ctx, id)
			}(i)
		}
		wg.Wait()
		return out
	}
	winners := func(rs []*Verification) []*Verification {
		var w []*Verification
		for _, r := range rs {
			if r != nil {
				w = append(w, r)
			}
		}
		return w
	}

	t.Run("returns the row to the first caller and null to subsequent reads", func(t *testing.T) {
		ia := mk(t, nil)
		create(t, ia, "consume:single", "user-1", time.Now().Add(time.Minute))
		first, err := ia.ConsumeVerificationValue(ctx, "consume:single")
		if err != nil || first == nil || first.Value != "user-1" {
			t.Fatalf("first = %+v %v", first, err)
		}
		second, err := ia.ConsumeVerificationValue(ctx, "consume:single")
		if err != nil || second != nil {
			t.Fatalf("second = %+v %v", second, err)
		}
	})
	t.Run("yields exactly one winner under concurrent consume", func(t *testing.T) {
		ia := mk(t, nil)
		create(t, ia, "consume:race", "user-2", time.Now().Add(time.Minute))
		w := winners(consumeAll(ia, "consume:race", 3))
		if len(w) != 1 || w[0].Value != "user-2" {
			t.Fatalf("winners = %+v", w)
		}
	})
	t.Run("returns null for an unknown identifier", func(t *testing.T) {
		ia := mk(t, nil)
		r, err := ia.ConsumeVerificationValue(ctx, "consume:missing")
		if err != nil || r != nil {
			t.Fatalf("r = %+v %v", r, err)
		}
	})
	t.Run("returns null when the row exists but has already expired", func(t *testing.T) {
		ia := mk(t, nil)
		create(t, ia, "consume:expired", "user-expired", time.Now().Add(-time.Second))
		r, err := ia.ConsumeVerificationValue(ctx, "consume:expired")
		if err != nil || r != nil {
			t.Fatalf("r = %+v %v", r, err)
		}
		replay, err := ia.FindVerificationValue(ctx, "consume:expired")
		if err != nil || replay != nil {
			t.Fatalf("replay = %+v %v", replay, err)
		}
	})
	t.Run("aborts the consume when a delete.before hook returns false", func(t *testing.T) {
		var veto pdCalls
		ia := mk(t, func(c *Config) {
			c.DatabaseHooks = &DatabaseHooks{Verification: DBModelHooks{Delete: DBOperationHooks{
				Before: func(ctx context.Context, d adapter.Record) (*DBHookResult, error) {
					veto.record(ctx, d)
					return &DBHookResult{Abort: true}, nil
				}}}}
		})
		create(t, ia, "consume:veto", "user-3", time.Now().Add(time.Minute))
		r, err := ia.ConsumeVerificationValue(ctx, "consume:veto")
		if err != nil || r != nil {
			t.Fatalf("r = %+v %v", r, err)
		}
		if veto.count() != 1 {
			t.Fatalf("veto called %d times", veto.count())
		}
		still, err := ia.FindVerificationValue(ctx, "consume:veto")
		if err != nil || still == nil {
			t.Fatalf("row should remain: %+v %v", still, err)
		}
	})
	t.Run("fires delete.after only for the winning racer", func(t *testing.T) {
		var after pdCalls
		ia := mk(t, func(c *Config) {
			c.DatabaseHooks = &DatabaseHooks{Verification: DBModelHooks{Delete: DBOperationHooks{
				After: func(ctx context.Context, d adapter.Record) error {
					after.record(ctx, d)
					return nil
				}}}}
		})
		create(t, ia, "consume:after-once", "user-4", time.Now().Add(time.Minute))
		if w := winners(consumeAll(ia, "consume:after-once", 2)); len(w) != 1 {
			t.Fatalf("winners = %d", len(w))
		}
		if after.count() != 1 {
			t.Fatalf("after hook called %d times", after.count())
		}
	})
	t.Run("consumes via the original identifier when storeIdentifier is hashed", func(t *testing.T) {
		ia := mk(t, func(c *Config) {
			c.Verification = &VerificationConfig{StoreIdentifier: &StoreIdentifier{Mode: "hashed"}}
		})
		create(t, ia, "consume:hashed", "user-5", time.Now().Add(time.Minute))
		r, err := ia.ConsumeVerificationValue(ctx, "consume:hashed")
		if err != nil || r == nil || r.Value != "user-5" {
			t.Fatalf("r = %+v %v", r, err)
		}
		replay, err := ia.ConsumeVerificationValue(ctx, "consume:hashed")
		if err != nil || replay != nil {
			t.Fatalf("replay = %+v %v", replay, err)
		}
	})
	t.Run("consumes the latest row and invalidates stale rows for the identifier", func(t *testing.T) {
		ia := mk(t, nil)
		create(t, ia, "consume:multi", "older", time.Now().Add(time.Minute))
		time.Sleep(5 * time.Millisecond)
		create(t, ia, "consume:multi", "newer", time.Now().Add(time.Minute))
		r, err := ia.ConsumeVerificationValue(ctx, "consume:multi")
		if err != nil || r == nil || r.Value != "newer" {
			t.Fatalf("consumed = %+v %v", r, err)
		}
		left, err := ia.FindVerificationValue(ctx, "consume:multi")
		if err != nil || left != nil {
			t.Fatalf("leftover = %+v %v", left, err)
		}
	})
	t.Run("uses secondary storage getAndDelete when verification values are storage-only", func(t *testing.T) {
		store := newPDStorage()
		ia := mk(t, func(c *Config) {
			c.Verification = &VerificationConfig{StoreInDatabase: false}
			c.SecondaryStorage = store
		})
		create(t, ia, "consume:secondary", "secondary-user", time.Now().Add(time.Minute))
		w := winners(consumeAll(ia, "consume:secondary", 2))
		if len(w) != 1 || w[0].Value != "secondary-user" {
			t.Fatalf("winners = %+v", w)
		}
		found := false
		for _, k := range store.getAndDeleteKeys {
			if k == "verification:consume:secondary" {
				found = true
			}
		}
		if !found {
			t.Errorf("getAndDelete keys = %v", store.getAndDeleteKeys)
		}
		if store.has("verification:consume:secondary") {
			t.Error("key not removed")
		}
	})
	t.Run("returns null when the secondary storage row has already expired", func(t *testing.T) {
		store := newPDStorage()
		ia := mk(t, func(c *Config) {
			c.Verification = &VerificationConfig{StoreInDatabase: false}
			c.SecondaryStorage = store
		})
		now := time.Now()
		store.put("verification:consume:secondary-expired", fmt.Sprintf(
			`{"id":"row-id","identifier":"consume:secondary-expired","value":"secondary-expired-user","expiresAt":%q,"createdAt":%q,"updatedAt":%q}`,
			pdISO(now.Add(-time.Second)), pdISO(now), pdISO(now)))
		r, err := ia.ConsumeVerificationValue(ctx, "consume:secondary-expired")
		if err != nil || r != nil {
			t.Fatalf("r = %+v %v", r, err)
		}
		if store.has("verification:consume:secondary-expired") {
			t.Error("expired row must still be consumed")
		}
	})
	t.Run("rehydrates string expiresAt from secondary storage JSON", func(t *testing.T) {
		store := newPDStorage()
		ia := mk(t, func(c *Config) {
			c.Verification = &VerificationConfig{StoreInDatabase: false}
			c.SecondaryStorage = store
		})
		create(t, ia, "consume:secondary-hydrate", "hydrate-user", time.Now().Add(time.Minute))
		r, err := ia.ConsumeVerificationValue(ctx, "consume:secondary-hydrate")
		if err != nil || r == nil || r.Value != "hydrate-user" || !r.ExpiresAt.After(time.Now()) {
			t.Fatalf("r = %+v %v", r, err)
		}
	})
	t.Run("returns null when secondary storage expiresAt cannot be parsed", func(t *testing.T) {
		store := newPDStorage()
		ia := mk(t, func(c *Config) {
			c.Verification = &VerificationConfig{StoreInDatabase: false}
			c.SecondaryStorage = store
		})
		now := time.Now()
		store.put("verification:consume:secondary-invalid-date", fmt.Sprintf(
			`{"id":"row-id","identifier":"consume:secondary-invalid-date","value":"bad-row","expiresAt":"not-a-date","createdAt":%q,"updatedAt":%q}`,
			pdISO(now), pdISO(now)))
		r, err := ia.ConsumeVerificationValue(ctx, "consume:secondary-invalid-date")
		if err != nil || r != nil {
			t.Fatalf("r = %+v %v", r, err)
		}
	})
}

// reserveVerificationValue (the upstream file declares this describe block twice; the
// second copy is identical minus the secondary-only case, so it is ported once).
func TestPortDBInternalAdapter_ReserveVerificationValue(t *testing.T) {
	ctx := context.Background()
	mk := func(t *testing.T) *InternalAdapter {
		return pdIA(pdNewAuth(t, Config{Database: pdUniqueIDFactory(memory.New(memory.NewDB()))}))
	}
	exp := func() time.Time { return time.Now().Add(time.Minute) }

	t.Run("returns true the first time and the row is findable", func(t *testing.T) {
		ia := mk(t)
		ok, err := ia.ReserveVerificationValue(ctx, "reserve:fresh", "jti-1", exp())
		if err != nil || !ok {
			t.Fatalf("reserved = %v %v", ok, err)
		}
		found, err := ia.FindVerificationValue(ctx, "reserve:fresh")
		if err != nil || found == nil || found.Value != "jti-1" {
			t.Fatalf("found = %+v %v", found, err)
		}
	})
	t.Run("returns false the second time for the same identifier", func(t *testing.T) {
		ia := mk(t)
		first, err := ia.ReserveVerificationValue(ctx, "reserve:once", "jti-2", exp())
		if err != nil || !first {
			t.Fatalf("first = %v %v", first, err)
		}
		second, err := ia.ReserveVerificationValue(ctx, "reserve:once", "jti-2-replay", exp())
		if err != nil || second {
			t.Fatalf("second = %v %v", second, err)
		}
	})
	t.Run("yields exactly one winner under concurrent reserve", func(t *testing.T) {
		ia := mk(t)
		res := make([]bool, 2)
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i := range res {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				res[i], errs[i] = ia.ReserveVerificationValue(ctx, "reserve:race", "jti-3", exp())
			}(i)
		}
		wg.Wait()
		if errs[0] != nil || errs[1] != nil || res[0] == res[1] {
			t.Fatalf("results = %v errs = %v", res, errs)
		}
	})
	t.Run("reserves independently across different identifiers", func(t *testing.T) {
		ia := mk(t)
		a, err1 := ia.ReserveVerificationValue(ctx, "reserve:independent-a", "jti-a", exp())
		b, err2 := ia.ReserveVerificationValue(ctx, "reserve:independent-b", "jti-b", exp())
		if err1 != nil || err2 != nil || !a || !b {
			t.Fatalf("a=%v b=%v errs=%v %v", a, b, err1, err2)
		}
	})
	t.Run("fails closed when verification reservation is secondary-storage-only", func(t *testing.T) {
		ia := pdIA(pdNewAuth(t, Config{Verification: &VerificationConfig{StoreInDatabase: false}, SecondaryStorage: newPDStorage()}))
		_, err := ia.ReserveVerificationValue(ctx, "reserve:secondary-only", "jti-secondary", exp())
		if err == nil || !strings.Contains(err.Error(), "requires database-backed verification storage") {
			t.Fatalf("err = %v", err)
		}
	})
}
