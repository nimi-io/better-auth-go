package betterauth

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// InternalAdapter implements Better Auth's model-level operations on top of the adapter
// and the optional secondary storage (db/internal-adapter.ts).
type InternalAdapter struct {
	a     *AuthContext
	hooks withHooks
	locks sync.Map // verification consume locks
}

func newInternalAdapter(a *AuthContext) *InternalAdapter {
	return &InternalAdapter{a: a, hooks: withHooks{a: a}}
}

func (ia *InternalAdapter) opts() *Config             { return ia.a.Options }
func (ia *InternalAdapter) storage() SecondaryStorage { return ia.a.SecondaryStorage }

func (ia *InternalAdapter) storeSessionInDB() bool {
	return ia.opts().Session != nil && ia.opts().Session.StoreSessionInDatabase
}

func (ia *InternalAdapter) preserveSessionInDB() bool {
	return ia.opts().Session != nil && ia.opts().Session.PreserveSessionInDatabase
}

func (ia *InternalAdapter) storeVerificationInDB() bool {
	return ia.opts().Verification != nil && ia.opts().Verification.StoreInDatabase
}

func (ia *InternalAdapter) sessionExpiration() time.Duration {
	if s := ia.opts().Session; s != nil && s.ExpiresIn > 0 {
		return s.ExpiresIn
	}
	return 7 * 24 * time.Hour
}

// ttlUntil mirrors getTTLSeconds: whole seconds at millisecond precision, floored at 0.
func ttlUntil(expires time.Time) time.Duration {
	secs := (expires.UnixMilli() - time.Now().UnixMilli()) / 1000
	if secs < 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

type activeSessionRef struct {
	Token     string
	ExpiresAt int64
}

func parseActiveSessions(raw string) []activeSessionRef {
	v, err := jsonx.Parse([]byte(raw))
	if err != nil {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []activeSessionRef
	for _, x := range arr {
		o, ok := x.(*jsonx.Object)
		if !ok {
			continue
		}
		t, _ := o.Get("token")
		e, _ := o.Get("expiresAt")
		ts, _ := t.(string)
		ef, _ := e.(float64)
		out = append(out, activeSessionRef{Token: ts, ExpiresAt: int64(ef)})
	}
	return out
}

func encodeActiveSessions(list []activeSessionRef) string {
	arr := make([]any, len(list))
	for i, r := range list {
		arr[i] = jsonx.O("token", r.Token, "expiresAt", float64(r.ExpiresAt))
	}
	return string(jsonx.MustMarshal(arr))
}

func (ia *InternalAdapter) activeSessionRefs(ctx context.Context, userID string) ([]activeSessionRef, error) {
	st := ia.storage()
	if st == nil {
		return nil, nil
	}
	raw, ok, err := st.Get(ctx, "active-sessions-"+userID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	return parseActiveSessions(raw), nil
}

func (ia *InternalAdapter) storedSessionJSON(s *Session, u *User) string {
	o := jsonx.O("session", toObject(s, ia.a.Tables.Table("session"), coreSessionFields, s.Additional, nil), "user", nil)
	if u != nil {
		o.Set("user", toObject(u, ia.a.Tables.Table("user"), coreUserFields, u.Additional, nil))
	}
	return string(jsonx.MustMarshal(o))
}

func parseStoredSession(raw string) (*Session, *User) {
	v, err := jsonx.Parse([]byte(raw))
	if err != nil {
		return nil, nil
	}
	o, ok := jsonx.ReviveDates(v).(*jsonx.Object)
	if !ok {
		return nil, nil
	}
	sv, _ := o.Get("session")
	uv, _ := o.Get("user")
	s := SessionFromRecord(sv)
	var u *User
	if uv != nil {
		u = UserFromRecord(uv)
	}
	return s, u
}

func (ia *InternalAdapter) deleteCachedUserSessions(ctx context.Context, userID string, refs []activeSessionRef) error {
	st := ia.storage()
	if st == nil {
		return nil
	}
	deleted := map[string]bool{}
	for _, r := range refs {
		deleted[r.Token] = true
		if err := st.Delete(ctx, r.Token); err != nil {
			return err
		}
	}
	now := time.Now().UnixMilli()
	var remaining []activeSessionRef
	current, err := ia.activeSessionRefs(ctx, userID)
	if err != nil {
		return err
	}
	for _, r := range current {
		if r.ExpiresAt > now && !deleted[r.Token] {
			remaining = append(remaining, r)
		}
	}
	sort.SliceStable(remaining, func(i, j int) bool { return remaining[i].ExpiresAt < remaining[j].ExpiresAt })
	key := "active-sessions-" + userID
	if len(remaining) > 0 {
		furthest := remaining[len(remaining)-1].ExpiresAt
		return st.Set(ctx, key, encodeActiveSessions(remaining), ttlUntil(time.UnixMilli(furthest)))
	}
	return st.Delete(ctx, key)
}

func (ia *InternalAdapter) queueCachedUserSessionDeletion(ctx context.Context, userID string, refs []activeSessionRef) error {
	if ia.storage() == nil {
		return nil
	}
	if refs == nil {
		var err error
		if refs, err = ia.activeSessionRefs(ctx, userID); err != nil {
			return err
		}
	}
	return ia.a.QueueAfterTransactionHook(ctx, func(c context.Context) error {
		return ia.deleteCachedUserSessions(c, userID, refs)
	}, func(err error) {
		ia.a.Logger.Error("Failed to delete committed user sessions from secondary storage", err)
	})
}

// RefreshUserSessions rewrites the cached user in every active session (secondary storage).
func (ia *InternalAdapter) RefreshUserSessions(ctx context.Context, user *User) error {
	st := ia.storage()
	if st == nil || user == nil {
		return nil
	}
	now := time.Now().UnixMilli()
	refs, err := ia.activeSessionRefs(ctx, user.ID)
	if err != nil {
		return err
	}
	for _, r := range refs {
		if r.ExpiresAt <= now {
			continue
		}
		raw, ok, err := st.Get(ctx, r.Token)
		if err != nil || !ok {
			continue
		}
		s, _ := parseStoredSession(raw)
		if s == nil {
			continue
		}
		if err := st.Set(ctx, r.Token, ia.storedSessionJSON(s, user), ttlUntil(s.ExpiresAt)); err != nil {
			return err
		}
	}
	return nil
}

// CreateOAuthUser creates a user and its account in one transaction.
func (ia *InternalAdapter) CreateOAuthUser(ctx context.Context, user, account adapter.Record) (*User, *Account, error) {
	var u *User
	var acc *Account
	err := ia.a.RunWithTransaction(ctx, func(ctx context.Context) error {
		data := mergeRecord(adapter.Record{"createdAt": time.Now(), "updatedAt": time.Now()}, user)
		if e, ok := data["email"].(string); ok {
			data["email"] = strings.ToLower(e)
		}
		created, err := ia.hooks.create(ctx, data, "user", nil)
		if err != nil {
			return err
		}
		if created == nil {
			return ErrMessage("BAD_REQUEST", "Failed to create user")
		}
		u = UserFromRecord(created)
		accData := mergeRecord(account, adapter.Record{"userId": u.ID, "createdAt": time.Now(), "updatedAt": time.Now()})
		createdAcc, err := ia.hooks.create(ctx, accData, "account", nil)
		if err != nil {
			return err
		}
		acc = AccountFromRecord(createdAcc)
		return nil
	})
	return u, acc, err
}

// CreateUser creates a user (validateUserInfo runs when configured).
func (ia *InternalAdapter) CreateUser(ctx context.Context, user adapter.Record, source UserInfoSource) (*User, error) {
	data := mergeRecord(adapter.Record{"createdAt": time.Now(), "updatedAt": time.Now()}, user)
	if e, ok := data["email"].(string); ok {
		data["email"] = strings.ToLower(e)
	}
	if ia.opts().User != nil && ia.opts().User.ValidateUserInfo != nil {
		source.Action = "create-user"
		if err := assertValidUserInfoSource(source); err != nil {
			return nil, err
		}
		ec := EndpointContextFrom(ctx)
		if ec == nil {
			ia.a.Logger.Error("Unable to run validateUserInfo: missing endpoint context")
			return nil, NewAPIError("FORBIDDEN", jsonx.O("code", "validation_context_missing", "message", "User validation requires an endpoint context"))
		}
		if err := assertValidUserInfo(ec, data, source); err != nil {
			return nil, err
		}
	}
	created, err := ia.hooks.create(ctx, data, "user", nil)
	if err != nil || created == nil {
		return nil, err
	}
	return UserFromRecord(created), nil
}

func assertValidUserInfoSource(s UserInfoSource) error {
	if s.Method == "" {
		return NewAPIError("FORBIDDEN", jsonx.O("code", "validation_source_missing", "message", "User validation source is required"))
	}
	if s.Method == "oauth" && s.ProviderID == "" {
		return NewAPIError("FORBIDDEN", jsonx.O("code", "validation_source_missing", "message", "OAuth user validation source requires oauth.providerId"))
	}
	if (s.Method == "sso-oidc" || s.Method == "sso-saml") && s.ProviderID == "" {
		return NewAPIError("FORBIDDEN", jsonx.O("code", "validation_source_missing", "message", "SSO user validation source requires sso.providerId"))
	}
	return nil
}

func assertValidUserInfo(ec *EndpointContext, user map[string]any, source UserInfoSource) error {
	validate := ec.Auth.Options.User.ValidateUserInfo
	if validate == nil {
		return nil
	}
	if err := assertValidUserInfoSource(source); err != nil {
		return err
	}
	res, err := validate(ec, user, source)
	if err != nil {
		ec.Auth.Logger.Error("validateUserInfo callback threw", err)
		return NewAPIError("FORBIDDEN", jsonx.O("code", "validation_failed", "message", "User validation failed"))
	}
	if res != nil && res.Error != "" {
		msg := res.ErrorDescription
		if msg == "" {
			msg = res.Error
		}
		return NewAPIError("FORBIDDEN", jsonx.O("code", res.Error, "message", msg))
	}
	return nil
}

// CreateAccount creates an account row.
func (ia *InternalAdapter) CreateAccount(ctx context.Context, account adapter.Record) (*Account, error) {
	data := mergeRecord(adapter.Record{"createdAt": time.Now(), "updatedAt": time.Now()}, account)
	created, err := ia.hooks.create(ctx, data, "account", nil)
	if err != nil || created == nil {
		return nil, err
	}
	return AccountFromRecord(created), nil
}

// LinkAccount is CreateAccount (linkAccount upstream).
func (ia *InternalAdapter) LinkAccount(ctx context.Context, account adapter.Record) (*Account, error) {
	return ia.CreateAccount(ctx, account)
}

// ListSessions returns the sessions of a user.
func (ia *InternalAdapter) ListSessions(ctx context.Context, userID string, onlyActive bool) ([]*Session, error) {
	if st := ia.storage(); st != nil {
		now := time.Now().UnixMilli()
		seen := map[string]bool{}
		var out []*Session
		refs, err := ia.activeSessionRefs(ctx, userID)
		if err != nil {
			return nil, err
		}
		for _, r := range refs {
			if r.ExpiresAt <= now || seen[r.Token] {
				continue
			}
			seen[r.Token] = true
			raw, ok, err := st.Get(ctx, r.Token)
			if err != nil || !ok {
				continue
			}
			s, _ := parseStoredSession(raw)
			if s != nil {
				out = append(out, s)
			}
		}
		return out, nil
	}
	where := []adapter.Where{{Field: "userId", Value: userID}}
	if onlyActive {
		where = append(where, adapter.Where{Field: "expiresAt", Value: time.Now(), Operator: adapter.Gt})
	}
	rows, err := ia.a.Adapter.FindMany(ctx, adapter.FindManyInput{Model: "session", Where: where})
	if err != nil {
		return nil, err
	}
	out := make([]*Session, len(rows))
	for i, r := range rows {
		out[i] = SessionFromRecord(r)
	}
	return out, nil
}

// ListUsers lists users.
func (ia *InternalAdapter) ListUsers(ctx context.Context, limit, offset int, sortBy *adapter.SortBy, where []adapter.Where) ([]*User, error) {
	rows, err := ia.a.Adapter.FindMany(ctx, adapter.FindManyInput{Model: "user", Limit: limit, Offset: offset, SortBy: sortBy, Where: where})
	if err != nil {
		return nil, err
	}
	out := make([]*User, len(rows))
	for i, r := range rows {
		out[i] = UserFromRecord(r)
	}
	return out, nil
}

// CountTotalUsers counts users.
func (ia *InternalAdapter) CountTotalUsers(ctx context.Context, where []adapter.Where) (int64, error) {
	return ia.a.Adapter.Count(ctx, "user", where)
}

// DeleteUser deletes a user with their sessions and accounts.
func (ia *InternalAdapter) DeleteUser(ctx context.Context, userID string) error {
	refs, err := ia.activeSessionRefs(ctx, userID)
	if err != nil {
		return err
	}
	byUser := []adapter.Where{{Field: "userId", Value: userID}}
	if ia.storage() == nil || ia.storeSessionInDB() {
		if _, err := ia.hooks.deleteMany(ctx, byUser, "session", nil, false); err != nil {
			return err
		}
	}
	if _, err := ia.hooks.deleteMany(ctx, byUser, "account", nil, false); err != nil {
		return err
	}
	ran, err := ia.hooks.delete(ctx, []adapter.Where{{Field: "id", Value: userID}}, "user", nil, false)
	if err != nil {
		return err
	}
	if ran {
		return ia.queueCachedUserSessionDeletion(ctx, userID, refs)
	}
	return nil
}

// CreateSessionOptions customises CreateSession.
type CreateSessionOptions struct {
	DontRememberMe bool
	// Override sets extra fields (id is ignored).
	Override adapter.Record
	// OverrideAll applies Override after the defaults (instead of before).
	OverrideAll bool
	// DeferSecondaryStorageWrites mirrors the session to secondary storage after commit.
	DeferSecondaryStorageWrites bool
}

// CreateSession creates a session for userID.
func (ia *InternalAdapter) CreateSession(ctx context.Context, userID string, o *CreateSessionOptions) (*Session, error) {
	if o == nil {
		o = &CreateSessionOptions{}
	}
	var headers map[string][]string
	if ec := EndpointContextFrom(ctx); ec != nil {
		if ec.Headers != nil {
			headers = ec.Headers
		} else if ec.Request != nil {
			headers = ec.Request.Header
		}
	}
	st := ia.storage()
	storeInDB := ia.storeSessionInDB()
	data := adapter.Record{}
	if st != nil && !storeInDB {
		id, ok := ia.a.GenerateID("session")
		if !ok {
			id = bacrypto.GenerateID()
		}
		data["id"] = id
	}
	ip, ua := "", ""
	if headers != nil {
		ip = GetIP(headers, ia.opts())
		if v := headers["User-Agent"]; len(v) > 0 {
			ua = v[0]
		}
	}
	data["ipAddress"] = ip
	data["userAgent"] = ua
	for k, v := range o.Override {
		if k != "id" {
			data[k] = v
		}
	}
	exp := ia.sessionExpiration()
	if o.DontRememberMe {
		exp = 24 * time.Hour
	}
	now := time.Now()
	expiresAt := now.Add(exp)
	data["expiresAt"] = expiresAt
	data["userId"] = userID
	data["token"] = bacrypto.GenerateID(32)
	data["createdAt"] = now
	data["updatedAt"] = now
	for k, v := range ia.a.sessionDefaultFields() {
		data[k] = v
	}
	if o.OverrideAll {
		for k, v := range o.Override {
			if k != "id" {
				data[k] = v
			}
		}
	}
	if t, ok := adapter.ToTime(data["expiresAt"]); ok {
		expiresAt = t
	}
	token, _ := data["token"].(string)
	mirror := func(ctx context.Context, sessionData adapter.Record) (adapter.Record, error) {
		if st == nil {
			return sessionData, nil
		}
		key := "active-sessions-" + userID
		nowMs := time.Now().UnixMilli()
		var list []activeSessionRef
		existing, err := ia.activeSessionRefs(ctx, userID)
		if err != nil {
			return nil, err
		}
		for _, r := range existing {
			if r.ExpiresAt > nowMs && r.Token != token {
				list = append(list, r)
			}
		}
		list = append(list, activeSessionRef{Token: token, ExpiresAt: expiresAt.UnixMilli()})
		sort.SliceStable(list, func(i, j int) bool { return list[i].ExpiresAt < list[j].ExpiresAt })
		furthest := list[len(list)-1].ExpiresAt
		if ttl := ttlUntil(time.UnixMilli(furthest)); ttl > 0 {
			if err := st.Set(ctx, key, encodeActiveSessions(list), ttl); err != nil {
				return nil, err
			}
		}
		userRec, err := ia.a.Adapter.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: userID}}})
		if err != nil {
			return nil, err
		}
		if ttl := ttlUntil(expiresAt); ttl > 0 {
			if err := st.Set(ctx, token, ia.storedSessionJSON(SessionFromRecord(sessionData), UserFromRecord(userRec)), ttl); err != nil {
				return nil, err
			}
		}
		return sessionData, nil
	}
	var custom *customFn
	if st != nil {
		custom = &customFn{executeMainFn: storeInDB, fn: func(ctx context.Context, d adapter.Record) (adapter.Record, error) {
			if o.DeferSecondaryStorageWrites {
				return d, nil
			}
			return mirror(ctx, d)
		}}
	}
	res, err := ia.hooks.create(ctx, data, "session", custom)
	if err != nil {
		return nil, err
	}
	if st != nil && o.DeferSecondaryStorageWrites && res != nil {
		created := res
		var onErr func(error)
		if storeInDB && !ia.preserveSessionInDB() {
			onErr = func(err error) { ia.a.Logger.Error("Failed to mirror committed session to secondary storage", err) }
		}
		if err := ia.a.QueueAfterTransactionHook(ctx, func(c context.Context) error {
			_, err := mirror(c, created)
			return err
		}, onErr); err != nil {
			return nil, err
		}
	}
	if res == nil {
		return nil, nil
	}
	return SessionFromRecord(res), nil
}

// FindSession finds a session (and its user) by token.
func (ia *InternalAdapter) FindSession(ctx context.Context, token string) (*SessionWithUser, error) {
	if st := ia.storage(); st != nil {
		raw, ok, err := st.Get(ctx, token)
		if err != nil {
			return nil, err
		}
		if !ok && (!ia.storeSessionInDB() || ia.preserveSessionInDB()) {
			return nil, nil
		}
		if ok {
			s, u := parseStoredSession(raw)
			if s == nil || u == nil {
				return nil, nil
			}
			return &SessionWithUser{Session: s, User: u}, nil
		}
	}
	rec, err := ia.a.Adapter.FindOne(ctx, adapter.FindOneInput{Model: "session",
		Where: []adapter.Where{{Field: "token", Value: token}}, Join: map[string]adapter.Join{"user": {}}})
	if err != nil || rec == nil {
		return nil, err
	}
	userRec, _ := rec["user"].(adapter.Record)
	if userRec == nil {
		return nil, nil
	}
	delete(rec, "user")
	return &SessionWithUser{Session: SessionFromRecord(rec), User: UserFromRecord(userRec)}, nil
}

// FindSessions finds several sessions by token.
func (ia *InternalAdapter) FindSessions(ctx context.Context, tokens []string, onlyActive bool) ([]*SessionWithUser, error) {
	if st := ia.storage(); st != nil {
		var out []*SessionWithUser
		for _, t := range tokens {
			raw, ok, err := st.Get(ctx, t)
			if err != nil || !ok {
				continue
			}
			s, u := parseStoredSession(raw)
			if s == nil {
				continue
			}
			if onlyActive && !s.ExpiresAt.After(time.Now()) {
				continue
			}
			out = append(out, &SessionWithUser{Session: s, User: u})
		}
		return out, nil
	}
	vals := make([]any, len(tokens))
	for i, t := range tokens {
		vals[i] = t
	}
	where := []adapter.Where{{Field: "token", Value: vals, Operator: adapter.In}}
	if onlyActive {
		where = append(where, adapter.Where{Field: "expiresAt", Value: time.Now(), Operator: adapter.Gt})
	}
	rows, err := ia.a.Adapter.FindMany(ctx, adapter.FindManyInput{Model: "session", Where: where, Join: map[string]adapter.Join{"user": {}}})
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	out := make([]*SessionWithUser, 0, len(rows))
	for _, r := range rows {
		ur, _ := r["user"].(adapter.Record)
		if ur == nil {
			return nil, nil
		}
		delete(r, "user")
		out = append(out, &SessionWithUser{Session: SessionFromRecord(r), User: UserFromRecord(ur)})
	}
	return out, nil
}

// UpdateSession updates a session by token.
func (ia *InternalAdapter) UpdateSession(ctx context.Context, token string, data adapter.Record) (*Session, error) {
	st := ia.storage()
	var custom *customFn
	if st != nil {
		custom = &customFn{executeMainFn: ia.storeSessionInDB(), fn: func(ctx context.Context, d adapter.Record) (adapter.Record, error) {
			raw, ok, err := st.Get(ctx, token)
			if err != nil || !ok {
				return nil, err
			}
			s, u := parseStoredSession(raw)
			if s == nil {
				return nil, nil
			}
			merged := mergeRecord(s.Record(), d)
			ns := SessionFromRecord(merged)
			nowMs := time.Now().UnixMilli()
			if ttl := ttlUntil(ns.ExpiresAt); ttl > 0 {
				if err := st.Set(ctx, token, ia.storedSessionJSON(ns, u), ttl); err != nil {
					return nil, err
				}
				key := "active-sessions-" + ns.UserID
				var list []activeSessionRef
				existing, err := ia.activeSessionRefs(ctx, ns.UserID)
				if err != nil {
					return nil, err
				}
				for _, r := range existing {
					if r.Token != token && r.ExpiresAt > nowMs {
						list = append(list, r)
					}
				}
				list = append(list, activeSessionRef{Token: token, ExpiresAt: ns.ExpiresAt.UnixMilli()})
				sort.SliceStable(list, func(i, j int) bool { return list[i].ExpiresAt < list[j].ExpiresAt })
				furthest := list[len(list)-1].ExpiresAt
				if furthest > nowMs {
					if err := st.Set(ctx, key, encodeActiveSessions(list), ttlUntil(time.UnixMilli(furthest))); err != nil {
						return nil, err
					}
				} else if err := st.Delete(ctx, key); err != nil {
					return nil, err
				}
			}
			return ns.Record(), nil
		}}
	}
	rec, err := ia.hooks.update(ctx, data, []adapter.Where{{Field: "token", Value: token}}, "session", custom)
	if err != nil || rec == nil {
		return nil, err
	}
	return SessionFromRecord(rec), nil
}

func (ia *InternalAdapter) endPreservedSessions(ctx context.Context, where []adapter.Where) (bool, error) {
	live := append(append([]adapter.Where(nil), where...), adapter.Where{Field: "expiresAt", Value: time.Now(), Operator: adapter.Gt})
	fn := func(ctx context.Context) error {
		_, err := ia.a.Adapter.UpdateMany(ctx, "session", live, adapter.Record{"expiresAt": time.Now()})
		return err
	}
	return ia.hooks.deleteMany(ctx, live, "session", &fn, false)
}

// DeleteSession deletes a session by token.
func (ia *InternalAdapter) DeleteSession(ctx context.Context, token string) error {
	if st := ia.storage(); st != nil {
		raw, ok, err := st.Get(ctx, token)
		if err != nil {
			return err
		}
		if ok {
			s, _ := parseStoredSession(raw)
			if s == nil {
				ia.a.Logger.Error("Session not found in secondary storage")
				return nil
			}
			key := "active-sessions-" + s.UserID
			if listRaw, ok, _ := st.Get(ctx, key); ok {
				nowMs := time.Now().UnixMilli()
				var filtered []activeSessionRef
				for _, r := range parseActiveSessions(listRaw) {
					if r.ExpiresAt > nowMs && r.Token != token {
						filtered = append(filtered, r)
					}
				}
				sorted := append([]activeSessionRef(nil), filtered...)
				sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].ExpiresAt < sorted[j].ExpiresAt })
				if len(filtered) > 0 && sorted[len(sorted)-1].ExpiresAt > time.Now().UnixMilli() {
					if err := st.Set(ctx, key, encodeActiveSessions(filtered), ttlUntil(time.UnixMilli(sorted[len(sorted)-1].ExpiresAt))); err != nil {
						return err
					}
				} else if err := st.Delete(ctx, key); err != nil {
					return err
				}
			} else {
				ia.a.Logger.Error("Active sessions list not found in secondary storage")
			}
		}
		if err := st.Delete(ctx, token); err != nil {
			return err
		}
		if !ia.storeSessionInDB() {
			return nil
		}
		if ia.preserveSessionInDB() {
			_, err := ia.endPreservedSessions(ctx, []adapter.Where{{Field: "token", Value: token}})
			return err
		}
	}
	_, err := ia.hooks.delete(ctx, []adapter.Where{{Field: "token", Value: token}}, "session", nil, false)
	return err
}

// DeleteAccounts deletes all accounts of a user.
func (ia *InternalAdapter) DeleteAccounts(ctx context.Context, userID string) error {
	_, err := ia.hooks.deleteMany(ctx, []adapter.Where{{Field: "userId", Value: userID}}, "account", nil, false)
	return err
}

// DeleteAccount deletes an account by id.
func (ia *InternalAdapter) DeleteAccount(ctx context.Context, id string) error {
	_, err := ia.hooks.delete(ctx, []adapter.Where{{Field: "id", Value: id}}, "account", nil, false)
	return err
}

// DeleteUserSessions deletes all sessions of a user.
func (ia *InternalAdapter) DeleteUserSessions(ctx context.Context, userID string) error {
	refs, err := ia.activeSessionRefs(ctx, userID)
	if err != nil {
		return err
	}
	if ia.storage() != nil {
		if !ia.storeSessionInDB() {
			return ia.queueCachedUserSessionDeletion(ctx, userID, refs)
		}
		if ia.preserveSessionInDB() {
			ran, err := ia.endPreservedSessions(ctx, []adapter.Where{{Field: "userId", Value: userID}})
			if err != nil {
				return err
			}
			if ran {
				return ia.queueCachedUserSessionDeletion(ctx, userID, refs)
			}
			return nil
		}
	}
	ran, err := ia.hooks.deleteMany(ctx, []adapter.Where{{Field: "userId", Value: userID}}, "session", nil, false)
	if err != nil {
		return err
	}
	if ran {
		return ia.queueCachedUserSessionDeletion(ctx, userID, refs)
	}
	return nil
}

// DeleteSessions deletes sessions by token.
func (ia *InternalAdapter) DeleteSessions(ctx context.Context, tokens []string) error {
	vals := make([]any, len(tokens))
	for i, t := range tokens {
		vals[i] = t
	}
	where := []adapter.Where{{Field: "token", Value: vals, Operator: adapter.In}}
	if st := ia.storage(); st != nil {
		for _, t := range tokens {
			if err := st.Delete(ctx, t); err != nil {
				return err
			}
		}
		if !ia.storeSessionInDB() {
			return nil
		}
		if ia.preserveSessionInDB() {
			_, err := ia.endPreservedSessions(ctx, where)
			return err
		}
	}
	_, err := ia.hooks.deleteMany(ctx, where, "session", nil, false)
	return err
}

// AccountOwner is the result of FindAccountOwnerByKey.
type AccountOwner struct {
	// Kind is "owned" or "orphaned".
	Kind    string
	User    *User
	Account *Account
}

// ErrDuplicateAccounts is returned when two accounts share the same provider account id.
var ErrDuplicateAccounts = errors.New("duplicate accounts")

// FindAccountOwnerByKey finds the account (and owning user) for a provider account.
func (ia *InternalAdapter) FindAccountOwnerByKey(ctx context.Context, providerID, accountID string) (*AccountOwner, error) {
	rows, err := ia.a.Adapter.FindMany(ctx, adapter.FindManyInput{Model: "account", Limit: 2,
		Where: []adapter.Where{{Field: "providerId", Value: providerID}, {Field: "accountId", Value: accountID}},
		Join:  map[string]adapter.Join{"user": {}}})
	if err != nil {
		return nil, err
	}
	if len(rows) > 1 {
		return nil, fmt.Errorf("Multiple accounts match the same accountId for provider %q. Resolve duplicate account identities before continuing.: %w", providerID, ErrDuplicateAccounts)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	ur, _ := rows[0]["user"].(adapter.Record)
	delete(rows[0], "user")
	acc := AccountFromRecord(rows[0])
	if ur == nil {
		return &AccountOwner{Kind: "orphaned", Account: acc}, nil
	}
	return &AccountOwner{Kind: "owned", User: UserFromRecord(ur), Account: acc}, nil
}

// UserWithAccounts is the result of FindUserByEmail.
type UserWithAccounts struct {
	User     *User
	Accounts []*Account
}

// FindUserByEmail finds a user by email (case-insensitively normalised to lower case).
func (ia *InternalAdapter) FindUserByEmail(ctx context.Context, email string, includeAccounts bool) (*UserWithAccounts, error) {
	in := adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "email", Value: strings.ToLower(email)}}}
	if includeAccounts {
		in.Join = map[string]adapter.Join{"account": {}}
	}
	rec, err := ia.a.Adapter.FindOne(ctx, in)
	if err != nil || rec == nil {
		return nil, err
	}
	out := &UserWithAccounts{}
	if accs, ok := rec["account"].([]adapter.Record); ok {
		for _, a := range accs {
			out.Accounts = append(out.Accounts, AccountFromRecord(a))
		}
	}
	delete(rec, "account")
	out.User = UserFromRecord(rec)
	return out, nil
}

// FindUserByID finds a user by id.
func (ia *InternalAdapter) FindUserByID(ctx context.Context, id string) (*User, error) {
	if id == "" {
		return nil, nil
	}
	rec, err := ia.a.Adapter.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: id}}})
	if err != nil || rec == nil {
		return nil, err
	}
	return UserFromRecord(rec), nil
}

func (ia *InternalAdapter) afterUserUpdate(ctx context.Context, u *User) error {
	return ia.a.QueueAfterTransactionHook(ctx, func(c context.Context) error { return ia.RefreshUserSessions(c, u) },
		func(err error) {
			ia.a.Logger.Error("Failed to refresh committed user sessions in secondary storage", err)
		})
}

// UpdateUser updates a user by id.
func (ia *InternalAdapter) UpdateUser(ctx context.Context, userID string, data adapter.Record) (*User, error) {
	data = mergeRecord(data, nil)
	if e, ok := data["email"].(string); ok && e != "" {
		data["email"] = strings.ToLower(e)
	}
	rec, err := ia.hooks.update(ctx, data, []adapter.Where{{Field: "id", Value: userID}}, "user", nil)
	if err != nil {
		return nil, err
	}
	u := UserFromRecord(rec)
	if err := ia.afterUserUpdate(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// UpdateUserByEmail updates a user by email.
func (ia *InternalAdapter) UpdateUserByEmail(ctx context.Context, email string, data adapter.Record) (*User, error) {
	data = mergeRecord(data, nil)
	if e, ok := data["email"].(string); ok && e != "" {
		data["email"] = strings.ToLower(e)
	}
	rec, err := ia.hooks.update(ctx, data, []adapter.Where{{Field: "email", Value: strings.ToLower(email)}}, "user", nil)
	if err != nil {
		return nil, err
	}
	u := UserFromRecord(rec)
	if err := ia.afterUserUpdate(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// UpdatePassword sets the credential password of a user.
func (ia *InternalAdapter) UpdatePassword(ctx context.Context, userID, password string) error {
	_, _, err := ia.hooks.updateMany(ctx, adapter.Record{"password": password}, []adapter.Where{
		{Field: "userId", Value: userID}, {Field: "providerId", Value: "credential"}, {Field: "accountId", Value: userID}}, "account")
	return err
}

func accountsFrom(rows []adapter.Record) []*Account {
	out := make([]*Account, len(rows))
	for i, r := range rows {
		out[i] = AccountFromRecord(r)
	}
	return out
}

// FindAccounts lists the accounts of a user.
func (ia *InternalAdapter) FindAccounts(ctx context.Context, userID string) ([]*Account, error) {
	rows, err := ia.a.Adapter.FindMany(ctx, adapter.FindManyInput{Model: "account", Where: []adapter.Where{{Field: "userId", Value: userID}}})
	if err != nil {
		return nil, err
	}
	return accountsFrom(rows), nil
}

// FindAccountByUserID is FindAccounts (findAccountByUserId upstream).
func (ia *InternalAdapter) FindAccountByUserID(ctx context.Context, userID string) ([]*Account, error) {
	return ia.FindAccounts(ctx, userID)
}

// FindCredentialAccount returns the email/password account of a user.
func (ia *InternalAdapter) FindCredentialAccount(ctx context.Context, userID string) (*Account, error) {
	rec, err := ia.a.Adapter.FindOne(ctx, adapter.FindOneInput{Model: "account", Where: []adapter.Where{
		{Field: "userId", Value: userID}, {Field: "providerId", Value: "credential"}, {Field: "accountId", Value: userID}}})
	if err != nil || rec == nil {
		return nil, err
	}
	return AccountFromRecord(rec), nil
}

// FindAccountByKey finds an account by (providerId, accountId).
func (ia *InternalAdapter) FindAccountByKey(ctx context.Context, providerID, accountID string) (*Account, error) {
	rows, err := ia.a.Adapter.FindMany(ctx, adapter.FindManyInput{Model: "account", Limit: 2,
		Where: []adapter.Where{{Field: "providerId", Value: providerID}, {Field: "accountId", Value: accountID}}})
	if err != nil {
		return nil, err
	}
	if len(rows) > 1 {
		return nil, fmt.Errorf("Multiple accounts match the same accountId for provider %q. Resolve duplicate account identities before continuing.: %w", providerID, ErrDuplicateAccounts)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return AccountFromRecord(rows[0]), nil
}

// UpdateAccount updates an account by id.
func (ia *InternalAdapter) UpdateAccount(ctx context.Context, id string, data adapter.Record) (*Account, error) {
	rec, err := ia.hooks.update(ctx, data, []adapter.Where{{Field: "id", Value: id}}, "account", nil)
	if err != nil || rec == nil {
		return nil, err
	}
	return AccountFromRecord(rec), nil
}

// ---- verification ----

func (ia *InternalAdapter) storageOption(identifier string) *StoreIdentifier {
	vc := ia.opts().Verification
	if vc == nil {
		return nil
	}
	for prefix, o := range vc.StoreIdentifierOverrides {
		if strings.HasPrefix(identifier, prefix) {
			o := o
			return &o
		}
	}
	return vc.StoreIdentifier
}

func isHashedOption(o *StoreIdentifier) bool {
	return o != nil && (o.Mode == "hashed" || o.Hash != nil)
}

func processIdentifier(identifier string, o *StoreIdentifier) (string, error) {
	if o == nil || (o.Mode != "hashed" && o.Hash == nil) {
		return identifier, nil
	}
	if o.Hash != nil {
		return o.Hash(identifier)
	}
	return bacrypto.Base64URLNoPad(bacrypto.SHA256([]byte(identifier))), nil
}

func verificationJSON(v adapter.Record) string {
	o := jsonx.NewObject()
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	order := map[string]int{"id": 0, "createdAt": 1, "updatedAt": 2, "value": 3, "identifier": 4, "expiresAt": 5}
	sort.SliceStable(keys, func(i, j int) bool {
		oi, iok := order[keys[i]]
		oj, jok := order[keys[j]]
		if iok && jok {
			return oi < oj
		}
		if iok != jok {
			return iok
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys {
		o.Set(k, v[k])
	}
	return string(jsonx.MustMarshal(o))
}

func parseVerificationJSON(raw string) *Verification {
	v, err := jsonx.Parse([]byte(raw))
	if err != nil {
		return nil
	}
	return VerificationFromRecord(jsonx.ReviveDates(v))
}

// CreateVerificationValue stores a verification value.
func (ia *InternalAdapter) CreateVerificationValue(ctx context.Context, identifier, value string, expiresAt time.Time, extra adapter.Record) (*Verification, error) {
	stored, err := processIdentifier(identifier, ia.storageOption(identifier))
	if err != nil {
		return nil, err
	}
	data := adapter.Record{"createdAt": time.Now(), "updatedAt": time.Now()}
	for k, v := range extra {
		data[k] = v
	}
	data["value"] = value
	data["expiresAt"] = expiresAt
	data["identifier"] = stored
	var custom *customFn
	if st := ia.storage(); st != nil {
		custom = &customFn{executeMainFn: ia.storeVerificationInDB(), fn: func(ctx context.Context, d adapter.Record) (adapter.Record, error) {
			exp, _ := adapter.ToTime(d["expiresAt"])
			if ttl := ttlUntil(exp); ttl > 0 {
				if err := st.Set(ctx, "verification:"+stored, verificationJSON(d), ttl); err != nil {
					return nil, err
				}
			}
			return d, nil
		}}
	}
	rec, err := ia.hooks.create(ctx, data, "verification", custom)
	if err != nil || rec == nil {
		return nil, err
	}
	return VerificationFromRecord(rec), nil
}

func (ia *InternalAdapter) cleanupExpiredVerifications(ctx context.Context) error {
	if vc := ia.opts().Verification; vc != nil && vc.DisableCleanup {
		return nil
	}
	_, err := ia.hooks.deleteMany(ctx, []adapter.Where{{Field: "expiresAt", Value: time.Now(), Operator: adapter.Lt}}, "verification", nil, false)
	return err
}

// FindVerificationValue returns the latest verification value for identifier.
func (ia *InternalAdapter) FindVerificationValue(ctx context.Context, identifier string) (*Verification, error) {
	opt := ia.storageOption(identifier)
	stored, err := processIdentifier(identifier, opt)
	if err != nil {
		return nil, err
	}
	if st := ia.storage(); st != nil {
		if raw, ok, err := st.Get(ctx, "verification:"+stored); err == nil && ok {
			if v := parseVerificationJSON(raw); v != nil {
				return v, nil
			}
		}
		if isHashedOption(opt) {
			if raw, ok, err := st.Get(ctx, "verification:"+identifier); err == nil && ok {
				if v := parseVerificationJSON(raw); v != nil {
					return v, nil
				}
			}
		}
		if !ia.storeVerificationInDB() {
			return nil, nil
		}
	}
	find := func(id string) ([]adapter.Record, error) {
		return ia.a.Adapter.FindMany(ctx, adapter.FindManyInput{Model: "verification",
			Where: []adapter.Where{{Field: "identifier", Value: id}}, SortBy: &adapter.SortBy{Field: "createdAt", Direction: "desc"}, Limit: 1})
	}
	rows, err := find(stored)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 && isHashedOption(opt) {
		if rows, err = find(identifier); err != nil {
			return nil, err
		}
	}
	if err := ia.cleanupExpiredVerifications(ctx); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return VerificationFromRecord(rows[0]), nil
}

// DeleteVerificationByIdentifier removes verification values for identifier.
func (ia *InternalAdapter) DeleteVerificationByIdentifier(ctx context.Context, identifier string) error {
	stored, err := processIdentifier(identifier, ia.storageOption(identifier))
	if err != nil {
		return err
	}
	if st := ia.storage(); st != nil {
		if err := st.Delete(ctx, "verification:"+stored); err != nil {
			return err
		}
	}
	if ia.storage() == nil || ia.storeVerificationInDB() {
		_, err := ia.hooks.delete(ctx, []adapter.Where{{Field: "identifier", Value: stored}}, "verification", nil, false)
		return err
	}
	return nil
}

func (ia *InternalAdapter) lock(key string) func() {
	v, _ := ia.locks.LoadOrStore(key, &sync.Mutex{})
	m := v.(*sync.Mutex)
	m.Lock()
	return m.Unlock
}

// ConsumeVerificationValue atomically reads and deletes the latest verification value,
// returning nil when it does not exist or has expired.
func (ia *InternalAdapter) ConsumeVerificationValue(ctx context.Context, identifier string) (*Verification, error) {
	opt := ia.storageOption(identifier)
	stored, err := processIdentifier(identifier, opt)
	if err != nil {
		return nil, err
	}
	candidates := []string{stored}
	if isHashedOption(opt) {
		candidates = append(candidates, identifier)
	}
	var consumed *Verification
	st := ia.storage()
	if st != nil && !ia.storeVerificationInDB() {
		for _, c := range candidates {
			raw, ok, err := st.GetAndDelete(ctx, "verification:"+c)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			v := parseVerificationJSON(raw)
			if v == nil || v.ExpiresAt.IsZero() {
				continue
			}
			for _, other := range candidates {
				if other != c {
					_ = st.Delete(ctx, "verification:"+other)
				}
			}
			consumed = v
			break
		}
	} else {
		consume := func(id string) (*Verification, error) {
			unlock := ia.lock("verification:" + id)
			defer unlock()
			var out *Verification
			err := ia.a.RunWithTransaction(ctx, func(ctx context.Context) error {
				where := []adapter.Where{{Field: "identifier", Value: id}}
				rows, err := ia.a.Adapter.FindMany(ctx, adapter.FindManyInput{Model: "verification", Where: where,
					SortBy: &adapter.SortBy{Field: "createdAt", Direction: "desc"}, Limit: 1})
				if err != nil || len(rows) == 0 {
					return err
				}
				latest := rows[0]
				idWhere := []adapter.Where{{Field: "id", Value: latest["id"]}}
				rec, err := ia.hooks.consumeOne(ctx, "verification", idWhere, func() (adapter.Record, error) {
					row, err := ia.a.Adapter.ConsumeOne(ctx, "verification", idWhere)
					if err != nil || row == nil {
						return nil, err
					}
					if _, err := ia.a.Adapter.DeleteMany(ctx, "verification", where); err != nil {
						return nil, err
					}
					return row, nil
				}, latest)
				if err != nil || rec == nil {
					return err
				}
				out = VerificationFromRecord(rec)
				return nil
			})
			return out, err
		}
		for _, c := range candidates {
			v, err := consume(c)
			if err != nil {
				return nil, err
			}
			if v != nil {
				consumed = v
				break
			}
		}
		if consumed != nil && st != nil {
			for _, c := range candidates {
				_ = st.Delete(ctx, "verification:"+c)
			}
		}
	}
	if consumed == nil || consumed.ExpiresAt.Before(time.Now()) {
		return nil, nil
	}
	return consumed, nil
}

// ReserveVerificationValue inserts a verification value keyed by the identifier hash,
// returning false when it already exists (single-use reservations).
func (ia *InternalAdapter) ReserveVerificationValue(ctx context.Context, identifier, value string, expiresAt time.Time) (bool, error) {
	reservationID := bacrypto.Base64URLNoPad(bacrypto.SHA256([]byte("reserve:" + identifier)))
	stored, err := processIdentifier(identifier, ia.storageOption(identifier))
	if err != nil {
		return false, err
	}
	st := ia.storage()
	if st != nil && !ia.storeVerificationInDB() {
		return false, errors.New("reserveVerificationValue requires database-backed verification storage. Set verification.storeInDatabase to true for flows that reserve verification values.")
	}
	_, err = ia.a.Adapter.Create(ctx, adapter.CreateInput{Model: "verification", ForceAllowID: true, Data: adapter.Record{
		"id": reservationID, "identifier": stored, "value": value, "expiresAt": expiresAt,
		"createdAt": time.Now(), "updatedAt": time.Now()}})
	if err != nil {
		existing, ferr := ia.a.Adapter.FindOne(ctx, adapter.FindOneInput{Model: "verification", Where: []adapter.Where{{Field: "id", Value: reservationID}}})
		if ferr == nil && existing != nil {
			return false, nil
		}
		return false, err
	}
	if st != nil {
		if ttl := ttlUntil(expiresAt); ttl > 0 {
			_ = st.Set(ctx, "verification:"+stored, verificationJSON(adapter.Record{"id": reservationID, "identifier": stored, "value": value, "expiresAt": expiresAt}), ttl)
		}
	}
	return true, nil
}

// UpdateVerificationByIdentifier updates a verification value.
func (ia *InternalAdapter) UpdateVerificationByIdentifier(ctx context.Context, identifier string, data adapter.Record) (*Verification, error) {
	stored, err := processIdentifier(identifier, ia.storageOption(identifier))
	if err != nil {
		return nil, err
	}
	if st := ia.storage(); st != nil {
		if raw, ok, err := st.Get(ctx, "verification:"+stored); err == nil && ok {
			if parsed := parseVerificationJSON(raw); parsed != nil {
				rec := mergeRecord(adapter.Record{"id": parsed.ID, "identifier": parsed.Identifier, "value": parsed.Value,
					"expiresAt": parsed.ExpiresAt, "createdAt": parsed.CreatedAt, "updatedAt": parsed.UpdatedAt}, data)
				exp, _ := adapter.ToTime(rec["expiresAt"])
				if ttl := ttlUntil(exp); ttl > 0 {
					if err := st.Set(ctx, "verification:"+stored, verificationJSON(rec), ttl); err != nil {
						return nil, err
					}
				}
				if !ia.storeVerificationInDB() {
					return VerificationFromRecord(rec), nil
				}
			}
		}
	}
	if ia.storage() == nil || ia.storeVerificationInDB() {
		rec, err := ia.hooks.update(ctx, data, []adapter.Where{{Field: "identifier", Value: stored}}, "verification", nil)
		if err != nil || rec == nil {
			return nil, err
		}
		return VerificationFromRecord(rec), nil
	}
	return VerificationFromRecord(data), nil
}
