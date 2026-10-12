package betterauth

import (
	"sort"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// User is a user row. Fields added by plugins or additionalFields are in Additional.
type User struct {
	ID            string
	Name          string
	Email         string
	EmailVerified bool
	Image         *string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	Additional    map[string]any
	absent        map[string]bool
}

// Session is a session row.
type Session struct {
	ID         string
	ExpiresAt  time.Time
	Token      string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	IPAddress  *string
	UserAgent  *string
	UserID     string
	Additional map[string]any
	absent     map[string]bool
}

// Account is an account row (credential or OAuth link).
type Account struct {
	ID                    string
	AccountID             string
	ProviderID            string
	UserID                string
	AccessToken           *string
	RefreshToken          *string
	IDToken               *string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	Scope                 *string
	Password              *string
	CreatedAt             time.Time
	UpdatedAt             time.Time
	Additional            map[string]any
	absent                map[string]bool
}

// Verification is a verification row.
type Verification struct {
	ID         string
	Identifier string
	Value      string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
	Additional map[string]any
}

// SessionWithUser is a session together with its user (the get-session payload).
type SessionWithUser struct {
	Session *Session
	User    *User
}

// Get returns a field value by logical name (core or additional).
func (u *User) Get(field string) any {
	switch field {
	case "id":
		return u.ID
	case "name":
		return u.Name
	case "email":
		return u.Email
	case "emailVerified":
		return u.EmailVerified
	case "image":
		if u.Image == nil {
			return nil
		}
		return *u.Image
	case "createdAt":
		return u.CreatedAt
	case "updatedAt":
		return u.UpdatedAt
	}
	return u.Additional[field]
}

// Get returns a field value by logical name.
func (s *Session) Get(field string) any {
	switch field {
	case "id":
		return s.ID
	case "expiresAt":
		return s.ExpiresAt
	case "token":
		return s.Token
	case "createdAt":
		return s.CreatedAt
	case "updatedAt":
		return s.UpdatedAt
	case "ipAddress":
		return strPtrVal(s.IPAddress)
	case "userAgent":
		return strPtrVal(s.UserAgent)
	case "userId":
		return s.UserID
	}
	return s.Additional[field]
}

// Get returns a field value by logical name.
func (a *Account) Get(field string) any {
	switch field {
	case "id":
		return a.ID
	case "accountId":
		return a.AccountID
	case "providerId":
		return a.ProviderID
	case "userId":
		return a.UserID
	case "accessToken":
		return strPtrVal(a.AccessToken)
	case "refreshToken":
		return strPtrVal(a.RefreshToken)
	case "idToken":
		return strPtrVal(a.IDToken)
	case "accessTokenExpiresAt":
		return timePtrVal(a.AccessTokenExpiresAt)
	case "refreshTokenExpiresAt":
		return timePtrVal(a.RefreshTokenExpiresAt)
	case "scope":
		return strPtrVal(a.Scope)
	case "password":
		return strPtrVal(a.Password)
	case "createdAt":
		return a.CreatedAt
	case "updatedAt":
		return a.UpdatedAt
	}
	return a.Additional[field]
}

// Get returns a field value by logical name.
func (v *Verification) Get(field string) any {
	switch field {
	case "id":
		return v.ID
	case "identifier":
		return v.Identifier
	case "value":
		return v.Value
	case "expiresAt":
		return v.ExpiresAt
	case "createdAt":
		return v.CreatedAt
	case "updatedAt":
		return v.UpdatedAt
	}
	return v.Additional[field]
}

func strPtrVal(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func timePtrVal(p *time.Time) any {
	if p == nil {
		return nil
	}
	return *p
}

// StrPtr returns a pointer to s.
func StrPtr(s string) *string { return &s }

func optString(v any) *string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		return &t
	case *string:
		return t
	}
	s := adapter.ToString(v)
	return &s
}

func optTime(v any) *time.Time {
	if v == nil {
		return nil
	}
	if t, ok := adapter.ToTime(v); ok {
		t = t.UTC()
		return &t
	}
	return nil
}

func reqTime(v any) time.Time {
	if t, ok := adapter.ToTime(v); ok {
		return t.UTC()
	}
	return time.Time{}
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return adapter.ToString(v)
}

func extras(rec map[string]any, core ...string) map[string]any {
	skip := map[string]bool{}
	for _, c := range core {
		skip[c] = true
	}
	var out map[string]any
	for k, v := range rec {
		if skip[k] {
			continue
		}
		if out == nil {
			out = map[string]any{}
		}
		out[k] = v
	}
	return out
}

// absentKeys returns which of the nullable core keys are missing from rec. Adapters that
// never wrote a column (like the memory adapter) omit it, and Better Auth then omits it
// from JSON output too, so the Go port keeps track of that.
func absentKeys(rec map[string]any, keys ...string) map[string]bool {
	var out map[string]bool
	for _, k := range keys {
		if _, ok := rec[k]; !ok {
			if out == nil {
				out = map[string]bool{}
			}
			out[k] = true
		}
	}
	return out
}

func (u *User) isAbsent(f string) bool       { return u.absent[f] }
func (s *Session) isAbsent(f string) bool    { return s.absent[f] }
func (a *Account) isAbsent(f string) bool    { return a.absent[f] }
func (v *Verification) isAbsent(string) bool { return false }

func plainRecord(v any) map[string]any {
	switch t := v.(type) {
	case map[string]any:
		return t
	case *jsonx.Object:
		m := map[string]any{}
		for _, k := range t.Keys() {
			x, _ := t.Get(k)
			m[k] = x
		}
		return m
	}
	return nil
}

// UserFromRecord converts an adapter record (or parsed JSON object) to a User.
func UserFromRecord(v any) *User {
	rec := plainRecord(v)
	if rec == nil {
		return nil
	}
	return &User{
		ID: str(rec["id"]), Name: str(rec["name"]), Email: str(rec["email"]),
		EmailVerified: adapter.ToBool(rec["emailVerified"]), Image: optString(rec["image"]),
		CreatedAt: reqTime(rec["createdAt"]), UpdatedAt: reqTime(rec["updatedAt"]),
		Additional: extras(rec, "id", "name", "email", "emailVerified", "image", "createdAt", "updatedAt"),
		absent:     absentKeys(rec, "image"),
	}
}

// SessionFromRecord converts a record to a Session.
func SessionFromRecord(v any) *Session {
	rec := plainRecord(v)
	if rec == nil {
		return nil
	}
	return &Session{
		ID: str(rec["id"]), ExpiresAt: reqTime(rec["expiresAt"]), Token: str(rec["token"]),
		CreatedAt: reqTime(rec["createdAt"]), UpdatedAt: reqTime(rec["updatedAt"]),
		IPAddress: optString(rec["ipAddress"]), UserAgent: optString(rec["userAgent"]),
		UserID:     str(rec["userId"]),
		Additional: extras(rec, "id", "expiresAt", "token", "createdAt", "updatedAt", "ipAddress", "userAgent", "userId", "user"),
		absent:     absentKeys(rec, "ipAddress", "userAgent"),
	}
}

// AccountFromRecord converts a record to an Account.
func AccountFromRecord(v any) *Account {
	rec := plainRecord(v)
	if rec == nil {
		return nil
	}
	return &Account{
		ID: str(rec["id"]), AccountID: str(rec["accountId"]), ProviderID: str(rec["providerId"]),
		UserID: str(rec["userId"]), AccessToken: optString(rec["accessToken"]),
		RefreshToken: optString(rec["refreshToken"]), IDToken: optString(rec["idToken"]),
		AccessTokenExpiresAt:  optTime(rec["accessTokenExpiresAt"]),
		RefreshTokenExpiresAt: optTime(rec["refreshTokenExpiresAt"]),
		Scope:                 optString(rec["scope"]), Password: optString(rec["password"]),
		CreatedAt: reqTime(rec["createdAt"]), UpdatedAt: reqTime(rec["updatedAt"]),
		Additional: extras(rec, "id", "accountId", "providerId", "userId", "accessToken", "refreshToken",
			"idToken", "accessTokenExpiresAt", "refreshTokenExpiresAt", "scope", "password", "createdAt", "updatedAt", "user"),
		absent: absentKeys(rec, "accessToken", "refreshToken", "idToken", "accessTokenExpiresAt", "refreshTokenExpiresAt", "scope", "password"),
	}
}

// VerificationFromRecord converts a record to a Verification.
func VerificationFromRecord(v any) *Verification {
	rec := plainRecord(v)
	if rec == nil {
		return nil
	}
	return &Verification{
		ID: str(rec["id"]), Identifier: str(rec["identifier"]), Value: str(rec["value"]),
		ExpiresAt: reqTime(rec["expiresAt"]), CreatedAt: reqTime(rec["createdAt"]), UpdatedAt: reqTime(rec["updatedAt"]),
		Additional: extras(rec, "id", "identifier", "value", "expiresAt", "createdAt", "updatedAt"),
	}
}

type getter interface {
	Get(string) any
	isAbsent(string) bool
}

var (
	coreUserFields         = []string{"name", "email", "emailVerified", "image", "createdAt", "updatedAt"}
	coreSessionFields      = []string{"expiresAt", "token", "createdAt", "updatedAt", "ipAddress", "userAgent", "userId"}
	coreAccountFields      = []string{"accountId", "providerId", "userId", "accessToken", "refreshToken", "idToken", "accessTokenExpiresAt", "refreshTokenExpiresAt", "scope", "password", "createdAt", "updatedAt"}
	coreVerificationFields = []string{"identifier", "value", "expiresAt", "createdAt", "updatedAt"}
)

// toObject renders a model in the key order the TypeScript adapter produces: schema field
// order (core, plugin, additional) followed by "id". Unknown extra keys are appended
// sorted. hidden lists keys to omit. Keys whose value is absent (nil Additional entry not
// present) are omitted; core nullable fields render as null.
func toObject(g getter, table *db.Table, core []string, additional map[string]any, hidden map[string]bool) *jsonx.Object {
	o := jsonx.NewObject()
	seen := map[string]bool{"id": true}
	var fields []string
	if table != nil {
		for _, f := range table.Fields {
			fields = append(fields, f.Name)
		}
	} else {
		fields = core
	}
	isCore := map[string]bool{}
	for _, c := range core {
		isCore[c] = true
	}
	for _, name := range fields {
		seen[name] = true
		if hidden[name] {
			continue
		}
		if isCore[name] {
			if !g.isAbsent(name) {
				o.Set(name, g.Get(name))
			}
			continue
		}
		if v, ok := additional[name]; ok {
			o.Set(name, v)
		}
	}
	var rest []string
	for k := range additional {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		if !hidden[k] {
			o.Set(k, additional[k])
		}
	}
	o.Set("id", g.Get("id"))
	return o
}

// MarshalJSON renders the user in Better Auth's key order.
func (u *User) MarshalJSON() ([]byte, error) {
	return jsonx.Marshal(toObject(u, nil, coreUserFields, u.Additional, nil))
}

// MarshalJSON renders the session in Better Auth's key order.
func (s *Session) MarshalJSON() ([]byte, error) {
	return jsonx.Marshal(toObject(s, nil, coreSessionFields, s.Additional, nil))
}

// MarshalJSON renders the account without secrets.
func (a *Account) MarshalJSON() ([]byte, error) {
	return jsonx.Marshal(toObject(a, nil, coreAccountFields, a.Additional, accountSecretFields))
}

// MarshalJSON renders the verification.
func (v *Verification) MarshalJSON() ([]byte, error) {
	return jsonx.Marshal(toObject(v, nil, coreVerificationFields, v.Additional, nil))
}

// MarshalJSON renders {"session":...,"user":...}.
func (s *SessionWithUser) MarshalJSON() ([]byte, error) {
	return jsonx.Marshal(jsonx.O("session", s.Session, "user", s.User))
}

var accountSecretFields = map[string]bool{"accessToken": true, "refreshToken": true, "idToken": true,
	"accessTokenExpiresAt": true, "refreshTokenExpiresAt": true, "password": true}

// Record returns the user as a plain record (logical field names).
func (u *User) Record() adapter.Record {
	r := adapter.Record{}
	for k, v := range u.Additional {
		r[k] = v
	}
	for _, f := range append(coreUserFields, "id") {
		if !u.isAbsent(f) {
			r[f] = u.Get(f)
		}
	}
	return r
}

// Record returns the session as a plain record.
func (s *Session) Record() adapter.Record {
	r := adapter.Record{}
	for k, v := range s.Additional {
		r[k] = v
	}
	for _, f := range append(coreSessionFields, "id") {
		if !s.isAbsent(f) {
			r[f] = s.Get(f)
		}
	}
	return r
}

// Record returns the account as a plain record.
func (a *Account) Record() adapter.Record {
	r := adapter.Record{}
	for k, v := range a.Additional {
		r[k] = v
	}
	for _, f := range append(coreAccountFields, "id") {
		if !a.isAbsent(f) {
			r[f] = a.Get(f)
		}
	}
	return r
}

// Clone returns a deep-enough copy of the user.
func (u *User) Clone() *User {
	if u == nil {
		return nil
	}
	c := *u
	c.absent = cloneBoolMap(u.absent)
	if u.Additional != nil {
		c.Additional = map[string]any{}
		for k, v := range u.Additional {
			c.Additional[k] = v
		}
	}
	return &c
}

// Clone returns a copy of the session.
func (s *Session) Clone() *Session {
	if s == nil {
		return nil
	}
	c := *s
	c.absent = cloneBoolMap(s.absent)
	if s.Additional != nil {
		c.Additional = map[string]any{}
		for k, v := range s.Additional {
			c.Additional[k] = v
		}
	}
	return &c
}

func cloneBoolMap(m map[string]bool) map[string]bool {
	if m == nil {
		return nil
	}
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// SetImage sets the image (nil for null) and marks it present.
func (u *User) SetImage(img *string) {
	u.Image = img
	delete(u.absent, "image")
}
