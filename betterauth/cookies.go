package betterauth

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// SecureCookiePrefix is prepended to cookie names when cookies are secure.
const SecureCookiePrefix = "__Secure-"

func (a *Auth) useSecureCookies(cfg *Config) bool {
	if cfg.Advanced != nil && cfg.Advanced.UseSecureCookies != nil {
		return *cfg.Advanced.UseSecureCookies
	}
	if cfg.DynamicBaseURL != nil {
		switch cfg.DynamicBaseURL.Protocol {
		case "https":
			return true
		case "http":
			return false
		}
	}
	if cfg.BaseURL != "" {
		return strings.HasPrefix(cfg.BaseURL, "https://")
	}
	return isProduction()
}

// newCookieGetter mirrors createCookieGetter.
func newCookieGetter(cfg *Config, secure bool) (func(name string, over *CookieOptions) AuthCookie, error) {
	prefix := ""
	if secure {
		prefix = SecureCookiePrefix
	}
	cross := cfg.Advanced != nil && cfg.Advanced.CrossSubDomainCookies != nil && cfg.Advanced.CrossSubDomainCookies.Enabled
	domain := ""
	if cross {
		domain = cfg.Advanced.CrossSubDomainCookies.Domain
		if domain == "" && cfg.BaseURL != "" {
			if u, err := parseJSURL(cfg.BaseURL); err == nil {
				domain = u.Hostname()
			}
		}
		if domain == "" && cfg.DynamicBaseURL == nil {
			return nil, errors.New("baseURL is required when crossSubdomainCookies are enabled.")
		}
	}
	return func(name string, over *CookieOptions) AuthCookie {
		cookiePrefix := "better-auth"
		if cfg.Advanced != nil && cfg.Advanced.CookiePrefix != "" {
			cookiePrefix = cfg.Advanced.CookiePrefix
		}
		full := cookiePrefix + "." + name
		var perCookie *CookieAttributes
		if cfg.Advanced != nil {
			if o, ok := cfg.Advanced.Cookies[name]; ok {
				if o.Name != "" {
					full = o.Name
				}
				perCookie = o.Attributes
			}
		}
		attrs := CookieOptions{Secure: prefix != "", SameSite: "lax", Path: "/", HTTPOnly: true}
		if cross {
			attrs.Domain = domain
		}
		if cfg.Advanced != nil {
			attrs = cfg.Advanced.DefaultCookieAttributes.applyTo(attrs)
		}
		attrs = attrs.merge(over)
		attrs = perCookie.applyTo(attrs)
		return AuthCookie{Name: prefix + full, Attributes: attrs}
	}, nil
}

func buildAuthCookies(cfg *Config, gen func(string, *CookieOptions) AuthCookie) AuthCookies {
	sessionMaxAge := 7 * 24 * 3600
	if cfg.Session != nil && cfg.Session.ExpiresIn > 0 {
		sessionMaxAge = int(cfg.Session.ExpiresIn / time.Second)
	}
	cacheMaxAge := 300
	if cfg.Session != nil && cfg.Session.CookieCache != nil && cfg.Session.CookieCache.MaxAge > 0 {
		cacheMaxAge = int(cfg.Session.CookieCache.MaxAge / time.Second)
	}
	return AuthCookies{
		SessionToken:      gen("session_token", &CookieOptions{MaxAge: Int(sessionMaxAge)}),
		SessionData:       gen("session_data", &CookieOptions{MaxAge: Int(cacheMaxAge)}),
		AccountData:       gen("account_data", &CookieOptions{MaxAge: Int(cacheMaxAge)}),
		DontRememberToken: gen("dont_remember", nil),
	}
}

// ---- chunked cookie store (cookies/session-store.ts) ----

const (
	maxCookieSize   = 4050
	maxCookieChunks = 100
)

type storeCookie struct {
	name  string
	value string
	attrs CookieOptions
}

func parseChunkIndex(cookieName, name string) (int, bool) {
	prefix := cookieName + "."
	if !strings.HasPrefix(name, prefix) {
		return 0, false
	}
	suffix := name[len(prefix):]
	n, err := strconv.Atoi(suffix)
	if err != nil || n < 0 || strconv.Itoa(n) != suffix {
		return 0, false
	}
	return n, true
}

type cookieStore struct {
	ctx        *EndpointContext
	storeName  string
	cookieName string
	opts       CookieOptions
	chunks     []string // existing chunk cookie names, in request order
}

func newCookieStore(storeName, cookieName string, opts CookieOptions, ctx *EndpointContext) *cookieStore {
	s := &cookieStore{ctx: ctx, storeName: storeName, cookieName: cookieName, opts: opts}
	for _, c := range parseCookieList(ctx.GetHeader("Cookie")) {
		if c.name == cookieName {
			s.chunks = append(s.chunks, c.name)
			continue
		}
		if _, ok := parseChunkIndex(cookieName, c.name); ok {
			s.chunks = append(s.chunks, c.name)
		}
	}
	return s
}

func (s *cookieStore) expireExisting() []storeCookie {
	var out []storeCookie
	for _, name := range s.chunks {
		a := s.opts
		a.MaxAge = Int(0)
		out = append(out, storeCookie{name: name, value: "", attrs: a})
	}
	s.chunks = nil
	return out
}

func upsert(list []storeCookie, c storeCookie) []storeCookie {
	for i := range list {
		if list[i].name == c.name {
			list[i] = c
			return list
		}
	}
	return append(list, c)
}

func (s *cookieStore) chunk(value string, opts CookieOptions) []storeCookie {
	cookies := s.expireExisting()
	attrs := opts
	overhead, _ := SerializeCookie(fmt.Sprintf("%s.%d", s.cookieName, maxCookieChunks-1), "", attrs)
	chunkSize := maxCookieSize - len(overhead)
	count := math.Inf(1)
	if chunkSize > 0 {
		count = math.Ceil(float64(len(value)) / float64(chunkSize))
	}
	if count <= 1 {
		s.chunks = append(s.chunks, s.cookieName)
		return upsert(cookies, storeCookie{name: s.cookieName, value: value, attrs: attrs})
	}
	if count > maxCookieChunks {
		s.ctx.Auth.Logger.Warn(s.storeName + " cookie is too large to store even after chunking, so the cookie cache was skipped. Reduce the cached data size or avoid storing this data in cookies.")
		return cookies
	}
	n := int(count)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("%s.%d", s.cookieName, i)
		start := i * chunkSize
		end := start + chunkSize
		if end > len(value) {
			end = len(value)
		}
		cookies = upsert(cookies, storeCookie{name: name, value: value[start:end], attrs: attrs})
		s.chunks = append(s.chunks, name)
	}
	s.ctx.Auth.Logger.Debug("CHUNKING_" + strings.ToUpper(s.storeName) + "_COOKIE")
	return cookies
}

func (s *cookieStore) clean() []storeCookie { return s.expireExisting() }

func (s *cookieStore) set(cookies []storeCookie) {
	for _, c := range cookies {
		s.ctx.SetCookie(c.name, c.value, c.attrs)
	}
}

// GetChunkedCookie reads a (possibly chunked) cookie value.
func GetChunkedCookie(ctx *EndpointContext, cookieName string) string {
	if v := ctx.GetCookie(cookieName); v != "" {
		return v
	}
	header := ctx.GetHeader("Cookie")
	if header == "" {
		return ""
	}
	type chunk struct {
		idx int
		v   string
	}
	var chunks []chunk
	for _, c := range parseCookieList(header) {
		if i, ok := parseChunkIndex(cookieName, c.name); ok {
			chunks = append(chunks, chunk{i, c.value})
		}
	}
	if len(chunks) == 0 {
		return ""
	}
	for i := 1; i < len(chunks); i++ {
		for j := i; j > 0 && chunks[j].idx < chunks[j-1].idx; j-- {
			chunks[j], chunks[j-1] = chunks[j-1], chunks[j]
		}
	}
	var b strings.Builder
	for _, c := range chunks {
		b.WriteString(c.v)
	}
	return b.String()
}

// ---- expiry helpers ----

func removeSetCookieEntries(ctx *EndpointContext, name string) {
	if ctx.ResponseHeaders == nil {
		return
	}
	existing := ctx.ResponseHeaders.Values("Set-Cookie")
	if len(existing) == 0 {
		return
	}
	var survivors []string
	for _, e := range existing {
		if strings.HasPrefix(e, name+"=") || strings.HasPrefix(e, name+".") {
			continue
		}
		survivors = append(survivors, e)
	}
	if len(survivors) == len(existing) {
		return
	}
	ctx.ResponseHeaders.Del("Set-Cookie")
	for _, s := range survivors {
		ctx.ResponseHeaders.Add("Set-Cookie", s)
	}
}

func hasPendingSetCookie(ctx *EndpointContext, name string) bool {
	if ctx.ResponseHeaders == nil {
		return false
	}
	for _, e := range ctx.ResponseHeaders.Values("Set-Cookie") {
		if strings.HasPrefix(e, name+"=") || strings.HasPrefix(e, name+".") {
			return true
		}
	}
	return false
}

// ExpireCookie removes pending Set-Cookie entries for the cookie and sets it with Max-Age=0.
func ExpireCookie(ctx *EndpointContext, c AuthCookie) {
	removeSetCookieEntries(ctx, c.Name)
	a := c.Attributes
	a.MaxAge = Int(0)
	ctx.SetCookie(c.Name, "", a)
}

// DeleteSessionCookie clears the session, cache, account and dont-remember cookies.
func DeleteSessionCookie(ctx *EndpointContext, skipDontRememberMe bool) {
	ac := ctx.Auth.AuthCookies
	ExpireCookie(ctx, ac.SessionToken)
	ExpireCookie(ctx, ac.SessionData)
	if ctx.Auth.storeAccountCookie() {
		ExpireCookie(ctx, ac.AccountData)
		st := newCookieStore("Account", ac.AccountData.Name, ac.AccountData.Attributes, ctx)
		st.set(st.clean())
	}
	if ctx.Auth.OAuthConfig.StoreStateStrategy == "cookie" {
		ExpireCookie(ctx, ctx.Auth.CreateAuthCookie("oauth_state", nil))
	}
	st := newCookieStore("Session", ac.SessionData.Name, ac.SessionData.Attributes, ctx)
	st.set(st.clean())
	if !skipDontRememberMe {
		ExpireCookie(ctx, ac.DontRememberToken)
	}
}

func (a *AuthContext) storeAccountCookie() bool {
	return a.Options.Account != nil && a.Options.Account.StoreAccountCookie != nil && *a.Options.Account.StoreAccountCookie
}

// ---- session cookie ----

// SetSessionCookie writes the signed session token cookie, the dont_remember cookie and the
// cookie cache (setSessionCookie). dontRememberMe nil means "keep the existing choice".
func SetSessionCookie(ctx *EndpointContext, s *SessionWithUser, dontRememberMe *bool, overrides *CookieOptions) error {
	ac := ctx.Auth.AuthCookies
	drm := false
	if dontRememberMe != nil {
		drm = *dontRememberMe
	} else {
		_, drm = ctx.GetSignedCookie(ac.DontRememberToken.Name, ctx.Auth.Secret)
	}
	opts := ac.SessionToken.Attributes
	if drm {
		opts.MaxAge = nil
	} else {
		opts.MaxAge = Int(int(ctx.Auth.SessionConfig.ExpiresIn / time.Second))
	}
	if overrides != nil {
		opts = opts.merge(overrides)
	}
	ctx.SetSignedCookie(ac.SessionToken.Name, s.Session.Token, ctx.Auth.Secret, opts)
	if drm {
		ctx.SetSignedCookie(ac.DontRememberToken.Name, "true", ctx.Auth.Secret, ac.DontRememberToken.Attributes)
	}
	if err := setCookieCache(ctx, s, drm); err != nil {
		return err
	}
	ctx.SetNewSession(s)
	return nil
}

func (a *AuthContext) cookieCacheConfig() *CookieCacheConfig {
	if a.Options.Session == nil {
		return nil
	}
	return a.Options.Session.CookieCache
}

func (a *AuthContext) cookieCacheEnabled() bool {
	c := a.cookieCacheConfig()
	return c != nil && c.Enabled
}

func (a *AuthContext) cookieCacheStrategy() string {
	if c := a.cookieCacheConfig(); c != nil && c.Strategy != "" {
		return c.Strategy
	}
	return "compact"
}

func (a *AuthContext) cookieCacheVersion(s *Session, u *User) string {
	c := a.cookieCacheConfig()
	if c == nil {
		return "1"
	}
	if c.VersionFunc != nil {
		return c.VersionFunc(s, u)
	}
	if c.Version != "" {
		return c.Version
	}
	return "1"
}

// sessionCacheObject renders the session for the cookie cache (additional fields with
// returned=false removed).
func (a *AuthContext) sessionCacheObject(s *Session) *jsonx.Object {
	hidden := map[string]bool{}
	if a.Options.Session != nil {
		for _, f := range a.Options.Session.AdditionalFields {
			if !f.IsReturned() {
				hidden[f.Name] = true
			}
		}
	}
	return toObject(s, a.Tables.Table("session"), coreSessionFields, s.Additional, hidden)
}

func setCookieCache(ctx *EndpointContext, s *SessionWithUser, dontRememberMe bool) error {
	a := ctx.Auth
	if !a.cookieCacheEnabled() {
		return nil
	}
	version := a.cookieCacheVersion(s.Session, s.User)
	sessionData := jsonx.O(
		"session", a.sessionCacheObject(s.Session),
		"user", a.UserOutput(s.User),
		"updatedAt", float64(time.Now().UnixMilli()),
		"version", version,
	)
	opts := a.AuthCookies.SessionData.Attributes
	if dontRememberMe {
		opts.MaxAge = nil
	}
	maxAge := 0
	if opts.MaxAge != nil {
		maxAge = *opts.MaxAge
	}
	expSeconds := maxAge
	if expSeconds == 0 {
		expSeconds = 60
	}
	expiresAt := float64(time.Now().Add(time.Duration(expSeconds) * time.Second).UnixMilli())
	ttl := maxAge
	if ttl == 0 {
		ttl = 300
	}
	var data string
	var err error
	switch a.cookieCacheStrategy() {
	case "jwe":
		data, err = bacrypto.SymmetricEncodeJWT(sessionData, a.SecretConfig, "better-auth-session", time.Duration(ttl)*time.Second)
	case "jwt":
		if a.SessionConfig.CookieCacheSigner != nil {
			data, err = a.SessionConfig.CookieCacheSigner.Sign(ctx, sessionData, time.Duration(ttl)*time.Second)
		} else {
			data, err = bacrypto.SignJWT(sessionData, a.Secret, time.Duration(ttl)*time.Second)
		}
	default:
		signed := sessionData.Clone().Set("expiresAt", expiresAt)
		payload := jsonx.MustMarshal(signed)
		sig := bacrypto.Base64URLNoPad(bacrypto.HMACSHA256([]byte(a.Secret), payload))
		data = bacrypto.Base64URLNoPad(jsonx.MustMarshal(jsonx.O("session", sessionData, "expiresAt", expiresAt, "signature", sig)))
	}
	if err != nil {
		return err
	}
	st := newCookieStore("Session", a.AuthCookies.SessionData.Name, opts, ctx)
	st.set(st.chunk(data, opts))

	if a.storeAccountCookie() && !hasPendingSetCookie(ctx, a.AuthCookies.AccountData.Name) {
		if acct := GetAccountCookie(ctx); acct != nil {
			if a.Options.Database == nil || acct.UserID == s.User.ID {
				return SetAccountCookie(ctx, acct)
			}
			ExpireCookie(ctx, a.AuthCookies.AccountData)
			ast := newCookieStore("Account", a.AuthCookies.AccountData.Name, a.AuthCookies.AccountData.Attributes, ctx)
			ast.set(ast.clean())
		}
	}
	return nil
}

// cookieCachePayload is the decoded cookie cache.
type cookieCachePayload struct {
	Session   *Session
	User      *User
	UpdatedAt float64
	Version   string
	ExpiresAt time.Time
}

func isISODateValue(v any) bool {
	_, ok := v.(time.Time)
	return ok
}

// parseCookieCachePayload validates the payload shape (cookieCachePayloadSchema). Dates
// must already be revived to time.Time.
func parseCookieCachePayload(v any) *cookieCachePayload {
	return parseCookieCachePayloadLog(v, nil)
}

// parseCookieCachePayloadLog validates the payload and warns through log on schema
// failures (absent or non-object payloads stay silent, as upstream).
func parseCookieCachePayloadLog(v any, log Logger) *cookieCachePayload {
	p, ok := v.(*jsonx.Object)
	if !ok || p == nil {
		return nil
	}
	out := validateCookieCachePayload(p)
	if out == nil && log != nil {
		log.Warn("Cookie cache payload failed schema validation")
	}
	return out
}

func validateCookieCachePayload(v any) *cookieCachePayload {
	o, ok := v.(*jsonx.Object)
	if !ok {
		return nil
	}
	sv, _ := o.Get("session")
	uv, _ := o.Get("user")
	so, ok1 := sv.(*jsonx.Object)
	uo, ok2 := uv.(*jsonx.Object)
	if !ok1 || !ok2 {
		return nil
	}
	upd, ok := o.Get("updatedAt")
	updF, isNum := upd.(float64)
	if !ok || !isNum {
		return nil
	}
	version := ""
	if vv, ok := o.Get("version"); ok {
		s, isStr := vv.(string)
		if !isStr {
			return nil
		}
		version = s
	}
	str := func(o *jsonx.Object, k string, required bool) bool {
		v, ok := o.Get(k)
		if !ok {
			return !required
		}
		if v == nil {
			return !required
		}
		_, isStr := v.(string)
		return isStr
	}
	date := func(o *jsonx.Object, k string, def bool) bool {
		v, ok := o.Get(k)
		if !ok {
			return def
		}
		return isISODateValue(v)
	}
	// session: id, createdAt, updatedAt, userId (coerced), expiresAt, token, ipAddress?, userAgent?
	if !str(so, "id", true) || !date(so, "createdAt", true) || !date(so, "updatedAt", true) ||
		!date(so, "expiresAt", false) || !str(so, "token", true) || !str(so, "ipAddress", false) || !str(so, "userAgent", false) {
		return nil
	}
	if uid, ok := so.Get("userId"); !ok || uid == nil {
		return nil
	}
	// user: id, createdAt, updatedAt, email, emailVerified (default false), name, image?
	if !str(uo, "id", true) || !date(uo, "createdAt", true) || !date(uo, "updatedAt", true) ||
		!str(uo, "email", true) || !str(uo, "name", true) || !str(uo, "image", false) {
		return nil
	}
	if ev, ok := uo.Get("emailVerified"); ok {
		if _, isBool := ev.(bool); !isBool {
			return nil
		}
	}
	user := UserFromRecord(uo)
	user.Email = strings.ToLower(user.Email)
	return &cookieCachePayload{Session: SessionFromRecord(so), User: user, UpdatedAt: updF, Version: version}
}

// decodeCookieCache mirrors decodeCookieCache in cookies/index.ts.
func decodeCookieCache(ctx *EndpointContext, value string) *cookieCachePayload {
	a := ctx.Auth
	switch a.cookieCacheStrategy() {
	case "jwe":
		decoded := bacrypto.SymmetricDecodeJWT(value, a.SecretConfig, "better-auth-session")
		if decoded == nil {
			return nil
		}
		p := parseCookieCachePayloadLog(jsonx.ReviveDates(decoded), a.Logger)
		if p == nil {
			return nil
		}
		p.ExpiresAt = expFromClaims(decoded)
		return p
	case "jwt":
		if a.SessionConfig.CookieCacheSigner != nil {
			payload, exp, ok := a.SessionConfig.CookieCacheSigner.Verify(ctx, value)
			if !ok {
				return nil
			}
			p := parseCookieCachePayloadLog(jsonx.ReviveDates(payload), a.Logger)
			if p == nil {
				return nil
			}
			p.ExpiresAt = exp
			return p
		}
		decoded, err := bacrypto.VerifyJWT(value, a.Secret)
		if err != nil {
			return nil
		}
		p := parseCookieCachePayloadLog(jsonx.ReviveDates(decoded), a.Logger)
		if p == nil {
			return nil
		}
		p.ExpiresAt = expFromClaims(decoded)
		return p
	}
	return decodeCompactCacheLog(value, a.Secret, a.Logger)
}

func expFromClaims(o *jsonx.Object) time.Time {
	if v, ok := o.Get("exp"); ok {
		if f, ok := v.(float64); ok && f != 0 {
			return time.UnixMilli(int64(f * 1000))
		}
	}
	return time.Now()
}

func decodeCompactCache(value, secret string) *cookieCachePayload {
	return decodeCompactCacheLog(value, secret, nil)
}

func decodeCompactCacheLog(value, secret string, log Logger) *cookieCachePayload {
	raw, err := bacrypto.DecodeBase64Loose(value)
	if err != nil {
		return nil
	}
	parsed, err := jsonx.Parse(raw)
	if err != nil {
		return nil
	}
	revived, ok := jsonx.ReviveDates(parsed).(*jsonx.Object)
	if !ok {
		return nil
	}
	sv, _ := revived.Get("session")
	session, ok := sv.(*jsonx.Object)
	if !ok {
		return nil
	}
	ev, _ := revived.Get("expiresAt")
	expiresAt, ok := ev.(float64)
	if !ok {
		return nil
	}
	sigV, _ := revived.Get("signature")
	sig, ok := sigV.(string)
	if !ok {
		return nil
	}
	signed := session.Clone().Set("expiresAt", expiresAt)
	payload, err := jsonx.Marshal(signed)
	if err != nil {
		return nil
	}
	got, err := bacrypto.DecodeBase64Loose(sig)
	if err != nil || !bacrypto.ConstantTimeEqual(got, bacrypto.HMACSHA256([]byte(secret), payload)) {
		return nil
	}
	p := parseCookieCachePayloadLog(session, log)
	if p == nil {
		return nil
	}
	p.ExpiresAt = time.UnixMilli(int64(expiresAt))
	return p
}

// ---- account cookie ----

// SetAccountCookie stores the account in the encrypted account_data cookie.
func SetAccountCookie(ctx *EndpointContext, acct *Account) error {
	a := ctx.Auth
	c := a.AuthCookies.AccountData
	opts := c.Attributes
	if opts.MaxAge == nil {
		opts.MaxAge = Int(300)
	}
	data, err := bacrypto.SymmetricEncodeJWT(accountCookieObject(acct), a.SecretConfig, "better-auth-account", time.Duration(*opts.MaxAge)*time.Second)
	if err != nil {
		return err
	}
	st := newCookieStore("Account", c.Name, opts, ctx)
	st.set(st.chunk(data, opts))
	return nil
}

func accountCookieObject(acct *Account) *jsonx.Object {
	o := toObject(acct, nil, coreAccountFields, acct.Additional, nil)
	for _, k := range o.Keys() {
		if v, _ := o.Get(k); v == nil {
			o.Delete(k)
		}
	}
	return o
}

// GetAccountCookie reads the account_data cookie (nil when missing or invalid).
func GetAccountCookie(ctx *EndpointContext) *Account {
	a := ctx.Auth
	v := GetChunkedCookie(ctx, a.AuthCookies.AccountData.Name)
	if v == "" {
		return nil
	}
	decoded := bacrypto.SymmetricDecodeJWT(v, a.SecretConfig, "better-auth-account")
	if decoded == nil {
		return nil
	}
	return AccountFromRecord(jsonx.ReviveDates(decoded))
}

// ---- framework helpers ----

// SessionCookieOptions configure GetSessionCookieWith.
type SessionCookieOptions struct {
	// CookiePrefix defaults to "better-auth"; CookieName to "session_token".
	CookiePrefix string
	CookieName   string
}

// GetSessionCookie returns the raw (signed) session token cookie from request headers, the
// equivalent of getSessionCookie in better-auth/cookies. It does not verify the signature.
func GetSessionCookie(h http.Header, cookiePrefix string) string {
	return GetSessionCookieWith(h, SessionCookieOptions{CookiePrefix: cookiePrefix})
}

// GetSessionCookieWith is GetSessionCookie with a custom cookie name.
func GetSessionCookieWith(h http.Header, o SessionCookieOptions) string {
	raw := h.Get("Cookie")
	if raw == "" {
		return ""
	}
	if o.CookiePrefix == "" {
		o.CookiePrefix = "better-auth"
	}
	if o.CookieName == "" {
		o.CookieName = "session_token"
	}
	cookies := map[string]string{}
	for _, c := range parseCookieList(raw) {
		cookies[c.name] = c.value
	}
	// parsedCookie.get("__Secure-"+name) ?? parsedCookie.get(name): a present-but-empty
	// secure cookie does not fall back to the plain one.
	get := func(name string) string {
		if v, ok := cookies[SecureCookiePrefix+name]; ok {
			return v
		}
		return cookies[name]
	}
	if v := get(o.CookiePrefix + "." + o.CookieName); v != "" {
		return v
	}
	return get(o.CookiePrefix + "-" + o.CookieName)
}

// StripSecureCookiePrefix removes a "__Secure-" or "__Host-" prefix.
func StripSecureCookiePrefix(name string) string {
	if strings.HasPrefix(name, SecureCookiePrefix) {
		return name[len(SecureCookiePrefix):]
	}
	return strings.TrimPrefix(name, "__Host-")
}

// SplitSetCookieHeader splits a comma-joined Set-Cookie header into individual cookies,
// ignoring commas inside attribute values such as Expires.
func SplitSetCookieHeader(setCookie string) []string {
	var out []string
	start := 0
	for i := 0; i < len(setCookie); i++ {
		if setCookie[i] != ',' {
			continue
		}
		j := i + 1
		for j < len(setCookie) && setCookie[j] == ' ' {
			j++
		}
		k := j
		for k < len(setCookie) && setCookie[k] != '=' && setCookie[k] != ';' && setCookie[k] != ',' {
			k++
		}
		if k < len(setCookie) && setCookie[k] == '=' {
			if part := strings.TrimSpace(setCookie[start:i]); part != "" {
				out = append(out, part)
			}
			start = j
			i = j - 1
		}
	}
	if last := strings.TrimSpace(setCookie[start:]); last != "" {
		out = append(out, last)
	}
	return out
}
