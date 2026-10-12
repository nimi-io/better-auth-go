package betterauth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/validate"
)

// AuthCookie is a cookie name with its attributes.
type AuthCookie struct {
	Name       string
	Attributes CookieOptions
}

// AuthCookies are the core cookies.
type AuthCookies struct {
	SessionToken      AuthCookie
	SessionData       AuthCookie
	DontRememberToken AuthCookie
	AccountData       AuthCookie
}

// CookieCacheSigner signs/verifies the "jwt" cookie cache (installed by the jwt plugin).
type CookieCacheSigner interface {
	Sign(ctx *EndpointContext, payload *jsonx.Object, maxAge time.Duration) (string, error)
	Verify(ctx *EndpointContext, token string) (payload *jsonx.Object, expiresAt time.Time, ok bool)
}

// SessionRuntime is the resolved session configuration (ctx.sessionConfig).
type SessionRuntime struct {
	ExpiresIn time.Duration
	UpdateAge time.Duration
	FreshAge  time.Duration
	// CookieRefreshCacheUpdateAge is set when refreshCache is enabled.
	CookieRefreshCache *time.Duration
	CookieCacheSigner  CookieCacheSigner
}

// RateLimitRuntime is the resolved rate limit configuration.
type RateLimitRuntime struct {
	Enabled     bool
	Window      time.Duration
	Max         int
	Storage     string
	CustomRules map[string]CustomRateLimitRule
}

// PasswordRuntime holds the password functions.
type PasswordRuntime struct {
	Hash      func(password string) (string, error)
	Verify    func(hash, password string) (bool, error)
	MinLength int
	MaxLength int
}

// OAuthRuntime is ctx.oauthConfig.
type OAuthRuntime struct {
	StoreStateStrategy   string
	SkipStateCookieCheck bool
}

// AuthContext is the runtime state shared by all endpoints (AuthContext upstream). A
// shallow copy is made per request so BaseURL and TrustedOrigins can vary per request.
type AuthContext struct {
	AppName string
	// BaseURL is the full base URL including the base path, e.g. "https://x.com/api/auth".
	BaseURL          string
	Options          *Config
	SocialProviders  []oauth2.Provider
	Tables           *db.Schema
	TrustedOrigins   []string
	TrustedProviders []string
	SessionConfig    SessionRuntime
	// Secret is the current secret; SecretConfig includes rotation.
	Secret           string
	SecretConfig     bacrypto.Secret
	RateLimit        RateLimitRuntime
	AuthCookies      AuthCookies
	Logger           Logger
	Adapter          adapter.Adapter
	InternalAdapter  *InternalAdapter
	SecondaryStorage SecondaryStorage
	Password         PasswordRuntime
	OAuthConfig      OAuthRuntime
	SkipCSRFCheck    bool
	SkipOriginCheck  bool
	// SkipOriginCheckPaths skips the origin check for path prefixes.
	SkipOriginCheckPaths []string
	// Extensions holds values contributed by plugin Init functions.
	Extensions map[string]any

	stateful  bool
	plugins   []*Plugin
	auth      *Auth
	extMu     *sync.RWMutex
	dbHooks   []dbHooksEntry
	cookieGen func(name string, over *CookieOptions) AuthCookie
}

// Plugins returns the registered plugins.
func (a *AuthContext) Plugins() []*Plugin { return a.plugins }

// HasPlugin reports whether a plugin with id is registered.
func (a *AuthContext) HasPlugin(id string) bool { return a.GetPlugin(id) != nil }

// GetPlugin returns a plugin by id.
func (a *AuthContext) GetPlugin(id string) *Plugin {
	for _, p := range a.plugins {
		if p.ID == id {
			return p
		}
	}
	return nil
}

// Get returns a plugin-provided extension value.
func (a *AuthContext) Get(key string) any {
	a.extMu.RLock()
	defer a.extMu.RUnlock()
	return a.Extensions[key]
}

// Set stores a plugin-provided extension value.
func (a *AuthContext) Set(key string, v any) {
	a.extMu.Lock()
	defer a.extMu.Unlock()
	a.Extensions[key] = v
}

// IsTrustedOrigin checks a URL against the trusted origins.
func (a *AuthContext) IsTrustedOrigin(u string, allowRelativePaths bool) bool {
	for _, o := range a.TrustedOrigins {
		if matchesOriginPattern(u, o, allowRelativePaths) {
			return true
		}
	}
	return false
}

// CreateAuthCookie builds a cookie definition (ctx.createAuthCookie).
func (a *AuthContext) CreateAuthCookie(name string, override *CookieOptions) AuthCookie {
	return a.cookieGen(name, override)
}

// GenerateID generates an id for model (ok=false when the database generates ids).
func (a *AuthContext) GenerateID(model string) (string, bool) {
	adv := a.Options.Advanced
	if adv != nil && adv.Database != nil {
		if adv.Database.GenerateIDFunc != nil {
			return adv.Database.GenerateIDFunc(model, 0)
		}
		switch adv.Database.GenerateID {
		case adapter.IDUUID:
			return bacrypto.RandomUUID(), true
		case adapter.IDSerial, adapter.IDNone:
			return "", false
		}
	}
	return bacrypto.GenerateID(), true
}

// RunInBackground runs fn using advanced.backgroundTasks or a goroutine.
func (a *AuthContext) RunInBackground(fn func()) {
	if a.Options.Advanced != nil && a.Options.Advanced.BackgroundTasks != nil {
		a.Options.Advanced.BackgroundTasks(fn)
		return
	}
	go fn()
}

// RunInBackgroundOrAwait runs fn in the background when backgroundTasks is configured,
// otherwise synchronously. Errors are logged, never returned (runInBackgroundOrAwait).
func (a *AuthContext) RunInBackgroundOrAwait(fn func() error) {
	run := func() {
		defer func() {
			if r := recover(); r != nil {
				a.Logger.Error("Failed to run background task:", r)
			}
		}()
		if err := fn(); err != nil {
			a.Logger.Error("Failed to run background task:", err)
		}
	}
	if a.Options.Advanced != nil && a.Options.Advanced.BackgroundTasks != nil {
		a.Options.Advanced.BackgroundTasks(run)
		return
	}
	run()
}

// Stateful reports whether sessions are stored server-side (database or secondary storage).
func (a *AuthContext) Stateful() bool { return a.stateful }

// clone makes the per-request copy.
func (a *AuthContext) clone() *AuthContext {
	c := *a
	return &c
}

// Middleware runs before an endpoint handler (the endpoint "use" list). It may set
// ctx.Session or ctx.Set values; returning an error aborts the request.
type Middleware func(ctx *EndpointContext) error

// HookHandler is a before/after hook. A before hook returning a non-nil value
// short-circuits the request with that response; an after hook returning a non-nil value
// replaces the response. Hooks may modify ctx (Body, Query, Headers) directly.
type HookHandler func(ctx *EndpointContext) (any, error)

// Hook is a plugin hook with a matcher.
type Hook struct {
	Matcher func(ctx *EndpointContext) bool
	Handler HookHandler
}

// PathMiddleware is a router-level middleware for paths matching Path ("/**", "/sign-in/*").
type PathMiddleware struct {
	Path       string
	Middleware Middleware
}

// PluginRateLimit is a plugin rate limit rule.
type PluginRateLimit struct {
	Window      time.Duration
	Max         int
	PathMatcher func(path string) bool
}

// PluginInit is returned by Plugin.Init to contribute options.
type PluginInit struct {
	TrustedOrigins     []string
	TrustedOriginsFunc func(r *http.Request) ([]string, error)
	DatabaseHooks      *DatabaseHooks
	// ApplyDefaults mutates the configuration, setting values the user left unset
	// (the defu(options, plugin.options) merge upstream).
	ApplyDefaults func(cfg *Config)
}

// PluginHooks are before/after hooks.
type PluginHooks struct {
	Before []Hook
	After  []Hook
}

// Plugin is a Better Auth plugin (BetterAuthPlugin).
type Plugin struct {
	ID      string
	Version string
	// Init runs once after the context is built; it may mutate ctx.
	Init        func(ctx *AuthContext) (*PluginInit, error)
	Endpoints   []*Endpoint
	Middlewares []PathMiddleware
	// OnRequest may replace the request or short-circuit with a response.
	OnRequest func(r *http.Request, ctx *AuthContext) (*http.Request, *Response, error)
	// OnResponse may replace the response.
	OnResponse func(resp *Response, ctx *AuthContext) (*Response, error)
	Hooks      PluginHooks
	Schema     []db.PluginTable
	RateLimit  []PluginRateLimit
	ErrorCodes []ErrorCode
	// Options exposes the plugin options to other plugins (GetPlugin(id).Options).
	Options any
}

// Endpoint is an API endpoint (createAuthEndpoint).
type Endpoint struct {
	// Key is the server API name, e.g. "signUpEmail".
	Key string
	// Path is the route, e.g. "/sign-up/email"; ":param" segments are supported.
	Path    string
	Methods []string
	// OperationID overrides the operation id used for hooks/OpenAPI.
	OperationID string
	// ServerOnly endpoints have no HTTP route.
	ServerOnly bool
	Body       validate.Schema
	Query      validate.Schema
	Use        []Middleware
	// AllowedMediaTypes defaults to ["application/json"].
	AllowedMediaTypes []string
	RequireHeaders    bool
	RequireRequest    bool
	NoStore           bool
	DisableBody       bool
	Metadata          map[string]any
	Handler           func(ctx *EndpointContext) (any, error)
}

// Response is a raw response returned by a handler (like returning `new Response()`).
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

type nullT struct{}

// Null makes a handler respond with the JSON literal null.
var Null any = nullT{}

type noContentT struct{}

// NoContent makes a handler respond with an empty body (JavaScript undefined).
var NoContent any = noContentT{}

// EndpointContext is the per-call context passed to handlers, middlewares and hooks.
type EndpointContext struct {
	ctx      context.Context
	Path     string
	Method   string
	Request  *http.Request
	Headers  http.Header
	Body     any
	Query    map[string]any
	Params   map[string]string
	Auth     *AuthContext
	Session  *SessionWithUser
	Endpoint *Endpoint
	// ResponseHeaders accumulates response headers (Set-Cookie is appended).
	ResponseHeaders http.Header
	// Returned holds the endpoint result (or *APIError) for after hooks.
	Returned       any
	ReturnedStatus int
	// OperationID of the endpoint being executed.
	OperationID string

	status     int
	values     map[string]any
	newSession *SessionWithUser
	cookies    map[string]string
}

// Context returns the Go context (it carries the active transaction, if any).
func (c *EndpointContext) Context() context.Context {
	if c.ctx == nil {
		return context.Background()
	}
	return c.ctx
}

// SetContext replaces the Go context.
func (c *EndpointContext) SetContext(ctx context.Context) { c.ctx = ctx }

// Set stores a middleware-provided value.
func (c *EndpointContext) Set(key string, v any) {
	if c.values == nil {
		c.values = map[string]any{}
	}
	c.values[key] = v
}

// Value returns a middleware-provided value.
func (c *EndpointContext) Value(key string) any { return c.values[key] }

// SetStatus overrides the response status.
func (c *EndpointContext) SetStatus(code int) { c.status = code }

// SetHeader sets a response header.
func (c *EndpointContext) SetHeader(key, value string) {
	if c.ResponseHeaders == nil {
		c.ResponseHeaders = http.Header{}
	}
	c.ResponseHeaders.Set(key, value)
}

// GetHeader reads a request header.
func (c *EndpointContext) GetHeader(key string) string {
	if c.Headers == nil {
		return ""
	}
	return c.Headers.Get(key)
}

func (c *EndpointContext) requestCookies() map[string]string {
	if c.cookies == nil {
		c.cookies = parseRequestCookies(c.GetHeader("Cookie"))
	}
	return c.cookies
}

func (c *EndpointContext) invalidateCookies() { c.cookies = nil }

// GetCookie reads a request cookie by full name ("" when missing).
func (c *EndpointContext) GetCookie(name string) string {
	return c.requestCookies()[name]
}

// GetSignedCookie verifies a signed cookie. It returns (value, true) when valid,
// ("", false) when missing, malformed or the signature does not match.
func (c *EndpointContext) GetSignedCookie(name, secret string) (string, bool) {
	value := c.requestCookies()[name]
	if value == "" {
		return "", false
	}
	pos := strings.LastIndex(value, ".")
	if pos < 1 {
		return "", false
	}
	signed, sig := value[:pos], value[pos+1:]
	if len(sig) != 44 || !strings.HasSuffix(sig, "=") {
		return "", false
	}
	if !bacrypto.VerifySignature(sig, signed, secret) {
		return "", false
	}
	return signed, true
}

// SetCookie appends a Set-Cookie header.
func (c *EndpointContext) SetCookie(name, value string, opts CookieOptions) string {
	s, err := SerializeCookie(name, value, opts)
	if err != nil {
		c.Auth.Logger.Error(err.Error())
		return ""
	}
	if c.ResponseHeaders == nil {
		c.ResponseHeaders = http.Header{}
	}
	c.ResponseHeaders.Add("Set-Cookie", s)
	return s
}

// SetSignedCookie appends a signed Set-Cookie header.
func (c *EndpointContext) SetSignedCookie(name, value, secret string, opts CookieOptions) string {
	s, err := SerializeSignedCookie(name, value, secret, opts)
	if err != nil {
		c.Auth.Logger.Error(err.Error())
		return ""
	}
	if c.ResponseHeaders == nil {
		c.ResponseHeaders = http.Header{}
	}
	c.ResponseHeaders.Add("Set-Cookie", s)
	return s
}

// Redirect returns an error that renders a 302 to u, carrying the response headers.
func (c *EndpointContext) Redirect(u string) *APIError {
	e := Redirect(u)
	return e
}

// BodyMap returns the body as an object (nil when it is not one).
func (c *EndpointContext) BodyMap() map[string]any {
	m, _ := c.Body.(map[string]any)
	return m
}

// BodyString returns a string body field.
func (c *EndpointContext) BodyString(key string) string {
	s, _ := c.BodyMap()[key].(string)
	return s
}

// BodyBool returns a boolean body field (nil when absent or not a boolean).
func (c *EndpointContext) BodyBool(key string) *bool {
	if b, ok := c.BodyMap()[key].(bool); ok {
		return &b
	}
	return nil
}

// QueryString returns a query parameter (first value).
func (c *EndpointContext) QueryString(key string) string {
	switch t := c.Query[key].(type) {
	case string:
		return t
	case []any:
		if len(t) > 0 {
			s, _ := t[0].(string)
			return s
		}
	case []string:
		if len(t) > 0 {
			return t[0]
		}
	}
	return ""
}

// HasQuery reports whether a query key is present.
func (c *EndpointContext) HasQuery(key string) bool {
	_, ok := c.Query[key]
	return ok
}

// NewSession returns the session set by setSessionCookie during this call.
func (c *EndpointContext) NewSession() *SessionWithUser { return c.newSession }

// SetNewSession records a newly created session (ctx.context.setNewSession).
func (c *EndpointContext) SetNewSession(s *SessionWithUser) { c.newSession = s }

// BaseURL is shorthand for c.Auth.BaseURL.
func (c *EndpointContext) BaseURL() string { return c.Auth.BaseURL }

// ---- Go context plumbing ----

type endpointCtxKey struct{}

// EndpointContextFrom returns the endpoint context stored in ctx (nil when called outside
// an endpoint), mirroring getCurrentAuthEndpointContext.
func EndpointContextFrom(ctx context.Context) *EndpointContext {
	if ctx == nil {
		return nil
	}
	ec, _ := ctx.Value(endpointCtxKey{}).(*EndpointContext)
	return ec
}

// requestState is per-request state shared by nested endpoint calls (defineRequestState).
type requestState struct {
	mu     sync.Mutex
	values map[any]any
}

type requestStateKey struct{}

func withRequestState(ctx context.Context) context.Context {
	if _, ok := ctx.Value(requestStateKey{}).(*requestState); ok {
		return ctx
	}
	return context.WithValue(ctx, requestStateKey{}, &requestState{values: map[any]any{}})
}

// RequestStateGet reads a request-scoped value.
func RequestStateGet(ctx context.Context, key any) (any, bool) {
	rs, ok := ctx.Value(requestStateKey{}).(*requestState)
	if !ok {
		return nil, false
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	v, ok := rs.values[key]
	return v, ok
}

// RequestStateSet stores a request-scoped value.
func RequestStateSet(ctx context.Context, key, value any) {
	rs, ok := ctx.Value(requestStateKey{}).(*requestState)
	if !ok {
		return
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.values[key] = value
}

type skipSessionRefreshKey struct{}

// SetShouldSkipSessionRefresh disables session refresh for the rest of the request.
func SetShouldSkipSessionRefresh(ctx context.Context, skip bool) {
	RequestStateSet(ctx, skipSessionRefreshKey{}, skip)
}

// ShouldSkipSessionRefresh reports whether session refresh is disabled for this request.
func ShouldSkipSessionRefresh(ctx context.Context) bool {
	v, _ := RequestStateGet(ctx, skipSessionRefreshKey{})
	b, _ := v.(bool)
	return b
}

func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}
