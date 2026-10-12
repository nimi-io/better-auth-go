// Package betterauth is a Go port of Better Auth (https://better-auth.com) that is
// wire-compatible with the official JavaScript clients and database-compatible with
// existing Better Auth databases.
//
//	auth, err := betterauth.New(betterauth.Config{
//		BaseURL:          "http://localhost:3000",
//		Secret:           os.Getenv("BETTER_AUTH_SECRET"),
//		Database:         memory.New(),
//		EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true},
//	})
//	mux.Handle("/api/auth/", auth.Handler())
package betterauth

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/memory"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/db"
)

// Version is the upstream Better Auth version this port tracks.
const Version = "1.7.7"

// DefaultSecret is used when no secret is configured outside production.
const DefaultSecret = "better-auth-secret-12345678901234567890"

// Auth is a configured Better Auth instance.
type Auth struct {
	cfg       *Config
	ctx       *AuthContext
	endpoints []*Endpoint
	byKey     map[string]*Endpoint
	router    *router
	memoryRL  *memoryRateLimiter
	// API exposes every endpoint as a Go function (auth.api upstream).
	API *API
	// ErrorCodes merges base and plugin error codes ($ERROR_CODES).
	ErrorCodes map[string]ErrorCode

	ipWarnOnce      sync.Once
	deprecationOnce sync.Once
	// observedWindow is the longest rate-limit window seen (ms), including dynamic rules.
	observedWindow atomic.Int64
}

// Context returns the shared AuthContext (auth.$context).
func (a *Auth) Context() *AuthContext { return a.ctx }

// Options returns the resolved configuration.
func (a *Auth) Options() *Config { return a.cfg }

// Endpoints returns all endpoints (core and plugin).
func (a *Auth) Endpoints() []*Endpoint { return a.endpoints }

func (a *Auth) endpoint(key string) *Endpoint { return a.byKey[key] }

// MustNew is New that panics on error.
func MustNew(cfg Config) *Auth {
	a, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return a
}

func estimateEntropy(s string) float64 {
	unique := map[rune]bool{}
	n := 0
	for _, r := range s {
		unique[r] = true
		n++
	}
	if len(unique) == 0 {
		return 0
	}
	return float64(n) * math.Log2(float64(len(unique)))
}

func parseSecretsEnv(v string) ([]SecretEntry, error) {
	if v == "" {
		return nil, nil
	}
	var out []SecretEntry
	for _, entry := range strings.Split(v, ",") {
		entry = strings.TrimSpace(entry)
		idx := strings.Index(entry, ":")
		if idx == -1 {
			return nil, fmt.Errorf("Invalid BETTER_AUTH_SECRETS entry: %q. Expected format: \"<version>:<secret>\"", entry)
		}
		ver, err := strconv.Atoi(strings.TrimSpace(entry[:idx]))
		if err != nil || ver < 0 {
			return nil, fmt.Errorf("Invalid version in BETTER_AUTH_SECRETS: %q. Version must be a non-negative integer.", entry[:idx])
		}
		val := strings.TrimSpace(entry[idx+1:])
		if val == "" {
			return nil, fmt.Errorf("Empty secret value for version %d in BETTER_AUTH_SECRETS.", ver)
		}
		out = append(out, SecretEntry{Version: ver, Value: val})
	}
	return out, nil
}

func validateSecretsArray(secrets []SecretEntry, log Logger) error {
	if len(secrets) == 0 {
		return errors.New("`secrets` array must contain at least one entry.")
	}
	seen := map[int]bool{}
	for _, s := range secrets {
		if s.Version < 0 {
			return fmt.Errorf("Invalid version %d in `secrets`. Version must be a non-negative integer.", s.Version)
		}
		if s.Value == "" {
			return fmt.Errorf("Empty secret value for version %d in `secrets`.", s.Version)
		}
		if seen[s.Version] {
			return fmt.Errorf("Duplicate version %d in `secrets`. Each version must be unique.", s.Version)
		}
		seen[s.Version] = true
	}
	cur := secrets[0]
	if len(cur.Value) < 32 {
		log.Warn(fmt.Sprintf("[better-auth] Warning: the current secret (version %d) should be at least 32 characters long for adequate security.", cur.Version))
	}
	if estimateEntropy(cur.Value) < 120 {
		log.Warn("[better-auth] Warning: the current secret appears low-entropy. Use a randomly generated secret for production.")
	}
	return nil
}

func validateSecret(secret string, log Logger) error {
	if isTestEnv() {
		return nil
	}
	if secret == DefaultSecret && isProduction() {
		return errors.New("You are using the default secret. Please set `BETTER_AUTH_SECRET` in your environment variables or pass `secret` in your auth config.")
	}
	if secret == "" {
		return errors.New("BETTER_AUTH_SECRET is missing. Set it in your environment or pass `secret` to betterauth.New(betterauth.Config{Secret: ...}).")
	}
	if len(secret) < 32 {
		log.Warn("[better-auth] Warning: your BETTER_AUTH_SECRET should be at least 32 characters long for adequate security. Generate one with `better-auth secret` or `openssl rand -base64 32`.")
	}
	if estimateEntropy(secret) < 120 {
		log.Warn("[better-auth] Warning: your BETTER_AUTH_SECRET appears low-entropy. Use a randomly generated secret for production.")
	}
	return nil
}

func schemaOptions(cfg *Config) db.Options {
	mo := func(m *ModelConfig) db.ModelOptions {
		if m == nil {
			return db.ModelOptions{}
		}
		return db.ModelOptions{ModelName: m.ModelName, Fields: m.Fields, AdditionalFields: m.AdditionalFields}
	}
	o := db.Options{HasSecondaryStorage: cfg.SecondaryStorage != nil}
	if cfg.User != nil {
		o.User = mo(&cfg.User.ModelConfig)
	}
	if cfg.Session != nil {
		o.Session = mo(&cfg.Session.ModelConfig)
		o.StoreSessionInDatabase = cfg.Session.StoreSessionInDatabase
	}
	if cfg.Account != nil {
		o.Account = mo(&cfg.Account.ModelConfig)
	}
	if cfg.Verification != nil {
		o.Verification = mo(&cfg.Verification.ModelConfig)
		o.StoreVerificationInDatabase = cfg.Verification.StoreInDatabase
	}
	if cfg.RateLimit != nil {
		o.RateLimit = db.ModelOptions{ModelName: cfg.RateLimit.ModelName, Fields: cfg.RateLimit.Fields}
		o.RateLimitInDatabase = cfg.RateLimit.Storage == "database"
	}
	for _, p := range cfg.Plugins {
		if len(p.Schema) > 0 {
			o.Plugins = append(o.Plugins, p.Schema)
		}
	}
	return o
}

// GetSchema returns the database schema for a configuration (used by the CLI).
func GetSchema(cfg Config) *db.Schema { return db.GetAuthTables(schemaOptions(&cfg)) }

// New creates a Better Auth instance.
func New(input Config) (*Auth, error) {
	cfg := input // shallow copy; nested pointers are shared with the caller
	log := cfg.Logger
	if log == nil {
		log = NewLogger(LevelWarn, nil)
	}
	stateful := cfg.Database != nil || cfg.SecondaryStorage != nil
	if !stateful {
		// stateless: sessions live in a JWE cookie cache
		sess := SessionConfig{}
		if cfg.Session != nil {
			sess = *cfg.Session
		}
		cc := CookieCacheConfig{}
		if sess.CookieCache != nil {
			cc = *sess.CookieCache
		} else {
			cc.Enabled = true
		}
		if sess.CookieCache == nil {
			cc.Strategy = "jwe"
			cc.RefreshCache = &RefreshCacheConfig{Enabled: true}
			cc.MaxAge = sess.ExpiresIn
			if cc.MaxAge == 0 {
				cc.MaxAge = 7 * 24 * time.Hour
			}
		}
		sess.CookieCache = &cc
		cfg.Session = &sess
	}
	if cfg.Database == nil {
		acc := AccountConfig{}
		if cfg.Account != nil {
			acc = *cfg.Account
		}
		if acc.StoreAccountCookie == nil {
			acc.StoreAccountCookie = Bool(true)
		}
		cfg.Account = &acc
	}
	if cfg.DynamicBaseURL != nil && len(cfg.DynamicBaseURL.AllowedHosts) == 0 {
		return nil, errors.New("baseURL.allowedHosts cannot be empty. Provide at least one allowed host pattern (e.g., [\"myapp.com\", \"*.vercel.app\"]).")
	}
	if cfg.BasePath == "" {
		cfg.BasePath = "/api/auth"
	}
	baseURL := ""
	if cfg.DynamicBaseURL == nil {
		u, err := getBaseURL(cfg.BaseURL, cfg.BasePath, nil, true, false)
		if err != nil {
			return nil, err
		}
		baseURL = u
		if baseURL == "" {
			log.Warn("[better-auth] Base URL is not set. Set the baseURL option or BETTER_AUTH_URL env, or use a dynamic baseURL with allowedHosts for multi-host setups. Without it the origin is derived from the incoming request, and callbacks and redirects may not work correctly.")
		}
	}
	// secrets
	secrets := cfg.Secrets
	if secrets == nil {
		s, err := parseSecretsEnv(os.Getenv("BETTER_AUTH_SECRETS"))
		if err != nil {
			return nil, err
		}
		secrets = s
	}
	legacy := cfg.Secret
	if legacy == "" {
		legacy = os.Getenv("BETTER_AUTH_SECRET")
	}
	if legacy == "" {
		legacy = os.Getenv("AUTH_SECRET")
	}
	var secret string
	var secretCfg bacrypto.Secret
	if len(secrets) > 0 {
		if err := validateSecretsArray(secrets, log); err != nil {
			return nil, err
		}
		secret = secrets[0].Value
		vs := make([]bacrypto.VersionedSecret, len(secrets))
		for i, s := range secrets {
			vs[i] = bacrypto.VersionedSecret{Version: s.Version, Value: s.Value}
		}
		ls := legacy
		if ls == DefaultSecret {
			ls = ""
		}
		secretCfg = bacrypto.Secret{Config: bacrypto.NewSecretConfig(vs, ls)}
	} else {
		secret = legacy
		if secret == "" {
			secret = DefaultSecret
		}
		if err := validateSecret(secret, log); err != nil {
			return nil, err
		}
		secretCfg = bacrypto.PlainSecret(secret)
	}
	cfg.Secret = secret
	if baseURL != "" {
		cfg.BaseURL = getOrigin(baseURL)
	} else if cfg.DynamicBaseURL == nil {
		cfg.BaseURL = ""
	}
	if cfg.Advanced != nil && cfg.Advanced.IPAddress != nil {
		if bad := findInvalidTrustedProxies(cfg.Advanced.IPAddress.TrustedProxies); len(bad) > 0 {
			log.Warn("Ignoring invalid `advanced.ipAddress.trustedProxies` entries: " + strings.Join(bad, ", ") + ". Each entry must be an IP address or CIDR range.")
		}
	}

	a := &Auth{cfg: &cfg, byKey: map[string]*Endpoint{}, memoryRL: &memoryRateLimiter{data: map[string]rlEntry{}}}
	schema := db.GetAuthTables(schemaOptions(&cfg))

	// adapter
	factory := cfg.Database
	if factory == nil {
		factory = memory.New()
	}
	aopts := adapter.Options{Schema: schema, Logger: log}
	if adv := cfg.Advanced; adv != nil && adv.Database != nil {
		aopts.IDMode = adv.Database.GenerateID
		aopts.GenerateID = adv.Database.GenerateIDFunc
		aopts.DefaultFindManyLimit = adv.Database.DefaultFindManyLimit
		aopts.Joins = adv.Database.Joins
	}
	ad, err := factory(aopts)
	if err != nil {
		return nil, err
	}

	secure := a.useSecureCookies(&cfg)
	cookieGen, err := newCookieGetter(&cfg, secure)
	if err != nil {
		return nil, err
	}

	ac := &AuthContext{
		AppName: cfg.AppName, BaseURL: baseURL, Options: &cfg, SocialProviders: cfg.SocialProviders,
		Tables: schema, Secret: secret, SecretConfig: secretCfg, Logger: log, Adapter: ad,
		SecondaryStorage: cfg.SecondaryStorage, Extensions: map[string]any{}, stateful: stateful,
		plugins: cfg.Plugins, auth: a, extMu: &sync.RWMutex{}, cookieGen: cookieGen,
	}
	if ac.AppName == "" {
		ac.AppName = "Better Auth"
	}
	ac.AuthCookies = buildAuthCookies(&cfg, cookieGen)
	ac.OAuthConfig.StoreStateStrategy = "cookie"
	if stateful {
		ac.OAuthConfig.StoreStateStrategy = "database"
	}
	if cfg.Account != nil {
		if cfg.Account.StoreStateStrategy != "" {
			ac.OAuthConfig.StoreStateStrategy = cfg.Account.StoreStateStrategy
		}
		ac.OAuthConfig.SkipStateCookieCheck = cfg.Account.SkipStateCookieCheck
	}
	// session runtime
	sr := SessionRuntime{ExpiresIn: 7 * 24 * time.Hour, UpdateAge: 24 * time.Hour, FreshAge: 24 * time.Hour}
	if s := cfg.Session; s != nil {
		if s.ExpiresIn > 0 {
			sr.ExpiresIn = s.ExpiresIn
		}
		if s.UpdateAge != nil {
			sr.UpdateAge = *s.UpdateAge
		}
		if s.FreshAge != nil {
			sr.FreshAge = *s.FreshAge
		}
		if cc := s.CookieCache; cc != nil && cc.RefreshCache != nil && cc.RefreshCache.Enabled {
			if stateful {
				log.Warn("[better-auth] `session.cookieCache.refreshCache` is enabled while `database` or `secondaryStorage` is configured. `refreshCache` is meant for stateless (DB-less) setups. Disabling `refreshCache` — remove it from your config to silence this warning.")
			} else {
				maxAge := cc.MaxAge
				if maxAge == 0 {
					maxAge = 5 * time.Minute
				}
				ua := time.Duration(math.Floor(maxAge.Seconds()*0.2)) * time.Second
				if cc.RefreshCache.UpdateAge != nil {
					ua = *cc.RefreshCache.UpdateAge
				}
				sr.CookieRefreshCache = &ua
			}
		}
	}
	ac.SessionConfig = sr
	// rate limit
	rl := RateLimitRuntime{Enabled: isProduction(), Window: 10 * time.Second, Max: 100, Storage: "memory"}
	if cfg.SecondaryStorage != nil {
		rl.Storage = "secondary-storage"
	}
	if r := cfg.RateLimit; r != nil {
		if r.Enabled != nil {
			rl.Enabled = *r.Enabled
		}
		if r.Window > 0 {
			rl.Window = r.Window
		}
		if r.Max > 0 {
			rl.Max = r.Max
		}
		if r.Storage != "" {
			rl.Storage = r.Storage
		}
		rl.CustomRules = r.CustomRules
	}
	ac.RateLimit = rl
	// password
	pw := PasswordRuntime{Hash: bacrypto.HashPassword, Verify: bacrypto.VerifyPassword, MinLength: 8, MaxLength: 128}
	if ep := cfg.EmailAndPassword; ep != nil {
		if ep.Password != nil && ep.Password.Hash != nil {
			pw.Hash = ep.Password.Hash
		}
		if ep.Password != nil && ep.Password.Verify != nil {
			pw.Verify = ep.Password.Verify
		}
		if ep.MinPasswordLength > 0 {
			pw.MinLength = ep.MinPasswordLength
		}
		if ep.MaxPasswordLength > 0 {
			pw.MaxLength = ep.MaxPasswordLength
		}
	}
	ac.Password = pw
	// CSRF / origin
	if adv := cfg.Advanced; adv != nil && adv.DisableCSRFCheck != nil {
		ac.SkipCSRFCheck = *adv.DisableCSRFCheck
	}
	if adv := cfg.Advanced; adv != nil && adv.DisableOriginCheck != nil {
		ac.SkipOriginCheck = *adv.DisableOriginCheck
	} else {
		ac.SkipOriginCheck = isTestEnv()
	}
	a.ctx = ac

	// endpoints
	eps := coreEndpoints()
	for _, p := range cfg.Plugins {
		eps = append(eps, p.Endpoints...)
	}
	eps = append(eps, okEndpoint(), errorEndpoint())
	a.checkEndpointConflicts()
	for _, ep := range eps {
		if ep.Key != "" {
			a.byKey[ep.Key] = ep
		}
	}
	// plugin endpoints override core endpoints with the same key (object spread)
	final := make([]*Endpoint, 0, len(eps))
	for _, ep := range eps {
		if ep.Key != "" && a.byKey[ep.Key] != ep {
			continue
		}
		final = append(final, ep)
	}
	a.endpoints = final

	// plugin init
	var dbHooks []dbHooksEntry
	var pluginOrigins []string
	var pluginOriginFns []func(*http.Request) ([]string, error)
	for _, p := range cfg.Plugins {
		if p.Init == nil {
			continue
		}
		res, err := p.Init(ac)
		if err != nil {
			return nil, fmt.Errorf("plugin %s init: %w", p.ID, err)
		}
		if res == nil {
			continue
		}
		if res.DatabaseHooks != nil {
			dbHooks = append(dbHooks, dbHooksEntry{source: "plugin:" + p.ID, hooks: res.DatabaseHooks})
		}
		pluginOrigins = append(pluginOrigins, res.TrustedOrigins...)
		if res.TrustedOriginsFunc != nil {
			pluginOriginFns = append(pluginOriginFns, res.TrustedOriginsFunc)
		}
		if res.ApplyDefaults != nil {
			res.ApplyDefaults(ac.Options)
		}
	}
	if len(pluginOrigins) > 0 || len(pluginOriginFns) > 0 {
		static := append(append([]string(nil), ac.Options.TrustedOrigins...), pluginOrigins...)
		ac.Options.TrustedOrigins = static
		if userFn := ac.Options.TrustedOriginsFunc; userFn != nil || len(pluginOriginFns) > 0 {
			fns := pluginOriginFns
			if userFn != nil {
				fns = append([]func(*http.Request) ([]string, error){userFn}, fns...)
			}
			ac.Options.TrustedOriginsFunc = func(r *http.Request) ([]string, error) {
				var out []string
				for _, f := range fns {
					v, err := f(r)
					if err != nil {
						return nil, err
					}
					for _, s := range v {
						if s != "" {
							out = append(out, s)
						}
					}
				}
				return out, nil
			}
		}
	}
	if cfg.DatabaseHooks != nil {
		dbHooks = append(dbHooks, dbHooksEntry{source: "user", hooks: cfg.DatabaseHooks})
	}
	ac.dbHooks = dbHooks
	ac.InternalAdapter = newInternalAdapter(ac)

	origins, err := a.trustedOrigins(ac.Options, nil)
	if err != nil {
		return nil, err
	}
	ac.TrustedOrigins = origins
	providers, err := a.trustedProviders(nil)
	if err != nil {
		return nil, err
	}
	ac.TrustedProviders = providers

	a.router = newRouter(a.endpoints)
	a.ErrorCodes = map[string]ErrorCode{}
	for _, p := range cfg.Plugins {
		for _, c := range p.ErrorCodes {
			a.ErrorCodes[c.Code] = c
		}
	}
	for k, v := range BaseErrorCodes {
		a.ErrorCodes[k] = v
	}
	a.API = &API{auth: a}
	return a, nil
}

func (a *Auth) checkEndpointConflicts() {
	type entry struct {
		plugin  string
		methods []string
	}
	reg := map[string][]entry{}
	var order []string
	for _, p := range a.cfg.Plugins {
		for _, ep := range p.Endpoints {
			if ep.Path == "" {
				continue
			}
			if _, ok := reg[ep.Path]; !ok {
				order = append(order, ep.Path)
			}
			methods := ep.Methods
			if len(methods) == 0 {
				methods = []string{"*"}
			}
			reg[ep.Path] = append(reg[ep.Path], entry{p.ID, methods})
		}
	}
	var msgs []string
	for _, path := range order {
		entries := reg[path]
		if len(entries) < 2 {
			continue
		}
		byMethod := map[string][]string{}
		conflict := false
		for _, e := range entries {
			for _, m := range e.methods {
				byMethod[m] = append(byMethod[m], e.plugin)
				if len(byMethod[m]) > 1 || m == "*" {
					conflict = true
				}
			}
		}
		if _, ok := byMethod["*"]; ok {
			conflict = true
		}
		if conflict {
			var plugins []string
			for _, e := range entries {
				plugins = append(plugins, e.plugin)
			}
			msgs = append(msgs, fmt.Sprintf("  - %q used by plugins: %s", path, strings.Join(plugins, ", ")))
		}
	}
	if len(msgs) > 0 {
		a.ctx.Logger.Error("Endpoint path conflicts detected! Multiple plugins are trying to use the same endpoint paths with conflicting HTTP methods:\n" + strings.Join(msgs, "\n"))
	}
}

// trustedOrigins mirrors getTrustedOrigins.
func (a *Auth) trustedOrigins(opts *Config, r *http.Request) ([]string, error) {
	var out []string
	if d := a.cfg.DynamicBaseURL; d != nil {
		for _, host := range d.AllowedHosts {
			if !strings.Contains(host, "://") {
				if d.Protocol == "" || d.Protocol == "https" || d.Protocol == "auto" {
					out = append(out, "https://"+host)
				}
				if d.Protocol == "http" || d.Protocol == "auto" || isLoopbackHost(strings.Split(host, ":")[0]) {
					out = append(out, "http://"+host)
				}
			} else {
				out = append(out, host)
			}
		}
		if d.Fallback != "" {
			if o := getOrigin(d.Fallback); o != "" {
				out = append(out, o)
			}
		}
	} else {
		base, err := getBaseURL(opts.BaseURL, opts.BasePath, r, true, false)
		if err == nil && base != "" {
			if o := getOrigin(base); o != "" {
				out = append(out, o)
			}
		}
	}
	out = append(out, opts.TrustedOrigins...)
	if opts.TrustedOriginsFunc != nil {
		extra, err := opts.TrustedOriginsFunc(r)
		if err != nil {
			return nil, err
		}
		out = append(out, extra...)
	}
	if env := os.Getenv("BETTER_AUTH_TRUSTED_ORIGINS"); env != "" {
		out = append(out, strings.Split(env, ",")...)
	}
	filtered := out[:0]
	for _, o := range out {
		if o != "" {
			filtered = append(filtered, o)
		}
	}
	return filtered, nil
}

func (a *Auth) trustedProviders(r *http.Request) ([]string, error) {
	acc := a.cfg.Account
	if acc == nil || acc.AccountLinking == nil {
		return []string{}, nil
	}
	if acc.AccountLinking.TrustedProvidersFunc != nil {
		v, err := acc.AccountLinking.TrustedProvidersFunc(r)
		if err != nil {
			return nil, err
		}
		return v, nil
	}
	out := []string{}
	for _, p := range acc.AccountLinking.TrustedProviders {
		if p != "" {
			out = append(out, p)
		}
	}
	return out, nil
}
