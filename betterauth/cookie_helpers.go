package betterauth

import (
	"errors"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// CookieCacheOptions configure GetCookieCache (the getCookieCache helper upstream).
type CookieCacheOptions struct {
	// CookiePrefix defaults to "better-auth"; CookieName to "session_data".
	CookiePrefix string
	CookieName   string
	// IsSecure selects the "__Secure-" prefix; nil means "production".
	IsSecure *bool
	// Secret defaults to BETTER_AUTH_SECRET.
	Secret string
	// Strategy is "compact" (default), "jwt" or "jwe".
	Strategy string
	// Version, when set, must match the cache version.
	Version     string
	VersionFunc func(session *Session, user *User) string
}

// ErrCookieCacheSecretMissing is returned when no secret is available.
var ErrCookieCacheSecretMissing = errors.New("getCookieCache requires a secret to be provided. Either pass it as an option or set the BETTER_AUTH_SECRET environment variable")

// GetCookieCache decodes the session cookie cache from request headers without touching the
// database, mirroring getCookieCache from better-auth/cookies. It returns nil when the cache
// is missing, invalid, expired or has a different version.
func GetCookieCache(h http.Header, o CookieCacheOptions) (*SessionWithUser, error) {
	raw := h.Get("Cookie")
	if raw == "" {
		return nil, nil
	}
	if o.CookiePrefix == "" {
		o.CookiePrefix = "better-auth"
	}
	if o.CookieName == "" {
		o.CookieName = "session_data"
	}
	secure := isProduction()
	if o.IsSecure != nil {
		secure = *o.IsSecure
	}
	name := o.CookiePrefix + "." + o.CookieName
	if secure {
		name = SecureCookiePrefix + name
	}
	cookies := parseCookieList(raw)
	value := ""
	type chunk struct {
		idx int
		v   string
	}
	var chunks []chunk
	for _, c := range cookies {
		if c.name == name {
			value = c.value
		} else if strings.HasPrefix(c.name, name+".") {
			parts := strings.Split(c.name, ".")
			if i, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
				chunks = append(chunks, chunk{i, c.value})
			}
		}
	}
	if value == "" && len(chunks) > 0 {
		sort.Slice(chunks, func(i, j int) bool { return chunks[i].idx < chunks[j].idx })
		var b strings.Builder
		for _, c := range chunks {
			b.WriteString(c.v)
		}
		value = b.String()
	}
	if value == "" {
		return nil, nil
	}
	secret := o.Secret
	if secret == "" {
		secret = os.Getenv("BETTER_AUTH_SECRET")
	}
	if secret == "" {
		return nil, ErrCookieCacheSecretMissing
	}
	var p *cookieCachePayload
	switch o.Strategy {
	case "jwe":
		decoded := bacrypto.SymmetricDecodeJWT(value, bacrypto.PlainSecret(secret), "better-auth-session")
		if decoded == nil {
			return nil, nil
		}
		p = parseCookieCachePayload(jsonx.ReviveDates(decoded))
	case "jwt":
		decoded, err := bacrypto.VerifyJWT(value, secret)
		if err != nil {
			return nil, nil
		}
		p = parseCookieCachePayload(jsonx.ReviveDates(decoded))
	default:
		p = decodeCompactCache(value, secret)
		if p != nil && p.ExpiresAt.Before(time.Now()) {
			return nil, nil
		}
	}
	if p == nil {
		return nil, nil
	}
	if o.Version != "" || o.VersionFunc != nil {
		want := o.Version
		if o.VersionFunc != nil {
			want = o.VersionFunc(p.Session, p.User)
		}
		if defaultVersion(p.Version) != want {
			return nil, nil
		}
	}
	if !p.Session.ExpiresAt.IsZero() && p.Session.ExpiresAt.Before(time.Now()) {
		return nil, nil
	}
	return &SessionWithUser{Session: p.Session, User: p.User}, nil
}
