package main

import (
	"os"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/bearer"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
)

// jwt plugin profiles (e2e/servers/profiles/jwt-*.mjs). The plain "jwt" profile name is
// taken by the core cookie-cache strategy profile.
func init() {
	profiles["jwt-plugin"] = func(cfg *betterauth.Config, env profileEnv) {
		cfg.Plugins = append(cfg.Plugins, bearer.New(), jwt.New(jwt.Options{
			JWT: &jwt.JWTOptions{Issuer: env.BaseURL, ExpirationTime: "1h"},
		}))
	}
	profiles["jwt-es256"] = func(cfg *betterauth.Config, _ profileEnv) {
		cfg.Plugins = append(cfg.Plugins, jwt.New(jwt.Options{
			JWKS: &jwt.JWKSOptions{KeyPairConfig: &jwt.JWKOptions{Alg: "ES256"}, JWKSPath: "/.well-known/jwks.json"},
		}))
	}
	profiles["jwt-cookie-cache"] = func(cfg *betterauth.Config, _ profileEnv) {
		cfg.Session = &betterauth.SessionConfig{CookieCache: &betterauth.CookieCacheConfig{Enabled: true, Strategy: "jwt", MaxAge: 5 * time.Minute}}
		cfg.Plugins = append(cfg.Plugins, jwt.New(jwt.Options{SessionCookieCache: true}))
	}
	// Shares DB_URL with the TypeScript server: JWKS rows (encrypted private keys) written by
	// one implementation are used by the other.
	profiles["jwt-shared"] = func(cfg *betterauth.Config, _ profileEnv) {
		cfg.Database = sharedDatabase(os.Getenv("DB_URL"))
		cfg.Plugins = append(cfg.Plugins, jwt.New())
	}
}
