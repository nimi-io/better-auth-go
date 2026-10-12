# better-auth-go

A Go port of [Better Auth](https://better-auth.com) (tracking **v1.7.7**) that is
**wire-compatible** with the official JavaScript clients and **database-compatible** with
existing Better Auth databases.

- Same routes under `/api/auth`, HTTP methods, JSON shapes, error bodies (`{ message, code }`),
  status codes and cookies, so `better-auth/client`, `better-auth/react` and friends work
  unmodified against a Go backend.
- Same table and column names (`user`, `session`, `account`, `verification`, camelCase
  columns), so you can point it at an existing Better Auth database. Passwords (scrypt) and
  sessions keep working.
- Signed cookies, the session cookie cache (`compact`, `jwt`, `jwe`) and encrypted values are
  byte-compatible with the TypeScript implementation: a cookie issued by one validates in
  the other when they share a secret.

See [COMPATIBILITY.md](COMPATIBILITY.md) for the feature-by-feature status.

> **Status:** Phase 1 (core email/password auth, sessions, cookie cache, CSRF/origin checks,
> rate limiting, secondary storage, hooks) is complete. Social OAuth, SQL/Mongo adapters, the
> CLI and plugins are being ported phase by phase; the matrix tracks progress.

## Install

```sh
go get github.com/nimi-io/better-auth-go
```

Requires Go 1.25+.

## Quickstart (net/http)

```go
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
)

func main() {
	auth := betterauth.MustNew(betterauth.Config{
		BaseURL:          "http://localhost:3000",
		Secret:           os.Getenv("BETTER_AUTH_SECRET"), // at least 32 random characters
		Database:         memory.New(),
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true},
	})

	app := http.NewServeMux()
	app.Handle("/api/me", auth.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := betterauth.SessionFromContext(r.Context())
		w.Write([]byte("hello " + session.User.Name))
	})))

	// Mount serves /api/auth/* and delegates everything else to app.
	log.Fatal(http.ListenAndServe(":3000", auth.Mount(app)))
}
```

On the frontend, use the official client as usual:

```ts
import { createAuthClient } from "better-auth/react";

export const authClient = createAuthClient({ baseURL: "http://localhost:3000" });

await authClient.signUp.email({ email, password, name });
const { data: session } = authClient.useSession();
```

> `http.ServeMux` cleans paths and redirects requests such as `//ok`. Better Auth answers
> those with 404, so use `auth.Mount` (or mount `auth.Handler()` directly) if you need
> byte-identical routing behaviour.

## Framework integration

`auth.Handler()` is a plain `http.Handler`, and `auth.Middleware` /
`auth.RequireSession` are standard `func(http.Handler) http.Handler` middlewares. Complete,
runnable examples live in [`examples/`](examples):

| Framework | Mount the handler | Example |
|---|---|---|
| net/http | `auth.Mount(app)` | [examples/nethttp](examples/nethttp/main.go) |
| chi | `r.Handle("/api/auth/*", auth.Handler())` | [examples/chi](examples/chi/main.go) |
| Gin | `r.Any("/api/auth/*path", gin.WrapH(auth.Handler()))` | [examples/gin](examples/gin/main.go) |
| Echo | `e.Any("/api/auth/*", echo.WrapHandler(auth.Handler()))` | [examples/echo](examples/echo/main.go) |
| Fiber | `app.All("/api/auth/*", adaptor.HTTPHandler(auth.Handler()))` | [examples/fiber](examples/fiber/main.go) |

## Server-side API

Every endpoint can be called from Go without HTTP (`auth.api` upstream):

```go
session, err := auth.API.GetSession(ctx, r.Header) // nil when signed out

res, err := auth.API.SignUpEmail(ctx, betterauth.SignUpEmailInput{
	Email: "a@example.com", Password: "password1234", Name: "Ada",
}, nil)
// res.Data is the JSON body, res.Headers carries Set-Cookie.

// Any endpoint (including plugin endpoints) by its key:
res, err = auth.API.Call(ctx, "changePassword", betterauth.CallInput{
	Headers: r.Header,
	Body:    map[string]any{"currentPassword": "old", "newPassword": "new-password"},
})
var apiErr *betterauth.APIError
if errors.As(err, &apiErr) {
	log.Println(apiErr.StatusCode, apiErr.Code(), apiErr.Message())
}
```

Server-only endpoints (for example `setPassword`) are reachable only through `auth.API`.

## Configuration highlights

```go
betterauth.Config{
	BaseURL:  "https://example.com",       // or DynamicBaseURL for multi-host setups
	BasePath: "/api/auth",                 // default
	Secret:   "...",                       // or Secrets for rotation
	Secrets:  []betterauth.SecretEntry{{Version: 2, Value: "new"}, {Version: 1, Value: "old"}},
	Database: memory.New(),
	SecondaryStorage: redisStorage,        // implements betterauth.SecondaryStorage
	EmailAndPassword: &betterauth.EmailAndPasswordConfig{
		Enabled:                  true,
		RequireEmailVerification: true,
		SendResetPassword: func(ctx context.Context, d betterauth.EmailData, r *http.Request) error {
			return mailer.Send(d.User.Email, "Reset your password", d.URL)
		},
	},
	EmailVerification: &betterauth.EmailVerificationConfig{
		SendVerificationEmail: sendVerification,
		SendOnSignUp:          betterauth.Bool(true),
	},
	Session: &betterauth.SessionConfig{
		ExpiresIn:   7 * 24 * time.Hour,
		UpdateAge:   betterauth.Duration(24 * time.Hour),
		CookieCache: &betterauth.CookieCacheConfig{Enabled: true, Strategy: "jwe", MaxAge: 5 * time.Minute},
	},
	User: &betterauth.UserConfig{
		ModelConfig: betterauth.ModelConfig{
			ModelName: "users",                                   // custom table name
			Fields:    map[string]string{"emailVerified": "email_verified"},
			AdditionalFields: []db.Field{{Name: "role", Type: db.TypeString, DefaultValue: "user", Input: db.False}},
		},
	},
	TrustedOrigins: []string{"https://app.example.com", "*.example.com"},
	RateLimit:      &betterauth.RateLimitConfig{Enabled: betterauth.Bool(true), Window: 10 * time.Second, Max: 100},
	Hooks: &betterauth.HooksConfig{
		Before: func(ctx *betterauth.EndpointContext) (any, error) { return nil, nil },
	},
	DatabaseHooks: &betterauth.DatabaseHooks{
		User: betterauth.DBModelHooks{Create: betterauth.DBOperationHooks{
			After: func(ctx context.Context, user adapter.Record) error { return nil },
		}},
	},
}
```

Field names mirror the TypeScript options (`emailAndPassword` → `EmailAndPassword`, ...).
Durations use `time.Duration`; options whose zero value is meaningful use pointers
(`betterauth.Bool`, `betterauth.Duration`).

## Plugins

Plugins are `*betterauth.Plugin` values with endpoints, schema, hooks, middlewares,
rate-limit rules and error codes, mirroring `BetterAuthPlugin`:

```go
func helloPlugin() *betterauth.Plugin {
	return &betterauth.Plugin{
		ID: "hello",
		Endpoints: []*betterauth.Endpoint{{
			Key: "hello", Path: "/hello", Methods: []string{"GET"},
			Use: []betterauth.Middleware{betterauth.SessionMiddleware},
			Handler: func(ctx *betterauth.EndpointContext) (any, error) {
				return jsonx.O("hello", ctx.Session.User.Name), nil
			},
		}},
		Schema: []db.PluginTable{{Key: "user", Fields: []db.Field{{Name: "nickname", Type: db.TypeString}}}},
	}
}
```

## Package layout

| Package | Purpose |
|---|---|
| `betterauth` | Config, `New`, HTTP handler, endpoints, cookies, sessions, hooks, server API |
| `adapter` | Generic adapter interface + transform layer (`createAdapterFactory`) |
| `adapter/memory` | In-memory adapter |
| `db` | Schema definitions (`GetAuthTables`, plugin tables, field options) |
| `crypto` | scrypt passwords, XChaCha20-Poly1305, JWT/JWE, random ids (byte-compatible with TS) |
| `jsonx` | JavaScript-compatible ordered JSON (needed for signature compatibility) |
| `validate` | zod-compatible validation with identical error messages |
| `oauth2` | OAuth provider interface |

## Testing

```sh
go test ./...                     # unit tests (includes ports of the upstream test suites)

cd e2e && npm install && npm test # official JS client against the Go server, diffed
                                  # against the real better-auth@1.7.7 server
```

The e2e suite runs every scenario through `better-auth/client` against both the Go server
and the reference TypeScript server, and asserts that normalised response bodies, status
codes, `Location` and `Set-Cookie` headers are identical. It also checks cross-compatibility:
session cookies and cookie caches issued by TypeScript validate in Go and vice versa, and
password hashes verify in both directions.
