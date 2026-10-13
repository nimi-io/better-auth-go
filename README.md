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
> rate limiting, secondary storage, hooks), Phase 2 (social OAuth: sign-in, callback,
> linking, id-token sign-in, all upstream providers) Phase 3 (PostgreSQL, MySQL, SQLite
> and MongoDB adapters, migrations, CLI) and Phase 4 (25 plugins) are complete. Enterprise
> packages (SSO, SCIM, OAuth provider, MCP) are next; the matrix tracks progress.

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

## Databases

The Go server uses the same tables, columns and stored encodings as TypeScript Better Auth,
so both can share one database (and the same `npx auth migrate` / `better-auth migrate`
schema).

```go
import (
	"database/sql"

	_ "github.com/jackc/pgx/v5/stdlib" // or github.com/go-sql-driver/mysql, modernc.org/sqlite

	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
)

db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
// MySQL:  sql.Open("mysql", "user:pass@tcp(host:3306)/app?parseTime=true")
// SQLite: sql.Open("sqlite", "file:app.db?_pragma=foreign_keys(1)")

auth := betterauth.MustNew(betterauth.Config{
	Database: sqladapter.New(db, sqladapter.Config{}), // dialect detected from the driver
	// ...
})

// Create missing tables/columns/indexes (ctx.runMigrations() upstream) ...
if err := auth.RunMigrations(ctx); err != nil { ... }
// ... or inspect the plan first.
plan, err := auth.PlanMigrations(ctx) // plan.ToBeCreated, plan.ToBeAdded, plan.SQL()
```

`sqladapter.Config` mirrors the Kysely adapter options (`Dialect`, `SchemaName` for a
PostgreSQL schema, `UsePlural`, `Transaction`, `DebugLogs`).

MongoDB:

```go
import "github.com/nimi-io/better-auth-go/adapter/mongodb"

client, _ := mongo.Connect(options.Client().ApplyURI(uri))
auth := betterauth.MustNew(betterauth.Config{
	Database: mongodb.New(client.Database("app"), mongodb.Config{Client: client}), // Client enables transactions
})
```

Notes: MySQL connections need `parseTime=true`, and a TypeScript server sharing a MySQL
database must use mysql2 with `timezone: "Z"`. With pgx, statements prepared before a
migration are re-prepared automatically; add `default_query_exec_mode=exec` to disable
statement caching entirely.

## CLI

```sh
go install github.com/nimi-io/better-auth-go/cmd/better-auth@latest

better-auth secret                                   # BETTER_AUTH_SECRET=...
better-auth migrate  --database-url "$DATABASE_URL"  # create missing tables/columns
better-auth generate --database-url "$DATABASE_URL"  # write the SQL to better-auth_migrations/
better-auth info --json
```

The standalone binary knows the default schema only. When you use plugins, additional
fields or renamed models, embed the CLI in your own binary so it sees your configuration:

```go
// cmd/auth/main.go
func main() {
	os.Exit(cli.Run(context.Background(), os.Args[1:], cli.Options{Auth: myapp.Auth()}))
}
```

## Social sign-in

Providers live in `providers/<id>` and are passed as `Config.SocialProviders`. Each package
exposes `New(Options)`; `Options` embeds `oauth2.ProviderOptions` (`ClientID`, `ClientSecret`,
`Scope`, `RedirectURI`, `MapProfileToUser`, `DisableSignUp`, ...) plus provider-specific
fields, mirroring `socialProviders.<id>` in TypeScript.

```go
import (
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/providers/github"
	"github.com/nimi-io/better-auth-go/providers/google"
)

betterauth.Config{
	// ...
	SocialProviders: []oauth2.Provider{
		github.New(github.Options{ProviderOptions: oauth2.ProviderOptions{
			ClientID: os.Getenv("GITHUB_CLIENT_ID"), ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		}}),
		google.New(google.Options{
			ProviderOptions: oauth2.ProviderOptions{ClientID: "...", ClientSecret: "..."},
			AccessType:      "offline",
		}),
	},
	Account: &betterauth.AccountConfig{
		AccountLinking: &betterauth.AccountLinkingConfig{TrustedProviders: []string{"google"}},
	},
}
```

The redirect URI to register with each provider is `<baseURL>/api/auth/callback/<id>`. The
JS client works unchanged: `authClient.signIn.social({ provider: "github" })`,
`authClient.linkSocial(...)`, and id-token sign-in
(`signIn.social({ provider: "google", idToken: { token } })`). Custom providers implement
`oauth2.Provider`, or build one with `oauth2.NewProvider(oauth2.Spec{...})`.

## Plugins

Built-in plugins live in `plugins/<name>` and mirror their TypeScript counterparts; the
official client plugins (`twoFactorClient`, `organizationClient`, ...) work unchanged.

```go
import (
	"github.com/nimi-io/better-auth-go/plugins/admin"
	"github.com/nimi-io/better-auth-go/plugins/organization"
	"github.com/nimi-io/better-auth-go/plugins/twofactor"
)

betterauth.Config{
	// ...
	Plugins: []*betterauth.Plugin{
		twofactor.New(twofactor.Options{Issuer: "My App"}),
		organization.New(organization.Options{Teams: &organization.TeamsOptions{Enabled: true}}),
		admin.New(admin.Options{}),
	},
}
```

Available: access, admin, anonymous, api-key (`apikey`), bearer, captcha, custom-session,
device-authorization, email-otp, generic-oauth, haveibeenpwned, jwt, last-login-method,
magic-link, multi-session, oauth-popup, oauth-proxy, one-tap, one-time-token, open-api,
organization, passkey, phone-number, siwe, two-factor (`twofactor`), username. Run
`auth.RunMigrations(ctx)` (or `better-auth migrate` embedded in your binary) after adding
plugins with schema.

### Writing plugins

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
| `adapter/sqladapter` | PostgreSQL / MySQL / SQLite adapter on `database/sql` (Kysely adapter port) |
| `adapter/sqladapter/migration` | Schema migrations (`getMigrations` port) |
| `adapter/mongodb` | MongoDB adapter |
| `adapter/adaptertest` | Shared adapter conformance suite |
| `cli`, `cmd/better-auth` | CLI: `migrate`, `generate`, `secret`, `info` |
| `db` | Schema definitions (`GetAuthTables`, plugin tables, field options) |
| `crypto` | scrypt passwords, XChaCha20-Poly1305, JWT/JWE, random ids (byte-compatible with TS) |
| `jsonx` | JavaScript-compatible ordered JSON (needed for signature compatibility) |
| `validate` | zod-compatible validation with identical error messages |
| `oauth2` | OAuth provider interface, provider framework (`NewProvider`), token/JWKS helpers |
| `oauth2/oauth2test` | Mock provider HTTP transport for tests |
| `providers/*` | Social providers (one package per provider id) |
| `jose` | JWK/JWS/JWT verification for id tokens |

## Testing

```sh
docker compose up -d              # PostgreSQL, MySQL, MongoDB for the adapter tests
go test ./...                     # unit tests (includes ports of the upstream test suites);
                                  # database tests skip when a server is unreachable,
                                  # BA_TEST_REQUIRE_DBS=1 makes that an error

cd e2e && npm install && npm test # official JS client against the Go server, diffed
                                  # against the real better-auth@1.7.7 server
```

The e2e suite runs every scenario through `better-auth/client` against both the Go server
and the reference TypeScript server, and asserts that normalised response bodies, status
codes, `Location` and `Set-Cookie` headers are identical. It also checks cross-compatibility:
session cookies and cookie caches issued by TypeScript validate in Go and vice versa, and
password hashes verify in both directions. The shared-database tests run both servers on
one SQLite, PostgreSQL, MySQL or MongoDB database and use each other's users, sessions and
tokens.
