# better-auth-go

A Go port of [Better Auth](https://better-auth.com), tracking **v1.7.7**, that is
**wire-compatible** with the official JavaScript clients and **database-compatible** with
existing Better Auth deployments.

Run a Go backend behind `better-auth/react` (or `vue`, `svelte`, `solid`, vanilla), point it
at the database your TypeScript Better Auth app already uses, or run Go and TypeScript
servers side by side on the same database: users, passwords, sessions, cookies, OAuth
accounts and plugin data are interchangeable.

```go
auth := betterauth.MustNew(betterauth.Config{
	BaseURL:          "http://localhost:3000",
	Secret:           os.Getenv("BETTER_AUTH_SECRET"),
	Database:         sqladapter.New(db, sqladapter.Config{}),
	EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true},
	SocialProviders:  []oauth2.Provider{github.New(github.Options{ProviderOptions: ghCreds})},
	Plugins:          []*betterauth.Plugin{twofactor.New(twofactor.Options{}), organization.New(organization.Options{})},
})
http.ListenAndServe(":3000", auth.Mount(app))
```

---

## Contents

- [Why](#why)
- [Compatibility guarantees](#compatibility-guarantees)
- [Status](#status)
- [Install](#install)
- [Quickstart](#quickstart)
- [How it fits together](#how-it-fits-together)
- [Framework integration](#framework-integration)
- [Sessions in your handlers](#sessions-in-your-handlers)
- [Server-side API](#server-side-api)
- [Email and password](#email-and-password)
- [Configuration reference](#configuration-reference)
- [Databases](#databases)
- [Migrations and the CLI](#migrations-and-the-cli)
- [Social sign-in](#social-sign-in)
- [Plugins](#plugins)
- [Enterprise](#enterprise)
- [Hooks](#hooks)
- [Security](#security)
- [Errors](#errors)
- [Writing plugins](#writing-plugins)
- [Running alongside TypeScript Better Auth](#running-alongside-typescript-better-auth)
- [Differences from TypeScript](#differences-from-typescript)
- [Package layout](#package-layout)
- [Testing](#testing)

---

## Why

Better Auth is a full-featured, framework-agnostic auth library for TypeScript. This project
brings the same server to Go without changing anything for your frontend or your data:

- **Keep the JS client.** The official `better-auth/client` and its plugins
  (`twoFactorClient`, `organizationClient`, `passkeyClient`, ...) talk to the Go server
  unmodified.
- **Keep your database.** Same tables, columns, encodings and migrations. Point the Go server
  at an existing Better Auth database and existing users can sign in.
- **Migrate incrementally.** Run Go and TypeScript servers on the same database during a
  migration; a session created by one is valid on the other.
- **Idiomatic Go.** A plain `http.Handler`, standard middleware, `context.Context`
  everywhere, typed configuration, `database/sql` and the official MongoDB driver.

## Compatibility guarantees

| Area | What is identical to TypeScript Better Auth v1.7.7 |
|---|---|
| HTTP | Routes under `/api/auth`, methods, request validation (zod error wording), JSON response shapes and key order, status codes, `{ message, code }` error bodies, redirects |
| Cookies | Names (`better-auth.session_token`, `__Secure-` prefix), signed values (`value.HMAC`), attributes, chunking, the session cookie cache (`compact`, `jwt`, `jwe`) |
| Crypto | scrypt password hashes, XChaCha20-Poly1305 `$ba$` envelopes, purpose-derived keys, JWE/JWT formats, secret rotation; values produced by one implementation verify in the other |
| Database | Table and column names (camelCase), column types (migration DDL is byte-identical to Kysely's), stored encodings (dates, booleans, JSON, arrays), `modelName` / `fields` / `additionalFields` |
| OAuth | Authorization URLs (parameter order included), state, PKCE, id-token sign-in, account linking rules, all 36 social providers |
| Plugins | Endpoints, schema, error codes and stored data of 25 plugins and the 5 enterprise packages (SSO, SCIM, OAuth provider, MCP, CIMD) |

How this is verified: the upstream `*.test.ts` files are ported to Go, and an e2e suite drives
the official JS client against the Go server **and** the real `better-auth@1.7.7` server,
then diffs normalised responses, status codes and `Set-Cookie` headers. Separate tests run
both servers on one SQLite, PostgreSQL, MySQL or MongoDB database. See
[COMPATIBILITY.md](COMPATIBILITY.md) for the feature-by-feature matrix and every known
difference.

## Status

| Phase | Scope | Status |
|---|---|---|
| 1 | Core: email/password, sessions, cookies and cookie cache, CSRF/origin checks, rate limiting, secondary storage, hooks | ✅ |
| 2 | Social OAuth: sign-in, callback (GET + form_post), linking, id-token sign-in, 36 providers | ✅ |
| 3 | PostgreSQL, MySQL, SQLite and MongoDB adapters, migrations, conformance suite, CLI | ✅ |
| 4 | 25 plugins (two-factor, passkey, organization, admin, api-key, jwt, ...) | ✅ |
| 5 | Enterprise: SSO (OIDC/SAML), SCIM, OAuth/OIDC provider, MCP | ✅ |

## Install

```sh
go get github.com/nimi-io/better-auth-go
```

Requires **Go 1.25** or newer. Database drivers are your choice; the examples use
`github.com/jackc/pgx/v5`, `github.com/go-sql-driver/mysql`, `modernc.org/sqlite` (pure Go)
and `go.mongodb.org/mongo-driver/v2`.

Generate a secret (at least 32 random characters):

```sh
go run github.com/nimi-io/better-auth-go/cmd/better-auth@latest secret
# BETTER_AUTH_SECRET=8f6c...
```

## Quickstart

### Server

```go
package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"

	_ "modernc.org/sqlite"

	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
	"github.com/nimi-io/better-auth-go/betterauth"
)

func main() {
	db, err := sql.Open("sqlite", "file:app.db?_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatal(err)
	}

	auth := betterauth.MustNew(betterauth.Config{
		BaseURL:  "http://localhost:3000",
		Secret:   os.Getenv("BETTER_AUTH_SECRET"),
		Database: sqladapter.New(db, sqladapter.Config{}),
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{
			Enabled: true,
		},
		TrustedOrigins: []string{"http://localhost:5173"}, // your frontend
	})

	// Create the user, session, account and verification tables.
	if err := auth.RunMigrations(context.Background()); err != nil {
		log.Fatal(err)
	}

	app := http.NewServeMux()
	app.Handle("/api/me", auth.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := betterauth.SessionFromContext(r.Context())
		w.Write([]byte("hello " + s.User.Name))
	})))

	// Mount serves /api/auth/* and passes every other request to app.
	log.Fatal(http.ListenAndServe(":3000", auth.Mount(app)))
}
```

`memory.New()` (`adapter/memory`) works too for prototypes and tests; it keeps everything in
process memory.

### Client

Use the official client exactly as you would with a TypeScript backend:

```ts
import { createAuthClient } from "better-auth/react";

export const authClient = createAuthClient({ baseURL: "http://localhost:3000" });

await authClient.signUp.email({ email: "ada@example.com", password: "correct horse", name: "Ada" });
await authClient.signIn.email({ email: "ada@example.com", password: "correct horse" });

function Profile() {
  const { data: session, isPending } = authClient.useSession();
  if (isPending) return null;
  return <p>{session ? `Signed in as ${session.user.email}` : "Signed out"}</p>;
}
```

### Try it with curl

```sh
curl -i -X POST localhost:3000/api/auth/sign-up/email \
  -H 'content-type: application/json' -H 'origin: http://localhost:3000' \
  -d '{"email":"ada@example.com","password":"correct horse","name":"Ada"}'

curl -i localhost:3000/api/auth/get-session -H 'cookie: better-auth.session_token=...'
```

## How it fits together

```
 browser ──► better-auth/client ──HTTP──► auth.Handler()  (/api/auth/*)
                                              │
                         ┌────────────────────┼────────────────────────┐
                         ▼                    ▼                        ▼
                  core endpoints        plugin endpoints         hooks & middleware
                (sign-in, session…)   (two-factor, org, …)    (origin check, rate limit)
                         │                    │
                         └──────► adapter.Adapter ◄──── auth.API (Go calls, no HTTP)
                                       │
                       memory │ PostgreSQL │ MySQL │ SQLite │ MongoDB
```

- `betterauth.New(Config)` builds an `*Auth`. It holds the router, the context
  (`auth.Context()`: adapter, internal adapter, cookies, secrets, logger) and the server API
  (`auth.API`).
- Every endpoint is an `*betterauth.Endpoint` with a key (`signUpEmail`), a path
  (`/sign-up/email`), validation schemas and a handler. Plugins add endpoints, schema, hooks,
  middleware, rate-limit rules and error codes.
- Adapters translate generic queries (`FindOne`, `FindMany`, `Update`, ...) for a database.
  The shared transform layer resolves renamed tables and columns, ids, defaults and joins,
  exactly like upstream's `createAdapterFactory`.

## Framework integration

`auth.Handler()` is a standard `http.Handler`; `auth.Middleware` and `auth.RequireSession`
are standard `func(http.Handler) http.Handler` middleware. Runnable examples live in
[`examples/`](examples).

| Framework | Mount the auth routes | Example |
|---|---|---|
| net/http | `http.ListenAndServe(addr, auth.Mount(app))` | [examples/nethttp](examples/nethttp/main.go) |
| chi | `r.Handle("/api/auth/*", auth.Handler())` | [examples/chi](examples/chi/main.go) |
| Gin | `r.Any("/api/auth/*path", gin.WrapH(auth.Handler()))` | [examples/gin](examples/gin/main.go) |
| Echo | `e.Any("/api/auth/*", echo.WrapHandler(auth.Handler()))` | [examples/echo](examples/echo/main.go) |
| Fiber | `app.All("/api/auth/*", adaptor.HTTPHandler(auth.Handler()))` | [examples/fiber](examples/fiber/main.go) |

```go
// chi: protect a route group
r := chi.NewRouter()
r.Handle("/api/auth/*", auth.Handler())
r.Group(func(r chi.Router) {
	r.Use(auth.RequireSession)
	r.Get("/api/dashboard", dashboard)
})

// Gin: read the session in a handler
r.GET("/api/me", gin.WrapH(auth.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	s := betterauth.SessionFromContext(r.Context())
	json.NewEncoder(w).Encode(s.User)
}))))
```

> `http.ServeMux` cleans paths and redirects requests such as `//ok` before they reach
> the handler. Better Auth answers those with 404, so use `auth.Mount` (or mount
> `auth.Handler()` without a mux in front) if you need byte-identical routing behaviour.

The handler is served at `BasePath` (default `/api/auth`). If your app sits behind a path
prefix or a proxy, set `BaseURL` to the public URL, or use `DynamicBaseURL` for multi-host
deployments.

## Sessions in your handlers

| Function | Behaviour |
|---|---|
| `auth.Middleware(next)` | Resolves the session (if any), stores it in the request context, and calls `next`. Refreshed cookies are written to the response. |
| `auth.RequireSession(next)` | Same, but answers `401 {"message":"Unauthorized","code":"UNAUTHORIZED"}` when there is no session. |
| `auth.ResolveSession(w, r)` | Resolves the session for one request (writing refreshed cookies to `w`). |
| `betterauth.SessionFromContext(ctx)` | Returns the `*SessionWithUser` stored by the middleware, or nil. |
| `auth.API.GetSession(ctx, headers)` | Resolves a session from request headers without HTTP (nil when signed out). |

```go
func dashboard(w http.ResponseWriter, r *http.Request) {
	s := betterauth.SessionFromContext(r.Context())
	fmt.Fprintf(w, "user %s, session expires %s", s.User.ID, s.Session.ExpiresAt)
}
```

Sessions behave exactly like upstream: they last `Session.ExpiresIn` (7 days by default),
are extended when older than `UpdateAge` (1 day), and can be cached in a signed cookie
(`Session.CookieCache`) to skip the database lookup on most requests.

## Server-side API

Every endpoint, including plugin endpoints, can be called from Go without HTTP (`auth.api`
upstream). Typed helpers exist for the common ones; everything else goes through
`auth.API.Call` with the endpoint key.

```go
// Sign up a user from a back-office tool.
res, err := auth.API.SignUpEmail(ctx, betterauth.SignUpEmailInput{
	Email: "ada@example.com", Password: "correct horse", Name: "Ada",
}, nil)
// res.Data is the JSON body; res.Headers carries Set-Cookie.

// Read the session of an incoming request.
session, err := auth.API.GetSession(ctx, r.Header)

// Any endpoint by key, with the caller's headers (cookies) for authenticated endpoints.
res, err = auth.API.Call(ctx, "changePassword", betterauth.CallInput{
	Headers: r.Header,
	Body:    map[string]any{"currentPassword": "old", "newPassword": "new-password"},
})

// Plugin endpoints work the same way.
res, err = auth.API.Call(ctx, "createOrganization", betterauth.CallInput{
	Headers: r.Header,
	Body:    map[string]any{"name": "Acme", "slug": "acme"},
})
```

Typed helpers: `GetSession`, `SignUpEmail`, `SignInEmail`, `SignOut`, `SetPassword`,
`ListSessions`, `RevokeSession`, `UpdateUser`, `ChangePassword`. Server-only endpoints (for
example `setPassword`, api-key `verifyApiKey`, two-factor `generateTOTP`) have no HTTP route
and are reachable only through `auth.API`.

## Email and password

```go
EmailAndPassword: &betterauth.EmailAndPasswordConfig{
	Enabled:                       true,
	RequireEmailVerification:      true, // block sign-in until the email is verified
	MinPasswordLength:             8,    // default 8
	MaxPasswordLength:             128,  // default 128
	AutoSignIn:                    betterauth.Bool(true),
	RevokeSessionsOnPasswordReset: true,
	SendResetPassword: func(ctx context.Context, d betterauth.EmailData, r *http.Request) error {
		return mailer.Send(d.User.Email, "Reset your password", d.URL)
	},
},
EmailVerification: &betterauth.EmailVerificationConfig{
	SendOnSignUp:                betterauth.Bool(true),
	AutoSignInAfterVerification: true,
	SendVerificationEmail: func(ctx context.Context, d betterauth.EmailData, r *http.Request) error {
		return mailer.Send(d.User.Email, "Verify your email", d.URL)
	},
},
User: &betterauth.UserConfig{
	ChangeEmail: &betterauth.ChangeEmailConfig{Enabled: true},
	DeleteUser:  &betterauth.DeleteUserConfig{Enabled: true},
},
```

`EmailData` carries `User`, the ready-to-send `URL` and the raw `Token`. Passwords are hashed
with scrypt (N=16384, r=16, p=1, 64-byte key, NFKC-normalised), the same format as
TypeScript, so existing hashes keep working. Supply `Password` (hash/verify functions) to use
your own algorithm.

Endpoints: `/sign-up/email`, `/sign-in/email`, `/sign-out`, `/get-session`,
`/request-password-reset`, `/reset-password`, `/reset-password/:token`, `/change-password`,
`/send-verification-email`, `/verify-email`, `/change-email`, `/update-user`,
`/update-session`, `/delete-user`, `/delete-user/callback`, `/list-sessions`,
`/revoke-session`, `/revoke-sessions`, `/revoke-other-sessions`, `/list-accounts`,
`/unlink-account`, `/link-social`, `/get-access-token`, `/refresh-token`, `/account-info`,
`/ok`, `/error`, plus the server-only `setPassword`.

## Configuration reference

Field names mirror the TypeScript options (`emailAndPassword` → `EmailAndPassword`). Durations
are `time.Duration`; options whose zero value means something use pointers
(`betterauth.Bool`, `betterauth.Duration`, `betterauth.Int`).

### Top level

| Field | Purpose |
|---|---|
| `AppName` | Display name (used e.g. as the TOTP issuer). |
| `BaseURL` / `DynamicBaseURL` | Public URL of the server, or allowed hosts for multi-host setups. Falls back to `BETTER_AUTH_URL`. |
| `BasePath` | Mount path of the auth routes (default `/api/auth`). |
| `Secret` / `Secrets` | Signing and encryption secret; `Secrets` (versioned) enables rotation. Falls back to `BETTER_AUTH_SECRET`, `AUTH_SECRET`, `BETTER_AUTH_SECRETS`. |
| `Database` | Adapter factory: `memory.New()`, `sqladapter.New(...)`, `mongodb.New(...)`. |
| `SecondaryStorage` | Key-value store (e.g. Redis) for sessions, rate limits and verification values. |
| `EmailAndPassword`, `EmailVerification` | See [Email and password](#email-and-password). |
| `SocialProviders` | OAuth providers from `providers/*`. |
| `Plugins` | Plugins from `plugins/*` or your own. |
| `User`, `Session`, `Account`, `Verification` | Model names, field renames, additional fields and behaviour per model. |
| `TrustedOrigins` / `TrustedOriginsFunc` | Origins allowed for CSRF/origin checks and callback URLs (wildcards like `https://*.example.com` supported). |
| `RateLimit` | Window, max requests, per-path rules, storage (`memory`, `database`, `secondary-storage`, custom). |
| `Advanced` | Cookies (prefix, attributes, cross-subdomain), secure-cookie override, IP address headers, id generation, CSRF/origin check switches. |
| `Hooks`, `DatabaseHooks` | Request hooks and per-model create/update/delete hooks. |
| `OnAPIError` | Error page URL, error callback, default error page customisation. |
| `DisabledPaths` | Endpoints to switch off (e.g. `/sign-up/email`). |
| `Logger` | Implement `betterauth.Logger`, or use `betterauth.NewLogger(level, nil)`. |

### Sessions

```go
Session: &betterauth.SessionConfig{
	ExpiresIn: 7 * 24 * time.Hour,
	UpdateAge: betterauth.Duration(24 * time.Hour), // refresh when older than this
	FreshAge:  betterauth.Duration(24 * time.Hour), // "fresh" sessions for sensitive actions
	CookieCache: &betterauth.CookieCacheConfig{
		Enabled:  true,
		Strategy: "compact", // "compact" (HMAC), "jwt" (HS256) or "jwe" (encrypted)
		MaxAge:   5 * time.Minute,
	},
	StoreSessionInDatabase: true, // with SecondaryStorage: keep a copy in the database
},
```

### Users, sessions and accounts: renames and additional fields

```go
User: &betterauth.UserConfig{
	ModelConfig: betterauth.ModelConfig{
		ModelName: "users",
		Fields:    map[string]string{"emailVerified": "email_verified"},
		AdditionalFields: []db.Field{
			{Name: "role", Type: db.TypeString, DefaultValue: "user", Input: db.False},
			{Name: "locale", Type: db.TypeString, Required: db.False},
		},
	},
},
```

`db.Field.Required` is tri-state like upstream's `required`: `nil` (unset) becomes a
`NOT NULL` column in migrations but stays optional in request validation; `db.True` /
`db.False` set it explicitly. `Input: db.False` hides a field from user input,
`Returned: db.False` hides it from API output.

### Accounts and linking

```go
Account: &betterauth.AccountConfig{
	EncryptOAuthTokens: true, // encrypt stored access/refresh tokens
	AccountLinking: &betterauth.AccountLinkingConfig{
		TrustedProviders:     []string{"google", "github"}, // link even if the email is unverified there
		AllowDifferentEmails: false,
		UpdateUserInfoOnLink: true,
	},
},
```

### Rate limiting

```go
RateLimit: &betterauth.RateLimitConfig{
	Enabled: betterauth.Bool(true), // on by default in production
	Window:  10 * time.Second,
	Max:     100,
	Storage: "secondary-storage", // "memory" (default), "database", "secondary-storage"
	CustomRules: map[string]betterauth.CustomRateLimitRule{
		"/sign-in/email": {Rule: &betterauth.RateLimitRule{Window: time.Minute, Max: 5}},
	},
},
```

Sensitive endpoints (sign-in, sign-up, password reset, OTP verification, ...) have stricter
built-in rules, and plugins register their own, exactly as upstream.

### Secondary storage

```go
type SecondaryStorage interface {
	Get(ctx context.Context, key string) (string, bool, error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	GetAndDelete(ctx context.Context, key string) (string, bool, error)
	Increment(ctx context.Context, key string, ttl time.Duration) (int64, error)
}
```

Implement it over Redis, Valkey, Memcached or anything else. `betterauth.NewMemoryStorage()`
is an in-process implementation for tests. Keys and values use the same format as
TypeScript, so both can share one Redis.

## Databases

The Go server uses the same tables, columns and stored encodings as TypeScript Better Auth.

### PostgreSQL, MySQL, SQLite

```go
import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
)

db, _ := sql.Open("pgx", "postgres://user:pass@localhost:5432/app")
// db, _ := sql.Open("mysql", "user:pass@tcp(localhost:3306)/app?parseTime=true")
// db, _ := sql.Open("sqlite", "file:app.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")

auth := betterauth.MustNew(betterauth.Config{
	Database: sqladapter.New(db, sqladapter.Config{
		// Dialect is detected from the driver; set it for wrapped or unusual drivers.
		Dialect:    sqladapter.Postgres,
		SchemaName: "auth", // PostgreSQL only: tables live in this schema
		DebugLogs:  false,
	}),
})
```

`sqladapter` is a port of upstream's Kysely adapter on top of `database/sql`: native joins,
transactions, atomic `consumeOne` / `incrementOne`, serial and UUID ids, case-insensitive
queries, plural table names.

Notes:

- **MySQL** needs `parseTime=true`. Dates are stored as UTC `timestamp(3)`; a TypeScript
  server sharing the database must use mysql2 with `timezone: "Z"`.
- **pgx** caches prepared statements. Statements prepared before a migration that adds
  columns are re-prepared automatically; add `default_query_exec_mode=exec` to the
  connection string to disable the cache entirely.
- **SQLite**: `modernc.org/sqlite` is pure Go (no cgo). Enable foreign keys in the DSN.

### MongoDB

```go
import (
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/nimi-io/better-auth-go/adapter/mongodb"
)

client, _ := mongo.Connect(options.Client().ApplyURI("mongodb://localhost:27017"))
auth := betterauth.MustNew(betterauth.Config{
	// Passing Client enables transactions (requires a replica set).
	Database: mongodb.New(client.Database("app"), mongodb.Config{Client: client}),
})
```

Documents match the TypeScript Mongo adapter exactly: `_id` as ObjectId (or UUID binary
with `generateId: "uuid"`), references stored as ObjectId, BSON dates, the same key order.
MongoDB needs no migrations; indexes declared by plugins are created on first write.

### In memory

```go
store := memory.NewDB()
auth := betterauth.MustNew(betterauth.Config{Database: memory.New(store)})
```

### Custom adapters

Implement `adapter.CustomAdapter` (create, find, count, update, delete with physical names)
and wrap it with `adapter.NewFactory`, which provides the full transform layer. Optional
interfaces add native transactions, atomic operations and migrations. Run the shared
conformance suite against your adapter:

```go
func TestConformance(t *testing.T) {
	adaptertest.Run(t, adaptertest.Harness{
		Name:    "my-adapter",
		Factory: func(t testing.TB, cfg *betterauth.Config) adapter.Factory { return myadapter.New(conn) },
		Migrate: func(ctx context.Context, auth *betterauth.Auth) error { resetDB(); return auth.RunMigrations(ctx) },
	})
}
```

The suite (`adapter/adaptertest`) is a port of upstream's adapter test suites: about 450
cases covering CRUD, operators, joins, transactions, numeric and UUID ids, case-insensitive
queries and an end-to-end auth flow.

## Migrations and the CLI

### From your code

```go
plan, err := auth.PlanMigrations(ctx) // compare the schema with the database
fmt.Println(plan.SQL())               // the exact SQL TypeScript's migrator would print
err = plan.Run(ctx)                   // or auth.RunMigrations(ctx)
```

The plan lists tables to create (`ToBeCreated`), columns to add (`ToBeAdded`) and indexes,
and refuses unsafe changes (e.g. adding a required column to a table with rows) the same way
upstream does. The schema includes your plugins and additional fields.

### `better-auth` CLI

```sh
go install github.com/nimi-io/better-auth-go/cmd/better-auth@latest

better-auth secret                                    # print a new BETTER_AUTH_SECRET
better-auth migrate  --database-url "$DATABASE_URL"   # create missing tables/columns (asks first; -y to skip)
better-auth generate --database-url "$DATABASE_URL"   # write SQL to better-auth_migrations/<timestamp>.sql
better-auth info --json                               # system, Go, module and config info (secrets redacted)
```

`--database-url` (or `DATABASE_URL`, also read from `.env`) accepts `postgres://...`,
`mysql://user:pass@host:3306/db` and `sqlite:path/to/app.db`.

The standalone binary only knows the default schema. When you use plugins, additional fields
or renamed models, embed the CLI in your own binary so it sees your configuration:

```go
// cmd/auth/main.go
package main

import (
	"context"
	"os"

	"github.com/nimi-io/better-auth-go/cli"
	"example.com/myapp/internal/authsetup"
)

func main() {
	os.Exit(cli.Run(context.Background(), os.Args[1:], cli.Options{Auth: authsetup.New()}))
}
```

```sh
go run ./cmd/auth migrate -y
```

## Social sign-in

All 36 upstream providers are available, one package each under `providers/`:

apple, atlassian, cloudflare, cognito, discord, dropbox, facebook, figma, github, gitlab,
google, huggingface, kakao, kick, line, linear, linkedin, microsoft (Entra ID), naver, notion,
paybin, paypal, polar, railway, reddit, roblox, salesforce, slack, spotify, tiktok, twitch,
twitter (X), vercel, vk, wechat, zoom.

```go
import (
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/providers/github"
	"github.com/nimi-io/better-auth-go/providers/google"
	"github.com/nimi-io/better-auth-go/providers/microsoft"
)

SocialProviders: []oauth2.Provider{
	github.New(github.Options{ProviderOptions: oauth2.ProviderOptions{
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
	}}),
	google.New(google.Options{
		ProviderOptions: oauth2.ProviderOptions{ClientID: "...", ClientSecret: "..."},
		AccessType:      "offline", // get a refresh token
		HD:              "example.com",
	}),
	microsoft.New(microsoft.Options{
		ProviderOptions: oauth2.ProviderOptions{ClientID: "...", ClientSecret: "..."},
		TenantID:        "common",
	}),
},
```

Register `<baseURL>/api/auth/callback/<provider-id>` as the redirect URI with each provider.
`oauth2.ProviderOptions` mirrors upstream's shared provider options: `Scope`,
`DisableDefaultScope`, `RedirectURI`, `Prompt`, `MapProfileToUser`, `GetUserInfo`,
`DisableSignUp`, `DisableImplicitSignUp`, `OverrideUserInfoOnSignIn`, `VerifyIDToken`, ...

On the client:

```ts
await authClient.signIn.social({ provider: "github", callbackURL: "/dashboard" });
await authClient.signIn.social({ provider: "google", idToken: { token: googleIdToken } }); // id-token sign-in
await authClient.linkSocial({ provider: "google" });
const { data } = await authClient.getAccessToken({ providerId: "github" });
```

Any OAuth 2.0 / OpenID Connect server can be added with the
[generic-oauth plugin](#generic-oauth--oidc) (discovery, PKCE, custom endpoints), and fully
custom providers implement `oauth2.Provider` or are built with
`oauth2.NewProvider(oauth2.Spec{...})`.

## Plugins

Plugins live in `plugins/<name>` and mirror their TypeScript counterparts, including
endpoints, schema, error codes and stored data. The matching client plugins from
`better-auth/client/plugins` work unchanged. Run migrations after adding a plugin that has
schema.

| Plugin | Package | What it adds |
|---|---|---|
| two-factor | `plugins/twofactor` | TOTP, email/SMS OTP, backup codes, trusted devices, sign-in challenge |
| passkey | `plugins/passkey` | WebAuthn registration and sign-in (go-webauthn), passkey management |
| organization | `plugins/organization` | Organizations, members, invitations, teams, roles, dynamic access control |
| admin | `plugins/admin` | User management, roles, bans, impersonation, session control |
| access | `plugins/access` | Role-based access control primitives used by admin and organization |
| api-key | `plugins/apikey` | API keys with hashing, prefixes, expiry, refill, rate limits, permissions, sessions from keys |
| jwt | `plugins/jwt` | JWKS endpoint, JWT issuance, key rotation, JWT-signed cookie cache |
| bearer | `plugins/bearer` | `Authorization: Bearer` session tokens |
| magic-link | `plugins/magiclink` | Passwordless sign-in links |
| email-otp | `plugins/emailotp` | One-time codes for sign-in, verification, password reset, email change |
| one-time-token | `plugins/onetimetoken` | Single-use tokens to hand a session to another app |
| username | `plugins/username` | Username sign-in, normalisation and validation |
| phone-number | `plugins/phonenumber` | Phone OTP sign-in, verification and password reset |
| anonymous | `plugins/anonymous` | Guest users that can be linked to real accounts later |
| multi-session | `plugins/multisession` | Several signed-in accounts per browser |
| custom-session | `plugins/customsession` | Transform the `/get-session` response |
| last-login-method | `plugins/lastloginmethod` | Remember how a user last signed in |
| generic-oauth | `plugins/genericoauth` | Any OAuth 2.0 / OIDC provider (discovery, presets for Auth0, Okta, Keycloak, Entra ID, ...) |
| oauth-proxy | `plugins/oauthproxy` | OAuth for preview deployments through a production callback |
| oauth-popup | `plugins/oauthpopup` | Popup-window OAuth flow |
| one-tap | `plugins/onetap` | Google One Tap |
| siwe | `plugins/siwe` | Sign-In with Ethereum (EIP-4361) |
| device-authorization | `plugins/deviceauthorization` | OAuth 2.0 Device Authorization Grant (RFC 8628) |
| captcha | `plugins/captcha` | Cloudflare Turnstile, reCAPTCHA, hCaptcha, CaptchaFox, Vercel BotID |
| haveibeenpwned | `plugins/haveibeenpwned` | Reject passwords found in breaches |
| open-api | `plugins/openapi` | OpenAPI 3.1 document of all endpoints and a Scalar reference page |
| sso | `plugins/sso` | Enterprise SSO over OIDC and SAML 2.0, domain verification, organization assignment |
| scim | `plugins/scim` | SCIM 2.0 user and group provisioning from identity providers |
| oauth-provider | `plugins/oauthprovider` | Make your app an OAuth 2.1 / OpenID Connect provider |
| mcp | `plugins/mcp` | Auth for MCP servers: protected-resource metadata and token checks |
| cimd | `plugins/cimd` | Client ID Metadata Documents (clients identified by a URL) |

### Two-factor authentication

```go
twofactor.New(twofactor.Options{
	Issuer: "My App",
	OTPOptions: &twofactor.OTPOptions{
		SendOTP: func(ctx context.Context, d twofactor.OTPData, ec *betterauth.EndpointContext) error {
			return mailer.Send(d.User.Email, "Your sign-in code", d.OTP)
		},
	},
})
```

```ts
import { twoFactorClient } from "better-auth/client/plugins";
const authClient = createAuthClient({
  plugins: [twoFactorClient({ onTwoFactorRedirect: () => (location.href = "/2fa") })],
});
const { data } = await authClient.twoFactor.enable({ password }); // data.totpURI → QR code
await authClient.twoFactor.verifyTotp({ code, trustDevice: true });
```

### Organizations, teams and roles

```go
organization.New(organization.Options{
	Teams:           &organization.TeamsOptions{Enabled: true},
	InvitationLimit: betterauth.Int(100),
	SendInvitationEmail: func(ctx *betterauth.EndpointContext, d organization.InvitationEmailData, r *http.Request) error {
		return mailer.Send(d.Email, "You're invited", "https://app.example.com/invite/"+d.ID)
	},
})
```

Custom roles use the access-control package:

```go
ac := access.New(access.Statements{
	"project": {"create", "update", "delete"},
})
owner := ac.NewRole(access.Statements{"project": {"create", "update", "delete"}})
member := ac.NewRole(access.Statements{"project": {"create"}})
```

### Admin

```go
admin.New(admin.Options{
	AdminUserIDs:        []string{"user_123"},
	DefaultBanExpiresIn: 7 * 24 * time.Hour,
})
```

Endpoints include `/admin/list-users` (search, filter, sort, paginate), `/admin/create-user`,
`/admin/set-role`, `/admin/ban-user`, `/admin/impersonate-user`, `/admin/revoke-user-sessions`
and `/admin/has-permission`.

### Passkeys

```go
passkey.New(passkey.Options{
	RPID:   "example.com",
	RPName: "My App",
	Origin: []string{"https://app.example.com"},
})
```

### Passwordless: magic links and email OTP

```go
magiclink.New(magiclink.Options{
	SendMagicLink: func(ctx *betterauth.EndpointContext, d magiclink.SendMagicLinkData) error {
		return mailer.Send(d.Email, "Sign in", d.URL)
	},
}),
emailotp.New(emailotp.Options{
	SendVerificationOTP: func(ctx *betterauth.EndpointContext, d emailotp.SendVerificationOTPData) error {
		return mailer.Send(d.Email, "Your code", d.OTP) // d.Type: sign-in, email-verification, forget-password, ...
	},
}),
```

### API keys

```go
apikey.New(apikey.Options{Configuration: apikey.Configuration{
	DefaultPrefix:           "sk_",
	EnableSessionForAPIKeys: true, // an x-api-key header acts as a session
}})
```

Keys are hashed exactly like TypeScript, so keys issued by either implementation verify on
both.

### JWT, JWKS and bearer tokens

```go
jwt.New(jwt.Options{JWT: &jwt.JWTOptions{Issuer: "https://api.example.com", Audience: "my-app"}}),
bearer.New(),
```

`GET /api/auth/jwks` serves the public keys (EdDSA by default; ES*, RS*, PS* supported) and
`GET /api/auth/token` issues a JWT for the current session. Private keys are encrypted at rest
in the same format as TypeScript.

### Generic OAuth / OIDC

```go
genericoauth.New(genericoauth.Options{Config: []genericoauth.Config{{
	ProviderID:   "keycloak",
	DiscoveryURL: "https://sso.example.com/realms/main/.well-known/openid-configuration",
	ClientID:     "app",
	ClientSecret: os.Getenv("KEYCLOAK_SECRET"),
	Scopes:       []string{"openid", "email", "profile"},
	PKCE:         betterauth.Bool(true),
}}})
```

Generic providers behave exactly like built-in social providers: `signIn.social({ provider:
"keycloak" })`, `/callback/keycloak`, account linking, token refresh. Presets are included for
Auth0, Okta, Keycloak, Microsoft Entra ID, Slack, LINE, Gumroad, Patreon, HubSpot and Yandex.

### OpenAPI

```go
openapi.New(openapi.Options{})
```

`GET /api/auth/open-api/generate-schema` returns an OpenAPI 3.1 document of every enabled
endpoint (identical to the TypeScript output for the same configuration), and
`/api/auth/reference` serves a Scalar API reference page.

## Enterprise

### Single sign-on (OIDC and SAML 2.0)

```go
sso.New(sso.Options{
	ProvisionUserOnEveryLogin: true, // re-run provisioning hooks on every SSO sign-in
	TrustEmailVerified:        true, // trust the IdP's email_verified claim
})
```

Organisations register their identity provider at runtime (`POST /sso/register` with an
OIDC issuer or SAML metadata); users then sign in with `authClient.signIn.sso({ email })`
or by provider id. The service-provider metadata is served at
`/api/auth/sso/saml2/sp/metadata`. SAML responses go through the same checks as upstream:
XML signature verification (goxmldsig, exclusive c14n), signature-wrapping and duplicate-ID
rejection, issuer, audience, recipient and destination binding, single-use InResponseTo,
assertion replay protection, clock-skew windows, size limits and algorithm policy.
Domain verification (`/sso/request-domain-verification`, `/sso/verify-domain`) proves
ownership with a DNS TXT record and can assign users to organizations by email domain.

### SCIM provisioning

```go
scim.New(scim.Options{
	Connections: []scim.ConnectionOptions{{
		ID:          "okta",
		Credentials: []scim.BearerCredential{{Type: "bearer", ID: "okta-1", Token: os.Getenv("SCIM_TOKEN")}},
	}},
})
```

Identity providers such as Okta and Entra ID create, update and deactivate users and groups
through `/api/auth/scim/v2/Users` and `/api/auth/scim/v2/Groups` (full PATCH and filter
support, `ServiceProviderConfig`, `Schemas` and `ResourceTypes` discovery, RFC 7644
errors). Managed connections with rotating tokens are available through the server API.

### OAuth 2.1 / OpenID Connect provider

```go
oauthprovider.New(oauthprovider.Options{
	LoginPage:   "/sign-in",
	ConsentPage: "/consent",
	Scopes:      []string{"openid", "profile", "email", "offline_access"},
})
```

Your app becomes an authorization server for other applications: discovery
(`/.well-known/openid-configuration`), authorization with PKCE and consent, the token
endpoint (authorization code, refresh token with reuse detection, client credentials,
device code), introspection, revocation, userinfo, end-session and back-channel logout,
dynamic client registration, client and consent management, DPoP, `private_key_jwt`,
pairwise subjects and RFC 8707 resource indicators. Tokens and clients are stored in the
same format as TypeScript, so either implementation can serve the same clients.

### MCP servers

```go
plugin := mcp.MustNew(mcp.Options{
	Options:  oauthprovider.Options{LoginPage: "/sign-in", ConsentPage: "/consent"},
	Resource: "https://mcp.example.com/mcp",
})
```

`mcp` configures the OAuth provider for the Model Context Protocol and serves the protected
resource metadata (`/.well-known/oauth-protected-resource`). Protect your MCP endpoint with
`mcp.RequireMcpAuth` or the net/http `mcp.Middleware`; unauthenticated requests receive the
`WWW-Authenticate` challenge MCP clients expect. Add `cimd` to let clients identify
themselves with a Client ID Metadata Document URL instead of registering first.

## Hooks

### Request hooks

Run code before or after every endpoint, like upstream's `hooks.before` / `hooks.after`:

```go
Hooks: &betterauth.HooksConfig{
	Before: func(ctx *betterauth.EndpointContext) (any, error) {
		if ctx.Path == "/sign-up/email" && !strings.HasSuffix(ctx.BodyString("email"), "@example.com") {
			return nil, betterauth.ErrMessage("BAD_REQUEST", "Only example.com addresses may sign up")
		}
		return nil, nil // continue
	},
	After: func(ctx *betterauth.EndpointContext) (any, error) {
		if ctx.Path == "/sign-in/email" {
			audit.Log("sign-in", ctx.Request)
		}
		return nil, nil
	},
},
```

Returning a value from a before hook short-circuits the endpoint; returning an error turns it
into an API error response.

### Database hooks

```go
DatabaseHooks: &betterauth.DatabaseHooks{
	User: betterauth.DBModelHooks{
		Create: betterauth.DBOperationHooks{
			Before: func(ctx context.Context, user adapter.Record) (*betterauth.DBHookResult, error) {
				return nil, nil // return data to merge, or an error to abort
			},
			After: func(ctx context.Context, user adapter.Record) error {
				return crm.CreateContact(user["email"].(string))
			},
		},
	},
},
```

Hooks exist for `User`, `Session`, `Account` and `Verification` × `Create`, `Update`,
`Delete`. After-hooks of operations inside a transaction run once it commits.

## Security

- **Origin and CSRF checks.** State-changing requests must come from `BaseURL` or a
  `TrustedOrigins` entry; callback and redirect URLs are validated the same way. Wildcards
  follow upstream's rules (`*` stays within one path segment, `**` crosses segments).
- **Cookies** are `HttpOnly`, `SameSite=Lax`, and `Secure` with the `__Secure-` prefix on
  HTTPS. Customise them under `Advanced.Cookies`, `Advanced.DefaultCookieAttributes`,
  `Advanced.CrossSubDomainCookies` and `Advanced.CookiePrefix`.
- **Rate limiting** is on by default in production, with stricter built-in rules for
  sensitive endpoints.
- **Secret rotation.** List versioned secrets in `Secrets`. New values are signed and
  encrypted with the current secret; older ones still verify and decrypt.
- **IP addresses** come from `Advanced.IPAddress` (e.g. `x-forwarded-for` behind trusted
  proxies); IPv6 addresses are grouped by subnet for rate limiting.
- **Enumeration protection.** Sign-up with an existing email and password-reset requests
  respond the same way whether or not the account exists, as upstream does.

## Errors

API errors are returned as `{ "message": "...", "code": "..." }` with the same status codes
and codes as TypeScript (`INVALID_EMAIL_OR_PASSWORD`, `USER_ALREADY_EXISTS`,
`SESSION_EXPIRED`, plugin codes like `INVALID_TWO_FACTOR_CODE`, ...). From Go:

```go
_, err := auth.API.SignInEmail(ctx, email, password, nil, nil)
var apiErr *betterauth.APIError
if errors.As(err, &apiErr) {
	log.Println(apiErr.StatusCode, apiErr.Code(), apiErr.Message())
}
```

Inside endpoints and hooks, create errors with `betterauth.ErrFrom(status, code)` or
`betterauth.ErrMessage(status, message)`. Browser-facing failures (for example an OAuth
callback error) redirect to `/api/auth/error`, or to `OnAPIError.ErrorURL` when set.

## Writing plugins

A plugin is a `*betterauth.Plugin` with an ID and any of: endpoints, schema, hooks, middleware,
rate-limit rules, error codes, an `Init` function, `OnRequest` / `OnResponse` handlers.

```go
func helloPlugin() *betterauth.Plugin {
	return &betterauth.Plugin{
		ID: "hello",
		Endpoints: []*betterauth.Endpoint{{
			Key:     "sayHello",
			Path:    "/hello",
			Methods: []string{"POST"},
			Use:     []betterauth.Middleware{betterauth.SessionMiddleware},
			Handler: func(ctx *betterauth.EndpointContext) (any, error) {
				greeting := ctx.BodyString("greeting")
				if greeting == "" {
					greeting = "hello"
				}
				return jsonx.O("message", greeting+", "+ctx.Session.User.Name), nil
			},
		}},
		Schema: []db.PluginTable{{
			Key:    "user",
			Fields: []db.Field{{Name: "nickname", Type: db.TypeString, Required: db.False}},
		}},
	}
}
```

- Validate bodies and queries with the `validate` package (`Endpoint.Body`,
  `Endpoint.Query`). It reproduces zod's validation and error wording, so validation errors
  look the same as in TypeScript (`[body.email] Invalid email address`).
- `jsonx` writes JSON with JavaScript semantics (ordered keys, JS number formatting); use
  `jsonx.O(k, v, ...)` for responses whose key order matters.
- `ctx.Auth` gives access to the adapter, the internal adapter (users, sessions, accounts,
  verification values), cookies, secrets and the logger.
- Set `Metadata["openapi"]` on endpoints to document them in the open-api plugin.

The built-in plugins under `plugins/` are complete, tested examples of every feature.

## Running alongside TypeScript Better Auth

Because responses, cookies, crypto and storage are identical, you can:

1. **Replace the backend only.** Keep your frontend and its `better-auth` client; point it at
   the Go server.
2. **Share a database.** Run the Go server on the database a TypeScript app already uses.
   Existing passwords, sessions, OAuth accounts, 2FA secrets, passkeys and API keys keep
   working. Use the same `BETTER_AUTH_SECRET` on both so signed cookies and encrypted values
   are interchangeable.
3. **Migrate gradually.** Run both servers on the same database and move routes over one at a
   time; a user signed in through one is signed in on the other.

Checklist for sharing: same secret(s), same `BasePath` and cookie prefix, same plugin set and
options, mysql2 with `timezone: "Z"` on the TypeScript side for MySQL, and run migrations from
one side (both produce the same schema).

## Differences from TypeScript

The goal is behavioural identity; the differences are deliberate and documented in
[COMPATIBILITY.md](COMPATIBILITY.md). The main ones:

- **Go-shaped options.** Durations are `time.Duration`, callbacks take `context.Context` or
  `*betterauth.EndpointContext`, and options that accept "value or function" upstream have a
  separate `...Func` field.
- **JSON key order in stored objects.** JSON objects taken from request bodies (organization
  metadata, role permissions, API key metadata) are stored with sorted keys instead of
  insertion order. The values are identical.
- **Search wildcards.** `contains` / `starts_with` / `ends_with` queries in the SQL adapter
  treat `%` and `_` literally (Kysely passes them through as wildcards).
- **Zoom provider.** `disableSignUp` and related options are honoured for Zoom; upstream
  ignores them for that provider.
- **Not ported (JS-specific):** the Kysely/Prisma/Drizzle adapters (replaced by
  `sqladapter`), Prisma/Drizzle schema generators, client-side type inference helpers, and the
  `init` / `ai` / `login` / `mcp` / `upgrade` CLI commands.

## Package layout

| Package | Purpose |
|---|---|
| `betterauth` | `Config`, `New`, HTTP handler, endpoints, cookies, sessions, hooks, middleware, server API |
| `adapter` | Generic adapter interface and transform layer (`createAdapterFactory`), migration contract |
| `adapter/memory` | In-memory adapter |
| `adapter/sqladapter` | PostgreSQL / MySQL / SQLite adapter on `database/sql` (Kysely adapter port) |
| `adapter/sqladapter/migration` | Schema introspection and migrations (`getMigrations` port) |
| `adapter/sqladapter/dialect` | SQL dialect detection and quoting |
| `adapter/mongodb` | MongoDB adapter |
| `adapter/adaptertest` | Shared adapter conformance suite |
| `db` | Schema definitions: core tables, plugin tables, field options |
| `crypto` | scrypt passwords, XChaCha20-Poly1305, JWT/JWE, HMAC, random ids |
| `jose` | JWK, JWS and JWT signing and verification (RS, PS, ES, EdDSA, HS) |
| `jsonx` | JavaScript-compatible ordered JSON |
| `validate` | zod-compatible validation with identical error messages, schema introspection |
| `oauth2` | OAuth provider interface, provider framework, token, JWKS and id-token helpers |
| `oauth2/oauth2test` | Mock IdP transport for tests |
| `providers/*` | 36 social providers |
| `plugins/*` | 25 plugins, the enterprise packages (sso, scim, oauthprovider, mcp, cimd) and the `access` control package |
| `cli`, `cmd/better-auth` | CLI: `migrate`, `generate`, `secret`, `info` |
| `examples/*` | Runnable integrations for net/http, chi, Gin, Echo and Fiber |
| `e2e` | Cross-implementation test suite against the real `better-auth@1.7.7` server |

## Testing

```sh
docker compose up -d   # PostgreSQL :5433, MySQL :3307, MongoDB :27018 for the database tests
go test ./...          # unit tests, ports of the upstream test suites, adapter conformance

cd e2e && npm install && npm test   # Go server vs the real better-auth@1.7.7 server
```

- **Unit tests** include the upstream `*.test.ts` files ported to Go (core, OAuth, adapters,
  migrations, every plugin): over 6,000 test cases. Database tests create and drop their own
  databases; they skip when a server is unreachable, and `BA_TEST_REQUIRE_DBS=1` turns those
  skips into failures (for CI).
- **The e2e suite** starts the Go server and the reference TypeScript server with the same
  configuration, drives both with the official client (and client plugins), and asserts that
  normalised response bodies, status codes, `Location` and `Set-Cookie` headers are
  identical. It also checks cross-compatibility: cookies, cookie caches, password hashes,
  JWTs, TOTP secrets, passkeys and API keys created by one implementation are accepted by the
  other, and both servers share SQLite, PostgreSQL, MySQL and MongoDB databases.
- **Fixtures** generated by the real TypeScript code (`e2e/scripts/gen-*.mjs`) pin
  byte-level formats: crypto, migration SQL, JWKS, two-factor and passkey data.

Environment overrides for the database tests: `BA_TEST_POSTGRES_URL`, `BA_TEST_MYSQL_DSN`,
`BA_TEST_MONGO_URI` (the users must be allowed to create databases).
