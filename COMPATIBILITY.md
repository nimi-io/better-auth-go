# Compatibility matrix — better-auth-go vs Better Auth v1.7.7

This file tracks every upstream feature (endpoint, plugin, provider, adapter, CLI command and
option) and its status in the Go port. Upstream reference: `better-auth/better-auth@v1.7.7`.

**Legend**

| Mark | Meaning |
|---|---|
| ⬜ | Not started |
| 🟡 | Implemented, Go unit tests only |
| ✅ | Implemented, covered by Go tests **and** the e2e suite (official JS client against the Go server) |
| ➖ | Not applicable to Go (reason given) |

## Phases

| Phase | Scope | Status |
|---|---|---|
| 1 | Core endpoints, cookies, sessions, cookie cache, CSRF/origin checks, rate limiter, secondary storage, hooks | ✅ |
| 2 | Social OAuth (sign-in/social, callback, state, PKCE, id-token sign-in, ~36 providers) | ✅ |
| 3 | Adapters (Postgres, MySQL, SQLite, MongoDB), conformance suite, migrations, CLI | ✅ |
| 4 | Plugins | ✅ |
| 5 | Enterprise (SSO, SCIM, OAuth provider, MCP) | ⬜ |

## Wire-level compatibility

| Item | Upstream source | Status |
|---|---|---|
| Error body `{ message, code }`, status codes, `VALIDATION_ERROR` messages (zod v4 wording) | `better-call` `error.mjs`, `validator.mjs` | ✅ |
| Routing: base path, trailing-slash 404, `skipTrailingSlashes`, `disabledPaths`, 404 for unknown method | `better-call` `router.mjs` | ✅ |
| Body parsing: JSON / form-urlencoded / `allowedMediaTypes` → 415, invalid JSON → 400 | `better-call` `utils.mjs` | ✅ |
| Signed cookies (`value.base64(HMAC-SHA256)`, URL-encoded, 44-char check) | `better-call` `crypto.mjs`, `context.mjs` | ✅ |
| Cookie names/prefix/`__Secure-`, attributes, `crossSubDomainCookies`, per-cookie overrides | `cookies/index.ts` | ✅ |
| Cookie chunking (`name.0`, `name.1`, …) for `session_data` / `account_data` | `cookies/session-store.ts` | ✅ |
| Cookie cache `compact` (HMAC, JS key order, JS `JSON.stringify` semantics) | `cookies/index.ts` | ✅ |
| Cookie cache `jwt` (HS256) | `crypto/jwt.ts` | ✅ |
| Cookie cache `jwe` (dir + A256CBC-HS512, HKDF key, JWK-thumbprint kid, secret rotation) | `crypto/jwt.ts` | ✅ |
| `account_data` cookie (JWE, salt `better-auth-account`) | `cookies/session-store.ts` | 🟡 |
| Password hashing (scrypt N=16384 r=16 p=1 dkLen=64, NFKC, hex salt) | `@better-auth/utils/password` | ✅ |
| Symmetric encryption (XChaCha20-Poly1305, `$ba$<v>$` envelope, purpose keys) | `crypto/index.ts`, `crypto/purpose.ts` | 🟡 |
| Email verification JWT (HS256, `email`/`updateTo`/`requestType`) | `api/routes/email-verification.ts` | ✅ |
| Random strings / ids (alphabets, rejection sampling) | `@better-auth/utils/random`, `core/utils/id.ts` | ✅ |
| Secret rotation (`secrets`, `BETTER_AUTH_SECRETS`) | `context/secret-utils.ts` | 🟡 |
| Database schema: default table/column names, `modelName`/`fields` renames, `additionalFields` | `core/db/get-tables.ts` | ✅ |

## Core options (`BetterAuthOptions`)

| Option | Status | Notes |
|---|---|---|
| `appName`, `baseURL` (static + dynamic `allowedHosts`), `basePath` | ✅ | |
| `secret`, `secrets`, env `BETTER_AUTH_SECRET`/`AUTH_SECRET`/`BETTER_AUTH_SECRETS`/`BETTER_AUTH_URL` | 🟡 | |
| `database` | ✅ | Go: `adapter.Factory` |
| `secondaryStorage` (`get`, `set`, `delete`, `getAndDelete`, `increment`) | ✅ | |
| `emailVerification.*` (`sendVerificationEmail`, `sendOnSignUp`, `sendOnSignIn`, `autoSignInAfterVerification`, `expiresIn`, `before/afterEmailVerification`) | ✅ | |
| `emailAndPassword.*` (`enabled`, `disableSignUp`, `requireEmailVerification`, `min/maxPasswordLength`, `sendResetPassword`, `resetPasswordTokenExpiresIn`, `onPasswordReset`, `password.hash/verify`, `autoSignIn`, `revokeSessionsOnPasswordReset`, `onExistingUserSignUp`, `customSyntheticUser`) | ✅ | |
| `socialProviders` | ✅ | `Config.SocialProviders` + `providers/*` |
| `plugins` | 🟡 | |
| `user.*` (`modelName`, `fields`, `additionalFields`, `validateUserInfo`, `changeEmail.*`, `deleteUser.*`) | ✅ | |
| `session.*` (`expiresIn`, `updateAge`, `disableSessionRefresh`, `deferSessionRefresh`, `storeSessionInDatabase`, `preserveSessionInDatabase`, `cookieCache.*`, `freshAge`, `additionalFields`) | ✅ | |
| `account.*` (`updateAccountOnSignIn`, `accountLinking.*`, `encryptOAuthTokens`, `skipStateCookieCheck`, `storeStateStrategy`, `storeAccountCookie`) | 🟡 | |
| `verification.*` (`disableCleanup`, `storeIdentifier`, `storeInDatabase`) | 🟡 | |
| `trustedOrigins` (static, wildcard, custom schemes, function) + env `BETTER_AUTH_TRUSTED_ORIGINS` | ✅ | |
| `rateLimit.*` (`enabled`, `window`, `max`, `customRules`, `storage`, `customStorage`, `modelName`, `fields`) | ✅ | |
| `advanced.ipAddress.*` (`ipAddressHeaders`, `disableIpTracking`, `ipv6Subnet`, `trustedProxies`) | 🟡 | |
| `advanced.useSecureCookies`, `disableCSRFCheck`, `disableOriginCheck`, `crossSubDomainCookies`, `cookies`, `defaultCookieAttributes`, `cookiePrefix` | ✅ | |
| `advanced.database.*` (`defaultFindManyLimit`, `generateId`, `joins`) | 🟡 | |
| `advanced.trustedProxyHeaders`, `backgroundTasks`, `skipTrailingSlashes` | 🟡 | |
| `logger` | ✅ | Go: `Logger` interface |
| `databaseHooks` (user/session/account/verification × create/update/delete × before/after) | 🟡 | |
| `onAPIError` (`throw`, `onError`, `errorURL`, `customizeDefaultErrorPage`) | 🟡 | |
| `hooks.before` / `hooks.after` | 🟡 | |
| `disabledPaths` | 🟡 | |
| `telemetry` | ➖ | No telemetry is sent by the Go port |
| `experimental.instrumentation` | ➖ | OpenTelemetry spans are not ported |
| `advanced.database.validateSchema` | ⬜ | |

## Database adapters

| Adapter | Status | Notes |
|---|---|---|
| Generic adapter interface + transform layer (`createAdapterFactory`) | ✅ | `adapter` package; exercised through every adapter below |
| Memory | ✅ | `adapter/memory` |
| PostgreSQL | ✅ | `adapter/sqladapter` (port of `kysely-adapter`), pgx via `database/sql` |
| MySQL | ✅ | `adapter/sqladapter`, go-sql-driver/mysql (`parseTime=true`) |
| SQLite | ✅ | `adapter/sqladapter`, modernc.org/sqlite (pure Go) or any `database/sql` SQLite driver |
| MongoDB | ✅ | `adapter/mongodb`, mongo-driver v2 |
| SQL Server | ➖ | Migration DDL is ported and fixture-checked for fresh databases; the adapter rejects `mssql` (no Go driver wired) |
| Shared conformance suite | ✅ | `adapter/adaptertest` (port of `packages/test-utils/src/adapter`): memory, PostgreSQL, MySQL, SQLite and MongoDB run every suite upstream runs for them, with upstream's per-adapter skips |
| Schema migrations (`getMigrations`) | ✅ | `adapter/sqladapter/migration`; DDL byte-identical to Kysely 0.29.6 output (59 fixtures generated by better-auth 1.7.7); schemas created by either implementation produce an empty plan on the other |
| Kysely / Prisma / Drizzle adapters | ➖ | JS ORMs; the Go `adapter/sqladapter` covers the same databases |

How compatibility is verified:
- `e2e/tests/shared-db.test.mjs` runs the Go server and the TypeScript server on one
  database (SQLite, PostgreSQL, MySQL — each migrated once by TypeScript and once by Go — and
  MongoDB): users, credential hashes, sessions and signed cookies, verification tokens,
  password changes, revocation and deletion made by one implementation work on the other.
- `adapter/mongodb` compares documents written by the TypeScript Mongo adapter and by Go
  (keys, key order, BSON types) and has each side read, update, increment and consume the
  other's rows.
- The SQL adapter's tests check the stored encoding per dialect against what the Kysely
  adapter writes.

Notes and intentional differences:
- `contains` / `starts_with` / `ends_with` escape `%` and `_` (they match literally, like the
  memory, Prisma and Drizzle adapters); upstream Kysely passes them through as wildcards.
- Empty `in` / `not_in` lists compile to `1 = 0` / `1 = 1` (Kysely emits invalid `in ()`).
- MySQL: dates are stored as UTC wall-clock `timestamp(3)`. A TypeScript server sharing the
  database must use mysql2 with `timezone: "Z"` (as upstream's own tests do);
  go-sql-driver's default `loc` is UTC. Use `parseTime=true`.
- PostgreSQL with pgx's default statement cache: statements prepared before a migration that
  adds columns are re-prepared automatically outside transactions (`cached plan must not
  change result type` is retried). To avoid the cache entirely, add
  `default_query_exec_mode=exec` to the connection string.
- MongoDB: reference fields renamed with `fieldName` are converted to ObjectId in where
  clauses (upstream misses them there).
- `db.Field.Required` is tri-state like upstream's `required` (`nil` = unset, `db.True`,
  `db.False`): unset fields become NOT NULL columns in migrations but stay optional in input
  validation, exactly as in TypeScript.

## CLI (`cmd/better-auth`, mirrors `npx auth`)

Two entry points: the standalone `cmd/better-auth` binary (default schema, `--database-url`
/ `DATABASE_URL`, `.env` loading) and the `cli` package (`cli.Run`) for embedding in your own
binary so `migrate` / `generate` see your full configuration (plugins, additional fields,
renamed models).

| Command | Status | Notes |
|---|---|---|
| `migrate` | ✅ | `--yes`, prompt, unsafe-change refusal and schema-problem reporting as upstream |
| `generate` (SQL schema) | ✅ | writes `better-auth_migrations/<timestamp>.sql` (or `--output`); unsafe changes get upstream's warning banner |
| `secret` | ✅ | |
| `info` | ✅ | system, Go and module info instead of Node/package manager; config with upstream's redaction rules; `--json`, `--copy` |
| `generate --adapter prisma\|drizzle` | ➖ | JS ORM schema generators |
| `init`, `ai`, `login`, `mcp`, `upgrade`, `create-admin`, `check` | ➖ | JS project scaffolding / tooling; out of scope |

## Social providers (`packages/core/src/social-providers`)

All 36 providers are ported, one package per provider id under `providers/`. Each package has
Go tests (authorization URL with the exact upstream query string, code exchange and refresh
request bodies, user-info mapping, account subject, overrides) plus every case of its upstream
`*.test.ts` and of `social-providers.test.ts` / `social.test.ts`. In `e2e/tests/oauth.test.mjs`:
- ✅ GitHub and Google run complete flows (redirect, callback, token exchange, user info,
  linking, id-token sign-in) on both servers against a mock IdP;
- every provider (🟡 rows included) has its authorization URL diffed against the TypeScript
  server: endpoint, every parameter and parameter order, with default options and with
  scopes, `loginHint` and `additionalParams`. Their token exchange and user-info calls are
  covered by Go tests only.

| Provider | Status | Provider | Status | Provider | Status |
|---|---|---|---|---|---|
| apple | 🟡 | atlassian | 🟡 | cloudflare | 🟡 |
| cognito | 🟡 | discord | 🟡 | dropbox | 🟡 |
| facebook | 🟡 | figma | 🟡 | github | ✅ |
| gitlab | 🟡 | google | ✅ | huggingface | 🟡 |
| kakao | 🟡 | kick | 🟡 | line | 🟡 |
| linear | 🟡 | linkedin | 🟡 | microsoft (Entra ID) | 🟡 |
| naver | 🟡 | notion | 🟡 | paybin | 🟡 |
| paypal | 🟡 | polar | 🟡 | railway | 🟡 |
| reddit | 🟡 | roblox | 🟡 | salesforce | 🟡 |
| slack | 🟡 | spotify | 🟡 | tiktok | 🟡 |
| twitch | 🟡 | twitter | 🟡 | vercel | 🟡 |
| vk | 🟡 | wechat | 🟡 | zoom | 🟡 |

Notes and intentional differences:
- `additionalParams` keep the request body's key order (JS enumeration order, array-index keys
  first). Calls through `auth.API` pass a Go map, so their extra params are sorted.
- Zoom: upstream omits `options` from the Zoom provider object, so `disableSignUp`,
  `disableImplicitSignUp` and `overrideUserInfoOnSignIn` are silently ignored for Zoom. The Go
  port honours them.
- Kick: an empty user list returns an error (upstream throws on `data[0]!`).
- Microsoft and Cognito validate options at construction: `New` panics like upstream throws;
  `TryNew` returns the error.
- JWKS documents are cached for 5 minutes and refetched on an unknown `kid` (upstream fetches
  per verification); verification results are identical.
- Provider `VerifyIDToken` overrides receive a `context.Context`; use
  `betterauth.EndpointContextFrom(ctx)` to reach the request.

## Plugins

Every plugin below runs its upstream test files ported to Go plus an e2e suite
(`e2e/tests/plugin-*.test.mjs`) that drives the official client plugin against the Go and
TypeScript servers and diffs the transcripts. Plugins that store data (two-factor, passkey,
api-key, jwt, email-otp, magic-link, one-time-token) are also checked on a shared database:
rows written by one implementation are used by the other. `plugins/access` holds the
access-control core shared by admin and organization.

Intentional differences: Go option types (durations, typed callbacks taking
`*betterauth.EndpointContext`); JSON objects taken from request bodies (organization/api-key
metadata, role permissions) are stored with sorted keys rather than insertion order (same
values); verify responses of passkey hide `returned: false` fields.

| Plugin | Upstream | Status |
|---|---|---|
| two-factor (TOTP, OTP, backup codes, trusted devices) | `plugins/twofactor` (upstream `plugins/two-factor`) | ✅ |
| passkey (WebAuthn) | `plugins/passkey` (upstream `packages/passkey`) | ✅ |
| organization (teams, roles, invitations, dynamic access control) | `plugins/organization` (upstream `plugins/organization`, `plugins/access`) | ✅ |
| admin | `plugins/admin` (upstream `plugins/admin`) | ✅ |
| magic-link | `plugins/magiclink` (upstream `plugins/magic-link`) | ✅ |
| email-otp | `plugins/emailotp` (upstream `plugins/email-otp`) | ✅ |
| jwt (JWKS, key rotation) | `plugins/jwt` (upstream `plugins/jwt`) | ✅ |
| bearer | `plugins/bearer` (upstream `plugins/bearer`) | ✅ |
| username | `plugins/username` (upstream `plugins/username`) | ✅ |
| anonymous | `plugins/anonymous` (upstream `plugins/anonymous`) | ✅ |
| phone-number | `plugins/phonenumber` (upstream `plugins/phone-number`) | ✅ |
| multi-session | `plugins/multisession` (upstream `plugins/multi-session`) | ✅ |
| one-tap | `plugins/onetap` (upstream `plugins/one-tap`) | ✅ |
| one-time-token | `plugins/onetimetoken` (upstream `plugins/one-time-token`) | ✅ |
| generic-oauth | `plugins/genericoauth` (upstream `plugins/generic-oauth`) | ✅ |
| api-key | `plugins/apikey` (upstream `packages/api-key`) | ✅ |
| captcha | `plugins/captcha` (upstream `plugins/captcha`) | ✅ |
| haveibeenpwned | `plugins/haveibeenpwned` (upstream `plugins/haveibeenpwned`) | ✅ |
| last-login-method | `plugins/lastloginmethod` (upstream `plugins/last-login-method`) | ✅ |
| custom-session | `plugins/customsession` (upstream `plugins/custom-session`) | ✅ |
| device-authorization | `plugins/deviceauthorization` (upstream `plugins/device-authorization`) | ✅ |
| oauth-proxy | `plugins/oauthproxy` (upstream `plugins/oauth-proxy`) | ✅ |
| oauth-popup | `plugins/oauthpopup` (upstream `plugins/oauth-popup`) | ✅ |
| open-api | `plugins/openapi` (upstream `plugins/open-api`) | ✅ |
| siwe | `plugins/siwe` (upstream `plugins/siwe`) | ✅ |
| additional-fields (client inference helper) | `plugins/additional-fields` | ➖ (TS type inference only) |
| sso (OIDC + SAML 2.0, domain verification) | `packages/sso` | ⬜ |
| scim (SCIM 2.0) | `packages/scim` | ⬜ |
| oauth-provider / OIDC provider | `packages/oauth-provider` | ⬜ |
| mcp | `packages/mcp`, `packages/cimd` | ⬜ |
| stripe | `packages/stripe` | ⬜ (not in the requested scope) |
| expo, electron | `packages/expo`, `packages/electron` | ⬜ (not in the requested scope) |
| redis-storage | `packages/redis-storage` | ⬜ (not in the requested scope) |

## Endpoints

Phase 1 notes:
- ✅ endpoints are covered by Go ports of the upstream `*.test.ts` files **and** by the e2e
  suite, which drives the official `better-auth@1.7.7` client against the Go server and the
  reference TypeScript server and diffs status, body, `Location` and `Set-Cookie`.
- 🟡 endpoints that need an OAuth provider are tested in Go with a mock provider (and the
  real provider code via `oauth2test`); the e2e suite does not yet diff them against TS.
- Phase 2: `e2e/tests/oauth.test.mjs` runs the real GitHub and Google provider code on both
  servers against a mock IdP (`e2e/servers/mock-idp.mjs`), covering redirect sign-in,
  callback errors, form_post, linking, implicit-linking refusal and id-token sign-in.
- Intentional difference: the Go port always stores `image` on sign-up (null when omitted)
  so real and synthetic duplicate-sign-up responses are indistinguishable. With a SQL
  database the TypeScript server returns the same `image: null`; only its in-memory
  adapter omits the key.

Generated from every `createAuthEndpoint` in v1.7.7. "server-only" endpoints have no HTTP route
and are reachable only through the Go server API (`auth.API`).

### Core

Upstream: `packages/better-auth/src/api/routes`

| Method | Path | Notes | Status |
|---|---|---|---|
| POST | `(server-only) setPassword` | server-only (no HTTP route); `auth.API.SetPassword` | 🟡 |
| GET | `/account-info` | mock OAuth provider | 🟡 |
| [GET, POST] | `/callback/:id` | GET + form_post; e2e against mock IdP (GitHub, Google) | ✅ |
| POST | `/change-email` |  | ✅ |
| POST | `/change-password` |  | ✅ |
| POST | `/delete-user` |  | ✅ |
| GET | `/delete-user/callback` |  | ✅ |
| GET | `/error` |  | ✅ |
| POST | `/get-access-token` | mock OAuth provider (refresh, encryption, account cookie) | 🟡 |
| [GET, POST] | `/get-session` |  | ✅ |
| POST | `/link-social` | e2e: link via callback, email mismatch | ✅ |
| GET | `/list-accounts` |  | ✅ |
| GET | `/list-sessions` |  | ✅ |
| GET | `/ok` |  | ✅ |
| POST | `/refresh-token` | mock OAuth provider | 🟡 |
| POST | `/request-password-reset` |  | ✅ |
| POST | `/reset-password` |  | ✅ |
| GET | `/reset-password/:token` |  | ✅ |
| POST | `/revoke-other-sessions` |  | ✅ |
| POST | `/revoke-session` |  | 🟡 |
| POST | `/revoke-sessions` |  | ✅ |
| POST | `/send-verification-email` |  | ✅ |
| POST | `/sign-in/email` |  | ✅ |
| POST | `/sign-in/social` | redirect + id-token flows; e2e against mock IdP | ✅ |
| POST | `/sign-out` |  | ✅ |
| POST | `/sign-up/email` |  | ✅ |
| POST | `/unlink-account` |  | ✅ |
| POST | `/update-session` |  | ✅ |
| POST | `/update-user` |  | ✅ |
| GET | `/verify-email` |  | ✅ |
| POST | `/verify-password` |  | 🟡 |

### plugin: admin

Upstream: `packages/better-auth/src/plugins/admin`

| Method | Path | Notes | Status |
|---|---|---|---|
| POST | `/admin/ban-user` |  | ⬜ |
| POST | `/admin/create-user` |  | ⬜ |
| GET | `/admin/get-user` |  | ⬜ |
| POST | `/admin/has-permission` |  | ⬜ |
| POST | `/admin/impersonate-user` |  | ⬜ |
| POST | `/admin/list-user-sessions` |  | ⬜ |
| GET | `/admin/list-users` |  | ⬜ |
| POST | `/admin/remove-user` |  | ⬜ |
| POST | `/admin/revoke-user-session` |  | ⬜ |
| POST | `/admin/revoke-user-sessions` |  | ⬜ |
| POST | `/admin/set-role` |  | ⬜ |
| POST | `/admin/set-user-password` |  | ⬜ |
| POST | `/admin/stop-impersonating` |  | ⬜ |
| POST | `/admin/unban-user` |  | ⬜ |
| POST | `/admin/update-user` |  | ⬜ |

### plugin: anonymous

Upstream: `packages/better-auth/src/plugins/anonymous`

| Method | Path | Notes | Status |
|---|---|---|---|
| POST | `/delete-anonymous-user` |  | ⬜ |
| POST | `/sign-in/anonymous` |  | ⬜ |

### plugin: custom-session

Upstream: `packages/better-auth/src/plugins/custom-session`

| Method | Path | Notes | Status |
|---|---|---|---|
| GET | `/get-session` |  | ⬜ |

### plugin: device-authorization

Upstream: `packages/better-auth/src/plugins/device-authorization`

| Method | Path | Notes | Status |
|---|---|---|---|
| GET | `/device` |  | ⬜ |
| POST | `/device/approve` |  | ⬜ |
| POST | `/device/code` |  | ⬜ |
| POST | `/device/deny` |  | ⬜ |
| POST | `/device/token` |  | ⬜ |

### plugin: email-otp

Upstream: `packages/better-auth/src/plugins/email-otp`

| Method | Path | Notes | Status |
|---|---|---|---|
| POST | `/email-otp/change-email` |  | ⬜ |
| POST | `/email-otp/check-verification-otp` |  | ⬜ |
| POST | `/email-otp/request-email-change` |  | ⬜ |
| POST | `/email-otp/request-password-reset` |  | ⬜ |
| POST | `/email-otp/reset-password` |  | ⬜ |
| POST | `/email-otp/send-verification-otp` |  | ⬜ |
| POST | `/email-otp/verify-email` |  | ⬜ |
| POST | `/forget-password/email-otp` |  | ⬜ |
| POST | `/sign-in/email-otp` |  | ⬜ |

### plugin: jwt

Upstream: `packages/better-auth/src/plugins/jwt`

| Method | Path | Notes | Status |
|---|---|---|---|
| GET | `/jwks` |  | ⬜ |
| GET | `/token` |  | ⬜ |

### plugin: magic-link

Upstream: `packages/better-auth/src/plugins/magic-link`

| Method | Path | Notes | Status |
|---|---|---|---|
| GET | `/magic-link/verify` |  | ⬜ |
| POST | `/sign-in/magic-link` |  | ⬜ |

### plugin: multi-session

Upstream: `packages/better-auth/src/plugins/multi-session`

| Method | Path | Notes | Status |
|---|---|---|---|
| GET | `/multi-session/list-device-sessions` |  | ⬜ |
| POST | `/multi-session/revoke` |  | ⬜ |
| POST | `/multi-session/set-active` |  | ⬜ |

### plugin: oauth-popup

Upstream: `packages/better-auth/src/plugins/oauth-popup`

| Method | Path | Notes | Status |
|---|---|---|---|
| GET | `/oauth-popup/start` |  | ⬜ |

### plugin: oauth-proxy

Upstream: `packages/better-auth/src/plugins/oauth-proxy`

| Method | Path | Notes | Status |
|---|---|---|---|
| GET | `/callback/:id/oauth-proxy` |  | ⬜ |
| GET | `/oauth-proxy-callback` |  | ⬜ |

### plugin: one-tap

Upstream: `packages/better-auth/src/plugins/one-tap`

| Method | Path | Notes | Status |
|---|---|---|---|
| POST | `/one-tap/callback` |  | ⬜ |

### plugin: one-time-token

Upstream: `packages/better-auth/src/plugins/one-time-token`

| Method | Path | Notes | Status |
|---|---|---|---|
| GET | `/one-time-token/generate` |  | ⬜ |
| POST | `/one-time-token/verify` |  | ⬜ |

### plugin: open-api

Upstream: `packages/better-auth/src/plugins/open-api`

| Method | Path | Notes | Status |
|---|---|---|---|
| GET | `/open-api/generate-schema` |  | ⬜ |

### plugin: organization

Upstream: `packages/better-auth/src/plugins/organization`

| Method | Path | Notes | Status |
|---|---|---|---|
| POST | `/organization/accept-invitation` |  | ⬜ |
| POST | `/organization/add-team-member` |  | ⬜ |
| POST | `/organization/cancel-invitation` |  | ⬜ |
| POST | `/organization/check-slug` |  | ⬜ |
| POST | `/organization/create` |  | ⬜ |
| POST | `/organization/create-role` |  | ⬜ |
| POST | `/organization/create-team` |  | ⬜ |
| POST | `/organization/delete` |  | ⬜ |
| POST | `/organization/delete-role` |  | ⬜ |
| GET | `/organization/get-active-member` |  | ⬜ |
| GET | `/organization/get-active-member-role` |  | ⬜ |
| GET | `/organization/get-full-organization` |  | ⬜ |
| GET | `/organization/get-invitation` |  | ⬜ |
| GET | `/organization/get-organization` |  | ⬜ |
| GET | `/organization/get-role` |  | ⬜ |
| POST | `/organization/has-permission` |  | ⬜ |
| POST | `/organization/invite-member` |  | ⬜ |
| POST | `/organization/leave` |  | ⬜ |
| GET | `/organization/list` |  | ⬜ |
| GET | `/organization/list-invitations` |  | ⬜ |
| GET | `/organization/list-members` |  | ⬜ |
| GET | `/organization/list-roles` |  | ⬜ |
| GET | `/organization/list-team-members` |  | ⬜ |
| GET | `/organization/list-teams` |  | ⬜ |
| GET | `/organization/list-user-invitations` |  | ⬜ |
| GET | `/organization/list-user-teams` |  | ⬜ |
| POST | `/organization/reject-invitation` |  | ⬜ |
| POST | `/organization/remove-member` |  | ⬜ |
| POST | `/organization/remove-team` |  | ⬜ |
| POST | `/organization/remove-team-member` |  | ⬜ |
| POST | `/organization/set-active` |  | ⬜ |
| POST | `/organization/set-active-team` |  | ⬜ |
| POST | `/organization/update` |  | ⬜ |
| POST | `/organization/update-member-role` |  | ⬜ |
| POST | `/organization/update-role` |  | ⬜ |
| POST | `/organization/update-team` |  | ⬜ |

### plugin: phone-number

Upstream: `packages/better-auth/src/plugins/phone-number`

| Method | Path | Notes | Status |
|---|---|---|---|
| POST | `/phone-number/request-password-reset` |  | ⬜ |
| POST | `/phone-number/reset-password` |  | ⬜ |
| POST | `/phone-number/send-otp` |  | ⬜ |
| POST | `/phone-number/verify` |  | ⬜ |
| POST | `/sign-in/phone-number` |  | ⬜ |

### plugin: siwe

Upstream: `packages/better-auth/src/plugins/siwe`

| Method | Path | Notes | Status |
|---|---|---|---|
| POST | `/siwe/verify` |  | ⬜ |

### plugin: two-factor

Upstream: `packages/better-auth/src/plugins/two-factor`

| Method | Path | Notes | Status |
|---|---|---|---|
| POST | `/two-factor/disable` |  | ⬜ |
| POST | `/two-factor/enable` |  | ⬜ |
| POST | `/two-factor/generate-backup-codes` |  | ⬜ |
| POST | `/two-factor/get-totp-uri` |  | ⬜ |
| POST | `/two-factor/send-otp` |  | ⬜ |
| POST | `/two-factor/verify-backup-code` |  | ⬜ |
| POST | `/two-factor/verify-otp` |  | ⬜ |
| POST | `/two-factor/verify-totp` |  | ⬜ |

### plugin: username

Upstream: `packages/better-auth/src/plugins/username`

| Method | Path | Notes | Status |
|---|---|---|---|
| POST | `/is-username-available` |  | ⬜ |
| POST | `/sign-in/username` |  | ⬜ |

### package: @better-auth/api-key

Upstream: `packages/api-key`

| Method | Path | Notes | Status |
|---|---|---|---|
| POST | `/api-key/create` |  | ⬜ |
| POST | `/api-key/delete` |  | ⬜ |
| GET | `/api-key/get` |  | ⬜ |
| GET | `/api-key/list` |  | ⬜ |
| POST | `/api-key/update` |  | ⬜ |

### package: @better-auth/electron

Upstream: `packages/electron`

| Method | Path | Notes | Status |
|---|---|---|---|
| GET | `/electron/init-oauth-proxy` |  | ⬜ |
| POST | `/electron/token` |  | ⬜ |
| POST | `/electron/transfer-user` |  | ⬜ |

### package: @better-auth/expo

Upstream: `packages/expo`

| Method | Path | Notes | Status |
|---|---|---|---|
| GET | `/expo-authorization-proxy` |  | ⬜ |

### package: @better-auth/oauth-provider

Upstream: `packages/oauth-provider`

| Method | Path | Notes | Status |
|---|---|---|---|
| GET | `/.well-known/oauth-authorization-server` | server-only (no HTTP route) | ⬜ |
| GET | `/.well-known/openid-configuration` | server-only (no HTTP route) | ⬜ |
| POST | `/admin/oauth2/create-client` | server-only (no HTTP route) | ⬜ |
| GET | `/admin/oauth2/resources` | server-only (no HTTP route) | ⬜ |
| POST | `/admin/oauth2/resources` | server-only (no HTTP route) | ⬜ |
| DELETE | `/admin/oauth2/resources/:identifier` | server-only (no HTTP route) | ⬜ |
| GET | `/admin/oauth2/resources/:identifier` | server-only (no HTTP route) | ⬜ |
| PATCH | `/admin/oauth2/resources/:identifier` | server-only (no HTTP route) | ⬜ |
| DELETE | `/admin/oauth2/resources/:identifier/clients/:client_id` | server-only (no HTTP route) | ⬜ |
| POST | `/admin/oauth2/resources/:identifier/clients/:client_id` | server-only (no HTTP route) | ⬜ |
| PATCH | `/admin/oauth2/update-client` | server-only (no HTTP route) | ⬜ |
| GET | `/oauth2/authorize` |  | ⬜ |
| POST | `/oauth2/client/rotate-secret` |  | ⬜ |
| POST | `/oauth2/consent` |  | ⬜ |
| POST | `/oauth2/continue` |  | ⬜ |
| POST | `/oauth2/create-client` |  | ⬜ |
| POST | `/oauth2/delete-client` |  | ⬜ |
| POST | `/oauth2/delete-consent` |  | ⬜ |
| GET | `/oauth2/end-session` |  | ⬜ |
| POST | `/oauth2/end-session/confirm` |  | ⬜ |
| GET | `/oauth2/get-client` |  | ⬜ |
| GET | `/oauth2/get-clients` |  | ⬜ |
| GET | `/oauth2/get-consent` |  | ⬜ |
| GET | `/oauth2/get-consents` |  | ⬜ |
| POST | `/oauth2/introspect` |  | ⬜ |
| GET | `/oauth2/public-client` |  | ⬜ |
| POST | `/oauth2/public-client-prelogin` |  | ⬜ |
| POST | `/oauth2/register` |  | ⬜ |
| POST | `/oauth2/revoke` |  | ⬜ |
| POST | `/oauth2/token` |  | ⬜ |
| POST | `/oauth2/update-client` |  | ⬜ |
| POST | `/oauth2/update-consent` |  | ⬜ |
| [GET, POST] | `/oauth2/userinfo` |  | ⬜ |

### package: @better-auth/passkey

Upstream: `packages/passkey`

| Method | Path | Notes | Status |
|---|---|---|---|
| POST | `/passkey/delete-passkey` |  | ⬜ |
| GET | `/passkey/generate-authenticate-options` |  | ⬜ |
| GET | `/passkey/generate-register-options` |  | ⬜ |
| GET | `/passkey/list-user-passkeys` |  | ⬜ |
| POST | `/passkey/update-passkey` |  | ⬜ |
| POST | `/passkey/verify-authentication` |  | ⬜ |
| POST | `/passkey/verify-registration` |  | ⬜ |

### package: @better-auth/scim

Upstream: `packages/scim`

| Method | Path | Notes | Status |
|---|---|---|---|
| GET | `/scim/v2/Groups` |  | ⬜ |
| POST | `/scim/v2/Groups` |  | ⬜ |
| DELETE | `/scim/v2/Groups/:groupId` |  | ⬜ |
| GET | `/scim/v2/Groups/:groupId` |  | ⬜ |
| PATCH | `/scim/v2/Groups/:groupId` |  | ⬜ |
| PUT | `/scim/v2/Groups/:groupId` |  | ⬜ |
| GET | `/scim/v2/ResourceTypes` |  | ⬜ |
| GET | `/scim/v2/ResourceTypes/:resourceTypeId` |  | ⬜ |
| GET | `/scim/v2/Schemas` |  | ⬜ |
| GET | `/scim/v2/Schemas/:schemaId` |  | ⬜ |
| GET | `/scim/v2/ServiceProviderConfig` |  | ⬜ |
| GET | `/scim/v2/Users` |  | ⬜ |
| POST | `/scim/v2/Users` |  | ⬜ |
| DELETE | `/scim/v2/Users/:userId` |  | ⬜ |
| GET | `/scim/v2/Users/:userId` |  | ⬜ |
| PATCH | `/scim/v2/Users/:userId` |  | ⬜ |
| PUT | `/scim/v2/Users/:userId` |  | ⬜ |

### package: @better-auth/sso

Upstream: `packages/sso`

| Method | Path | Notes | Status |
|---|---|---|---|
| POST | `/sign-in/sso` |  | ⬜ |
| [GET, POST] | `/sso/callback` |  | ⬜ |
| [GET, POST] | `/sso/callback/:providerId` |  | ⬜ |
| POST | `/sso/delete-provider` |  | ⬜ |
| GET | `/sso/get-provider` |  | ⬜ |
| GET | `/sso/providers` |  | ⬜ |
| POST | `/sso/register` |  | ⬜ |
| POST | `/sso/request-domain-verification` |  | ⬜ |
| POST | `/sso/saml2/logout/:providerId` |  | ⬜ |
| [GET, POST] | `/sso/saml2/sp/acs/:providerId` |  | ⬜ |
| GET | `/sso/saml2/sp/metadata` |  | ⬜ |
| [GET, POST] | `/sso/saml2/sp/slo/:providerId` |  | ⬜ |
| POST | `/sso/update-provider` |  | ⬜ |
| POST | `/sso/verify-domain` |  | ⬜ |

### package: @better-auth/stripe

Upstream: `packages/stripe`

| Method | Path | Notes | Status |
|---|---|---|---|
| POST | `/stripe/webhook` |  | ⬜ |
| POST | `/subscription/billing-portal` |  | ⬜ |
| POST | `/subscription/cancel` |  | ⬜ |
| GET | `/subscription/list` |  | ⬜ |
| POST | `/subscription/restore` |  | ⬜ |
| GET | `/subscription/success` |  | ⬜ |
| POST | `/subscription/upgrade` |  | ⬜ |
