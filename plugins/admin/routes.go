package admin

import (
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

const sessionKey = "admin.session"

// adminMiddleware requires an authoritative (cookie-cache bypassing) session.
func adminMiddleware(ctx *betterauth.EndpointContext) error {
	s, err := betterauth.GetAuthoritativeSessionFromCtx(ctx)
	if err != nil {
		return err
	}
	if s == nil || s.Session == nil {
		return betterauth.ErrStatus("UNAUTHORIZED")
	}
	ctx.Session = s
	ctx.Set(sessionKey, s)
	return nil
}

func adminSession(ctx *betterauth.EndpointContext) *betterauth.SessionWithUser {
	if s, ok := ctx.Value(sessionKey).(*betterauth.SessionWithUser); ok {
		return s
	}
	return ctx.Session
}

func userRole(u *betterauth.User) string {
	if u == nil {
		return ""
	}
	s, _ := u.Get("role").(string)
	return s
}

func can(opts *Options, s *betterauth.SessionWithUser, permissions map[string][]string) bool {
	return HasPermission(HasPermissionInput{UserID: s.User.ID, Role: userRole(s.User), Options: opts, Permissions: permissions})
}

func forbidden(code betterauth.ErrorCode) error { return betterauth.ErrFrom("FORBIDDEN", code) }

func badRequest(code betterauth.ErrorCode) error { return betterauth.ErrFrom("BAD_REQUEST", code) }

func userNotFound() error { return betterauth.ErrFrom("NOT_FOUND", betterauth.ErrUserNotFound) }

// parseRoles joins an array of roles with commas.
func parseRoles(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		parts := make([]string, len(t))
		for i, x := range t {
			parts[i] = jsString(x)
		}
		return strings.Join(parts, ",")
	case []string:
		return strings.Join(t, ",")
	}
	return jsString(v)
}

func roleList(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case []string:
		out := make([]any, len(t))
		for i, s := range t {
			out[i] = s
		}
		return out
	}
	return []any{v}
}

// checkRoleValues validates requested roles (INVALID_ROLE_TYPE / non-existent role).
func checkRoleValues(opts *Options, v any) error {
	for _, r := range roleList(v) {
		s, ok := r.(string)
		if !ok {
			return badRequest(ErrInvalidRoleType)
		}
		if opts.Roles != nil {
			if _, exists := opts.Roles[s]; !exists {
				return badRequest(ErrNotAllowedToSetNonExistentValue)
			}
		}
	}
	return nil
}

func assertPasswordLength(ctx *betterauth.EndpointContext, pw string, short bool) error {
	n := jsonx.EncodeUTF16Length(pw)
	if short && n < ctx.Auth.Password.MinLength {
		ctx.Auth.Logger.Warn("Password is too short")
		return betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrPasswordTooShort)
	}
	if n > ctx.Auth.Password.MaxLength {
		ctx.Auth.Logger.Warn("Password is too long")
		return betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrPasswordTooLong)
	}
	return nil
}

func secondsFromNow(sec float64) time.Time {
	return time.Now().Add(time.Duration(sec * float64(time.Second)))
}

// ---- /admin/set-role ----

func setRoleEndpoint(opts *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "setRole", Path: "/admin/set-role", Methods: []string{"POST"},
		Body: validate.Object(
			validate.F("userId", validate.Describe(coerceString(""), "The user id")),
			validate.F("role", validate.Describe(validate.Union(
				validate.Describe(validate.String(), "The role to set. `admin` or `user` by default"),
				validate.Array(validate.Describe(validate.String(), "The roles to set. `admin` or `user` by default")),
			), "The role to set, this can be a string or an array of strings. Eg: `admin` or `[admin, user]`")),
		),
		RequireHeaders: true, Use: []betterauth.Middleware{adminMiddleware},
		Metadata: openapi("setRole"),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			s := adminSession(ctx)
			if !can(opts, s, map[string][]string{"user": {"set-role"}}) {
				return nil, forbidden(ErrNotAllowedToChangeUsersRole)
			}
			body := ctx.BodyMap()
			role := body["role"]
			if opts.Roles != nil {
				for _, r := range roleList(role) {
					if _, ok := opts.Roles[jsString(r)]; !ok {
						return nil, badRequest(ErrNotAllowedToSetNonExistentValue)
					}
				}
			}
			userID := ctx.BodyString("userId")
			ia := ctx.Auth.InternalAdapter
			existing, err := ia.FindUserByID(ctx.Context(), userID)
			if err != nil {
				return nil, err
			}
			if existing == nil {
				return nil, userNotFound()
			}
			updated, err := ia.UpdateUser(ctx.Context(), userID, adapter.Record{"role": parseRoles(role)})
			if err != nil {
				return nil, err
			}
			return jsonx.O("user", ctx.Auth.UserOutput(updated)), nil
		},
	}
}

// ---- /admin/get-user ----

func getUserEndpoint(opts *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "getUser", Path: "/admin/get-user", Methods: []string{"GET"},
		Query: validate.Object(validate.F("id", validate.Describe(validate.String(), "The id of the User"))),
		Use:   []betterauth.Middleware{adminMiddleware}, Metadata: openapi("getUser"),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			id := ctx.QueryString("id")
			if !can(opts, adminSession(ctx), map[string][]string{"user": {"get"}}) {
				return nil, forbidden(ErrNotAllowedToGetUser)
			}
			u, err := ctx.Auth.InternalAdapter.FindUserByID(ctx.Context(), id)
			if err != nil {
				return nil, err
			}
			if u == nil {
				return nil, userNotFound()
			}
			return ctx.Auth.UserOutput(u), nil
		},
	}
}

// ---- /admin/create-user ----

func createUserEndpoint(opts *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "createUser", Path: "/admin/create-user", Methods: []string{"POST"},
		Body: validate.Object(
			validate.F("email", validate.Describe(validate.String(), "The email of the user")),
			validate.F("password", validate.Optional(validate.String())),
			validate.F("name", validate.Describe(validate.String(), "The name of the user")),
			validate.F("role", validate.Optional(validate.Union(
				validate.Describe(validate.String(), "The role of the user"),
				validate.Array(validate.Describe(validate.String(), "The roles of user")),
			))),
			validate.F("data", validate.Optional(validate.Record(validate.Any()))),
		),
		Metadata: openapi("createUser"),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			session, err := betterauth.GetAuthoritativeSessionFromCtx(ctx)
			if err != nil {
				return nil, err
			}
			if session == nil && (ctx.Request != nil || ctx.Headers != nil) {
				return nil, betterauth.ErrStatus("UNAUTHORIZED")
			}
			if session != nil && !can(opts, session, map[string][]string{"user": {"create"}}) {
				return nil, forbidden(ErrNotAllowedToCreateUsers)
			}
			body := ctx.BodyMap()
			data, _ := body["data"].(map[string]any)
			userData := map[string]any{}
			dataRole, hasDataRole := data["role"]
			for k, v := range data {
				if k != "role" {
					userData[k] = v
				}
			}
			requested, hasRequested := body["role"]
			if !hasRequested || requested == nil {
				// body.role ?? data.role
				if hasDataRole && !validate.IsUndefined(dataRole) {
					requested, hasRequested = dataRole, true
				}
			}
			if hasRequested {
				if session != nil && !can(opts, session, map[string][]string{"user": {"set-role"}}) {
					return nil, forbidden(ErrNotAllowedToChangeUsersRole)
				}
				if err := checkRoleValues(opts, requested); err != nil {
					return nil, err
				}
			}
			if session != nil {
				for _, k := range []string{"banned", "banReason", "banExpires"} {
					if _, ok := userData[k]; ok {
						if !can(opts, session, map[string][]string{"user": {"ban"}}) {
							return nil, forbidden(ErrNotAllowedToBanUsers)
						}
						break
					}
				}
			}
			email := strings.ToLower(ctx.BodyString("email"))
			if !validate.IsEmail(email) {
				return nil, betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrInvalidEmail)
			}
			password := ctx.BodyString("password")
			if password != "" {
				if err := assertPasswordLength(ctx, password, false); err != nil {
					return nil, err
				}
			}
			ia := ctx.Auth.InternalAdapter
			existing, err := ia.FindUserByEmail(ctx.Context(), email, false)
			if err != nil {
				return nil, err
			}
			if existing != nil {
				return nil, badRequest(ErrUserAlreadyExistsUseAnotherEmail)
			}
			rec := adapter.Record{}
			for k, v := range userData {
				rec[k] = v
			}
			rec["email"] = email
			rec["name"] = body["name"]
			if hasRequested {
				rec["role"] = parseRoles(requested)
			} else {
				rec["role"] = opts.DefaultRole
			}
			user, err := ia.CreateUser(ctx.Context(), rec, betterauth.UserInfoSource{Method: "admin"})
			if err != nil {
				return nil, err
			}
			if user == nil {
				return nil, betterauth.ErrFrom("INTERNAL_SERVER_ERROR", ErrFailedToCreateUser)
			}
			if password != "" {
				hashed, err := ctx.Auth.Password.Hash(password)
				if err != nil {
					return nil, err
				}
				if _, err := ia.LinkAccount(ctx.Context(), adapter.Record{
					"providerId": "credential", "accountId": user.ID, "password": hashed, "userId": user.ID,
				}); err != nil {
					return nil, err
				}
			}
			return jsonx.O("user", ctx.Auth.UserOutput(user)), nil
		},
	}
}

// ---- /admin/update-user ----

func adminUpdateUserEndpoint(opts *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "adminUpdateUser", Path: "/admin/update-user", Methods: []string{"POST"},
		Body: validate.Object(
			validate.F("userId", validate.Describe(coerceString(""), "The user id")),
			validate.F("data", validate.Describe(validate.RecordOf(validate.Any(), validate.Any()), "The user data to update")),
		),
		Use: []betterauth.Middleware{adminMiddleware}, Metadata: openapi("adminUpdateUser"),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			s := adminSession(ctx)
			if !can(opts, s, map[string][]string{"user": {"update"}}) {
				return nil, forbidden(ErrNotAllowedToUpdateUsers)
			}
			body := ctx.BodyMap()
			userID := ctx.BodyString("userId")
			data, _ := body["data"].(map[string]any)
			if len(data) == 0 {
				return nil, badRequest(ErrNoDataToUpdate)
			}
			has := func(k string) bool { _, ok := data[k]; return ok }
			if has("password") {
				return nil, badRequest(ErrPasswordCannotBeUpdatedViaUpdateUser)
			}
			if has("role") {
				if !can(opts, s, map[string][]string{"user": {"set-role"}}) {
					return nil, forbidden(ErrNotAllowedToChangeUsersRole)
				}
				if err := checkRoleValues(opts, data["role"]); err != nil {
					return nil, err
				}
				data["role"] = parseRoles(roleList(data["role"]))
			}
			if has("banned") || has("banReason") || has("banExpires") {
				if !can(opts, s, map[string][]string{"user": {"ban"}}) {
					return nil, forbidden(ErrNotAllowedToBanUsers)
				}
				if data["banned"] == true && userID == s.User.ID {
					return nil, badRequest(ErrYouCannotBanYourself)
				}
			}
			ia := ctx.Auth.InternalAdapter
			if has("email") || has("emailVerified") {
				if !can(opts, s, map[string][]string{"user": {"set-email"}}) {
					return nil, forbidden(ErrNotAllowedToSetUsersEmail)
				}
				if has("email") {
					email := strings.ToLower(jsString(data["email"]))
					if !validate.IsEmail(email) {
						return nil, betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrInvalidEmail)
					}
					existing, err := ia.FindUserByEmail(ctx.Context(), email, false)
					if err != nil {
						return nil, err
					}
					if existing != nil && existing.User.ID != userID {
						return nil, badRequest(ErrUserAlreadyExistsUseAnotherEmail)
					}
					data["email"] = email
				}
			}
			existing, err := ia.FindUserByID(ctx.Context(), userID)
			if err != nil {
				return nil, err
			}
			if existing == nil {
				return nil, userNotFound()
			}
			updated, err := ia.UpdateUser(ctx.Context(), userID, adapter.Record(data))
			if err != nil {
				return nil, err
			}
			if data["banned"] == true {
				if err := ia.DeleteUserSessions(ctx.Context(), userID); err != nil {
					return nil, err
				}
			}
			return ctx.Auth.UserOutput(updated), nil
		},
	}
}

// ---- /admin/list-users ----

var whereOperators = []string{"eq", "ne", "lt", "lte", "gt", "gte", "in", "not_in", "contains", "starts_with", "ends_with"}

// jsNumber implements Number(v) for query values.
func jsNumber(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case bool:
		if t {
			return 1
		}
		return 0
	case nil:
		return 0
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0
		}
		ls := strings.ToLower(s)
		for _, p := range []struct {
			prefix string
			base   int
		}{{"0x", 16}, {"0o", 8}, {"0b", 2}} {
			if strings.HasPrefix(ls, p.prefix) {
				n, err := strconv.ParseUint(s[2:], p.base, 64)
				if err != nil {
					return math.NaN()
				}
				return float64(n)
			}
		}
		switch s {
		case "Infinity", "+Infinity":
			return math.Inf(1)
		case "-Infinity":
			return math.Inf(-1)
		}
		if strings.ContainsAny(ls, "xn_") || strings.Contains(ls, "inf") {
			return math.NaN()
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return math.NaN()
		}
		return f
	case []any:
		switch len(t) {
		case 0:
			return 0
		case 1:
			return jsNumber(jsString(t[0]))
		}
	}
	return math.NaN()
}

// numberOrUndefined is `Number(v) || undefined`.
func numberOrUndefined(v any, present bool) (float64, bool) {
	if !present {
		return 0, false
	}
	n := jsNumber(v)
	if n == 0 || math.IsNaN(n) {
		return 0, false
	}
	return n, true
}

func listUsersEndpoint(opts *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "listUsers", Path: "/admin/list-users", Methods: []string{"GET"},
		Use: []betterauth.Middleware{adminMiddleware},
		Query: validate.Object(
			validate.F("searchValue", validate.Optional(validate.String())),
			validate.F("searchField", validate.Optional(validate.Describe(validate.Enum("email", "name"),
				"The field to search in, defaults to email. Can be `email` or `name`. Eg: \"name\""))),
			validate.F("searchOperator", validate.Optional(validate.Describe(validate.Enum("contains", "starts_with", "ends_with"),
				"The operator to use for the search. Can be `contains`, `starts_with` or `ends_with`. Eg: \"contains\""))),
			validate.F("limit", validate.Optional(validate.Union(validate.Describe(validate.String(), "The number of users to return"), validate.Number()))),
			validate.F("offset", validate.Optional(validate.Union(validate.Describe(validate.String(), "The offset to start from"), validate.Number()))),
			validate.F("sortBy", validate.Optional(validate.Describe(validate.String(), "The field to sort by"))),
			validate.F("sortDirection", validate.Optional(validate.Describe(validate.Enum("asc", "desc"), "The direction to sort by"))),
			validate.F("filterField", validate.Optional(validate.Describe(validate.String(), "The field to filter by"))),
			// z.string().or(z.number()).or(z.boolean()).or(z.array(...)).or(z.array(...)) nests unions.
			validate.F("filterValue", validate.Optional(validate.Union(validate.Union(validate.Union(validate.Union(
				validate.Describe(validate.String(), "The value to filter by"), validate.Number()), validate.Boolean()),
				validate.Array(validate.String())), validate.Array(validate.Number())))),
			validate.F("filterOperator", validate.Optional(validate.Describe(validate.Enum(whereOperators...), "The operator to use for the filter"))),
		),
		Metadata: openapi("listUsers"),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			if !can(opts, adminSession(ctx), map[string][]string{"user": {"list"}}) {
				return nil, forbidden(ErrNotAllowedToListUsers)
			}
			q := ctx.Query
			str := func(k string) string { s, _ := q[k].(string); return s }
			or := func(s, def string) string {
				if s == "" {
					return def
				}
				return s
			}
			var where []adapter.Where
			if sv := str("searchValue"); sv != "" {
				where = append(where, adapter.Where{Field: or(str("searchField"), "email"),
					Operator: adapter.Operator(or(str("searchOperator"), "contains")), Value: sv})
			}
			if fv, ok := q["filterValue"]; ok && !validate.IsUndefined(fv) {
				where = append(where, adapter.Where{Field: or(str("filterField"), "email"),
					Operator: adapter.Operator(or(str("filterOperator"), "eq")), Value: fv})
			}
			limitV, limitRaw := q["limit"]
			offsetV, offsetRaw := q["offset"]
			limit, hasLimit := numberOrUndefined(limitV, limitRaw)
			offset, hasOffset := numberOrUndefined(offsetV, offsetRaw)
			var sortBy *adapter.SortBy
			if sb := str("sortBy"); sb != "" {
				sortBy = &adapter.SortBy{Field: sb, Direction: or(str("sortDirection"), "asc")}
			}
			users, err := ctx.Auth.InternalAdapter.ListUsers(ctx.Context(), toInt(limit), toInt(offset), sortBy, where)
			var total int64
			if err == nil {
				total, err = ctx.Auth.InternalAdapter.CountTotalUsers(ctx.Context(), where)
			}
			if err != nil {
				return jsonx.O("users", []any{}, "total", 0), nil
			}
			out := make([]any, len(users))
			for i, u := range users {
				out[i] = ctx.Auth.UserOutput(u)
			}
			res := jsonx.O("users", out, "total", total)
			if hasLimit {
				res.Set("limit", limit)
			}
			if hasOffset {
				res.Set("offset", offset)
			}
			return res, nil
		},
	}
}

func toInt(f float64) int {
	if math.IsInf(f, 0) || math.IsNaN(f) || f <= 0 {
		return 0
	}
	if f > math.MaxInt32 {
		return math.MaxInt32
	}
	return int(f)
}

// ---- /admin/list-user-sessions ----

func listUserSessionsEndpoint(opts *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "listUserSessions", Path: "/admin/list-user-sessions", Methods: []string{"POST"},
		Use:  []betterauth.Middleware{adminMiddleware},
		Body: validate.Object(validate.F("userId", validate.Describe(coerceString(""), "The user id"))), Metadata: openapi("listUserSessions"),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			if !can(opts, adminSession(ctx), map[string][]string{"session": {"list"}}) {
				return nil, forbidden(ErrNotAllowedToListUsersSessions)
			}
			sessions, err := ctx.Auth.InternalAdapter.ListSessions(ctx.Context(), ctx.BodyString("userId"), false)
			if err != nil {
				return nil, err
			}
			out := make([]any, len(sessions))
			for i, s := range sessions {
				out[i] = ctx.Auth.SessionOutput(s)
			}
			return jsonx.O("sessions", out), nil
		},
	}
}

// ---- /admin/unban-user, /admin/ban-user ----

func unbanUserEndpoint(opts *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "unbanUser", Path: "/admin/unban-user", Methods: []string{"POST"},
		Body: validate.Object(validate.F("userId", validate.Describe(coerceString(""), "The user id"))),
		Use:  []betterauth.Middleware{adminMiddleware}, Metadata: openapi("unbanUser"),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			if !can(opts, adminSession(ctx), map[string][]string{"user": {"ban"}}) {
				return nil, forbidden(ErrNotAllowedToBanUsers)
			}
			userID := ctx.BodyString("userId")
			ia := ctx.Auth.InternalAdapter
			existing, err := ia.FindUserByID(ctx.Context(), userID)
			if err != nil {
				return nil, err
			}
			if existing == nil {
				return nil, userNotFound()
			}
			u, err := ia.UpdateUser(ctx.Context(), userID, adapter.Record{
				"banned": false, "banExpires": nil, "banReason": nil, "updatedAt": time.Now(),
			})
			if err != nil {
				return nil, err
			}
			return jsonx.O("user", ctx.Auth.UserOutput(u)), nil
		},
	}
}

func banUserEndpoint(opts *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "banUser", Path: "/admin/ban-user", Methods: []string{"POST"},
		Body: validate.Object(
			validate.F("userId", validate.Describe(coerceString(""), "The user id")),
			validate.F("banReason", validate.Optional(validate.Describe(validate.String(), "The reason for the ban"))),
			validate.F("banExpiresIn", validate.Optional(validate.Describe(validate.Number(), "The number of seconds until the ban expires"))),
		),
		Use: []betterauth.Middleware{adminMiddleware}, Metadata: openapi("banUser"),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			s := adminSession(ctx)
			if !can(opts, s, map[string][]string{"user": {"ban"}}) {
				return nil, forbidden(ErrNotAllowedToBanUsers)
			}
			userID := ctx.BodyString("userId")
			ia := ctx.Auth.InternalAdapter
			existing, err := ia.FindUserByID(ctx.Context(), userID)
			if err != nil {
				return nil, err
			}
			if existing == nil {
				return nil, userNotFound()
			}
			if userID == s.User.ID {
				return nil, badRequest(ErrYouCannotBanYourself)
			}
			reason := ctx.BodyString("banReason")
			if reason == "" {
				reason = opts.DefaultBanReason
			}
			if reason == "" {
				reason = "No reason"
			}
			var expires any
			if n, _ := ctx.BodyMap()["banExpiresIn"].(float64); n != 0 {
				expires = secondsFromNow(n)
			} else if opts.DefaultBanExpiresIn != 0 {
				expires = time.Now().Add(opts.DefaultBanExpiresIn)
			}
			u, err := ia.UpdateUser(ctx.Context(), userID, adapter.Record{
				"banned": true, "banReason": reason, "banExpires": expires, "updatedAt": time.Now(),
			})
			if err != nil {
				return nil, err
			}
			if err := ia.DeleteUserSessions(ctx.Context(), userID); err != nil {
				return nil, err
			}
			return jsonx.O("user", ctx.Auth.UserOutput(u)), nil
		},
	}
}

// ---- impersonation ----

func impersonateUserEndpoint(opts *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "impersonateUser", Path: "/admin/impersonate-user", Methods: []string{"POST"},
		Body: validate.Object(validate.F("userId", validate.Describe(coerceString(""), "The user id"))),
		Use:  []betterauth.Middleware{adminMiddleware}, Metadata: openapi("impersonateUser"),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			s := adminSession(ctx)
			if !can(opts, s, map[string][]string{"user": {"impersonate"}}) {
				return nil, forbidden(ErrNotAllowedToImpersonateUsers)
			}
			ia := ctx.Auth.InternalAdapter
			target, err := ia.FindUserByID(ctx.Context(), ctx.BodyString("userId"))
			if err != nil {
				return nil, err
			}
			if target == nil {
				return nil, userNotFound()
			}
			adminRoles := make([]string, len(opts.AdminRoles))
			for i, r := range opts.AdminRoles {
				adminRoles[i] = strings.TrimSpace(r)
			}
			targetRole := userRole(target)
			if targetRole == "" {
				targetRole = opts.DefaultRole
			}
			if targetRole == "" {
				targetRole = "user"
			}
			isTargetAdmin := slices.Contains(opts.AdminUserIDs, target.ID)
			for _, r := range strings.Split(targetRole, ",") {
				if slices.Contains(adminRoles, r) {
					isTargetAdmin = true
				}
			}
			if isTargetAdmin && !opts.AllowImpersonatingAdmins &&
				!can(opts, s, map[string][]string{"user": {"impersonate-admins"}}) {
				return nil, forbidden(ErrYouCannotImpersonateAdmins)
			}
			duration := opts.ImpersonationSessionDuration
			if duration == 0 {
				duration = time.Hour
			}
			session, err := ia.CreateSession(ctx.Context(), target.ID, &betterauth.CreateSessionOptions{
				DontRememberMe: true, OverrideAll: true,
				Override: adapter.Record{"impersonatedBy": s.User.ID, "expiresAt": time.Now().Add(duration)},
			})
			if err != nil {
				return nil, err
			}
			if session == nil {
				return nil, betterauth.ErrFrom("INTERNAL_SERVER_ERROR", ErrFailedToCreateUser)
			}
			cookies := ctx.Auth.AuthCookies
			betterauth.DeleteSessionCookie(ctx, false)
			drm, _ := ctx.GetSignedCookie(cookies.DontRememberToken.Name, ctx.Auth.Secret)
			adminCookie := ctx.Auth.CreateAuthCookie("admin_session", nil)
			ctx.SetSignedCookie(adminCookie.Name, s.Session.Token+":"+drm, ctx.Auth.Secret, cookies.SessionToken.Attributes)
			if err := betterauth.SetSessionCookie(ctx, &betterauth.SessionWithUser{Session: session, User: target}, betterauth.Bool(true), nil); err != nil {
				return nil, err
			}
			return jsonx.O("session", ctx.Auth.SessionOutput(session), "user", ctx.Auth.UserOutput(target)), nil
		},
	}
}

func stopImpersonatingEndpoint() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "stopImpersonating", Path: "/admin/stop-impersonating", Methods: []string{"POST"},
		RequireHeaders: true,
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			s, err := betterauth.GetSessionFromCtx(ctx, nil)
			if err != nil {
				return nil, err
			}
			if s == nil {
				return nil, betterauth.ErrStatus("UNAUTHORIZED")
			}
			impersonatedBy, _ := s.Session.Get("impersonatedBy").(string)
			if impersonatedBy == "" {
				return nil, betterauth.ErrMessage("BAD_REQUEST", "You are not impersonating anyone")
			}
			ia := ctx.Auth.InternalAdapter
			user, err := ia.FindUserByID(ctx.Context(), impersonatedBy)
			if err != nil {
				return nil, err
			}
			if user == nil {
				return nil, betterauth.ErrMessage("INTERNAL_SERVER_ERROR", "Failed to find user")
			}
			adminCookie := ctx.Auth.CreateAuthCookie("admin_session", nil)
			value, ok := ctx.GetSignedCookie(adminCookie.Name, ctx.Auth.Secret)
			if !ok || value == "" {
				return nil, betterauth.ErrMessage("INTERNAL_SERVER_ERROR", "Failed to find admin session")
			}
			parts := strings.Split(value, ":")
			token, drm := parts[0], ""
			if len(parts) > 1 {
				drm = parts[1]
			}
			adminSess, err := ia.FindSession(ctx.Context(), token)
			if err != nil {
				return nil, err
			}
			if adminSess == nil || adminSess.Session.UserID != user.ID {
				return nil, betterauth.ErrMessage("INTERNAL_SERVER_ERROR", "Failed to find admin session")
			}
			if err := ia.DeleteSession(ctx.Context(), s.Session.Token); err != nil {
				return nil, err
			}
			if err := betterauth.SetSessionCookie(ctx, adminSess, betterauth.Bool(drm != ""), nil); err != nil {
				return nil, err
			}
			betterauth.ExpireCookie(ctx, adminCookie)
			return jsonx.O("session", ctx.Auth.SessionOutput(adminSess.Session), "user", ctx.Auth.UserOutput(adminSess.User)), nil
		},
	}
}

// ---- session revocation, removal, password ----

func revokeUserSessionEndpoint(opts *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "revokeUserSession", Path: "/admin/revoke-user-session", Methods: []string{"POST"},
		Body: validate.Object(validate.F("sessionToken", validate.Describe(validate.String(), "The session token"))),
		Use:  []betterauth.Middleware{adminMiddleware}, Metadata: openapi("revokeUserSession"),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			if !can(opts, adminSession(ctx), map[string][]string{"session": {"revoke"}}) {
				return nil, forbidden(ErrNotAllowedToRevokeUsersSessions)
			}
			if err := ctx.Auth.InternalAdapter.DeleteSession(ctx.Context(), ctx.BodyString("sessionToken")); err != nil {
				return nil, err
			}
			return jsonx.O("success", true), nil
		},
	}
}

func revokeUserSessionsEndpoint(opts *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "revokeUserSessions", Path: "/admin/revoke-user-sessions", Methods: []string{"POST"},
		Body: validate.Object(validate.F("userId", validate.Describe(coerceString(""), "The user id"))),
		Use:  []betterauth.Middleware{adminMiddleware}, Metadata: openapi("revokeUserSessions"),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			if !can(opts, adminSession(ctx), map[string][]string{"session": {"revoke"}}) {
				return nil, forbidden(ErrNotAllowedToRevokeUsersSessions)
			}
			if err := ctx.Auth.InternalAdapter.DeleteUserSessions(ctx.Context(), ctx.BodyString("userId")); err != nil {
				return nil, err
			}
			return jsonx.O("success", true), nil
		},
	}
}

func removeUserEndpoint(opts *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "removeUser", Path: "/admin/remove-user", Methods: []string{"POST"},
		Body: validate.Object(validate.F("userId", validate.Describe(coerceString(""), "The user id"))),
		Use:  []betterauth.Middleware{adminMiddleware}, Metadata: openapi("removeUser"),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			s := adminSession(ctx)
			if !can(opts, s, map[string][]string{"user": {"delete"}}) {
				return nil, forbidden(ErrNotAllowedToDeleteUsers)
			}
			userID := ctx.BodyString("userId")
			if userID == s.User.ID {
				return nil, badRequest(ErrYouCannotRemoveYourself)
			}
			ia := ctx.Auth.InternalAdapter
			u, err := ia.FindUserByID(ctx.Context(), userID)
			if err != nil {
				return nil, err
			}
			if u == nil {
				return nil, userNotFound()
			}
			if err := ia.DeleteUserSessions(ctx.Context(), userID); err != nil {
				return nil, err
			}
			if err := ia.DeleteUser(ctx.Context(), userID); err != nil {
				return nil, err
			}
			return jsonx.O("success", true), nil
		},
	}
}

func setUserPasswordEndpoint(opts *Options) *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "setUserPassword", Path: "/admin/set-user-password", Methods: []string{"POST"},
		Body: validate.Object(
			validate.F("newPassword", validate.Describe(validate.String().MinMessage(1, "newPassword cannot be empty"), "The new password")),
			validate.F("userId", validate.Describe(coerceString("userId cannot be empty"), "The user id")),
		),
		Use: []betterauth.Middleware{adminMiddleware}, Metadata: openapi("setUserPassword"),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			if !can(opts, adminSession(ctx), map[string][]string{"user": {"set-password"}}) {
				return nil, forbidden(ErrNotAllowedToSetUsersPassword)
			}
			newPassword, userID := ctx.BodyString("newPassword"), ctx.BodyString("userId")
			if err := assertPasswordLength(ctx, newPassword, true); err != nil {
				return nil, err
			}
			ia := ctx.Auth.InternalAdapter
			u, err := ia.FindUserByID(ctx.Context(), userID)
			if err != nil {
				return nil, err
			}
			if u == nil {
				return nil, userNotFound()
			}
			hashed, err := ctx.Auth.Password.Hash(newPassword)
			if err != nil {
				return nil, err
			}
			cred, err := ia.FindCredentialAccount(ctx.Context(), userID)
			if err != nil {
				return nil, err
			}
			if cred != nil {
				if err := ia.UpdatePassword(ctx.Context(), userID, hashed); err != nil {
					return nil, err
				}
			} else if _, err := ia.CreateAccount(ctx.Context(), adapter.Record{
				"userId": userID, "providerId": "credential", "accountId": u.ID, "password": hashed,
			}); err != nil {
				return nil, err
			}
			return jsonx.O("status", true), nil
		},
	}
}

// ---- /admin/has-permission ----

func userHasPermissionEndpoint(opts *Options) *betterauth.Endpoint {
	perms := validate.Record(validate.Array(validate.String()))
	return &betterauth.Endpoint{
		Key: "userHasPermission", Path: "/admin/has-permission", Methods: []string{"POST"},
		Body: validate.And(
			validate.Object(
				// .optional().meta(...): descriptions on optional wrappers are not emitted upstream.
				validate.F("userId", validate.Optional(coerceString(""))),
				validate.F("role", validate.Optional(validate.String())),
			),
			xor(validate.Object(validate.F("permission", perms)), validate.Object(validate.F("permissions", perms))),
		),
		Metadata: openapi("userHasPermission"),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			body := ctx.BodyMap()
			rawPerms, _ := body["permissions"].(map[string]any)
			if rawPerms == nil {
				return nil, betterauth.ErrMessage("BAD_REQUEST", "invalid permission check. no permission(s) were passed.")
			}
			session, err := betterauth.GetAuthoritativeSessionFromCtx(ctx)
			if err != nil {
				return nil, err
			}
			if session == nil && (ctx.Request != nil || ctx.Headers != nil) {
				return nil, betterauth.ErrStatus("UNAUTHORIZED")
			}
			userID, role := ctx.BodyString("userId"), ctx.BodyString("role")
			if session == nil && userID == "" && role == "" {
				return nil, betterauth.ErrMessage("BAD_REQUEST", "user id or role is required")
			}
			var id, r string
			found := false
			switch {
			case session != nil:
				id, r, found = session.User.ID, userRole(session.User), true
			case role != "":
				id, r, found = userID, role, true
			case userID != "":
				u, err := ctx.Auth.InternalAdapter.FindUserByID(ctx.Context(), userID)
				if err != nil {
					return nil, err
				}
				if u != nil {
					id, r, found = u.ID, userRole(u), true
				}
			}
			if !found {
				return nil, betterauth.ErrMessage("BAD_REQUEST", "user not found")
			}
			permissions := map[string][]string{}
			for k, v := range rawPerms {
				var actions []string
				for _, a := range roleList(v) {
					if s, ok := a.(string); ok {
						actions = append(actions, s)
					}
				}
				permissions[k] = actions
			}
			result := HasPermission(HasPermissionInput{UserID: id, Role: r, Options: opts, Permissions: permissions})
			return jsonx.O("error", nil, "success", result), nil
		},
	}
}
