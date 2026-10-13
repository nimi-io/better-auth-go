package oauthprovider

import (
	"errors"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
)

// Port of packages/oauth-provider/src/register.ts (dynamic client registration and the
// shared client creation path).

func metaErr(desc string) *betterauth.APIError {
	return oauthErr("BAD_REQUEST", "invalid_client_metadata", desc)
}

func mdStr(o *jsonx.Object, k string) string { return objString(o, k) }

func mdHas(o *jsonx.Object, k string) bool {
	if o == nil {
		return false
	}
	v, ok := o.Get(k)
	return ok && v != nil && v != jsonx.Undefined && !isUndef(v)
}

func mdStrings(o *jsonx.Object, k string) []string {
	if !mdHas(o, k) {
		return nil
	}
	v, _ := o.Get(k)
	return toStrings(v)
}

func mdBool(o *jsonx.Object, k string) *bool {
	if !mdHas(o, k) {
		return nil
	}
	v, _ := o.Get(k)
	b, ok := v.(bool)
	if !ok {
		return nil
	}
	return &b
}

func (o *resolved) registrationScopes() []string {
	base := o.ClientRegistrationDefaultScopes
	if base == nil {
		base = o.Scopes
	}
	return uniqueStrings(append(append([]string{}, base...), o.ClientRegistrationAllowedScopes...))
}

func resolveRegistrationGrantTypes(md *jsonx.Object) ([]string, error) {
	if !mdHas(md, "grant_types") {
		return []string{"authorization_code"}, nil
	}
	g := mdStrings(md, "grant_types")
	if len(g) == 0 {
		return nil, metaErr("grant_types must contain at least one grant type")
	}
	return g, nil
}

// applyRegistrationDefaults is applyOAuthClientRegistrationDefaults.
func applyRegistrationDefaults(md *jsonx.Object, defaultAppType string) (*jsonx.Object, error) {
	grants, err := resolveRegistrationGrantTypes(md)
	if err != nil {
		return nil, err
	}
	out := md.Clone()
	if !mdHas(out, "token_endpoint_auth_method") {
		out.Set("token_endpoint_auth_method", "client_secret_basic")
	}
	if !mdHas(out, "application_type") {
		if defaultAppType == "" {
			out.Set("application_type", jsonx.Undefined)
		} else {
			out.Set("application_type", defaultAppType)
		}
	}
	out.Set("grant_types", stringsToAny(grants))
	if !mdHas(md, "response_types") {
		if contains(grants, "authorization_code") {
			out.Set("response_types", []any{"code"})
		} else {
			out.Set("response_types", jsonx.Undefined)
		}
	}
	return out, nil
}

var forbiddenNativeSchemes = map[string]bool{"file": true, "ftp": true, "mailto": true, "javascript": true, "data": true, "vbscript": true}

func invalidRedirectURI(desc string) error {
	return oauthErr("BAD_REQUEST", "invalid_redirect_uri", desc)
}

var rawHTTPAuthority = regexp.MustCompile(`(?i)^http://([^/?#]*)`)
var localhostDots = regexp.MustCompile(`(?i)^localhost\.+$`)

func rawHTTPHostname(uri string) string {
	m := rawHTTPAuthority.FindStringSubmatch(uri)
	if m == nil || m[1] == "" {
		return ""
	}
	hp := m[1][strings.LastIndex(m[1], "@")+1:]
	if strings.HasPrefix(hp, "[") {
		end := strings.Index(hp, "]")
		if end < 0 {
			return ""
		}
		return strings.ToLower(hp[:end+1])
	}
	return strings.ToLower(strings.Split(hp, ":")[0])
}

func validateClientRedirectURI(uri, appType string) error {
	u, err := parseURL(uri)
	if err != nil {
		return invalidRedirectURI("redirect URI must be an absolute URI: " + uri)
	}
	if strings.Contains(uri, "#") || urlHasCredentials(u) {
		return invalidRedirectURI("redirect URI must not include credentials or a fragment: " + uri)
	}
	host := u.Hostname()
	if localhostDots.MatchString(host) {
		return invalidRedirectURI("redirect URI localhost must not include trailing dots: " + uri)
	}
	loopback := isLoopbackIP(host) || host == "localhost"
	raw := rawHTTPHostname(uri)
	nativeLoopback := raw == "localhost" || raw == "127.0.0.1" || raw == "[::1]"
	if appType == "web" {
		if u.Scheme != "https" || loopback {
			return invalidRedirectURI("web clients require https redirect URIs on non-loopback hosts: " + uri)
		}
		return nil
	}
	switch u.Scheme {
	case "https":
		if loopback {
			return invalidRedirectURI("native clients must not use https loopback redirect URIs: " + uri)
		}
		return nil
	case "http":
		if !nativeLoopback {
			return invalidRedirectURI("native clients may use http only on the exact loopback hosts localhost, 127.0.0.1, or [::1]: " + uri)
		}
		return nil
	}
	if forbiddenNativeSchemes[u.Scheme] || !isReverseDomainPrivateUseRedirectURI(uri, u) {
		return invalidRedirectURI("native private-use redirect URI schemes must be well-formed reverse-domain names, omit the naming authority, and must not use a reserved scheme: " + uri)
	}
	return nil
}

type checkSettings struct {
	source string // "dynamic", "managed", "clientMetadataDocument", ""
	ctx    *betterauth.EndpointContext
}

// checkOAuthClient validates client metadata (checkOAuthClient).
func checkOAuthClient(md *jsonx.Object, o *resolved, s checkSettings) error {
	cimd := s.source == "clientMetadataDocument"
	def := "web"
	if cimd {
		def = ""
	}
	c, err := applyRegistrationDefaults(md, def)
	if err != nil {
		return err
	}
	method := mdStr(c, "token_endpoint_auth_method")
	if method == "" {
		method = "client_secret_basic"
	}
	if !contains(o.supportedAuthMethods(true), method) {
		return metaErr("unsupported token_endpoint_auth_method " + method)
	}
	if v, ok := c.Get("dpop_bound_access_tokens"); ok && v != jsonx.Undefined && !isUndef(v) {
		if _, isBool := v.(bool); !isBool {
			return metaErr("dpop_bound_access_tokens must be a boolean")
		}
	}
	grants := mdStrings(c, "grant_types")
	var responseTypes []string
	hasResponseTypes := mdHas(c, "response_types")
	if hasResponseTypes {
		responseTypes = mdStrings(c, "response_types")
	}
	appV, _ := c.Get("application_type")
	appType, _ := appV.(string)
	if mdHas(c, "application_type") && appType != "web" && appType != "native" {
		return metaErr("application_type must be web or native")
	}
	redirects := mdStrings(c, "redirect_uris")
	if contains(grants, "authorization_code") && len(redirects) == 0 {
		return oauthErr("BAD_REQUEST", "invalid_redirect_uri", "Redirect URIs are required for authorization_code and implicit grant types")
	}
	for _, uri := range redirects {
		t := appType
		if t == "" {
			t = "web"
			if cimd {
				t = "native"
			}
		}
		if err := validateClientRedirectURI(uri, t); err != nil {
			return err
		}
	}
	supported := o.supportedGrantTypes()
	if cimd {
		ok := false
		for _, g := range grants {
			if contains(supported, g) {
				ok = true
			}
		}
		if !ok {
			return metaErr("no mutually supported grant_type among " + strings.Join(grants, ", "))
		}
	} else {
		for _, g := range grants {
			if !contains(supported, g) {
				return metaErr("unsupported grant_type " + g)
			}
		}
	}
	if contains(grants, "authorization_code") && !contains(responseTypes, "code") {
		return metaErr("When 'authorization_code' grant type is used, 'code' response type must be included")
	}
	if !contains(grants, "authorization_code") && contains(responseTypes, "code") {
		return metaErr("When 'code' response type is used, 'authorization_code' grant type must be included")
	}
	if mdHas(c, "subject_type") {
		st := mdStr(c, "subject_type")
		if st != "public" && st != "pairwise" {
			return metaErr(`subject_type must be "public" or "pairwise"`)
		}
		if st == "pairwise" && o.PairwiseSecret == "" {
			return metaErr("pairwise subject_type requires server pairwiseSecret configuration")
		}
		if st == "pairwise" && len(redirects) > 1 {
			hosts := map[string]bool{}
			for _, r := range redirects {
				if u, err := parseURL(r); err == nil {
					hosts[u.Host] = true
				}
			}
			if len(hosts) > 1 {
				return metaErr("pairwise clients with redirect_uris on different hosts require a sector_identifier_uri, which is not yet supported. All redirect_uris must share the same host.")
			}
		}
	}
	var requested []string
	for _, sc := range strings.Split(mdStr(c, "scope"), " ") {
		if sc != "" {
			requested = append(requested, sc)
		}
	}
	validates := s.source == "dynamic" || cimd
	allowed := o.Scopes
	if validates {
		allowed = o.registrationScopes()
	}
	for _, sc := range requested {
		if !contains(allowed, sc) {
			return oauthErr("BAD_REQUEST", "invalid_scope", "cannot request scope "+sc)
		}
	}
	if validates {
		if b := mdBool(c, "require_pkce"); b != nil && !*b {
			return metaErr("pkce is required for registered clients.")
		}
	}
	hasJwks, hasJwksURI := mdHas(c, "jwks"), mdStr(c, "jwks_uri") != ""
	if hasJwks || hasJwksURI {
		if hasJwks && hasJwksURI {
			return metaErr("jwks and jwks_uri are mutually exclusive")
		}
		if hasJwksURI {
			raw := mdStr(c, "jwks_uri")
			u, err := parseURL(raw)
			if err != nil {
				return metaErr("jwks_uri must be a valid URL")
			}
			if u.Scheme != "https" {
				return metaErr("jwks_uri must use HTTPS")
			}
			if urlHasCredentials(u) {
				return metaErr("jwks_uri must not contain credentials")
			}
			if strings.Contains(raw, "#") {
				return metaErr("jwks_uri must not include a fragment component")
			}
			if isPrivateHostname(u.Hostname()) {
				return metaErr("jwks_uri must not point to a private or reserved address")
			}
			if s.ctx != nil && !s.ctx.Auth.IsTrustedOrigin(u.String(), false) {
				cid := mdStr(c, "client_id")
				sameOrigin := cimd && cid != "" && canParseURL(cid) && urlOrigin(cid) == originOf(u)
				if !sameOrigin {
					return metaErr("jwks_uri must belong to a trusted origin or the Client ID Metadata Document origin")
				}
			}
		}
		if hasJwks {
			v, _ := c.Get("jwks")
			if r := ValidatePublicClientJwks(v); !r.Valid {
				return metaErr(r.Error)
			}
		}
	}
	if method == "private_key_jwt" && !hasJwks && !hasJwksURI {
		return metaErr("private_key_jwt requires either jwks or jwks_uri")
	}
	if mdHas(c, "backchannel_logout_uri") {
		if o.DisableJwtPlugin {
			return metaErr("backchannel_logout_uri requires the jwt plugin (disableJwtPlugin must be false)")
		}
		raw := mdStr(c, "backchannel_logout_uri")
		u, err := parseURL(raw)
		if err != nil {
			return metaErr("backchannel_logout_uri must be an absolute URL")
		}
		if strings.Contains(raw, "#") {
			return metaErr("backchannel_logout_uri must not include a fragment component")
		}
		if u.Scheme != "https" {
			return metaErr("backchannel_logout_uri must use https")
		}
		if urlHasCredentials(u) {
			return metaErr("backchannel_logout_uri must not contain credentials")
		}
		if isPrivateHostname(u.Hostname()) {
			return metaErr("backchannel_logout_uri must not point to a private or reserved address")
		}
	}
	return nil
}

// registrationInput is CreateOAuthClientRegistrationInput / RegisterClientMetadataDocumentInput.
type registrationInput struct {
	metadata                *jsonx.Object
	source                  string
	userID                  string
	referenceID             string
	clientID                string
	requestedResources      []string
	clientCredentialsScopes []string
	clientDiscoveryID       string
	existingClient          *SchemaClient
}

// ClientRegistrationResult is OAuthClientRegistrationResult.
type ClientRegistrationResult struct {
	Client       *SchemaClient
	ClientSecret string
	Resources    []string
	Created      bool
}

type registrationCollision struct {
	kind       string
	clientID   string
	resourceID string
	cause      error
}

func (c *registrationCollision) Error() string { return c.cause.Error() }

func persistRegistration(ctx *betterauth.EndpointContext, o *resolved, in registrationInput) (*ClientRegistrationResult, error) {
	md := in.metadata
	if in.source == "dynamic" && mdStr(md, "scope") == "" {
		md = md.Clone()
		sc := o.ClientRegistrationDefaultScopes
		if sc == nil {
			sc = o.Scopes
		}
		md.Set("scope", strings.Join(sc, " "))
	}
	def := "web"
	if in.source == "clientMetadataDocument" {
		def = ""
	}
	body, err := applyRegistrationDefaults(md, def)
	if err != nil {
		return nil, err
	}
	method := mdStr(body, "token_endpoint_auth_method")
	isPublic := method == "none"
	isPKJ := method == "private_key_jwt"
	isExt := o.isExtensionAuthMethod(method)
	if err := checkOAuthClient(body, o, checkSettings{source: in.source, ctx: ctx}); err != nil {
		return nil, err
	}
	clientID := in.clientID
	if clientID == "" && o.GenerateClientID != nil {
		clientID = o.GenerateClientID()
	}
	if clientID == "" {
		clientID = bacrypto.RandomString(32, "a-z", "A-Z")
	}
	secret := ""
	if !isPublic && !isPKJ && !isExt {
		if o.GenerateClientSecret != nil {
			secret = o.GenerateClientSecret()
		}
		if secret == "" {
			secret = bacrypto.RandomString(32, "a-z", "A-Z")
		}
	}
	stored := ""
	if secret != "" {
		stored, err = storeClientSecret(ctx, o, secret)
		if err != nil {
			return nil, err
		}
	}
	var requirePKCE *bool
	if b := mdBool(body, "require_pkce"); b != nil {
		requirePKCE = b
	} else if in.source == "dynamic" && !isPublic && o.ClientRegistrationRequirePKCE != nil && !*o.ClientRegistrationRequirePKCE {
		requirePKCE = boolPtr(false)
	}
	iat := time.Now().Unix()
	effective := body.Clone()
	if in.source == "dynamic" || in.source == "clientMetadataDocument" {
		effective.Set("scope", strings.Join(o.registrationScopes(), " "))
	}
	effective.Delete("resources")
	if !mdHas(effective, "redirect_uris") {
		effective.Set("redirect_uris", []any{})
	}
	effective.Set("disabled", jsonx.Undefined)
	if stored != "" {
		var exp any = 0
		if in.source == "dynamic" && o.ClientRegistrationClientSecretExpiration != nil {
			e, err := jwt.ToExpJWT(o.ClientRegistrationClientSecretExpiration, iat)
			if err != nil {
				return nil, err
			}
			exp = float64(e)
		}
		effective.Set("client_secret_expires_at", exp)
	} else {
		effective.Set("client_secret_expires_at", jsonx.Undefined)
	}
	effective.Set("client_id", clientID)
	if stored != "" {
		effective.Set("client_secret", stored)
	} else {
		effective.Set("client_secret", jsonx.Undefined)
	}
	effective.Set("client_id_issued_at", float64(iat))
	if requirePKCE != nil {
		effective.Set("require_pkce", *requirePKCE)
	} else {
		effective.Set("require_pkce", jsonx.Undefined)
	}
	effective.Set("user_id", jsonx.Undefined)
	effective.Set("reference_id", jsonx.Undefined)
	if in.source != "clientMetadataDocument" {
		if in.referenceID != "" {
			effective.Set("reference_id", in.referenceID)
		} else if in.userID != "" {
			effective.Set("user_id", in.userID)
		}
	}
	schema := oauthToSchema(effective)
	switch in.source {
	case "clientMetadataDocument":
		schema.ClientCredentialsScopes = []string{}
		if in.existingClient != nil && in.existingClient.ClientCredentialsScopes != nil {
			schema.ClientCredentialsScopes = in.existingClient.ClientCredentialsScopes
		}
		schema.ClientDiscoveryID = in.clientDiscoveryID
	case "managed":
		schema.ClientCredentialsScopes = nonNil(in.clientCredentialsScopes)
	default:
		schema.ClientCredentialsScopes = []string{}
	}
	record := schema.ToRecord()
	if in.source != "clientMetadataDocument" {
		record["clientDiscoveryId"] = nil
	}
	if in.source == "clientMetadataDocument" && !mdHas(body, "application_type") {
		record["applicationType"] = nil
	}
	var resources []string
	if in.source == "dynamic" {
		resources, err = resolveRegistrationResources(ctx, o, in.requestedResources)
	} else {
		resources, err = resolveRegistrationResources(ctx, o, nil)
	}
	if err != nil {
		return nil, err
	}
	result := &ClientRegistrationResult{ClientSecret: secret, Resources: resources}
	err = ctx.Transaction(func() error {
		c := ctx.Context()
		if in.existingClient != nil {
			upd := copyRecord(record)
			setBoolOrNil(upd, "disabled", in.existingClient.Disabled)
			setBoolOrNil(upd, "skipConsent", in.existingClient.SkipConsent)
			setBoolOrNil(upd, "enableEndSession", in.existingClient.EnableEndSession)
			if in.existingClient.CreatedAt != nil {
				upd["createdAt"] = *in.existingClient.CreatedAt
			}
			upd["updatedAt"] = time.Unix(iat, 0)
			r, err := ctx.Auth.Adapter.Update(c, modelClient, []adapter.Where{{Field: "clientId", Value: clientID},
				{Field: "clientDiscoveryId", Value: in.clientDiscoveryID}}, upd)
			if err != nil {
				return err
			}
			if r == nil {
				return oauthErr("BAD_REQUEST", "invalid_client", "client no longer exists")
			}
			result.Client = ClientFromRecord(r)
		} else {
			data := copyRecord(record)
			data["createdAt"] = time.Unix(iat, 0)
			data["updatedAt"] = time.Unix(iat, 0)
			r, err := ctx.Auth.Adapter.Create(c, adapter.CreateInput{Model: modelClient, Data: data})
			if err != nil {
				if in.source == "clientMetadataDocument" && isUniqueConstraintError(err) {
					return &registrationCollision{kind: "oauth-client-row-unique", clientID: clientID, cause: err}
				}
				return err
			}
			result.Client = ClientFromRecord(r)
			result.Created = true
		}
		linked := map[string]bool{}
		if len(resources) > 0 {
			links, err := ctx.Auth.Adapter.FindMany(c, adapter.FindManyInput{Model: modelClientResource,
				Where: []adapter.Where{{Field: "clientId", Value: clientID}}})
			if err != nil {
				return err
			}
			for _, l := range links {
				linked[recStr(l, "resourceId")] = true
			}
		}
		now := time.Now()
		for _, rid := range resources {
			if linked[rid] {
				continue
			}
			if _, err := ctx.Auth.Adapter.Create(c, adapter.CreateInput{Model: modelClientResource,
				Data: adapter.Record{"clientId": clientID, "resourceId": rid, "createdAt": now}}); err != nil {
				if in.source == "clientMetadataDocument" && isUniqueConstraintError(err) {
					return &registrationCollision{kind: "oauth-client-resource-link-unique", clientID: clientID, resourceID: rid, cause: err}
				}
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func setBoolOrNil(r adapter.Record, k string, b *bool) {
	if b == nil {
		delete(r, k)
		return
	}
	r[k] = *b
}

var uniqueCodes = map[string]bool{"1062": true, "11000": true, "23505": true, "ER_DUP_ENTRY": true, "P2002": true, "SQLITE_CONSTRAINT_UNIQUE": true}
var uniqueMsgRe = regexp.MustCompile(`(?i)duplicate|unique constraint|unique key`)

func isUniqueConstraintError(err error) bool {
	for e := err; e != nil; e = errors.Unwrap(e) {
		if s, ok := e.(interface{ SQLState() string }); ok && uniqueCodes[s.SQLState()] {
			return true
		}
		if uniqueMsgRe.MatchString(e.Error()) {
			return true
		}
	}
	return false
}

func resolveRegistrationResources(ctx *betterauth.EndpointContext, o *resolved, requested []string) ([]string, error) {
	allowed := uniqueStrings(append(append([]string{}, o.ClientRegistrationDefaultResources...), o.ClientRegistrationAllowedResources...))
	for _, id := range requested {
		if !contains(allowed, id) {
			return nil, oauthErr("BAD_REQUEST", "invalid_target", "requested resource "+id+" is not allowed for client registration")
		}
	}
	res := uniqueStrings(append(append([]string{}, o.ClientRegistrationDefaultResources...), requested...))
	for _, id := range res {
		r, err := getResource(ctx, o, id)
		if err != nil {
			return nil, err
		}
		if r == nil {
			return nil, oauthErr("BAD_REQUEST", "invalid_target", "requested resource "+id+" does not exist")
		}
		if r.Disabled {
			return nil, oauthErr("BAD_REQUEST", "invalid_target", "requested resource "+id+" is disabled")
		}
	}
	if res == nil {
		res = []string{}
	}
	return res, nil
}

func registrationResponse(o *resolved, r *ClientRegistrationResult) *jsonx.Object {
	c := r.Client.Clone()
	if r.ClientSecret != "" {
		c.ClientSecret = o.prefix().ClientSecret + r.ClientSecret
	} else {
		c.ClientSecret = ""
	}
	out := SchemaToOAuth(c)
	if len(r.Resources) > 0 {
		out.Set("resources", stringsToAny(r.Resources))
	}
	return out
}

func adminRegistrationResponse(o *resolved, r *ClientRegistrationResult) *jsonx.Object {
	out := registrationResponse(o, r)
	out.Set("client_credentials_scopes", stringsToAny(nonNil(r.Client.ClientCredentialsScopes)))
	return out
}

// registerEndpoint handles POST /oauth2/register.
func registerEndpoint(ctx *betterauth.EndpointContext, o *resolved, body *jsonx.Object) (any, error) {
	if !o.AllowDynamicClientRegistration {
		return nil, oauthErr("FORBIDDEN", "access_denied", "Client registration is disabled")
	}
	session, err := betterauth.GetSessionFromCtx(ctx, nil)
	if err != nil {
		return nil, err
	}
	var tokenAuth *InitialAccessTokenAuthorization
	if session == nil {
		tokenAuth, err = authorizeInitialAccessToken(ctx, o, body)
		if err != nil {
			return nil, err
		}
	}
	if session == nil && tokenAuth == nil && !o.AllowUnauthenticatedClientRegistration {
		e := betterauth.NewAPIError("UNAUTHORIZED", jsonx.O("error_description", "Authentication required for client registration"))
		e.Headers.Set("WWW-Authenticate", "Bearer")
		e.Headers.Set("Cache-Control", "no-store")
		e.Headers.Set("Pragma", "no-cache")
		return nil, e
	}
	if session == nil && tokenAuth == nil && contains(mdStrings(body, "grant_types"), "client_credentials") {
		return nil, metaErr("client_credentials grant requires authenticated registration")
	}
	var requested []string
	for _, r := range mdStrings(body, "resources") {
		if r != "" {
			requested = append(requested, r)
		}
	}
	if session != nil {
		if err := assertClientPrivileges(ctx, session, o, "create"); err != nil {
			return nil, err
		}
	}
	referenceID := ""
	if tokenAuth != nil {
		referenceID = tokenAuth.ReferenceID
	}
	if referenceID == "" && session != nil && o.ClientReference != nil {
		referenceID, err = o.ClientReference(UserSessionContext{Ctx: ctx, Headers: ctx.Headers, User: session.User, Session: session.Session})
		if err != nil {
			return nil, err
		}
	}
	in := registrationInput{metadata: body, source: "dynamic", referenceID: referenceID, requestedResources: requested}
	if referenceID == "" && session != nil {
		in.userID = session.Session.UserID
	}
	res, err := persistRegistration(ctx, o, in)
	if err != nil {
		return nil, err
	}
	ctx.SetStatus(201)
	return registrationResponse(o, res), nil
}

func authorizeInitialAccessToken(ctx *betterauth.EndpointContext, o *resolved, md *jsonx.Object) (*InitialAccessTokenAuthorization, error) {
	bearerErr := func(status, code, desc string) error {
		e := oauthErr(status, code, desc)
		e.Headers.Set("WWW-Authenticate", `Bearer error="`+code+`"`)
		e.Headers.Set("Cache-Control", "no-store")
		e.Headers.Set("Pragma", "no-cache")
		return e
	}
	token, err := parseBearerToken(ctx.GetHeader("Authorization"))
	if err != nil {
		return nil, bearerErr("BAD_REQUEST", "invalid_request", "Malformed initial access token Authorization header")
	}
	if token == "" || ctx.Headers == nil {
		return nil, nil
	}
	if o.ValidateInitialAccessToken == nil {
		return nil, bearerErr("UNAUTHORIZED", "invalid_token", "Invalid initial access token")
	}
	a, err := o.ValidateInitialAccessToken(InitialAccessTokenContext{Ctx: ctx, InitialAccessToken: token, Headers: ctx.Headers,
		ClientMetadata: objectToMap(md)})
	if err != nil {
		if _, ok := betterauth.AsAPIError(err); ok {
			return nil, err
		}
		return nil, oauthErr("INTERNAL_SERVER_ERROR", "server_error", "Initial access token validation failed")
	}
	if a == nil {
		return nil, bearerErr("UNAUTHORIZED", "invalid_token", "Invalid initial access token")
	}
	return a, nil
}

// RegisterClientMetadataDocumentInput registers a client from a Client ID Metadata
// Document (RegisterClientMetadataDocumentInput).
type RegisterClientMetadataDocumentInput struct {
	Metadata          *jsonx.Object
	ClientID          string
	ClientDiscoveryID string
	ExistingClient    *SchemaClient
}

// RegisterClientMetadataDocument creates or refreshes the client row backing a Client ID
// Metadata Document (registerClientMetadataDocument, used by the cimd package).
func RegisterClientMetadataDocument(ctx *betterauth.EndpointContext, in RegisterClientMetadataDocumentInput) (*ClientRegistrationResult, error) {
	o, err := pluginOptions(ctx.Auth)
	if err != nil {
		return nil, err
	}
	if in.ExistingClient != nil && in.ExistingClient.ClientDiscoveryID != in.ClientDiscoveryID {
		return nil, oauthErr("BAD_REQUEST", "invalid_client", "client_id is already owned by a different registration source")
	}
	if mdHas(in.Metadata, "backchannel_logout_uri") || mdHas(in.Metadata, "backchannel_logout_session_required") {
		return nil, metaErr("Client ID Metadata Documents cannot register a back-channel logout target")
	}
	m := mdStr(in.Metadata, "token_endpoint_auth_method")
	if m == "" {
		m = "none"
	}
	if m != "none" && m != "private_key_jwt" {
		return nil, metaErr("Client ID Metadata Document clients cannot use a shared secret")
	}
	md := in.Metadata.Clone()
	md.Set("token_endpoint_auth_method", m)
	md.Set("client_secret", jsonx.Undefined)
	md.Set("client_secret_expires_at", jsonx.Undefined)
	ri := registrationInput{metadata: md, source: "clientMetadataDocument", clientID: in.ClientID,
		clientDiscoveryID: in.ClientDiscoveryID, existingClient: in.ExistingClient}
	res, err := persistRegistration(ctx, o, ri)
	if err == nil {
		return res, nil
	}
	var col *registrationCollision
	if !errors.As(err, &col) {
		return nil, err
	}
	cur, ferr := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: modelClient,
		Where: []adapter.Where{{Field: "clientId", Value: in.ClientID}}})
	current := ClientFromRecord(cur)
	if ferr != nil || col.clientID != in.ClientID || current == nil || current.ClientDiscoveryID != in.ClientDiscoveryID {
		return nil, col.cause
	}
	if col.kind == "oauth-client-resource-link-unique" {
		link, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: modelClientResource,
			Where: []adapter.Where{{Field: "clientId", Value: col.clientID}, {Field: "resourceId", Value: col.resourceID}}})
		if err != nil || link == nil {
			return nil, col.cause
		}
	}
	ri.existingClient = current
	res, err = persistRegistration(ctx, o, ri)
	if errors.As(err, &col) {
		return nil, col.cause
	}
	return res, err
}

// createOAuthClientEndpoint handles /oauth2/create-client and /admin/oauth2/create-client.
func createOAuthClientEndpoint(ctx *betterauth.EndpointContext, o *resolved, admin bool) (any, error) {
	session, err := betterauth.GetSessionFromCtx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if err := assertClientPrivileges(ctx, session, o, "create"); err != nil {
		return nil, err
	}
	if session == nil {
		return nil, apiErr("UNAUTHORIZED")
	}
	referenceID := ""
	if o.ClientReference != nil {
		referenceID, err = o.ClientReference(UserSessionContext{Ctx: ctx, Headers: ctx.Headers, User: session.User, Session: session.Session})
		if err != nil {
			return nil, err
		}
	}
	md := mapToObjectOrdered(ctx.Body)
	raw := mdStrings(md, "client_credentials_scopes")
	md.Delete("client_credentials_scopes")
	var cc []string
	if admin {
		cc = normalizeClientCredentialsScopes(raw)
	}
	grants, err := resolveRegistrationGrantTypes(md)
	if err != nil {
		return nil, err
	}
	if err := validateClientCredentialsScopes(cc, grants, mdStr(md, "token_endpoint_auth_method"), o); err != nil {
		return nil, err
	}
	if len(cc) > 0 {
		if err := assertClientPrivileges(ctx, session, o, "configure-client-credentials-scopes"); err != nil {
			return nil, err
		}
	}
	in := registrationInput{metadata: md, source: "managed", referenceID: referenceID, clientCredentialsScopes: cc}
	if referenceID == "" {
		in.userID = session.Session.UserID
	}
	res, err := persistRegistration(ctx, o, in)
	if err != nil {
		return nil, err
	}
	ctx.SetStatus(201)
	if admin {
		return adminRegistrationResponse(o, res), nil
	}
	return registrationResponse(o, res), nil
}

// mapToObjectOrdered converts a validated body into an ordered object.
func mapToObjectOrdered(v any) *jsonx.Object {
	if o := asObject(v); o != nil {
		return o.Clone()
	}
	return jsonx.NewObject()
}

// oauthToSchema converts wire client metadata into a schema client (oauthToSchema).
func oauthToSchema(in *jsonx.Object) *SchemaClient {
	c := &SchemaClient{
		ClientID: mdStr(in, "client_id"), ClientSecret: mdStr(in, "client_secret"), Disabled: mdBool(in, "disabled"),
		UserID: mdStr(in, "user_id"), Name: mdStr(in, "client_name"), URI: mdStr(in, "client_uri"), Icon: mdStr(in, "logo_uri"),
		Contacts: mdStrings(in, "contacts"), Tos: mdStr(in, "tos_uri"), Policy: mdStr(in, "policy_uri"),
		SoftwareID: mdStr(in, "software_id"), SoftwareVersion: mdStr(in, "software_version"),
		SoftwareStatement: mdStr(in, "software_statement"), RedirectURIs: mdStrings(in, "redirect_uris"),
		PostLogoutRedirectURIs: mdStrings(in, "post_logout_redirect_uris"), BackchannelLogoutURI: mdStr(in, "backchannel_logout_uri"),
		BackchannelLogoutSessionRequired: mdBool(in, "backchannel_logout_session_required"),
		TokenEndpointAuthMethod:          mdStr(in, "token_endpoint_auth_method"), GrantTypes: mdStrings(in, "grant_types"),
		ResponseTypes: mdStrings(in, "response_types"), JwksURI: mdStr(in, "jwks_uri"), ApplicationType: mdStr(in, "application_type"),
		SkipConsent: mdBool(in, "skip_consent"), EnableEndSession: mdBool(in, "enable_end_session"),
		RequirePKCE: mdBool(in, "require_pkce"), DPoPBoundAccessTokens: mdBool(in, "dpop_bound_access_tokens"),
		SubjectType: mdStr(in, "subject_type"), ReferenceID: mdStr(in, "reference_id"),
	}
	if v, ok := in.Get("client_secret_expires_at"); ok {
		if n := numberish(v); n != 0 && !math.IsNaN(n) {
			t := time.UnixMilli(int64(n * 1000))
			c.ExpiresAt = &t
		}
	}
	if v, ok := in.Get("client_id_issued_at"); ok {
		if n := numberish(v); n != 0 {
			t := time.UnixMilli(int64(n * 1000))
			c.CreatedAt = &t
		}
	}
	if mdHas(in, "scope") {
		c.Scopes = strings.Split(mdStr(in, "scope"), " ")
	}
	if mdHas(in, "jwks") {
		v, _ := in.Get("jwks")
		b, _ := jsonx.Marshal(normalizeJSON(v))
		c.Jwks = string(b)
	}
	var meta *jsonx.Object
	if mdHas(in, "metadata") {
		v, _ := in.Get("metadata")
		meta = asObject(v)
	}
	if m := stripReservedMetadata(meta); m != nil && m.Len() > 0 {
		b, _ := jsonx.Marshal(m)
		c.Metadata = string(b)
	}
	return c
}

func numberish(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case string:
		return jsNumber(t)
	}
	return 0
}

// SchemaToOAuth converts a schema client into RFC 7591 client metadata (schemaToOAuth).
func SchemaToOAuth(c *SchemaClient) *jsonx.Object {
	out := jsonx.NewObject()
	md, _ := ParseClientMetadata(c.Metadata)
	mergeInto(out, stripReservedMetadata(md))
	set := func(k string, v any) {
		if v == nil {
			out.Set(k, jsonx.Undefined)
			return
		}
		out.Set(k, v)
	}
	str := func(k, v string) {
		if v == "" {
			out.Set(k, jsonx.Undefined)
		} else {
			out.Set(k, v)
		}
	}
	list := func(k string, v []string) {
		if v == nil {
			out.Set(k, jsonx.Undefined)
		} else {
			out.Set(k, stringsToAny(v))
		}
	}
	boolean := func(k string, v *bool) {
		if v == nil {
			out.Set(k, jsonx.Undefined)
		} else {
			out.Set(k, *v)
		}
	}
	out.Set("client_id", c.ClientID)
	str("client_secret", c.ClientSecret)
	if c.ClientSecret != "" {
		if c.ExpiresAt != nil {
			out.Set("client_secret_expires_at", math.Round(float64(c.ExpiresAt.UnixMilli())/1000))
		} else {
			out.Set("client_secret_expires_at", 0)
		}
	} else {
		out.Set("client_secret_expires_at", jsonx.Undefined)
	}
	if c.Scopes != nil {
		out.Set("scope", strings.Join(c.Scopes, " "))
	} else {
		out.Set("scope", jsonx.Undefined)
	}
	str("user_id", c.UserID)
	if c.CreatedAt != nil {
		out.Set("client_id_issued_at", math.Round(float64(c.CreatedAt.UnixMilli())/1000))
	} else {
		out.Set("client_id_issued_at", jsonx.Undefined)
	}
	str("client_name", c.Name)
	str("client_uri", c.URI)
	str("logo_uri", c.Icon)
	list("contacts", c.Contacts)
	str("tos_uri", c.Tos)
	str("policy_uri", c.Policy)
	if c.Jwks != "" {
		pv, err := jsonx.Parse([]byte(c.Jwks))
		if err == nil {
			set("jwks", pv)
		} else {
			out.Set("jwks", jsonx.Undefined)
		}
	} else {
		out.Set("jwks", jsonx.Undefined)
	}
	str("jwks_uri", c.JwksURI)
	str("software_id", c.SoftwareID)
	str("software_version", c.SoftwareVersion)
	str("software_statement", c.SoftwareStatement)
	out.Set("redirect_uris", stringsToAny(nonNil(c.RedirectURIs)))
	list("post_logout_redirect_uris", c.PostLogoutRedirectURIs)
	str("backchannel_logout_uri", c.BackchannelLogoutURI)
	boolean("backchannel_logout_session_required", c.BackchannelLogoutSessionRequired)
	str("token_endpoint_auth_method", c.TokenEndpointAuthMethod)
	list("grant_types", c.GrantTypes)
	list("response_types", c.ResponseTypes)
	str("application_type", c.ApplicationType)
	boolean("disabled", c.Disabled)
	boolean("skip_consent", c.SkipConsent)
	boolean("enable_end_session", c.EnableEndSession)
	boolean("require_pkce", c.RequirePKCE)
	boolean("dpop_bound_access_tokens", c.DPoPBoundAccessTokens)
	str("subject_type", c.SubjectType)
	str("reference_id", c.ReferenceID)
	return out
}

// ---- oauthClient/client-credentials.ts & privileges.ts ----

func normalizeClientCredentialsScopes(scopes []string) []string {
	var out []string
	for _, s := range scopes {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	out = uniqueStrings(out)
	if out == nil {
		out = []string{}
	}
	return out
}

func validateClientCredentialsScopes(scopes, grants []string, method string, o *resolved) error {
	if len(scopes) == 0 {
		return nil
	}
	if !contains(grants, "client_credentials") {
		return metaErr("client_credentials_scopes requires the client_credentials grant")
	}
	if method == "none" {
		return metaErr("public clients cannot be assigned client_credentials scopes")
	}
	var invalid []string
	for _, s := range scopes {
		if !contains(o.Scopes, s) || isUserDelegatedScope(s) {
			invalid = append(invalid, s)
		}
	}
	if len(invalid) > 0 {
		return oauthErr("BAD_REQUEST", "invalid_scope", "The following client_credentials scopes are invalid: "+strings.Join(invalid, ", "))
	}
	return nil
}

func assertClientPrivileges(ctx *betterauth.EndpointContext, s *betterauth.SessionWithUser, o *resolved, action string) error {
	if s == nil {
		return apiErr("UNAUTHORIZED")
	}
	if ctx.Headers == nil {
		return apiErr("BAD_REQUEST")
	}
	if action == "configure-client-credentials-scopes" && o.ClientPrivileges == nil {
		return apiErr("UNAUTHORIZED")
	}
	if o.ClientPrivileges != nil {
		ok, err := o.ClientPrivileges(PrivilegeContext{Ctx: ctx, Headers: ctx.Headers, Action: action, User: s.User, Session: s.Session})
		if err != nil {
			return err
		}
		if !ok {
			return apiErr("UNAUTHORIZED")
		}
	}
	return nil
}
