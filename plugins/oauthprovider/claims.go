package oauthprovider

import (
	"strconv"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Ports of signed-query.ts, standard-claims.ts, authentication-context.ts,
// claims-request.ts and claims.ts.

// ---- signed-query.ts ----

const (
	signedQueryIssuedAtParam      = "ba_iat"
	postLoginClearedParam         = "ba_pl"
	signedQueryParameterNameParam = "ba_param"
)

// canonicalizeOAuthQueryParams sorts params by key then value.
func canonicalizeOAuthQueryParams(p *searchParams) *searchParams { return p.sorted() }

func setSignedOAuthQueryParameterNames(p *searchParams) {
	p.delete(signedQueryParameterNameParam)
	names := sortedCopyJS(append(p.keys(), signedQueryParameterNameParam))
	names = uniqueStrings(names)
	for _, n := range names {
		p.append(signedQueryParameterNameParam, n)
	}
}

func sortedCopyJS(in []string) []string {
	out := uniqueStrings(in)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && jsLess(out[j], out[j-1]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// BuildSignedOAuthQuery keeps only the signed parameters of a login page query string
// (buildSignedOAuthQuery, used by the client plugin). It returns "" when the query is not
// signed.
func BuildSignedOAuthQuery(search string) string {
	p := parseSearchParams(search)
	if !p.has("sig") {
		return ""
	}
	names := p.getAll(signedQueryParameterNameParam)
	if len(names) == 0 {
		return ""
	}
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	out := newSearchParams()
	for _, e := range p.list {
		if e.k == "sig" || e.k == signedQueryParameterNameParam || set[e.k] {
			out.append(e.k, e.v)
		}
	}
	return out.String()
}

// getSignedQueryIssuedAt reads ba_iat (milliseconds) from a signed query.
func getSignedQueryIssuedAt(oauthQuery string) *time.Time {
	raw := parseSearchParams(oauthQuery).getString(signedQueryIssuedAtParam)
	if raw == "" {
		return nil
	}
	n := jsNumber(raw)
	if n != n || n <= 0 || n > 8.64e15 {
		return nil
	}
	t := time.UnixMilli(int64(n))
	return &t
}

// ---- standard-claims.ts ----

func splitDisplayName(name string) (given, family string, ok bool) {
	var parts []string
	for _, p := range strings.Split(name, " ") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) <= 1 {
		return "", "", false
	}
	return strings.Join(parts[:len(parts)-1], " "), parts[len(parts)-1], true
}

// resolveStandardClaim returns the claim value (jsonx.Undefined when undefined).
func resolveStandardClaim(name string, u *betterauth.User) any {
	switch name {
	case "name":
		return u.Name
	case "picture":
		if u.Image == nil {
			return jsonx.Undefined
		}
		return *u.Image
	case "given_name":
		g, _, ok := splitDisplayName(u.Name)
		if !ok {
			return jsonx.Undefined
		}
		return g
	case "family_name":
		_, f, ok := splitDisplayName(u.Name)
		if !ok {
			return jsonx.Undefined
		}
		return f
	case "email":
		return u.Email
	case "email_verified":
		return u.EmailVerified
	}
	return jsonx.Undefined
}

// getSupportedClaims is advertisedMetadata.claims_supported ?? opts.claims.
func (o *resolved) supportedClaims() []string {
	if o.AdvertisedMetadata != nil && o.AdvertisedMetadata.ClaimsSupported != nil {
		return o.AdvertisedMetadata.ClaimsSupported
	}
	return o.Claims
}

// ---- authentication-context.ts ----

const level0ACR = "0"

var reservedIDTokenClaims = map[string]bool{"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true,
	"iat": true, "jti": true, "auth_time": true, "nonce": true, "acr": true, "amr": true, "azp": true,
	"sid": true, "at_hash": true, "c_hash": true, "s_hash": true}

func stripClaims(claims *jsonx.Object, reserved map[string]bool, label string, log betterauth.Logger) *jsonx.Object {
	out := jsonx.NewObject()
	if claims == nil {
		return out
	}
	var stripped []string
	for _, k := range claims.Keys() {
		if reserved[k] {
			stripped = append(stripped, k)
			continue
		}
		v, _ := claims.Get(k)
		out.Set(k, v)
	}
	if len(stripped) > 0 && log != nil {
		log.Warn("oauth-provider: stripped reserved " + label + " claim name(s): " + strings.Join(stripped, ", ") + ". The AS owns these claim values.")
	}
	return out
}

func stripReservedIDTokenClaims(claims *jsonx.Object, log betterauth.Logger) *jsonx.Object {
	return stripClaims(claims, reservedIDTokenClaims, "id-token", log)
}

// ---- claims-request.ts ----

// claimsRequest is a parsed OIDC claims request object.
type claimsRequest struct {
	raw      *jsonx.Object
	userinfo *jsonx.Object
	acr      *jsonx.Object
}

func isClaimMember(v any) bool {
	if v == nil {
		return true
	}
	_, ok := v.(*jsonx.Object)
	return ok
}

// parseOIDCClaimsRequest validates a claims request (string or object) and returns it,
// nil when invalid.
func parseOIDCClaimsRequest(value any) *claimsRequest {
	v := value
	if s, ok := value.(string); ok {
		pv, err := jsonx.Parse([]byte(s))
		if err != nil {
			return nil
		}
		v = pv
	}
	o := asObject(v)
	if o == nil {
		return nil
	}
	cr := &claimsRequest{raw: o}
	if uv, ok := o.Get("userinfo"); ok && !isUndef(uv) {
		u := asObject(uv)
		if u == nil {
			return nil
		}
		for _, k := range u.Keys() {
			m, _ := u.Get(k)
			if !isClaimMember(m) {
				return nil
			}
		}
		cr.userinfo = u
	}
	if iv, ok := o.Get("id_token"); ok && !isUndef(iv) {
		id := asObject(iv)
		if id == nil {
			return nil
		}
		for _, k := range id.Keys() {
			m, _ := id.Get(k)
			if k == "acr" {
				if m == nil {
					continue
				}
				a := asObject(m)
				if a == nil {
					return nil
				}
				if e, ok := a.Get("essential"); ok {
					if _, isBool := e.(bool); !isBool {
						return nil
					}
				}
				if e, ok := a.Get("value"); ok {
					if _, isStr := e.(string); !isStr {
						return nil
					}
				}
				if e, ok := a.Get("values"); ok {
					arr, isArr := e.([]any)
					if !isArr {
						return nil
					}
					for _, x := range arr {
						if _, isStr := x.(string); !isStr {
							return nil
						}
					}
				}
				cr.acr = a
				continue
			}
			if !isClaimMember(m) {
				return nil
			}
		}
	}
	return cr
}

func isValidOIDCClaimsRequest(value any) bool {
	return value == nil || isUndef(value) || parseOIDCClaimsRequest(value) != nil
}

// getRequestedUserInfoClaims returns the requested userinfo claim names filtered by the
// supported claims (nil supported = no filter).
func getRequestedUserInfoClaims(value any, supported []string) []string {
	if value == nil || isUndef(value) {
		return []string{}
	}
	cr := parseOIDCClaimsRequest(value)
	if cr == nil || cr.userinfo == nil {
		return []string{}
	}
	names := cr.userinfo.Keys()
	if supported == nil {
		return names
	}
	out := []string{}
	for _, n := range names {
		if contains(supported, n) {
			out = append(out, n)
		}
	}
	return out
}

func canSatisfyEssentialACRRequest(value any, currentACR string) bool {
	if value == nil || isUndef(value) {
		return true
	}
	cr := parseOIDCClaimsRequest(value)
	if cr == nil {
		return false
	}
	if cr.acr == nil {
		return true
	}
	if e, _ := cr.acr.Get("essential"); e != true {
		return true
	}
	valueMatches := true
	if v, ok := cr.acr.Get("value"); ok {
		valueMatches = v == currentACR
	}
	valuesMatch := true
	if v, ok := cr.acr.Get("values"); ok {
		arr, _ := v.([]any)
		valuesMatch = false
		for _, x := range arr {
			if x == currentACR {
				valuesMatch = true
			}
		}
	}
	return valueMatches && valuesMatch
}

// filterClaimsRequestUserInfoClaims keeps only the allowed userinfo claims (nil when the
// result would be empty or the request is invalid).
func filterClaimsRequestUserInfoClaims(value any, allowed []string) *jsonx.Object {
	cr := parseOIDCClaimsRequest(value)
	if cr == nil {
		return nil
	}
	userinfo := jsonx.NewObject()
	if cr.userinfo != nil {
		for _, k := range cr.userinfo.Keys() {
			if contains(allowed, k) {
				v, _ := cr.userinfo.Get(k)
				userinfo.Set(k, v)
			}
		}
	}
	out := jsonx.NewObject()
	if userinfo.Len() > 0 {
		for _, k := range cr.raw.Keys() {
			v, _ := cr.raw.Get(k)
			if k == "userinfo" {
				v = userinfo
			}
			out.Set(k, v)
		}
	} else {
		for _, k := range cr.raw.Keys() {
			if k == "userinfo" {
				continue
			}
			v, _ := cr.raw.Get(k)
			out.Set(k, v)
		}
	}
	if out.Len() == 0 {
		return nil
	}
	return out
}

// ---- claims.ts ----

var reservedAccessTokenClaims = map[string]bool{"iss": true, "sub": true, "aud": true, "exp": true, "iat": true,
	"jti": true, "client_id": true, "scope": true, "auth_time": true, "acr": true, "amr": true, "cnf": true}

type accessTokenClaimsInput struct {
	ctx                  *betterauth.EndpointContext
	opts                 *resolved
	user                 *betterauth.User
	client               *SchemaClient
	scopes               []string
	resources            []string
	referenceID          string
	metadata             *jsonx.Object
	grantType            string
	sessionID            string
	perRequestClaims     *jsonx.Object
	resourcePolicyClaims *jsonx.Object
}

func mergeInto(dst, src *jsonx.Object) {
	if src == nil {
		return
	}
	for _, k := range src.Keys() {
		v, _ := src.Get(k)
		dst.Set(k, v)
	}
}

// resolveAccessTokenClaims merges extension, per-request, plugin and resource-policy
// claims and strips reserved names.
func resolveAccessTokenClaims(in accessTokenClaimsInput) (*jsonx.Object, error) {
	ext, err := collectExtensionAccessTokenClaims(in.opts, ClaimExtensionInput{
		Ctx: in.ctx, User: in.user, Client: in.client, Scopes: in.scopes, GrantType: in.grantType,
		ReferenceID: in.referenceID, SessionID: in.sessionID, Resources: in.resources, Metadata: in.metadata,
	})
	if err != nil {
		return nil, err
	}
	var plugin *jsonx.Object
	if in.opts.CustomAccessTokenClaims != nil {
		plugin, err = in.opts.CustomAccessTokenClaims(AccessTokenClaimsInput{Ctx: in.ctx, User: in.user,
			ReferenceID: in.referenceID, Scopes: in.scopes, Resources: in.resources, Metadata: in.metadata})
		if err != nil {
			return nil, err
		}
	}
	merged := jsonx.NewObject()
	mergeInto(merged, ext)
	mergeInto(merged, in.perRequestClaims)
	mergeInto(merged, plugin)
	mergeInto(merged, in.resourcePolicyClaims)
	return stripClaims(merged, reservedAccessTokenClaims, "access-token", in.ctx.Auth.Logger), nil
}

func formatMillis(t time.Time) string { return strconv.FormatInt(t.UnixMilli(), 10) }
