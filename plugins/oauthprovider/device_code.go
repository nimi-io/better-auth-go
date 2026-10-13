package oauthprovider

import (
	"errors"
	"strings"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/deviceauthorization"
	"github.com/nimi-io/better-auth-go/validate"
)

// Port of packages/oauth-provider/src/device-code.ts: the OAuth device authorization grant
// (RFC 8628) served by the device-authorization plugin and redeemed at /oauth2/token.

// DeviceCodeGrantType is the RFC 8628 grant type.
const DeviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

func deviceResourceSchema() zSchema {
	return zUnion(resourceURI(), zArray(resourceURI(), 1), zLiteral(""))
}

func parseScopeList(scope string) []string {
	s := strings.TrimSpace(scope)
	if s == "" {
		return []string{}
	}
	return strings.Fields(s)
}

type deviceClientAuthorization struct {
	auth   *AuthenticatedClient
	scopes []string
}

func exchangeOAuthDeviceCode(in GrantHandlerInput) (any, error) {
	ctx, provider := in.Ctx, in.Provider
	body := bodyMap(ctx)
	deviceCode, _ := body["device_code"].(string)
	if deviceCode == "" {
		return nil, oauthErr("BAD_REQUEST", "invalid_request", "device_code is required")
	}
	bodyClientID, _ := body["client_id"].(string)
	res, err := deviceauthorization.RedeemDeviceCode(ctx, deviceauthorization.RedeemInput{
		DeviceCode: deviceCode,
		AuthorizeRedemption: func(rec adapter.Record) (*deviceauthorization.RedemptionAuthorization, error) {
			oc := recStr(rec, "oauthClientId")
			if oc == "" {
				return nil, oauthErr("BAD_REQUEST", "invalid_grant", "invalid device code")
			}
			if bodyClientID != "" && oc != bodyClientID {
				return nil, oauthErr("BAD_REQUEST", "invalid_grant", "Client ID mismatch")
			}
			scopes := parseScopeList(recStr(rec, "scope"))
			auth, err := provider.AuthenticateClient(&ClientAuthenticationRequest{RequireCredentials: boolPtr(false)})
			if err != nil {
				return nil, err
			}
			if oc != auth.Client.ClientID {
				return nil, oauthErr("BAD_REQUEST", "invalid_grant", "Client ID mismatch")
			}
			if err := validateClientScopes(auth.Client, scopes); err != nil {
				return nil, err
			}
			return &deviceauthorization.RedemptionAuthorization{
				OwnershipWhere: adapter.Where{Field: "oauthClientId", Value: auth.Client.ClientID},
				Context:        &deviceClientAuthorization{auth: auth, scopes: scopes},
			}, nil
		},
		PrepareRedemption: func(rec adapter.Record, c any) (any, error) {
			a := c.(*deviceClientAuthorization)
			requested := toResourceList(body["resource"])
			bound := recStrings(rec, "resources")
			if requested != nil {
				if bound == nil {
					return nil, oauthErr("BAD_REQUEST", "invalid_target", "Requested resource was not authorized by the user")
				}
				for _, r := range requested {
					if !contains(bound, r) {
						return nil, oauthErr("BAD_REQUEST", "invalid_target", "Requested resource was not authorized by the user")
					}
				}
			}
			resources := requested
			if resources == nil {
				resources = bound
			}
			if _, err := resolveResourcePolicy(ctx, in.opts, stringsToAnyOrNil(resources), a.auth.Client.ClientID, a.scopes); err != nil {
				return nil, err
			}
			return resources, nil
		},
	})
	if err != nil {
		return nil, err
	}
	a := res.AuthorizationContext.(*deviceClientAuthorization)
	resources, _ := res.RedemptionContext.([]string)
	return provider.IssueTokens(TokenIssueParams{Client: a.auth.Client, Scopes: a.scopes, User: res.User,
		Resources: resources, Confirmation: a.auth.Confirmation})
}

func buildOAuthDeviceGrant() (*deviceauthorization.Grant, *Extension) {
	ext := &Extension{
		Grants: []ExtensionGrant{{GrantType: DeviceCodeGrantType, Handler: exchangeOAuthDeviceCode}},
		Metadata: func(in MetadataExtensionInput) *jsonx.Object {
			return jsonx.O("device_authorization_endpoint", in.Ctx.Auth.BaseURL+"/device/code")
		},
	}
	strField := func(desc string) validate.Schema {
		return validate.Describe(validate.Optional(validate.String()), desc)
	}
	g := &deviceauthorization.Grant{
		RequestSchemaFields: []validate.Field{
			validate.F("client_secret", strField("OAuth client secret")),
			validate.F("client_assertion", strField("OAuth client assertion")),
			validate.F("client_assertion_type", strField("OAuth client assertion type")),
			validate.F("resource", validate.Describe(toValidate(zOptional(deviceResourceSchema())),
				"RFC 8707 resource indicator(s) to bind to this authorization request")),
		},
		RequestErrorCodes: []string{"invalid_target"},
		RequestOpenAPIResponses: map[string]any{
			"401": jsonx.O("description", "Invalid Basic client authentication",
				"headers", jsonx.O("WWW-Authenticate", jsonx.O("description", "Basic client authentication challenge",
					"schema", jsonx.O("type", "string", "example", "Basic"))),
				"content", jsonx.O("application/json", jsonx.O("schema", jsonx.O("type", "object",
					"properties", jsonx.O("error", jsonx.O("type", "string", "enum", []any{"invalid_client"}),
						"error_description", jsonx.O("type", "string")),
					"required", []any{"error"})))),
		},
		OnRequestValidationError: func(issues []validate.Issue) error {
			if len(issues) == 0 {
				return nil
			}
			for _, is := range issues {
				if len(is.Path) == 0 || is.Path[0] != "resource" {
					return nil
				}
			}
			return oauthErr("BAD_REQUEST", "invalid_target", "Invalid resource indicator")
		},
		DeviceCodeSchemaFields: []db.Field{
			{Name: "resources", Type: db.TypeStringArray, Required: db.False},
			{Name: "oauthClientId", Type: db.TypeString, Required: db.False},
		},
		AuthorizeRequest: func(ctx *betterauth.EndpointContext, request map[string]any) (*deviceauthorization.GrantAuthorization, error) {
			bodyCopy := copyBody(ctx)
			hasAuth, err := normalizeClientAuthenticationParameters(ctx, bodyCopy)
			if err != nil {
				return nil, err
			}
			if form := extractRepeatedResourceFromForm(ctx); form != nil {
				var v any = stringsToAny(form)
				if len(form) == 1 {
					v = form[0]
				}
				parsed, issues := zParse(deviceResourceSchema(), v)
				if len(issues) > 0 {
					return nil, oauthErr("BAD_REQUEST", "invalid_target", "Invalid resource indicator")
				}
				request["resource"] = parsed
			}
			p := ctx.Auth.GetPlugin("oauth-provider")
			if p == nil {
				return nil, nil
			}
			o := p.Options.(*resolved)
			scopeStr, hasScope := request["scope"].(string)
			scopes := parseScopeList(scopeStr)
			if hasScope {
				request["scope"] = strings.Join(scopes, " ")
			}
			resource := request["resource"]
			if resource == "" {
				resource = nil
			}
			api := newProviderAPI(ctx, o, DeviceCodeGrantType)
			clientID, _ := request["client_id"].(string)
			if clientID == "" && !hasAuth {
				return nil, oauthErr("BAD_REQUEST", "invalid_request", "client_id is required")
			}
			if clientID != "" {
				c, err := getClient(ctx, o, clientID)
				if err != nil {
					return nil, err
				}
				if c == nil && !hasAuth {
					return nil, nil
				}
			}
			authed, err := api.AuthenticateClient(&ClientAuthenticationRequest{Scopes: scopes, RequireCredentials: boolPtr(false)})
			if err != nil {
				return nil, err
			}
			if clientID != "" && authed.ClientID != clientID {
				return nil, oauthErr("BAD_REQUEST", "invalid_client", "Client ID mismatch")
			}
			if _, err := resolveResourcePolicy(ctx, o, resource, authed.ClientID, scopes); err != nil {
				return nil, err
			}
			var resVal any
			if l := toResourceList(resource); l != nil {
				resVal = stringsToAny(l)
			}
			return &deviceauthorization.GrantAuthorization{ClientID: authed.ClientID,
				DeviceCodeFields: map[string]any{"oauthClientId": authed.ClientID, "resources": resVal}}, nil
		},
		AssertSessionRedemption: func(ctx *betterauth.EndpointContext, rec adapter.Record) error {
			if _, ok := rec["oauthClientId"].(string); !ok {
				return nil
			}
			return oauthErr("BAD_REQUEST", "invalid_grant", "This device code must be exchanged at the OAuth token endpoint (/oauth2/token).")
		},
		GetVerificationContext: func(rec adapter.Record) map[string]any {
			if _, ok := rec["oauthClientId"].(string); !ok {
				return nil
			}
			v, ok := rec["resources"]
			if !ok || v == nil {
				return nil
			}
			arr, isArr := asArray(v)
			if !isArr {
				return nil
			}
			for _, x := range arr {
				if _, s := x.(string); !s {
					return nil
				}
			}
			return map[string]any{"resource": toAudienceClaim(toStrings(arr))}
		},
		VerificationOpenAPIProperties: map[string]any{
			"resource": jsonx.O("oneOf", []any{jsonx.O("type", "string"), jsonx.O("type", "array", "items", jsonx.O("type", "string"))},
				"description", "The requested resource indicators, returned only to the authenticated user who owns this request"),
		},
	}
	return g, ext
}

// OAuthDeviceAuthorization returns the device-authorization plugin wired to the OAuth
// provider (oauthDeviceAuthorization): device codes are bound to OAuth clients and
// redeemed at /oauth2/token with the RFC 8628 grant type.
func OAuthDeviceAuthorization(options deviceauthorization.Options) *betterauth.Plugin {
	g, ext := buildOAuthDeviceGrant()
	options.Grant = g
	p := deviceauthorization.New(options)
	inner := p.Init
	p.Init = func(ac *betterauth.AuthContext) (*betterauth.PluginInit, error) {
		var res *betterauth.PluginInit
		if inner != nil {
			r, err := inner(ac)
			if err != nil {
				return nil, err
			}
			res = r
		}
		count := 0
		for _, pl := range ac.Plugins() {
			if pl.ID == "device-authorization" {
				count++
			}
		}
		if count > 1 {
			return nil, errors.New("oauthDeviceAuthorization() cannot be combined with another Device Authorization plugin.")
		}
		if ac.GetPlugin("oauth-provider") == nil {
			return nil, errors.New("oauthDeviceAuthorization() requires oauthProvider() or mcp().")
		}
		if err := ExtendOAuthProvider(ac, ext); err != nil {
			return nil, err
		}
		return res, nil
	}
	return p
}
