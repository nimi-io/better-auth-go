package sso

import (
	"strings"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/validate"
)

// Request schemas (routes/schemas.ts).

func d(s validate.Schema, description string) validate.Schema {
	return validate.Describe(s, description)
}

func opt(s validate.Schema) validate.Schema { return validate.Optional(s) }

// refine is z.string().refine(fn, { message }).
func refine(inner validate.Schema, fn func(string) bool, message string) validate.Schema {
	return validate.Custom(func(v any, path []any) (any, []validate.Issue) {
		out, issues := validate.Validate(inner, v)
		if len(issues) > 0 {
			for i := range issues {
				issues[i].Path = append(append([]any{}, path...), issues[i].Path...)
			}
			return nil, issues
		}
		if s, ok := out.(string); ok && !fn(s) {
			return nil, []validate.Issue{validate.NewIssue(path, "custom", message)}
		}
		return out, nil
	})
}

// unionWithMessage is z.union([...], message).
func unionWithMessage(message string, options ...validate.Schema) validate.Schema {
	u := validate.Union(options...)
	return validate.Custom(func(v any, path []any) (any, []validate.Issue) {
		out, issues := validate.Validate(u, v)
		if len(issues) == 0 {
			return out, nil
		}
		if len(issues) == 1 && issues[0].Code == "invalid_union" && len(issues[0].Path) == 0 {
			return nil, []validate.Issue{validate.NewIssue(path, "invalid_union", message)}
		}
		for i := range issues {
			issues[i].Path = append(append([]any{}, path...), issues[i].Path...)
		}
		return nil, issues
	})
}

// nonEmptyStringArray is z.array(z.string()).nonempty().
func nonEmptyStringArray() validate.Schema {
	arr := validate.Array(validate.String())
	return validate.Custom(func(v any, path []any) (any, []validate.Issue) {
		out, issues := validate.Validate(arr, v)
		if len(issues) > 0 {
			for i := range issues {
				issues[i].Path = append(append([]any{}, path...), issues[i].Path...)
			}
			return nil, issues
		}
		if a, ok := out.([]any); ok && len(a) == 0 {
			return nil, []validate.Issue{validate.NewIssue(path, "too_small", "Too small: expected array to have >=1 items")}
		}
		return out, nil
	})
}

func isURLString(s string) bool {
	_, issues := validate.Validate(validate.URL(), s)
	return len(issues) == 0
}

var samlRedirectURLSchema = refine(validate.String(), func(u string) bool {
	return isSafeSAMLRedirectPath(u) || isURLString(u)
}, "Expected an absolute URL or a relative path starting with /")

func oidcMappingSchema() validate.Schema {
	return opt(validate.StrictObject(
		validate.F("email", d(validate.String(), "Field mapping for email (defaults to 'email')")),
		validate.F("emailVerified", opt(d(validate.String(), "Field mapping for email verification (defaults to 'email_verified')"))),
		validate.F("name", d(validate.String(), "Field mapping for name (defaults to 'name')")),
		validate.F("image", opt(d(validate.String(), "Field mapping for image (defaults to 'picture')"))),
		validate.F("extraFields", opt(validate.Record(validate.Any()))),
	))
}

func samlMappingSchema() validate.Schema {
	return opt(validate.StrictObject(
		validate.F("email", d(validate.String(), "Field mapping for email (defaults to 'email')")),
		validate.F("emailVerified", opt(d(validate.String(), "Field mapping for email verification"))),
		validate.F("name", d(validate.String(), "Field mapping for name (defaults to 'displayName')")),
		validate.F("firstName", opt(d(validate.String(), "Field mapping for first name (defaults to 'givenName')"))),
		validate.F("lastName", opt(d(validate.String(), "Field mapping for last name (defaults to 'surname')"))),
		validate.F("extraFields", opt(validate.Record(validate.Any()))),
	))
}

func signingCertSchema(description string) validate.Schema {
	return d(validate.Union(validate.String(), nonEmptyStringArray()), description)
}

func oidcConfigFields() []validate.Field {
	return []validate.Field{
		validate.F("clientId", d(validate.String(), "The client ID")),
		validate.F("clientSecret", opt(d(validate.String(), "The client secret. Required for client_secret_basic/client_secret_post. Optional for private_key_jwt."))),
		validate.F("authorizationEndpoint", opt(d(validate.URL(), "The authorization endpoint"))),
		validate.F("tokenEndpoint", opt(d(validate.URL(), "The token endpoint"))),
		validate.F("userInfoEndpoint", opt(d(validate.URL(), "The user info endpoint"))),
		validate.F("tokenEndpointAuthentication", opt(validate.Enum("client_secret_post", "client_secret_basic", "private_key_jwt"))),
		validate.F("privateKeyId", opt(validate.String())),
		validate.F("privateKeyAlgorithm", opt(validate.String())),
		validate.F("jwksEndpoint", opt(d(validate.URL(), "The JWKS endpoint"))),
		validate.F("discoveryEndpoint", opt(validate.URL())),
		validate.F("skipDiscovery", opt(d(validate.Boolean(), "Skip OIDC discovery during registration. When true, you must provide authorizationEndpoint, tokenEndpoint, and jwksEndpoint manually."))),
		validate.F("scopes", opt(d(validate.Array(validate.String()), "The scopes to request. Defaults to ['openid', 'email', 'profile', 'offline_access']"))),
		validate.F("pkce", validate.Default(d(validate.Boolean(), "Whether to use PKCE for the authorization flow"), true)),
		validate.F("overrideUserInfo", opt(validate.Boolean())),
		validate.F("mapping", oidcMappingSchema()),
	}
}

func samlServiceSchema(descBinding, descLocation string) validate.Schema {
	var b, l validate.Schema = validate.String(), validate.URL()
	if descBinding != "" {
		b = d(b, descBinding)
	}
	if descLocation != "" {
		l = d(l, descLocation)
	}
	return validate.Object(validate.F("Binding", b), validate.F("Location", l))
}

func samlIdPConfigFields() []validate.Field {
	return []validate.Field{
		validate.F("cert", opt(signingCertSchema("IdP signing certificate(s). Pass a single PEM string or an array for rolling rotation. Takes precedence over the top-level `cert`."))),
		validate.F("privateKey", opt(validate.String())),
		validate.F("privateKeyPass", opt(validate.String())),
		validate.F("isAssertionEncrypted", opt(validate.Boolean())),
		validate.F("encPrivateKey", opt(validate.String())),
		validate.F("encPrivateKeyPass", opt(validate.String())),
		validate.F("singleSignOnService", opt(d(validate.Array(samlServiceSchema("The binding type for the SSO service", "The URL for the SSO service")), "Single Sign-On service configuration"))),
		validate.F("singleLogoutService", opt(validate.Array(samlServiceSchema("", "")))),
	}
}

func samlIdPMetadataSchema() validate.Schema {
	withMetadata := validate.Object(append(samlIdPConfigFields(),
		validate.F("metadata", validate.String().Min(1)),
		validate.F("entityID", opt(validate.String())))...)
	withEntityID := validate.Object(append(samlIdPConfigFields(),
		validate.F("metadata", opt(validate.UndefinedValue())),
		validate.F("entityID", validate.String().Min(1)))...)
	return unionWithMessage("idpMetadata.entityID is required when IdP metadata XML is not provided", withMetadata, withEntityID)
}

func samlIdPMetadataUpdateSchema() validate.Schema {
	return validate.Object(append(samlIdPConfigFields(),
		validate.F("metadata", opt(validate.String().Min(1))),
		validate.F("entityID", opt(validate.String().Min(1))))...)
}

func samlConfigFields(update bool) []validate.Field {
	spMeta := validate.Object(
		validate.F("metadata", opt(validate.String())),
		validate.F("entityID", opt(validate.String())),
		validate.F("binding", opt(validate.String())),
		validate.F("privateKey", opt(validate.String())),
		validate.F("privateKeyPass", opt(validate.String())),
		validate.F("isAssertionEncrypted", opt(validate.Boolean())),
		validate.F("encPrivateKey", opt(validate.String())),
		validate.F("encPrivateKeyPass", opt(validate.String())),
	)
	entryPoint := d(validate.URL(), "The IdP SSO URL (entry point)")
	idpInitiated := opt(samlRedirectURLSchema)
	idpMeta := samlIdPMetadataSchema()
	if update {
		entryPoint = opt(entryPoint)
		idpInitiated = opt(validate.Nullable(samlRedirectURLSchema))
		idpMeta = opt(samlIdPMetadataUpdateSchema())
	}
	fields := []validate.Field{
		validate.F("entryPoint", entryPoint),
		validate.F("cert", opt(signingCertSchema("IdP signing certificate(s). Pass a single PEM string or an array for rolling rotation. Omit when `idpMetadata.metadata` XML carries the certs. When both this and `idpMetadata.cert` are set, `idpMetadata.cert` wins."))),
		validate.F("audience", opt(validate.String())),
		validate.F("callbackUrl", opt(refine(validate.String(), func(u string) bool { return !strings.Contains(u, "#") }, "callbackUrl must not contain a fragment"))),
		validate.F("idpInitiatedCallbackUrl", idpInitiated),
		validate.F("idpMetadata", idpMeta),
		validate.F("spMetadata", opt(spMeta)),
		validate.F("wantAssertionsSigned", opt(validate.Boolean())),
		validate.F("authnRequestsSigned", opt(validate.Boolean())),
		validate.F("signatureAlgorithm", opt(validate.String())),
		validate.F("digestAlgorithm", opt(validate.String())),
		validate.F("identifierFormat", opt(validate.String())),
		validate.F("privateKey", opt(validate.String())),
		validate.F("mapping", samlMappingSchema()),
	}
	return fields
}

// additionalFieldsSchema ports toZodSchema({ fields, isClientSide: true }) plus the
// blocked input fields (input: false accepted as any so the handler can reject them).
func additionalFieldsSchema(fields []db.Field, partial bool) []validate.Field {
	var out []validate.Field
	for _, f := range fields {
		if !f.IsInput() {
			out = append(out, validate.F(f.Name, opt(validate.Any())))
			continue
		}
		var s validate.Schema
		switch f.Type {
		case db.TypeString:
			s = validate.String()
		case db.TypeNumber:
			s = validate.Number()
		case db.TypeBoolean:
			s = validate.Boolean()
		case db.TypeStringArray:
			s = validate.Array(validate.String())
		case db.TypeNumberArray:
			s = validate.Array(validate.Number())
		default:
			s = validate.Any()
		}
		if f.IsOptional() || partial {
			s = validate.Nullish(s)
		}
		out = append(out, validate.F(f.Name, s))
	}
	return out
}

func registerBodySchema(o *Options) validate.Schema {
	fields := []validate.Field{
		validate.F("providerId", d(validate.String(), "The ID of the provider. This is used to identify the provider during login and callback")),
		validate.F("issuer", d(validate.URL(), "The issuer URL of the provider")),
		validate.F("domain", d(validate.String(), "The domain(s) of the provider. For enterprise multi-domain SSO where a single IdP serves multiple email domains, use comma-separated values (e.g., 'company.com,subsidiary.com,acquired-company.com')")),
		validate.F("oidcConfig", opt(validate.Object(oidcConfigFields()...))),
		validate.F("samlConfig", opt(validate.Object(samlConfigFields(false)...))),
		validate.F("organizationId", opt(d(validate.String(), "If organization plugin is enabled, the organization id to link the provider to"))),
		validate.F("overrideUserInfo", validate.Default(d(validate.Boolean(), "Override user info with the provider info. Defaults to false"), false)),
	}
	return validate.Object(mergeFields(fields, additionalFieldsSchema(o.additionalFields(), false))...)
}

func partialFields(fields []validate.Field) []validate.Field {
	out := make([]validate.Field, len(fields))
	for i, f := range fields {
		info := validate.Inspect(f.Schema)
		if info.Kind == validate.KindOptional {
			out[i] = f
		} else {
			out[i] = validate.F(f.Name, opt(f.Schema))
		}
	}
	return out
}

func updateBodySchema(o *Options) validate.Schema {
	oidcPartial := partialFields(oidcConfigFields())
	// zod's .partial() keeps the inner .default(true) of pkce
	for i, f := range oidcPartial {
		if f.Name == "pkce" {
			oidcPartial[i] = validate.F("pkce", validate.Default(d(validate.Boolean(), "Whether to use PKCE for the authorization flow"), true))
		}
	}
	fields := []validate.Field{
		validate.F("issuer", opt(validate.URL())),
		validate.F("domain", opt(validate.String())),
		validate.F("oidcConfig", opt(validate.Object(oidcPartial...))),
		validate.F("samlConfig", opt(validate.Object(samlConfigFields(true)...))),
		validate.F("providerId", validate.String()),
	}
	return validate.Object(mergeFields(fields, additionalFieldsSchema(o.additionalFields(), true))...)
}

func mergeFields(base []validate.Field, extra []validate.Field) []validate.Field {
	idx := map[string]int{}
	out := append([]validate.Field(nil), base...)
	for i, f := range out {
		idx[f.Name] = i
	}
	for _, f := range extra {
		if i, ok := idx[f.Name]; ok {
			out[i] = f
			continue
		}
		idx[f.Name] = len(out)
		out = append(out, f)
	}
	return out
}

// parseAdditionalFields validates additional field input (parseSSOProviderAdditionalFields).
func parseAdditionalFields(o *Options, data map[string]any, action string) (map[string]any, error) {
	fields := o.additionalFields()
	for _, f := range fields {
		if !f.IsInput() {
			if _, ok := data[f.Name]; ok {
				return nil, badRequest(f.Name + " is not allowed to be set")
			}
		}
	}
	return betterauth.SSOParseInputData(data, fields, action)
}
