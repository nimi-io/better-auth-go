package oauthprovider

import "github.com/nimi-io/better-auth-go/db"

// Port of packages/oauth-provider/src/schema.ts. Table and column names (and their
// order) match upstream so databases can be shared with the TypeScript implementation.

// Model keys.
const (
	modelClient          = "oauthClient"
	modelResource        = "oauthResource"
	modelClientResource  = "oauthClientResource"
	modelRefreshToken    = "oauthRefreshToken"
	modelAccessToken     = "oauthAccessToken"
	modelConsent         = "oauthConsent"
	modelClientAssertion = "oauthClientAssertion"
)

func f(name string, t db.FieldType, required *bool) db.Field {
	return db.Field{Name: name, Type: t, Required: required}
}

func withRef(fl db.Field, model, field, onDelete string) db.Field {
	fl.References = &db.Reference{Model: model, Field: field, OnDelete: onDelete}
	return fl
}

func withIndex(fl db.Field) db.Field  { fl.Index = true; return fl }
func withUnique(fl db.Field) db.Field { fl.Unique = true; return fl }
func withDefault(fl db.Field, v any) db.Field {
	fl.DefaultValue = v
	return fl
}

// Schema returns the plugin tables with the schema option (model / field renames)
// applied (mergeSchema(schema, opts.schema)).
func Schema(o SchemaOptions) []db.PluginTable {
	T, F := db.True, db.False
	tables := []db.PluginTable{
		{Key: modelClient, ModelName: modelClient, Fields: []db.Field{
			withUnique(f("clientId", db.TypeString, T)),
			f("clientSecret", db.TypeString, F),
			f("clientDiscoveryId", db.TypeString, F),
			withDefault(f("disabled", db.TypeBoolean, F), false),
			f("skipConsent", db.TypeBoolean, F),
			f("enableEndSession", db.TypeBoolean, F),
			f("subjectType", db.TypeString, F),
			f("scopes", db.TypeStringArray, F),
			withDefault(f("clientCredentialsScopes", db.TypeStringArray, F), []any{}),
			withIndex(withRef(f("userId", db.TypeString, F), "user", "id", "")),
			f("createdAt", db.TypeDate, F),
			f("updatedAt", db.TypeDate, F),
			f("name", db.TypeString, F),
			f("uri", db.TypeString, F),
			f("icon", db.TypeString, F),
			f("contacts", db.TypeStringArray, F),
			f("tos", db.TypeString, F),
			f("policy", db.TypeString, F),
			f("softwareId", db.TypeString, F),
			f("softwareVersion", db.TypeString, F),
			f("softwareStatement", db.TypeString, F),
			f("redirectUris", db.TypeStringArray, T),
			f("postLogoutRedirectUris", db.TypeStringArray, F),
			f("backchannelLogoutUri", db.TypeString, F),
			f("backchannelLogoutSessionRequired", db.TypeBoolean, F),
			f("tokenEndpointAuthMethod", db.TypeString, F),
			f("applicationType", db.TypeString, F),
			f("jwks", db.TypeString, F),
			f("jwksUri", db.TypeString, F),
			f("grantTypes", db.TypeStringArray, F),
			f("responseTypes", db.TypeStringArray, F),
			f("requirePKCE", db.TypeBoolean, F),
			withDefault(f("dpopBoundAccessTokens", db.TypeBoolean, F), false),
			f("referenceId", db.TypeString, F),
			f("metadata", db.TypeJSON, F),
		}},
		{Key: modelResource, ModelName: modelResource, Fields: []db.Field{
			withUnique(f("identifier", db.TypeString, T)),
			f("name", db.TypeString, T),
			f("accessTokenTtl", db.TypeNumber, F),
			f("refreshTokenTtl", db.TypeNumber, F),
			f("signingAlgorithm", db.TypeString, F),
			f("signingKeyId", db.TypeString, F),
			f("allowedScopes", db.TypeStringArray, F),
			f("customClaims", db.TypeJSON, F),
			withDefault(f("dpopBoundAccessTokensRequired", db.TypeBoolean, F), false),
			withDefault(f("disabled", db.TypeBoolean, F), false),
			f("createdAt", db.TypeDate, F),
			f("updatedAt", db.TypeDate, F),
			withDefault(f("policyVersion", db.TypeNumber, F), 1),
			f("metadata", db.TypeJSON, F),
		}},
		{Key: modelClientResource, ModelName: modelClientResource, Fields: []db.Field{
			withIndex(withRef(f("clientId", db.TypeString, T), modelClient, "clientId", db.OnDeleteCascade)),
			withIndex(withRef(f("resourceId", db.TypeString, T), modelResource, "identifier", db.OnDeleteCascade)),
			f("metadata", db.TypeJSON, F),
			f("createdAt", db.TypeDate, F),
		}, Indexes: []db.Index{{Fields: []string{"clientId", "resourceId"}, Unique: true}}},
		{Key: modelRefreshToken, ModelName: modelRefreshToken, Fields: []db.Field{
			withUnique(f("token", db.TypeString, T)),
			withIndex(withRef(f("clientId", db.TypeString, T), modelClient, "clientId", "")),
			withIndex(withRef(f("sessionId", db.TypeString, F), "session", "id", db.OnDeleteSetNull)),
			withIndex(withRef(f("userId", db.TypeString, T), "user", "id", "")),
			f("referenceId", db.TypeString, F),
			withIndex(f("authorizationCodeId", db.TypeString, F)),
			f("resources", db.TypeStringArray, F),
			f("requestedUserInfoClaims", db.TypeStringArray, F),
			f("expiresAt", db.TypeDate, nil),
			f("createdAt", db.TypeDate, nil),
			f("revoked", db.TypeDate, F),
			f("rotatedAt", db.TypeDate, F),
			f("rotationReplayResponse", db.TypeString, F),
			f("rotationReplayExpiresAt", db.TypeDate, F),
			f("authTime", db.TypeDate, F),
			f("confirmation", db.TypeJSON, F),
			f("scopes", db.TypeStringArray, T),
		}},
		{Key: modelAccessToken, ModelName: modelAccessToken, Fields: []db.Field{
			withUnique(f("token", db.TypeString, nil)),
			withIndex(withRef(f("clientId", db.TypeString, T), modelClient, "clientId", "")),
			withIndex(withRef(f("sessionId", db.TypeString, F), "session", "id", db.OnDeleteSetNull)),
			withIndex(withRef(f("userId", db.TypeString, F), "user", "id", "")),
			f("referenceId", db.TypeString, F),
			withIndex(f("authorizationCodeId", db.TypeString, F)),
			f("resources", db.TypeStringArray, F),
			f("requestedUserInfoClaims", db.TypeStringArray, F),
			withIndex(withRef(f("refreshId", db.TypeString, F), modelRefreshToken, "id", "")),
			f("expiresAt", db.TypeDate, nil),
			f("createdAt", db.TypeDate, nil),
			f("revoked", db.TypeDate, F),
			f("confirmation", db.TypeJSON, F),
			f("scopes", db.TypeStringArray, T),
		}},
		{Key: modelConsent, ModelName: modelConsent, Fields: []db.Field{
			withIndex(withRef(f("clientId", db.TypeString, T), modelClient, "clientId", "")),
			withIndex(withRef(f("userId", db.TypeString, F), "user", "id", "")),
			f("referenceId", db.TypeString, F),
			f("resources", db.TypeStringArray, F),
			f("requestedUserInfoClaims", db.TypeStringArray, F),
			f("scopes", db.TypeStringArray, T),
			f("createdAt", db.TypeDate, nil),
			f("updatedAt", db.TypeDate, nil),
		}},
		{Key: modelClientAssertion, ModelName: modelClientAssertion, Fields: []db.Field{
			f("expiresAt", db.TypeDate, T),
		}},
	}
	for i := range tables {
		mo, ok := o[tables[i].Key]
		if !ok {
			continue
		}
		if mo.ModelName != "" {
			tables[i].ModelName = mo.ModelName
		}
		for j := range tables[i].Fields {
			if c := mo.Fields[tables[i].Fields[j].Name]; c != "" {
				tables[i].Fields[j].FieldName = c
			}
		}
		tables[i].Fields = append(tables[i].Fields, mo.AdditionalFields...)
	}
	return tables
}
