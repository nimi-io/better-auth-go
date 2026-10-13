package oauthprovider

import (
	"reflect"
	"testing"

	"github.com/nimi-io/better-auth-go/db"
)

// Port of schema.test.ts.

func mxSchemaTable(t *testing.T, key string) *db.PluginTable {
	t.Helper()
	for _, tb := range Schema(nil) {
		if tb.Key == key {
			tb := tb
			return &tb
		}
	}
	return nil
}

func mxSchemaField(t *testing.T, model, field string) *db.Field {
	t.Helper()
	tb := mxSchemaTable(t, model)
	if tb == nil {
		return nil
	}
	for _, f := range tb.Fields {
		if f.Name == field {
			f := f
			return &f
		}
	}
	return nil
}

func TestMx_OAuthProviderSchema(t *testing.T) {
	t.Run("indexes OAuth foreign-key fields", func(t *testing.T) {
		for _, pair := range [][2]string{
			{"oauthClient", "userId"},
			{"oauthRefreshToken", "clientId"},
			{"oauthRefreshToken", "sessionId"},
			{"oauthRefreshToken", "userId"},
			{"oauthAccessToken", "clientId"},
			{"oauthAccessToken", "sessionId"},
			{"oauthAccessToken", "userId"},
			{"oauthAccessToken", "refreshId"},
			{"oauthConsent", "clientId"},
			{"oauthConsent", "userId"},
			{"oauthClientResource", "clientId"},
			{"oauthClientResource", "resourceId"},
		} {
			f := mxSchemaField(t, pair[0], pair[1])
			if f == nil || f.References == nil || !f.Index {
				t.Fatalf("%s.%s: %+v", pair[0], pair[1], f)
			}
		}
	})
	t.Run("enforces one client-resource link per pair with a compound unique index", func(t *testing.T) {
		tb := mxSchemaTable(t, "oauthClientResource")
		found := false
		for _, idx := range tb.Indexes {
			if reflect.DeepEqual(idx.Fields, []string{"clientId", "resourceId"}) && idx.Unique {
				found = true
			}
		}
		if !found {
			t.Fatalf("indexes: %+v", tb.Indexes)
		}
	})
	t.Run("defaults new client_credentials scope authority to an empty array", func(t *testing.T) {
		f := mxSchemaField(t, "oauthClient", "clientCredentialsScopes")
		if f == nil || f.Type != db.TypeStringArray || f.Required == nil || *f.Required {
			t.Fatalf("field: %+v", f)
		}
		if arr, ok := f.DefaultValue.([]any); !ok || len(arr) != 0 {
			t.Fatalf("default: %#v", f.DefaultValue)
		}
	})
	t.Run("declares the oauthResource entity with the expected policy seams", func(t *testing.T) {
		req := func(name string) *db.Field {
			f := mxSchemaField(t, "oauthResource", name)
			if f == nil {
				t.Fatalf("oauthResource.%s missing from schema", name)
			}
			return f
		}
		isRequired := func(f *db.Field) bool { return f.Required != nil && *f.Required }
		if !req("identifier").Unique || !isRequired(req("identifier")) {
			t.Fatal("identifier must be unique and required")
		}
		if !isRequired(req("name")) {
			t.Fatal("name must be required")
		}
		for _, n := range []string{"accessTokenTtl", "refreshTokenTtl", "signingAlgorithm", "signingKeyId", "allowedScopes", "customClaims"} {
			if isRequired(req(n)) {
				t.Fatalf("%s must not be required", n)
			}
		}
		if req("disabled").DefaultValue != false {
			t.Fatalf("disabled default: %v", req("disabled").DefaultValue)
		}
		if dv := req("policyVersion").DefaultValue; dv != 1 && dv != float64(1) {
			t.Fatalf("policyVersion default: %v", dv)
		}
		req("metadata")
	})
	t.Run("declares DPoP sender-constraint storage with enforcement state", func(t *testing.T) {
		if f := mxSchemaField(t, "oauthClient", "dpopBoundAccessTokens"); f == nil || f.DefaultValue != false {
			t.Fatalf("client dpopBoundAccessTokens: %+v", f)
		}
		if f := mxSchemaField(t, "oauthResource", "dpopBoundAccessTokensRequired"); f == nil || f.DefaultValue != false {
			t.Fatalf("resource dpopBoundAccessTokensRequired: %+v", f)
		}
		for _, pair := range [][2]string{{"oauthRefreshToken", "confirmation"}, {"oauthAccessToken", "confirmation"},
			{"oauthRefreshToken", "authorizationCodeId"}, {"oauthAccessToken", "authorizationCodeId"}} {
			if mxSchemaField(t, pair[0], pair[1]) == nil {
				t.Fatalf("%s.%s missing", pair[0], pair[1])
			}
		}
		for _, n := range []string{"tokenFormat", "encryptionAlgorithm", "encryptionKeyId", "requireMtls"} {
			if mxSchemaField(t, "oauthResource", n) != nil {
				t.Fatalf("oauthResource.%s should not exist", n)
			}
		}
		if mxSchemaField(t, "oauthRefreshToken", "senderConstraintType") != nil || mxSchemaField(t, "oauthRefreshToken", "senderConstraintKey") != nil {
			t.Fatal("sender constraint columns should not exist")
		}
	})
}
