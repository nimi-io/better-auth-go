package scim

// Port of upstream discovery.test.ts ("SCIM discovery"). Like upstream, the auth instance
// registers only the discovery endpoints in a standalone plugin (no SCIM plugin).

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

func discoveryTestAuth(t *testing.T) *betterauth.Auth {
	t.Helper()
	a, err := betterauth.New(betterauth.Config{
		BaseURL:   testBaseURL,
		Secret:    testAuthSecret,
		Logger:    betterauth.NopLogger{},
		RateLimit: &betterauth.RateLimitConfig{Enabled: betterauth.Bool(false)},
		Database:  memory.New(memory.NewDB()),
		Plugins:   []*betterauth.Plugin{{ID: "scim-discovery-test", Endpoints: discoveryEndpoints()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func discoveryCall(t *testing.T, a *betterauth.Auth, key string, in betterauth.CallInput) (map[string]any, *betterauth.APIError) {
	t.Helper()
	res, err := a.API.Call(context.Background(), key, in)
	if err != nil {
		ae, ok := betterauth.AsAPIError(err)
		if !ok {
			t.Fatalf("%s: %v", key, err)
		}
		return nil, ae
	}
	var m map[string]any
	if err := res.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m, nil
}

func TestDiscovery_SCIMDiscovery(t *testing.T) {
	t.Run("describes supported protocol capabilities without an organization dependency", func(t *testing.T) {
		a := discoveryTestAuth(t)
		config, ae := discoveryCall(t, a, "getSCIMServiceProviderConfig", betterauth.CallInput{})
		if ae != nil {
			t.Fatalf("error %d", ae.StatusCode)
		}
		rapMatchObject(t, config, `{
			"patch": {"supported": true},
			"bulk": {"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
			"filter": {"supported": true, "maxResults": 100},
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
			"meta": {
				"resourceType": "ServiceProviderConfig",
				"location": "http://localhost:3000/api/auth/scim/v2/ServiceProviderConfig"
			}
		}`)
		schemes, _ := config["authenticationSchemes"].([]any)
		if len(schemes) != 1 {
			t.Fatalf("authenticationSchemes = %v", config["authenticationSchemes"])
		}
		rapMatchObject(t, schemes[0], `{"type":"oauthbearertoken","primary":true}`)
		if strings.Contains(string(jsonx.MustMarshal(config)), "organization") {
			t.Fatal("config mentions organization")
		}
	})

	t.Run("returns supported schemas and resource types as SCIM ListResponses", func(t *testing.T) {
		a := discoveryTestAuth(t)
		schemas, ae := discoveryCall(t, a, "getSCIMSchemas", betterauth.CallInput{})
		if ae != nil {
			t.Fatal(ae.StatusCode)
		}
		resourceTypes, ae := discoveryCall(t, a, "getSCIMResourceTypes", betterauth.CallInput{})
		if ae != nil {
			t.Fatal(ae.StatusCode)
		}
		rapMatchObject(t, schemas, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":3,"startIndex":1,"itemsPerPage":3}`)
		var ids []string
		for _, r := range schemas["Resources"].([]any) {
			ids = append(ids, r.(map[string]any)["id"].(string))
		}
		wantIDs := []string{
			"urn:ietf:params:scim:schemas:core:2.0:User",
			"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
			"urn:ietf:params:scim:schemas:core:2.0:Group",
		}
		if !reflect.DeepEqual(ids, wantIDs) {
			t.Fatalf("schema ids = %v", ids)
		}
		rapMatchObject(t, resourceTypes, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":2,"startIndex":1,"itemsPerPage":2}`)
		var summary []any
		for _, r := range resourceTypes["Resources"].([]any) {
			rt := r.(map[string]any)
			s := map[string]any{"id": rt["id"], "endpoint": rt["endpoint"], "schema": rt["schema"]}
			if ext, ok := rt["schemaExtensions"]; ok {
				s["schemaExtensions"] = ext
			}
			summary = append(summary, s)
		}
		rapEqual(t, summary, `[
			{
				"id": "User",
				"endpoint": "/Users",
				"schema": "urn:ietf:params:scim:schemas:core:2.0:User",
				"schemaExtensions": [
					{"schema": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", "required": false}
				]
			},
			{"id": "Group", "endpoint": "/Groups", "schema": "urn:ietf:params:scim:schemas:core:2.0:Group"}
		]`)
	})

	t.Run("returns SCIM errors for unknown schema and resource type identifiers", func(t *testing.T) {
		a := discoveryTestAuth(t)
		_, ae := discoveryCall(t, a, "getSCIMSchema", betterauth.CallInput{Params: map[string]string{"schemaId": "unknown"}})
		if ae == nil {
			t.Fatal("expected error")
		}
		rapMatchObject(t, errBody(ae), `{"detail":"Schema not found","schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"404"}`)
		_, ae = discoveryCall(t, a, "getSCIMResourceType", betterauth.CallInput{Params: map[string]string{"resourceTypeId": "unknown"}})
		if ae == nil {
			t.Fatal("expected error")
		}
		rapMatchObject(t, errBody(ae), `{"detail":"Resource type not found","schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"404"}`)
	})
}
