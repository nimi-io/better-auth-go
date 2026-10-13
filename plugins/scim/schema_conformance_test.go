package scim

// Port of upstream schema-conformance.test.ts ("SCIM core schema conformance").

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/openapi"
)

func scAttribute(t *testing.T, attributes []any, name string) *jsonx.Object {
	t.Helper()
	for _, a := range attributes {
		o := a.(*jsonx.Object)
		if getStr(o, "name") == name {
			return o
		}
	}
	t.Fatalf("Expected %s attribute", name)
	return nil
}

func scSubAttribute(t *testing.T, attribute *jsonx.Object, name string) *jsonx.Object {
	t.Helper()
	subs := getArr(attribute, "subAttributes")
	if subs == nil {
		t.Fatalf("Expected %s to have sub-attributes", getStr(attribute, "name"))
	}
	return scAttribute(t, subs, name)
}

func scNames(list []any) []string {
	var out []string
	for _, a := range list {
		out = append(out, getStr(a.(*jsonx.Object), "name"))
	}
	return out
}

func scExpectNames(t *testing.T, list []any, want ...string) {
	t.Helper()
	if got := scNames(list); !reflect.DeepEqual(got, want) {
		t.Fatalf("attribute names = %v, want %v", got, want)
	}
}

// scValue converts a JSON string to the value given to a schema.
func scValue(t *testing.T, s string) any {
	t.Helper()
	v, err := jsonx.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func scSafeParseOK(t *testing.T, s zSchema, input string) bool {
	t.Helper()
	_, issues := zParse(s, scValue(t, input))
	return len(issues) == 0
}

func scParse(t *testing.T, s zSchema, input string) any {
	t.Helper()
	out, issues := zParse(s, scValue(t, input))
	if len(issues) > 0 {
		t.Fatalf("parse %s: %+v", input, issues)
	}
	return out
}

func scOpenAPIResource(t *testing.T, key string) *jsonx.Object {
	t.Helper()
	doc, _ := openapiDocs.Get(key)
	var cur any = doc
	for _, k := range []string{"responses", "201", "content", MediaType, "schema"} {
		o, ok := cur.(*jsonx.Object)
		if !ok {
			t.Fatalf("openapi %s: missing %s", key, k)
		}
		cur, _ = o.Get(k)
	}
	return cur.(*jsonx.Object)
}

func TestSchemaConformance_SCIMCoreSchemaConformance(t *testing.T) {
	userSchema := discoverySchema(SchemaUser)
	enterpriseSchema := discoverySchema(SchemaEnterpriseUser)
	groupSchema := discoverySchema(SchemaGroup)

	t.Run("uses one registry for validation, discovery, and query capabilities", func(t *testing.T) {
		// The Go port has no single registry object; assert the equivalent facts. Object
		// identity checks (inputSchema/discoverySchema/openAPISchema toBe) have no Go
		// equivalent beyond the shared package-level values used below.
		descs := schemaDescriptors(resourceUser)
		var ids []string
		var enterprise *schemaDescriptor
		for i := range descs {
			ids = append(ids, descs[i].id)
			if descs[i].id == SchemaEnterpriseUser {
				enterprise = &descs[i]
			}
		}
		if !containsString(ids, SchemaUser) || enterprise == nil {
			t.Fatalf("User schema descriptors = %v", ids)
		}
		if enterprise.canonicalAttribute != "enterprise" || enterprise.responseAttribute != SchemaEnterpriseUser {
			t.Fatalf("enterprise descriptor = %+v", *enterprise)
		}
		if coreSchemaID(resourceUser) != SchemaUser || coreSchemaID(resourceGroup) != SchemaGroup {
			t.Fatal("core schema ids")
		}
		if userSchema == nil || enterpriseSchema == nil || groupSchema == nil {
			t.Fatal("discovery schemas missing")
		}
		// The openAPI enterprise schema is the User resource's enterprise property.
		ent, ok := scOpenAPIResource(t, "createSCIMUser").Get("properties")
		if !ok {
			t.Fatal("no properties")
		}
		if !ent.(*jsonx.Object).Has(SchemaEnterpriseUser) {
			t.Fatal("openapi User resource lacks enterprise property")
		}
		// Filter attributes.
		for rt, attrs := range map[resourceType][]string{
			resourceUser:  {"id", "userName", "externalId", "emails.value"},
			resourceGroup: {"id", "displayName", "externalId"},
		} {
			for _, a := range attrs {
				if got := canonicalizeFilterAttribute(rt, a); got != a {
					t.Fatalf("%s filter attribute %s -> %q", rt, a, got)
				}
			}
		}
		if got := canonicalizeFilterAttribute(resourceUser, `emails[type eq "work"].value`); got != "emails.work.value" {
			t.Fatalf("work email filter -> %q", got)
		}
		for _, a := range []string{"userName", "emails.value"} {
			if canonicalizeFilterAttribute(resourceGroup, a) != "" {
				t.Fatalf("Group must not support %s", a)
			}
		}
		if canonicalizeFilterAttribute(resourceUser, "displayName") != "" {
			t.Fatal("User must not support displayName filter")
		}
	})

	t.Run("advertises the SCIM response media type through OpenAPI", func(t *testing.T) {
		e := newEnv(t, Options{Connections: []ConnectionOptions{staticConnection("open-api", "open-api-token")}},
			envOptions{mutate: func(cfg *betterauth.Config) {
				cfg.Plugins = append(cfg.Plugins, openapi.New(openapi.Options{}))
			}})
		res, err := e.auth.API.Call(context.Background(), "generateOpenAPISchema", betterauth.CallInput{})
		if err != nil {
			t.Fatal(err)
		}
		b, err := res.JSON()
		if err != nil {
			t.Fatal(err)
		}
		doc := rapPlain(t, string(b)).(map[string]any)
		rapMatchObject(t, doc["paths"].(map[string]any)["/scim/v2/Users"].(map[string]any)["post"].(map[string]any)["responses"].(map[string]any)["201"], `{
			"content": {
				"application/scim+json": {
					"schema": {
						"properties": {
							"title": {"type": "string"},
							"phoneNumbers": {"type": "array", "maxItems": 10},
							"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
								"type": "object",
								"properties": {"manager": {"type": "object"}}
							},
							"schemas": {
								"items": {
									"enum": [
										"urn:ietf:params:scim:schemas:core:2.0:User",
										"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
									]
								}
							}
						}
					}
				}
			}
		}`)
		r400 := doc["paths"].(map[string]any)["/scim/v2/Users"].(map[string]any)["post"].(map[string]any)["responses"].(map[string]any)["400"].(map[string]any)
		if _, ok := r400["content"].(map[string]any)["application/scim+json"].(map[string]any); !ok {
			t.Fatalf("400 content = %v", r400)
		}
	})

	t.Run("advertises only the persisted User profile", func(t *testing.T) {
		attrs := getArr(userSchema, "attributes")
		scExpectNames(t, attrs, "userName", "displayName", "active", "name", "emails", "title", "userType",
			"preferredLanguage", "locale", "timezone", "phoneNumbers", "addresses", "roles", "entitlements")
		for _, n := range scNames(attrs) {
			if n == "id" || n == "externalId" {
				t.Fatalf("unexpected %s attribute", n)
			}
		}
		rapMatchObject(t, scAttribute(t, attrs, "userName"), `{"required":true,"caseExact":false,"mutability":"readWrite","returned":"default","uniqueness":"server"}`)
		rapMatchObject(t, scAttribute(t, attrs, "displayName"), `{"required":false,"caseExact":false,"mutability":"readWrite","returned":"default","uniqueness":"none"}`)
		name := scAttribute(t, attrs, "name")
		rapMatchObject(t, name, `{"required":false,"mutability":"readWrite","returned":"default","uniqueness":"none"}`)
		scExpectNames(t, getArr(name, "subAttributes"), "formatted", "givenName", "familyName", "middleName", "honorificPrefix", "honorificSuffix")
		rapMatchObject(t, scSubAttribute(t, name, "formatted"), `{"required":false,"caseExact":false,"mutability":"readWrite","returned":"default","uniqueness":"none"}`)
		emails := scAttribute(t, attrs, "emails")
		rapMatchObject(t, emails, `{"required":false,"mutability":"readWrite","returned":"default","uniqueness":"none"}`)
		scExpectNames(t, getArr(emails, "subAttributes"), "value", "type", "primary")
		rapMatchObject(t, scSubAttribute(t, emails, "value"), `{"required":true,"caseExact":false,"mutability":"readWrite","returned":"default","uniqueness":"none"}`)
		rapMatchObject(t, scSubAttribute(t, emails, "primary"), `{"required":false,"mutability":"readWrite","returned":"default"}`)
		for _, n := range []string{"title", "userType", "preferredLanguage", "locale", "timezone"} {
			rapMatchObject(t, scAttribute(t, attrs, n), `{"required":false,"mutability":"readWrite","returned":"default"}`)
		}
		for _, n := range []string{"phoneNumbers", "addresses", "roles", "entitlements"} {
			rapMatchObject(t, scAttribute(t, attrs, n), `{"multiValued":true,"required":false,"mutability":"readWrite","returned":"default"}`)
		}

		if scSafeParseOK(t, apiUserSchema, `{"userName":""}`) {
			t.Fatal("empty userName accepted")
		}
		if scSafeParseOK(t, apiUserSchema, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"directory-user-without-email"}`) {
			t.Fatal("user without email accepted")
		}
		if scSafeParseOK(t, apiUserSchema, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"directory-user","emails":[{"value":"`+strings.Repeat("a", 255)+`@example.com","primary":true}]}`) {
			t.Fatal("overlong email accepted")
		}
		if scSafeParseOK(t, apiUserSchema, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"ada@example.com","emails":[{"value":"first@example.com","type":"work"},{"value":"second@example.com","type":"WORK"}]}`) {
			t.Fatal("duplicate email types accepted")
		}
		rapEqual(t, scParse(t, apiUserSchema, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"ADA@EXAMPLE.COM","name":{"formatted":"Ada Lovelace","givenName":"Ada"}}`),
			`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"ADA@EXAMPLE.COM","name":{"formatted":"Ada Lovelace","givenName":"Ada"}}`)
	})

	t.Run("validates and advertises the built-in Enterprise User extension", func(t *testing.T) {
		attrs := getArr(enterpriseSchema, "attributes")
		scExpectNames(t, attrs, "employeeNumber", "costCenter", "organization", "division", "department", "manager")
		for _, n := range []string{"employeeNumber", "costCenter", "organization", "division", "department"} {
			rapMatchObject(t, scAttribute(t, attrs, n), `{"required":false,"mutability":"readWrite","returned":"default"}`)
		}
		manager := scAttribute(t, attrs, "manager")
		rapMatchObject(t, manager, `{"type":"complex","multiValued":false,"mutability":"readWrite","returned":"default"}`)
		rapMatchObject(t, scSubAttribute(t, manager, "value"), `{"required":false,"mutability":"readWrite","returned":"default"}`)
		rapMatchObject(t, scSubAttribute(t, manager, "$ref"), `{"referenceTypes":["User"],"mutability":"readWrite","returned":"default"}`)
		rapMatchObject(t, scSubAttribute(t, manager, "displayName"), `{"mutability":"readOnly","returned":"default"}`)

		const ent = SchemaEnterpriseUser
		rapEqual(t, scParse(t, apiUserSchema, `{"schemas":["`+ent+`","`+SchemaUser+`"],"userName":"entra-declared@example.com"}`),
			`{"schemas":["`+SchemaUser+`","`+ent+`"],"userName":"entra-declared@example.com"}`)
		rapMatchObject(t, scParse(t, apiUserSchema, `{"schemas":["`+SchemaUser+`","`+ent+`"],"userName":"entra-manager@example.com","`+ent+`":{"employeeNumber":" 42 ","manager":" manager-1 "}}`),
			`{"`+ent+`":{"employeeNumber":"42","manager":{"value":"manager-1"}}}`)
		rapEqual(t, scParse(t, apiUserSchema, `{"schemas":["`+SchemaUser+`","`+ent+`"],"userName":"rfc-manager@example.com",
			"`+ent+`":{"manager":{"value":"external-manager","$ref":"https://directory.example/Users/external-manager","displayName":"External Manager"}},
			"password":"not accepted","ims":[{"value":"not accepted"}],"photos":[{"value":"not accepted"}],"x509Certificates":[{"value":"not accepted"}]}`),
			`{"schemas":["`+SchemaUser+`","`+ent+`"],"userName":"rfc-manager@example.com","`+ent+`":{"manager":{"value":"external-manager","$ref":"https://directory.example/Users/external-manager"}}}`)
		rapMatchObject(t, scParse(t, apiUserSchema, `{"schemas":["`+SchemaUser+`","`+ent+`"],"userName":"entra-manager-array@example.com",
			"`+ent+`":{"manager":[{"value":"manager-2","$ref":"/scim/v2/Users/manager-2","displayName":"Manager Two"}]}}`),
			`{"`+ent+`":{"manager":{"value":"manager-2","$ref":"/scim/v2/Users/manager-2"}}}`)
		rapMatchObject(t, scParse(t, apiUserSchema, `{"schemas":["`+SchemaUser+`","`+ent+`"],"userName":"reference-only-manager@example.com",
			"`+ent+`":{"manager":{"$ref":"/scim/v2/Users/manager-3","displayName":"Ignored client display value"}}}`),
			`{"`+ent+`":{"manager":{"$ref":"/scim/v2/Users/manager-3"}}}`)
		rapEqual(t, scParse(t, apiUserSchema, `{"schemas":["`+SchemaUser+`","`+ent+`"],"userName":"display-only-manager@example.com",
			"`+ent+`":{"manager":{"displayName":"Ignored client display value"}}}`),
			`{"schemas":["`+SchemaUser+`","`+ent+`"],"userName":"display-only-manager@example.com","`+ent+`":{}}`)

		_, issues := zParse(apiUserSchema, scValue(t, `{"schemas":["`+SchemaUser+`"],"userName":"undeclared@example.com","`+ent+`":{"employeeNumber":"42"}}`))
		if len(issues) == 0 {
			t.Fatal("undeclared enterprise extension accepted")
		}
		if !reflect.DeepEqual(issues[0].Path, []any{"schemas"}) || !strings.Contains(issues[0].Message, ent) {
			t.Fatalf("issue[0] = %+v", issues[0])
		}
		if scSafeParseOK(t, apiUserSchema, `{"schemas":["`+SchemaUser+`","urn:example:params:scim:schemas:extension:2.0:User"],"userName":"unknown@example.com"}`) {
			t.Fatal("unknown extension accepted")
		}
		if scSafeParseOK(t, apiUserSchema, `{"schemas":["`+SchemaUser+`","`+ent+`"],"userName":"invalid-manager@example.com","`+ent+`":{"manager":[]}}`) {
			t.Fatal("empty manager array accepted")
		}
		if scSafeParseOK(t, apiUserSchema, `{"schemas":["`+SchemaUser+`"],"userName":"invalid-boolean@example.com","phoneNumbers":[{"value":"+1-555-0100","primary":"true"}]}`) {
			t.Fatal("string boolean accepted")
		}
	})

	t.Run("requires unique case-insensitive defined types on User multi-valued attributes", func(t *testing.T) {
		cases := []struct{ attribute, values string }{
			{"emails", `[{"value":"first@example.com","type":"Work","primary":true},{"value":"second@example.com","type":"work"}]`},
			{"phoneNumbers", `[{"value":"+1-555-0100","type":"Work"},{"value":"+1-555-0101","type":"work"}]`},
			{"addresses", `[{"formatted":"First office","type":"Work"},{"formatted":"Second office","type":"work"}]`},
			{"roles", `[{"value":"first-role","type":"Work"},{"value":"second-role","type":"work"}]`},
			{"entitlements", `[{"value":"first-entitlement","type":"Work"},{"value":"second-entitlement","type":"work"}]`},
		}
		for _, c := range cases {
			if scSafeParseOK(t, apiUserSchema, `{"schemas":["`+SchemaUser+`"],"userName":"`+c.attribute+`@example.com","`+c.attribute+`":`+c.values+`}`) {
				t.Fatalf("%s: duplicate types accepted", c.attribute)
			}
			canonical := `{"schemas":["` + SchemaUser + `"],"name":{"formatted":"Typed User"},`
			if c.attribute == "emails" {
				canonical += `"emails":` + c.values + `}`
			} else {
				canonical += `"emails":[{"value":"typed@example.com","primary":true}],"` + c.attribute + `":` + c.values + `}`
			}
			if scSafeParseOK(t, canonicalUserAttributesSchema, canonical) {
				t.Fatalf("%s canonical: duplicate types accepted", c.attribute)
			}
		}
		if !scSafeParseOK(t, apiUserSchema, `{"schemas":["`+SchemaUser+`"],"userName":"untyped@example.com",
			"emails":[{"value":"first@example.com","primary":true},{"value":"second@example.com"}],
			"phoneNumbers":[{"value":"+1-555-0100"},{"value":"+1-555-0101"}],
			"addresses":[{"formatted":"First office"},{"formatted":"Second office"}],
			"roles":[{"value":"first-role"},{"value":"second-role"}],
			"entitlements":[{"value":"first-entitlement"},{"value":"second-entitlement"}]}`) {
			t.Fatal("untyped multi-valued attributes rejected")
		}
	})

	t.Run("rejects an address whose only content is its type or primary flag", func(t *testing.T) {
		if scSafeParseOK(t, apiUserSchema, `{"schemas":["`+SchemaUser+`"],"userName":"typeless-address@example.com","addresses":[{"type":"work"}]}`) {
			t.Fatal("type-only address accepted")
		}
		if scSafeParseOK(t, apiUserSchema, `{"schemas":["`+SchemaUser+`"],"userName":"primary-only-address@example.com","addresses":[{"type":"work","primary":true}]}`) {
			t.Fatal("primary-only address accepted")
		}
		if !scSafeParseOK(t, apiUserSchema, `{"schemas":["`+SchemaUser+`"],"userName":"content-address@example.com","addresses":[{"type":"work","locality":"Cambridge"}]}`) {
			t.Fatal("address with content rejected")
		}
	})

	t.Run("advertises canonical User-only Group memberships", func(t *testing.T) {
		attrs := getArr(groupSchema, "attributes")
		scExpectNames(t, attrs, "displayName", "members")
		rapMatchObject(t, scAttribute(t, attrs, "displayName"), `{"required":true,"caseExact":false,"mutability":"readWrite","returned":"default","uniqueness":"server"}`)
		members := scAttribute(t, attrs, "members")
		rapMatchObject(t, members, `{"required":false,"mutability":"readWrite","returned":"default","uniqueness":"none"}`)
		scExpectNames(t, getArr(members, "subAttributes"), "value", "$ref", "display", "type")
		rapMatchObject(t, scSubAttribute(t, members, "value"), `{"required":true,"caseExact":false,"mutability":"immutable","returned":"default","uniqueness":"none"}`)
		rapMatchObject(t, scSubAttribute(t, members, "$ref"), `{"referenceTypes":["User"],"mutability":"immutable","returned":"default"}`)
		rapMatchObject(t, scSubAttribute(t, members, "display"), `{"mutability":"readOnly","returned":"default"}`)
		rapMatchObject(t, scSubAttribute(t, members, "type"), `{"canonicalValues":["User"],"mutability":"immutable","returned":"default"}`)

		if scSafeParseOK(t, apiGroupSchema, `{"displayName":"Engineering","members":[{}]}`) {
			t.Fatal("empty member accepted")
		}
		rapEqual(t, scParse(t, apiGroupSchema, `{"schemas":["`+SchemaGroup+`"],"displayName":"Engineering","members":[{"value":"scim-user-id","$ref":"https://example.com/scim/v2/Users/scim-user-id","display":"not persisted","type":"User"}]}`),
			`{"schemas":["`+SchemaGroup+`"],"displayName":"Engineering","members":[{"value":"scim-user-id","type":"User"}]}`)
	})

	t.Run("requires only fields that survive every response projection", func(t *testing.T) {
		user := scOpenAPIResource(t, "createSCIMUser")
		rapEqual(t, objGet(user, "required"), []any{"schemas", "id"})
		props, _ := getObj(user, "properties")
		for _, k := range []string{"externalId", "title", "phoneNumbers", SchemaEnterpriseUser} {
			if !props.Has(k) {
				t.Fatalf("User properties lack %s", k)
			}
		}
		entProps, _ := getObj(props, SchemaEnterpriseUser)
		entProps, _ = getObj(entProps, "properties")
		manager, _ := getObj(entProps, "manager")
		managerProps, _ := getObj(manager, "properties")
		if managerProps == nil || managerProps.Has("displayName") {
			t.Fatalf("manager properties = %s", jsonx.MustMarshal(managerProps))
		}
		schemas, _ := getObj(props, "schemas")
		items, _ := getObj(schemas, "items")
		rapEqual(t, objGet(items, "enum"), []any{SchemaUser, SchemaEnterpriseUser})
		name, _ := getObj(props, "name")
		emails, _ := getObj(props, "emails")
		emailItems, _ := getObj(emails, "items")
		meta, _ := getObj(props, "meta")
		for label, o := range map[string]*jsonx.Object{"name": name, "emails.items": emailItems, "meta": meta} {
			if o == nil || o.Has("required") {
				t.Fatalf("User %s: %s", label, jsonx.MustMarshal(o))
			}
		}

		group := scOpenAPIResource(t, "createSCIMGroup")
		rapEqual(t, objGet(group, "required"), []any{"schemas", "id"})
		gprops, _ := getObj(group, "properties")
		gmembers, _ := getObj(gprops, "members")
		gmemberItems, _ := getObj(gmembers, "items")
		gmeta, _ := getObj(gprops, "meta")
		for label, o := range map[string]*jsonx.Object{"members.items": gmemberItems, "meta": gmeta} {
			if o == nil || o.Has("required") {
				t.Fatalf("Group %s: %s", label, jsonx.MustMarshal(o))
			}
		}
	})
}
