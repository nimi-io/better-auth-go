package openapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// Port of packages/better-auth/src/plugins/open-api/open-api.test.ts.

func newInstance(t *testing.T, mutate func(c *betterauth.Config), plugins ...*betterauth.Plugin) *betterauth.Auth {
	t.Helper()
	t.Setenv("NODE_ENV", "test")
	cfg := betterauth.Config{
		BaseURL:          "http://localhost:3000",
		Secret:           "test-secret-that-is-long-enough-for-tests-1234567890",
		Database:         memory.New(),
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true},
		Logger:           betterauth.NopLogger{},
		Plugins:          plugins,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := betterauth.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

// generate calls auth.api.generateOpenAPISchema() and returns the parsed document.
func generate(t *testing.T, a *betterauth.Auth) map[string]any {
	t.Helper()
	res, err := a.API.Call(context.Background(), "generateOpenAPISchema", betterauth.CallInput{})
	if err != nil {
		t.Fatalf("generateOpenAPISchema: %v", err)
	}
	b, err := res.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func get(t *testing.T, v any, path ...string) any {
	t.Helper()
	cur := v
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("path %v: %q is not an object (%T)", path, p, cur)
		}
		cur, ok = m[p]
		if !ok {
			t.Fatalf("path %v: missing %q", path, p)
		}
	}
	return cur
}

func lookup(v any, path ...string) (any, bool) {
	cur := v
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func obj(t *testing.T, v any, path ...string) map[string]any {
	t.Helper()
	m, ok := get(t, v, path...).(map[string]any)
	if !ok {
		t.Fatalf("path %v is not an object", path)
	}
	return m
}

func strList(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func equalJSON(t *testing.T, got any, want string) {
	t.Helper()
	var w any
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, w) {
		g, _ := json.Marshal(got)
		t.Fatalf("got %s, want %s", g, want)
	}
}

func postBodySchema(t *testing.T, doc map[string]any, path string) map[string]any {
	t.Helper()
	return obj(t, doc, "paths", path, "post", "requestBody", "content", "application/json", "schema")
}

func successResponses() *jsonx.Object {
	return jsonx.O("200", jsonx.O("description", "Success", "content", jsonx.O("application/json", jsonx.O("schema",
		jsonx.O("type", "object", "properties", jsonx.O("success", jsonx.O("type", "boolean")), "required", []any{"success"})))))
}

func okHandler(*betterauth.EndpointContext) (any, error) { return jsonx.O("success", true), nil }

var nullableIntersectionPlugin = &betterauth.Plugin{
	ID: "nullable-intersection-test",
	Endpoints: []*betterauth.Endpoint{{
		Key: "nullableIntersection", Path: "/test/nullable-intersection", Methods: []string{"POST"},
		Body: validate.And(
			validate.Nullable(validate.Object(validate.F("email", validate.String()))),
			validate.Nullable(validate.Object(validate.F("otp", validate.String()))),
		),
		Metadata: map[string]any{"openapi": jsonx.O(
			"operationId", "nullableIntersectionTest",
			"description", "Test nullable object intersection request bodies",
			"responses", successResponses(),
		)},
		Handler: okHandler,
	}},
}

var defaultBodyPlugin = &betterauth.Plugin{
	ID: "default-body-test",
	Endpoints: []*betterauth.Endpoint{{
		Key: "defaultBody", Path: "/test/default-body", Methods: []string{"POST"},
		Body: validate.Default(validate.Object(validate.F("rememberMe", validate.Boolean())), map[string]any{"rememberMe": true}),
		Metadata: map[string]any{"openapi": jsonx.O(
			"operationId", "defaultBodyTest",
			"description", "Test default-wrapped request bodies",
			"responses", successResponses(),
		)},
		Handler: okHandler,
	}},
}

var unionIntersectionPlugin = &betterauth.Plugin{
	ID: "union-intersection-test",
	Endpoints: []*betterauth.Endpoint{{
		Key: "chooseRole", Path: "/test/choose-role", Methods: []string{"POST"},
		Body: validate.And(
			validate.Object(validate.F("organizationId", validate.Optional(validate.String()))),
			validate.Union(
				validate.Object(validate.F("roleName", validate.String())),
				validate.Object(validate.F("roleId", validate.String())),
			),
		),
		Handler: okHandler,
	}},
}

var recordIntersectionPlugin = &betterauth.Plugin{
	ID: "record-intersection-test",
	Endpoints: []*betterauth.Endpoint{{
		Key: "updateFields", Path: "/test/update-fields", Methods: []string{"POST"},
		Body: validate.And(
			validate.Object(validate.F("knownField", validate.String())),
			validate.RecordOf(
				validate.Describe(validate.String().Min(2), "Custom field names must be at least two characters"),
				validate.Boolean(),
			),
		),
		Handler: okHandler,
	}},
}

var queryConstraintsPlugin = &betterauth.Plugin{
	ID: "query-constraints-test",
	Endpoints: []*betterauth.Endpoint{{
		Key: "constrainedQuery", Path: "/test/query-constraints", Methods: []string{"GET"},
		Query: validate.Object(
			validate.F("direct", validate.String().Min(3)),
			validate.F("optional", validate.Optional(validate.String().Min(4))),
			validate.F("defaulted", validate.Default(validate.String().Min(5), "abcde")),
			validate.F("bounded", validate.String().Min(6).Max(12)),
		),
		Handler: okHandler,
	}},
}

var defaultFactoryCallCount = 0

// defaultFactoryBodyPlugin: Go defaults are values, so there is no factory to evaluate;
// the counter documents that generation never validates (and so never defaults) a body.
var defaultFactoryBodyPlugin = &betterauth.Plugin{
	ID: "default-factory-body-test",
	Endpoints: []*betterauth.Endpoint{{
		Key: "defaultFactoryBody", Path: "/test/default-factory-body", Methods: []string{"POST"},
		Body: validate.Preprocess(func(v any) any {
			if validate.IsUndefined(v) {
				defaultFactoryCallCount++
			}
			return v
		}, validate.Default(validate.Object(validate.F("nonce", validate.String())), map[string]any{"nonce": "generated"})),
		Handler: okHandler,
	}},
}

var wrapperDefaultFactoryCallCount = 0

var wrapperSemanticsPlugin = &betterauth.Plugin{
	ID: "wrapper-semantics-test",
	Endpoints: []*betterauth.Endpoint{{
		Key: "wrapperSemantics", Path: "/test/wrapper-semantics", Methods: []string{"POST"},
		Body: validate.Object(
			validate.F("optionalNullable", validate.Nullable(validate.Optional(validate.String()))),
			validate.F("nullableDefault", validate.Nullable(validate.Preprocess(func(v any) any {
				if validate.IsUndefined(v) {
					wrapperDefaultFactoryCallCount++
				}
				return v
			}, validate.Default(validate.String(), "generated-default")))),
			validate.F("prefaulted", validate.Prefault(validate.String(), "prefaulted-value")),
			validate.F("nonOptional", validate.NonOptional(validate.Optional(validate.String()))),
			validate.F("unionOptional", validate.Union(validate.String(), validate.UndefinedValue())),
			validate.F("unknownPayload", validate.Unknown()),
			validate.F("anyPayload", validate.Any()),
			validate.F("undefinedPayload", validate.UndefinedValue()),
			validate.F("voidPayload", validate.Void()),
			validate.F("caughtPayload", validate.Catch(validate.String(), "caught-value")),
			validate.F("caughtOptional", validate.Catch(validate.Optional(validate.String()), "caught-value")),
			validate.F("preprocessedOptional", validate.Preprocess(func(v any) any { return v }, validate.Optional(validate.String()))),
			validate.F("intersectionOptional", validate.And(validate.Optional(validate.String()), validate.Optional(validate.String()))),
		),
		Handler: okHandler,
	}},
}

// The email-otp, phone-number and username fixtures below mirror the request body schemas
// and user schema fields of the upstream plugins the spec instantiates
// (email-otp/routes.ts, phone-number/routes.ts, username/schema.ts), so the generator is
// exercised against the same shapes independently of those Go packages.

func emailOTPFixture() *betterauth.Plugin {
	email := validate.Describe(validate.String(), "Email address")
	otp := validate.Describe(validate.String(), "OTP")
	post := func(key, path string, body validate.Schema) *betterauth.Endpoint {
		return &betterauth.Endpoint{Key: key, Path: path, Methods: []string{"POST"}, Body: body, Handler: okHandler}
	}
	typ := validate.F("type", validate.Enum("email-verification", "sign-in", "forget-password", "change-email"))
	return &betterauth.Plugin{ID: "email-otp", Endpoints: []*betterauth.Endpoint{
		post("sendVerificationOTP", "/email-otp/send-verification-otp", validate.Object(validate.F("email", email), typ)),
		post("checkVerificationOTP", "/email-otp/check-verification-otp", validate.Object(validate.F("email", email), typ, validate.F("otp", otp))),
		post("verifyEmailOTP", "/email-otp/verify-email", validate.Object(validate.F("email", email), validate.F("otp", otp))),
		post("signInEmailOTP", "/sign-in/email-otp", validate.And(validate.Object(
			validate.F("email", validate.Describe(validate.String(), "Email address to sign in")),
			validate.F("otp", validate.Describe(validate.String(), "OTP sent to the email")),
			validate.F("name", validate.Optional(validate.Describe(validate.String(), `User display name. Only used if the user is registering for the first time. Eg: "my-name"`))),
			validate.F("image", validate.Optional(validate.Describe(validate.String(), "User profile image URL. Only used if the user is registering for the first time."))),
		), validate.Record(validate.Any()))),
		post("requestPasswordResetEmailOTP", "/email-otp/request-password-reset", validate.Object(validate.F("email", email))),
		post("forgetPasswordEmailOTP", "/forget-password/email-otp", validate.Object(validate.F("email", email))),
		post("resetPasswordEmailOTP", "/email-otp/reset-password", validate.Object(
			validate.F("email", email), validate.F("otp", otp), validate.F("password", validate.String()))),
		post("requestEmailChangeEmailOTP", "/email-otp/request-email-change", validate.Object(
			validate.F("newEmail", email), validate.F("otp", validate.Optional(otp)))),
		post("changeEmailEmailOTP", "/email-otp/change-email", validate.Object(validate.F("newEmail", email), validate.F("otp", otp))),
	}}
}

func phoneNumberFixture() *betterauth.Plugin {
	post := func(key, path string, body validate.Schema) *betterauth.Endpoint {
		return &betterauth.Endpoint{Key: key, Path: path, Methods: []string{"POST"}, Body: body, Handler: okHandler}
	}
	phone := validate.Describe(validate.String(), `Phone number to verify. Eg: "+1234567890"`)
	return &betterauth.Plugin{ID: "phone-number", Endpoints: []*betterauth.Endpoint{
		post("signInPhoneNumber", "/sign-in/phone-number", validate.Object(
			validate.F("phoneNumber", phone), validate.F("password", validate.String()),
			validate.F("rememberMe", validate.Optional(validate.Boolean())))),
		post("sendPhoneNumberOTP", "/phone-number/send-otp", validate.Object(validate.F("phoneNumber", phone))),
		post("verifyPhoneNumber", "/phone-number/verify", validate.And(validate.Object(
			validate.F("phoneNumber", phone),
			validate.F("code", validate.Describe(validate.String(), `OTP code. Eg: "123456"`)),
			validate.F("disableSession", validate.Optional(validate.Describe(validate.Boolean(), "Disable session creation after verification. Eg: false"))),
			validate.F("updatePhoneNumber", validate.Optional(validate.Describe(validate.Boolean(), "Check if there is a session and update the phone number. Eg: true"))),
		), validate.Record(validate.Any()))),
		post("requestPasswordResetPhoneNumber", "/phone-number/request-password-reset", validate.Object(validate.F("phoneNumber", phone))),
		post("resetPasswordPhoneNumber", "/phone-number/reset-password", validate.Object(
			validate.F("otp", validate.String()), validate.F("phoneNumber", phone), validate.F("newPassword", validate.String()))),
	}}
}

func usernameFixture() *betterauth.Plugin {
	return &betterauth.Plugin{ID: "username", Schema: []db.PluginTable{{Key: "user", Fields: []db.Field{
		{Name: "username", Type: db.TypeString, Required: db.False, Sortable: true, Unique: true, Returned: db.True},
		{Name: "displayUsername", Type: db.TypeString, Required: db.False},
	}}}}
}

func additionalFieldsConfig(c *betterauth.Config) {
	c.User = &betterauth.UserConfig{ModelConfig: betterauth.ModelConfig{AdditionalFields: []db.Field{
		{Name: "role", Type: db.TypeString, Required: db.True, DefaultValue: "user"},
		{Name: "preferences", Type: db.TypeString, Required: db.False},
	}}}
}

func TestOpenAPI(t *testing.T) {
	auth := newInstance(t, additionalFieldsConfig, New(Options{}))
	authWithEmailOTP := newInstance(t, nil, New(Options{}), emailOTPFixture())
	authWithPhoneNumber := newInstance(t, nil, phoneNumberFixture(), New(Options{}))
	authWithNullableIntersection := newInstance(t, nil, New(Options{}), nullableIntersectionPlugin)
	authWithDefaultBody := newInstance(t, nil, New(Options{}), defaultBodyPlugin)
	authWithUnionIntersection := newInstance(t, nil, New(Options{}), unionIntersectionPlugin)
	authWithRecordIntersection := newInstance(t, nil, New(Options{}), recordIntersectionPlugin)
	authWithQueryConstraints := newInstance(t, nil, New(Options{}), queryConstraintsPlugin)
	authWithDefaultFactoryBody := newInstance(t, nil, New(Options{}), defaultFactoryBodyPlugin)
	authWithWrapperSemantics := newInstance(t, nil, New(Options{}), wrapperSemanticsPlugin)

	t.Run("should generate OpenAPI schema", func(t *testing.T) {
		schema := generate(t, auth)
		raw, err := os.ReadFile("testdata/open-api.test.ts.snap.json")
		if err != nil {
			t.Fatal(err)
		}
		var snapshot map[string]any
		if err := json.Unmarshal(raw, &snapshot); err != nil {
			t.Fatal(err)
		}
		// The snapshot was generated by a server whose baseURL is http://localhost:3000.
		if !reflect.DeepEqual(schema, snapshot) {
			t.Fatalf("schema does not match the upstream snapshot:\n%s", diffJSON(schema, snapshot, ""))
		}
	})

	t.Run("should mark model id fields as required and read-only", func(t *testing.T) {
		schema := generate(t, auth)
		schemas := obj(t, schema, "components", "schemas")
		equalJSON(t, get(t, schemas, "User", "properties", "id"), `{"readOnly":true,"type":"string"}`)
		if !contains(strList(get(t, schemas, "User", "required")), "id") {
			t.Fatal("User.required should contain id")
		}
		equalJSON(t, get(t, schemas, "User", "properties", "emailVerified"), `{"default":false,"readOnly":true,"type":"boolean"}`)
		if !contains(strList(get(t, schemas, "User", "required")), "emailVerified") {
			t.Fatal("User.required should contain emailVerified")
		}
		equalJSON(t, get(t, schemas, "Session", "properties", "id"), `{"readOnly":true,"type":"string"}`)
		if !contains(strList(get(t, schemas, "Session", "required")), "id") {
			t.Fatal("Session.required should contain id")
		}
	})

	t.Run("should include additionalFields in the User schema", func(t *testing.T) {
		schema := generate(t, auth)
		schemas := obj(t, schema, "components", "schemas")
		equalJSON(t, get(t, schemas, "User", "properties", "role"), `{"type":"string","default":"user"}`)
		equalJSON(t, get(t, schemas, "User", "properties", "preferences"), `{"type":"string"}`)
		req := strList(get(t, schemas, "User", "required"))
		if !contains(req, "role") || contains(req, "preferences") {
			t.Fatalf("unexpected User.required %v", req)
		}
	})

	t.Run("should map array additionalFields to OpenAPI array schemas", func(t *testing.T) {
		a := newInstance(t, func(c *betterauth.Config) {
			c.User = &betterauth.UserConfig{ModelConfig: betterauth.ModelConfig{AdditionalFields: []db.Field{
				{Name: "tags", Type: db.TypeStringArray, Required: db.False},
				{Name: "scores", Type: db.TypeNumberArray, Required: db.True},
			}}}
		}, New(Options{}))
		schemas := obj(t, generate(t, a), "components", "schemas")
		equalJSON(t, get(t, schemas, "User", "properties", "tags"), `{"type":"array","items":{"type":"string"}}`)
		equalJSON(t, get(t, schemas, "User", "properties", "scores"), `{"type":"array","items":{"type":"number"}}`)
		req := strList(get(t, schemas, "User", "required"))
		if contains(req, "tags") || !contains(req, "scores") {
			t.Fatalf("unexpected User.required %v", req)
		}
	})

	t.Run("should allow every JSON value in additional field request bodies", func(t *testing.T) {
		a := newInstance(t, func(c *betterauth.Config) {
			c.User = &betterauth.UserConfig{ModelConfig: betterauth.ModelConfig{AdditionalFields: []db.Field{
				{Name: "metadata", Type: db.TypeJSON},
			}}}
		}, New(Options{}))
		doc := generate(t, a)
		equalJSON(t, get(t, postBodySchema(t, doc, "/sign-up/email"), "properties", "metadata"), `{}`)
		equalJSON(t, get(t, postBodySchema(t, doc, "/update-user"), "properties", "metadata"), `{}`)
	})

	t.Run("should include additionalFields on sign-up and update-user request bodies", func(t *testing.T) {
		doc := generate(t, auth)
		signUp := postBodySchema(t, doc, "/sign-up/email")
		equalJSON(t, get(t, signUp, "properties", "role"), `{"type":"string","default":"user"}`)
		equalJSON(t, get(t, signUp, "properties", "preferences"), `{"type":"string"}`)
		if req := strList(signUp["required"]); contains(req, "role") || contains(req, "preferences") {
			t.Fatalf("unexpected sign-up required %v", req)
		}
		update := postBodySchema(t, doc, "/update-user")
		equalJSON(t, get(t, update, "properties", "role"), `{"type":"string","default":"user"}`)
		equalJSON(t, get(t, update, "properties", "preferences"), `{"type":"string"}`)
		if req := strList(update["required"]); contains(req, "role") || contains(req, "preferences") {
			t.Fatalf("unexpected update-user required %v", req)
		}
	})

	t.Run("should mark explicitly required additionalFields as required on sign-up", func(t *testing.T) {
		a := newInstance(t, func(c *betterauth.Config) {
			c.User = &betterauth.UserConfig{ModelConfig: betterauth.ModelConfig{AdditionalFields: []db.Field{
				{Name: "nickname", Type: db.TypeString, Required: db.True},
				{Name: "optionalNote", Type: db.TypeString},
			}}}
		}, New(Options{}))
		signUp := postBodySchema(t, generate(t, a), "/sign-up/email")
		equalJSON(t, get(t, signUp, "properties", "nickname"), `{"type":"string"}`)
		equalJSON(t, get(t, signUp, "properties", "optionalNote"), `{"type":"string"}`)
		req := strList(signUp["required"])
		if !contains(req, "nickname") || contains(req, "optionalNote") {
			t.Fatalf("unexpected sign-up required %v", req)
		}
	})

	t.Run("should include username plugin fields on sign-up and update-user request bodies", func(t *testing.T) {
		a := newInstance(t, nil, New(Options{}), usernameFixture())
		doc := generate(t, a)
		signUp := postBodySchema(t, doc, "/sign-up/email")
		equalJSON(t, get(t, signUp, "properties", "username"), `{"type":"string"}`)
		equalJSON(t, get(t, signUp, "properties", "displayUsername"), `{"type":"string"}`)
		req := strList(signUp["required"])
		for _, k := range []string{"name", "email", "password"} {
			if !contains(req, k) {
				t.Fatalf("sign-up required %v should contain %s", req, k)
			}
		}
		if contains(req, "username") || contains(req, "displayUsername") {
			t.Fatalf("unexpected sign-up required %v", req)
		}
		update := postBodySchema(t, doc, "/update-user")
		equalJSON(t, get(t, update, "properties", "username"), `{"type":"string"}`)
		equalJSON(t, get(t, update, "properties", "displayUsername"), `{"type":"string"}`)
	})

	t.Run("should omit runtime-generated defaults from model schemas", func(t *testing.T) {
		schemas := obj(t, generate(t, auth), "components", "schemas")
		for _, p := range [][]string{{"User", "createdAt"}, {"User", "updatedAt"}, {"Session", "createdAt"}} {
			if _, ok := lookup(schemas, p[0], "properties", p[1], "default"); ok {
				t.Fatalf("%s.%s should have no default", p[0], p[1])
			}
		}
	})

	t.Run("should properly handle nested objects in request body schema", func(t *testing.T) {
		props := obj(t, postBodySchema(t, generate(t, auth), "/sign-in/social"), "properties")
		idToken := obj(t, props, "idToken")
		if idToken["type"] != "object" {
			t.Fatalf("idToken type %v", idToken["type"])
		}
		for _, k := range []string{"token", "accessToken", "refreshToken"} {
			if get(t, idToken, "properties", k, "type") != "string" {
				t.Fatalf("idToken.%s should be a string", k)
			}
		}
		req := strList(idToken["required"])
		if !contains(req, "token") || contains(req, "accessToken") || contains(req, "refreshToken") {
			t.Fatalf("unexpected idToken.required %v", req)
		}
	})

	t.Run("should keep optional primitive types non-nullable", func(t *testing.T) {
		props := obj(t, postBodySchema(t, generate(t, auth), "/sign-in/social"), "properties")
		for _, k := range []string{"accessToken", "refreshToken"} {
			p := obj(t, props, "idToken", "properties", k)
			if p["type"] != "string" {
				t.Fatalf("%s type %v", k, p["type"])
			}
			if _, ok := p["nullable"]; ok {
				t.Fatalf("%s should not be nullable", k)
			}
		}
	})

	t.Run("should use OpenAPI 3.1 nullable format for get-session response", func(t *testing.T) {
		s := obj(t, generate(t, auth), "paths", "/get-session", "post", "responses", "200", "content", "application/json", "schema")
		types := strList(s["type"])
		if !contains(types, "object") || !contains(types, "null") {
			t.Fatalf("unexpected type %v", s["type"])
		}
		if _, ok := s["nullable"]; ok {
			t.Fatal("nullable must not be used")
		}
	})

	t.Run("should emit unique operationIds across multi-method endpoints", func(t *testing.T) {
		paths := obj(t, generate(t, auth), "paths")
		seen := map[string]bool{}
		for _, item := range paths {
			for _, m := range []string{"get", "post", "put", "patch", "delete"} {
				id, ok := lookup(item, m, "operationId")
				if !ok {
					continue
				}
				s := id.(string)
				if seen[s] {
					t.Fatalf("duplicate operationId %s", s)
				}
				seen[s] = true
			}
		}
		if get(t, paths, "/get-session", "get", "operationId") != "getSession" ||
			get(t, paths, "/get-session", "post", "operationId") != "getSessionPost" {
			t.Fatal("unexpected get-session operationIds")
		}
	})

	t.Run("should infer path parameters for routes with dynamic segments", func(t *testing.T) {
		paths := obj(t, generate(t, auth), "paths")
		want := map[string]any{"name": "id", "in": "path", "required": true, "schema": map[string]any{"type": "string"}}
		for _, m := range []string{"get", "post"} {
			found := false
			for _, p := range get(t, paths, "/callback/{id}", m, "parameters").([]any) {
				if reflect.DeepEqual(p, want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("/callback/{id} %s should have the id path parameter", m)
			}
		}
	})

	t.Run("should not share operation parameter or response objects across methods", func(t *testing.T) {
		doc := Generate(auth.Context())
		paths, _ := doc.Get("paths")
		op := func(path, method string) *jsonx.Object {
			item, _ := paths.(*jsonx.Object).Get(path)
			o, _ := item.(*jsonx.Object).Get(method)
			return o.(*jsonx.Object)
		}
		member := func(o *jsonx.Object, keys ...string) any {
			var cur any = o
			for _, k := range keys {
				cur, _ = cur.(*jsonx.Object).Get(k)
			}
			return cur
		}
		gp, pp := member(op("/get-session", "get"), "parameters"), member(op("/get-session", "post"), "parameters")
		if reflect.ValueOf(gp).Pointer() == reflect.ValueOf(pp).Pointer() && len(gp.([]any)) > 0 {
			t.Fatal("get-session parameters are shared")
		}
		if member(op("/get-session", "get"), "responses", "200") == member(op("/get-session", "post"), "responses", "200") {
			t.Fatal("get-session 200 responses are shared")
		}
		cg, cp := member(op("/callback/{id}", "get"), "parameters").([]any), member(op("/callback/{id}", "post"), "parameters").([]any)
		if &cg[0] == &cp[0] || cg[0] == cp[0] {
			t.Fatal("callback parameters are shared")
		}
	})

	t.Run("should serialize the generated schema without circular response refs", func(t *testing.T) {
		srv := httptest.NewServer(auth.Handler())
		defer srv.Close()
		res, err := http.Get(srv.URL + "/api/auth/open-api/generate-schema")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		if res.StatusCode != 200 {
			t.Fatalf("status %d", res.StatusCode)
		}
		if strings.Contains(string(body), "[Circular ref") {
			t.Fatal("circular ref in output")
		}
	})

	t.Run("should keep optional object types non-nullable", func(t *testing.T) {
		schema := postBodySchema(t, generate(t, auth), "/sign-in/social")
		if contains(strList(schema["required"]), "idToken") {
			t.Fatal("idToken should be optional")
		}
		idToken := obj(t, schema, "properties", "idToken")
		if idToken["type"] != "object" {
			t.Fatalf("idToken type %v", idToken["type"])
		}
		if _, ok := idToken["anyOf"]; ok {
			t.Fatal("idToken should not use anyOf")
		}
		if _, ok := idToken["nullable"]; ok {
			t.Fatal("idToken should not be nullable")
		}
	})

	t.Run("should generate OpenAPI 3.1 compliant schemas from Zod types", func(t *testing.T) {
		doc := generate(t, auth)
		if !strings.HasPrefix(doc["openapi"].(string), "3.1.") {
			t.Fatalf("openapi %v", doc["openapi"])
		}
		var check func(v any, path string)
		check = func(v any, path string) {
			switch x := v.(type) {
			case map[string]any:
				for k, c := range x {
					if k == "nullable" {
						t.Fatalf("Found deprecated 'nullable' property at %s.%s", path, k)
					}
					check(c, path+"."+k)
				}
			case []any:
				for i, c := range x {
					check(c, fmt.Sprintf("%s.%d", path, i))
				}
			}
		}
		check(postBodySchema(t, doc, "/sign-in/social"), "signInSocialRequestBody")
	})

	t.Run("should not require token/user in /sign-in/social response and allow redirect to be true or false", func(t *testing.T) {
		s := obj(t, generate(t, auth), "paths", "/sign-in/social", "post", "responses", "200", "content", "application/json", "schema")
		equalJSON(t, s["required"], `["redirect"]`)
		redirect := obj(t, s, "properties", "redirect")
		if _, ok := redirect["enum"]; ok || redirect["type"] != "boolean" {
			t.Fatalf("unexpected redirect schema %v", redirect)
		}
		for _, k := range []string{"token", "user", "url"} {
			get(t, s, "properties", k)
		}
	})

	t.Run("should correctly unwrap ZodDefault and infer inner type", func(t *testing.T) {
		doc := generate(t, auth)
		baseTypes := func(v any) []string {
			if arr, ok := v.([]any); ok {
				var out []string
				for _, x := range arr {
					if x != "null" {
						out = append(out, x.(string))
					}
				}
				return out
			}
			s, _ := v.(string)
			return []string{s}
		}
		signIn := obj(t, postBodySchema(t, doc, "/sign-in/email"), "properties", "rememberMe")
		bt := baseTypes(signIn["type"])
		if !contains(bt, "boolean") || contains(bt, "string") {
			t.Fatalf("unexpected rememberMe type %v", signIn["type"])
		}
		if _, ok := signIn["default"]; ok {
			t.Fatal("rememberMe should have no default")
		}
		signUp := obj(t, postBodySchema(t, doc, "/sign-up/email"), "properties", "rememberMe")
		if !contains(baseTypes(signUp["type"]), "boolean") {
			t.Fatalf("unexpected sign-up rememberMe type %v", signUp["type"])
		}
	})

	t.Run("should include request bodies for all email OTP POST endpoints", func(t *testing.T) {
		paths := obj(t, generate(t, authWithEmailOTP), "paths")
		for _, p := range []string{
			"/email-otp/send-verification-otp", "/email-otp/check-verification-otp", "/email-otp/verify-email",
			"/sign-in/email-otp", "/email-otp/request-password-reset", "/forget-password/email-otp",
			"/email-otp/reset-password", "/email-otp/request-email-change", "/email-otp/change-email",
		} {
			if _, ok := lookup(paths, p, "post", "requestBody"); !ok {
				t.Fatalf("%s has no request body", p)
			}
		}
	})

	t.Run("should merge object and record intersections for email OTP sign-in request bodies", func(t *testing.T) {
		rb := obj(t, generate(t, authWithEmailOTP), "paths", "/sign-in/email-otp", "post", "requestBody")
		if rb["required"] != true {
			t.Fatal("request body should be required")
		}
		s := obj(t, rb, "content", "application/json", "schema")
		if s["type"] != "object" {
			t.Fatalf("type %v", s["type"])
		}
		equalJSON(t, s["required"], `["email","otp"]`)
		for _, k := range []string{"email", "otp", "name", "image"} {
			if get(t, s, "properties", k, "type") != "string" {
				t.Fatalf("%s should be a string", k)
			}
		}
		equalJSON(t, s["additionalProperties"], `{}`)
	})

	for _, path := range []string{"/sign-in/phone-number", "/phone-number/send-otp", "/phone-number/request-password-reset", "/phone-number/reset-password"} {
		t.Run("emits a request body for "+path, func(t *testing.T) {
			if _, ok := lookup(generate(t, authWithPhoneNumber), "paths", path, "post", "requestBody"); !ok {
				t.Fatalf("%s has no request body", path)
			}
		})
	}

	t.Run("emits the phone-number verification request body", func(t *testing.T) {
		rb := obj(t, generate(t, authWithPhoneNumber), "paths", "/phone-number/verify", "post", "requestBody")
		if rb["required"] != true {
			t.Fatal("request body should be required")
		}
		s := obj(t, rb, "content", "application/json", "schema")
		if s["type"] != "object" {
			t.Fatalf("type %v", s["type"])
		}
		for k, typ := range map[string]string{"phoneNumber": "string", "code": "string", "disableSession": "boolean", "updatePhoneNumber": "boolean"} {
			if get(t, s, "properties", k, "type") != typ {
				t.Fatalf("%s should be a %s", k, typ)
			}
		}
		equalJSON(t, s["required"], `["phoneNumber","code"]`)
		equalJSON(t, s["additionalProperties"], `{}`)
	})

	t.Run("should keep plain email OTP request bodies as object schemas", func(t *testing.T) {
		rb := obj(t, generate(t, authWithEmailOTP), "paths", "/email-otp/reset-password", "post", "requestBody")
		if rb["required"] != true {
			t.Fatal("request body should be required")
		}
		s := obj(t, rb, "content", "application/json", "schema")
		if s["type"] != "object" {
			t.Fatalf("type %v", s["type"])
		}
		equalJSON(t, s["required"], `["email","otp","password"]`)
		if _, ok := s["additionalProperties"]; ok {
			t.Fatal("additionalProperties should be absent")
		}
	})

	t.Run("should preserve nullable object intersections when merging schemas", func(t *testing.T) {
		rb := obj(t, generate(t, authWithNullableIntersection), "paths", "/test/nullable-intersection", "post", "requestBody")
		if rb["required"] != true {
			t.Fatal("request body should be required")
		}
		s := obj(t, rb, "content", "application/json", "schema")
		equalJSON(t, s["type"], `["object","null"]`)
		if get(t, s, "properties", "email", "type") != "string" || get(t, s, "properties", "otp", "type") != "string" {
			t.Fatal("email and otp should be strings")
		}
		equalJSON(t, s["required"], `["email","otp"]`)
	})

	t.Run("should mark default-wrapped request bodies as optional", func(t *testing.T) {
		rb := obj(t, generate(t, authWithDefaultBody), "paths", "/test/default-body", "post", "requestBody")
		if rb["required"] != false {
			t.Fatal("request body should be optional")
		}
		s := obj(t, rb, "content", "application/json", "schema")
		if s["type"] != "object" || get(t, s, "properties", "rememberMe", "type") != "boolean" {
			t.Fatalf("unexpected schema %v", s)
		}
		if _, ok := s["default"]; ok {
			t.Fatal("default should be omitted")
		}
	})

	t.Run("should represent object intersections with union branches", func(t *testing.T) {
		rb := obj(t, generate(t, authWithUnionIntersection), "paths", "/test/choose-role", "post", "requestBody")
		if rb["required"] != true {
			t.Fatal("request body should be required")
		}
		allOf, _ := get(t, rb, "content", "application/json", "schema", "allOf").([]any)
		if len(allOf) != 2 {
			t.Fatalf("allOf %v", allOf)
		}
		equalJSON(t, allOf[0], `{"type":"object","properties":{"organizationId":{"type":"string"}}}`)
		equalJSON(t, allOf[1], `{"anyOf":[{"type":"object","properties":{"roleName":{"type":"string"}},"required":["roleName"]},{"type":"object","properties":{"roleId":{"type":"string"}},"required":["roleId"]}]}`)
	})

	t.Run("should preserve record key schemas when merging object intersections", func(t *testing.T) {
		s := postBodySchema(t, generate(t, authWithRecordIntersection), "/test/update-fields")
		if s["type"] != "object" {
			t.Fatalf("type %v", s["type"])
		}
		equalJSON(t, s["required"], `["knownField"]`)
		if get(t, s, "properties", "knownField", "type") != "string" {
			t.Fatal("knownField should be a string")
		}
		equalJSON(t, s["additionalProperties"], `{"type":"boolean"}`)
		equalJSON(t, s["propertyNames"], `{"description":"Custom field names must be at least two characters","minLength":2,"type":"string"}`)
	})

	t.Run("should preserve string length constraints for wrapped query parameters", func(t *testing.T) {
		item := obj(t, generate(t, authWithQueryConstraints), "paths", "/test/query-constraints")
		param := func(name string) map[string]any {
			for _, p := range get(t, item, "get", "parameters").([]any) {
				if p.(map[string]any)["name"] == name {
					return p.(map[string]any)["schema"].(map[string]any)
				}
			}
			t.Fatalf("Expected path to define %s parameter", name)
			return nil
		}
		match := func(got map[string]any, want map[string]any) {
			for k, v := range want {
				if !reflect.DeepEqual(got[k], v) {
					t.Fatalf("got %v, want %v", got, want)
				}
			}
		}
		match(param("direct"), map[string]any{"minLength": 3.0, "type": "string"})
		match(param("optional"), map[string]any{"minLength": 4.0, "type": "string"})
		match(param("defaulted"), map[string]any{"minLength": 5.0, "type": "string"})
		match(param("bounded"), map[string]any{"maxLength": 12.0, "minLength": 6.0, "type": "string"})
	})

	t.Run("should not evaluate request body default factories", func(t *testing.T) {
		defaultFactoryCallCount = 0
		rb := obj(t, generate(t, authWithDefaultFactoryBody), "paths", "/test/default-factory-body", "post", "requestBody")
		if rb["required"] != false {
			t.Fatal("request body should be optional")
		}
		if defaultFactoryCallCount != 0 {
			t.Fatal("default factory was evaluated")
		}
		s := obj(t, rb, "content", "application/json", "schema")
		if _, ok := s["default"]; ok {
			t.Fatal("default should be omitted")
		}
		if get(t, s, "properties", "nonce", "type") != "string" {
			t.Fatal("nonce should be a string")
		}
	})

	t.Run("should compute required fields through Zod wrapper schemas", func(t *testing.T) {
		wrapperDefaultFactoryCallCount = 0
		rb := obj(t, generate(t, authWithWrapperSemantics), "paths", "/test/wrapper-semantics", "post", "requestBody")
		if rb["required"] != true {
			t.Fatal("request body should be required")
		}
		s := obj(t, rb, "content", "application/json", "schema")
		req := strList(s["required"])
		sort.Strings(req)
		want := []string{"anyPayload", "caughtPayload", "intersectionOptional", "nonOptional", "undefinedPayload", "unionOptional", "unknownPayload", "voidPayload"}
		if !reflect.DeepEqual(req, want) {
			t.Fatalf("required %v, want %v", req, want)
		}
		if wrapperDefaultFactoryCallCount != 0 {
			t.Fatal("default factory was evaluated")
		}
		prop := func(k string) map[string]any { return obj(t, s, "properties", k) }
		equalJSON(t, prop("optionalNullable")["type"], `["string","null"]`)
		equalJSON(t, prop("nullableDefault")["type"], `["string","null"]`)
		if _, ok := prop("nullableDefault")["default"]; ok {
			t.Fatal("nullableDefault default should be omitted")
		}
		if prop("prefaulted")["type"] != "string" {
			t.Fatal("prefaulted should be a string")
		}
		if _, ok := prop("prefaulted")["default"]; ok {
			t.Fatal("prefaulted default should be omitted")
		}
		if prop("nonOptional")["type"] != "string" || prop("unionOptional")["type"] != "string" {
			t.Fatal("nonOptional / unionOptional should be strings")
		}
		for _, k := range []string{"unknownPayload", "anyPayload", "undefinedPayload", "voidPayload"} {
			equalJSON(t, prop(k), `{}`)
		}
		for _, k := range []string{"caughtPayload", "caughtOptional", "preprocessedOptional"} {
			if prop(k)["type"] != "string" {
				t.Fatalf("%s should be a string", k)
			}
		}
		if _, ok := prop("intersectionOptional")["allOf"]; !ok {
			t.Fatal("intersectionOptional should use allOf")
		}
		if contains(req, "caughtOptional") || contains(req, "preprocessedOptional") {
			t.Fatal("caughtOptional / preprocessedOptional should be optional")
		}
	})
}

// diffJSON describes the first differences between two parsed JSON values.
func diffJSON(got, want any, path string) string {
	var out []string
	var walk func(g, w any, p string)
	walk = func(g, w any, p string) {
		if len(out) > 20 {
			return
		}
		gm, gok := g.(map[string]any)
		wm, wok := w.(map[string]any)
		if gok && wok {
			for k := range gm {
				if _, ok := wm[k]; !ok {
					out = append(out, p+"/"+k+": only in go")
				} else {
					walk(gm[k], wm[k], p+"/"+k)
				}
			}
			for k := range wm {
				if _, ok := gm[k]; !ok {
					out = append(out, p+"/"+k+": only in upstream")
				}
			}
			return
		}
		if !reflect.DeepEqual(g, w) {
			gb, _ := json.Marshal(g)
			wb, _ := json.Marshal(w)
			out = append(out, p+": go="+string(gb)+" upstream="+string(wb))
		}
	}
	walk(got, want, path)
	sort.Strings(out)
	return strings.Join(out, "\n")
}
