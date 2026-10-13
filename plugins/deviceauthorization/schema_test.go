package deviceauthorization

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// Port of packages/better-auth/src/plugins/device-authorization/schema.test.ts.

func schemaGrant(fields ...db.Field) *Grant {
	return &Grant{DeviceCodeSchemaFields: fields}
}

func deviceCodeTable(t *testing.T, p *betterauth.Plugin) *db.Table {
	t.Helper()
	tables := betterauth.GetSchema(betterauth.Config{Plugins: []*betterauth.Plugin{p}})
	tbl := tables.Table("deviceCode")
	if tbl == nil {
		t.Fatal("deviceCode table missing")
	}
	return tbl
}

func endpoint(p *betterauth.Plugin, key string) *betterauth.Endpoint {
	for _, ep := range p.Endpoints {
		if ep.Key == key {
			return ep
		}
	}
	return nil
}

func responses(t *testing.T, ep *betterauth.Endpoint) *jsonx.Object {
	t.Helper()
	meta := ep.Metadata["openapi"].(*jsonx.Object)
	r, _ := meta.Get("responses")
	return r.(*jsonx.Object)
}

func errorEnum(t *testing.T, resp *jsonx.Object, status string) []any {
	t.Helper()
	var cur any = resp
	for _, k := range []string{status, "content", "application/json", "schema", "properties", "error", "enum"} {
		cur, _ = cur.(*jsonx.Object).Get(k)
	}
	return cur.([]any)
}

func TestDeviceAuthorizationSchema(t *testing.T) {
	t.Run("uniquely indexes device authorization lookup fields", func(t *testing.T) {
		want := []db.Index{{Fields: []string{"deviceCode"}, Unique: true}, {Fields: []string{"userCode"}, Unique: true}}
		if got := Schema(Options{})[0].Indexes; !reflect.DeepEqual(got, want) {
			t.Fatalf("indexes %v", got)
		}
	})
	t.Run("does not add OAuth resource fields to standalone installations", func(t *testing.T) {
		p := New(Options{})
		tbl := deviceCodeTable(t, p)
		for _, f := range []string{"resource", "resources", "oauthClientId"} {
			if _, ok := tbl.Field(f); ok {
				t.Fatalf("unexpected field %s", f)
			}
		}
		// The endpoint's error contract: invalid_target is not a documented error code.
		for _, c := range errorEnum(t, responses(t, endpoint(p, "deviceCode")), "400") {
			if c == "invalid_target" {
				t.Fatal("invalid_target documented")
			}
		}
	})
	t.Run("declares server_error for failed device-code issuance", func(t *testing.T) {
		resp := responses(t, endpoint(New(Options{}), "deviceCode"))
		for _, c := range errorEnum(t, resp, "400") {
			if c == "server_error" {
				t.Fatal("400 should not list server_error")
			}
		}
		if got := errorEnum(t, resp, "500"); !reflect.DeepEqual(got, []any{"server_error"}) {
			t.Fatalf("500 enum %v", got)
		}
	})
	t.Run("adds grant-specific responses to the device-code OpenAPI contract", func(t *testing.T) {
		g := schemaGrant()
		g.RequestOpenAPIResponses = map[string]any{"401": jsonx.O("description", "Grant authentication failed")}
		resp := responses(t, endpoint(New(Options{Grant: g}), "deviceCode"))
		r, _ := resp.Get("401")
		if d, _ := r.(*jsonx.Object).Get("description"); d != "Grant authentication failed" {
			t.Fatalf("401 %v", r)
		}
	})
	t.Run("rejects grant fields that redefine the base device-code schema", func(t *testing.T) {
		_, err := ParseOptions(Options{Grant: schemaGrant(
			db.Field{Name: "status", Type: db.TypeString, Required: db.False},
			db.Field{Name: "clientId", Type: db.TypeString, Required: db.True},
		)})
		if err == nil || err.Error() != "Device authorization grant fields must be additional and cannot redefine deviceCode fields: status, clientId" {
			t.Fatalf("err %v", err)
		}
		if _, err := betterauth.New(betterauth.Config{Secret: strings.Repeat("s", 40), Logger: betterauth.NopLogger{},
			Plugins: []*betterauth.Plugin{New(Options{Grant: schemaGrant(db.Field{Name: "status", Type: db.TypeString})})}}); err == nil {
			t.Fatal("expected betterauth.New to fail")
		}
	})
	t.Run("rejects grant fields that redefine request or verification contracts", func(t *testing.T) {
		g := schemaGrant()
		g.RequestSchemaFields = []validate.Field{validate.F("scope", validate.String())}
		if _, err := ParseOptions(Options{Grant: g}); err == nil || err.Error() != "Device authorization grant request fields must be additional and cannot redefine request fields: scope" {
			t.Fatalf("err %v", err)
		}
		g = schemaGrant()
		g.VerificationOpenAPIProperties = map[string]any{"status": map[string]any{"type": "string"}}
		if _, err := ParseOptions(Options{Grant: g}); err == nil || err.Error() != "Device authorization grant verification fields must be additional and cannot redefine response fields: status" {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("preserves grant array fields in the portable logical schema", func(t *testing.T) {
		tbl := deviceCodeTable(t, New(Options{Grant: schemaGrant(
			db.Field{Name: "resources", Type: db.TypeStringArray, Required: db.False},
			db.Field{Name: "oauthClientId", Type: db.TypeString, Required: db.False},
		)}))
		r, ok := tbl.Field("resources")
		if !ok || r.Type != db.TypeStringArray || !r.IsOptional() {
			t.Fatalf("resources %+v", r)
		}
		o, ok := tbl.Field("oauthClientId")
		if !ok || o.Type != db.TypeString || !o.IsOptional() {
			t.Fatalf("oauthClientId %+v", o)
		}
	})
}

// Extra coverage for Go-specific helpers.
func TestHelpers(t *testing.T) {
	t.Run("isUniqueConstraintError", func(t *testing.T) {
		for _, err := range []error{&prismaError{Code: "P2002"}, &sqlServerError{Code: "EREQUEST", Number: 2601},
			errString("UNIQUE constraint failed: deviceCode.userCode"), errString("duplicate key value violates unique constraint"),
			errString("Error 1062: Duplicate entry 'x' for key 'y'"), errString("E11000 duplicate key error")} {
			if !isUniqueConstraintError(err) {
				t.Fatalf("%v not detected", err)
			}
		}
		if isUniqueConstraintError(errString("connection refused")) {
			t.Fatal("false positive")
		}
	})
	t.Run("schema option renames model and fields", func(t *testing.T) {
		pt := Schema(Options{Schema: &SchemaOptions{DeviceCode: ModelOptions{ModelName: "device_codes", Fields: map[string]string{"userCode": "user_code"}}}})[0]
		if pt.ModelName != "device_codes" {
			t.Fatal(pt.ModelName)
		}
		for _, f := range pt.Fields {
			if f.Name == "userCode" && f.FieldName != "user_code" {
				t.Fatal(f.FieldName)
			}
		}
	})
	t.Run("time strings", func(t *testing.T) {
		for in, want := range map[string]float64{"30m": 1800000, "5s": 5000, "5min": 300000, "1 hour": 3600000, "2d": 172800000, "-1s": -1000, "1s ago": -1000} {
			if got, err := ParseTimeString(in); err != nil || got != want {
				t.Fatalf("%s: %v %v", in, got, err)
			}
		}
		if _, err := ParseTimeString("soon"); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("verification URIs", func(t *testing.T) {
		v, c, _ := buildVerificationURIs("/device?lang=en&user_code=OLD", "http://localhost:3000/api/auth", "A B")
		if v != "http://localhost:3000/device?lang=en&user_code=OLD" || c != "http://localhost:3000/device?lang=en&user_code=A+B" {
			t.Fatalf("%s %s", v, c)
		}
	})
}

type errString string

func (e errString) Error() string { return string(e) }
