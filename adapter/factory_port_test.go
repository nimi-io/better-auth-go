package adapter

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Port of e2e/adapter/test/adapter-factory/adapter-factory.test.ts (and its snapshot).
//
// Upstream builds the adapter through betterAuth({ ...options, database }) and reads
// (await auth.$context).adapter; that is the factory adapter itself, so the Go port calls
// NewFactory directly with the schema betterAuth would build (db.GetAuthTables) and the
// advanced.database options mapped onto adapter.Options.
//
// Upstream's `toHaveProperty(key)` also passes for keys whose value is undefined, because
// transformOutput writes every schema key. The Go factory omits undefined keys, so those
// assertions are expressed as "undefined" (absent or nil) checks via undef.

type e2eOpts struct {
	cfg    func(*Config)
	opts   Options
	schema db.Options
	driver *fakeDriver
}

// e2eAdapter is createTestAdapter: the default config merged with props.config, wrapping
// a driver that implements every method (consumeOne / incrementOne return null).
func e2eAdapter(t testing.TB, o e2eOpts) Adapter {
	t.Helper()
	cfg := Config{
		AdapterID:        "test-id",
		AdapterName:      "Test Adapter",
		UsePlural:        false,
		SupportsJSON:     true,
		SupportsDates:    boolp(true),
		SupportsBooleans: boolp(true),
	}
	if o.cfg != nil {
		o.cfg(&cfg)
	}
	d := o.driver
	if d == nil {
		d = &fakeDriver{}
	}
	return newAdapter(t, cfg, &fakeAtomicDriver{fakeDriver: d}, o.opts, o.schema)
}

// captureCreate returns a driver recording the data passed to create.
func captureCreate(into *Record) *fakeDriver {
	return &fakeDriver{create: func(_ context.Context, _, _ string, data Record) (Record, error) {
		*into = data
		return data, nil
	}}
}

// captureUpdate returns a driver recording the update passed to update.
func captureUpdate(into *Record) *fakeDriver {
	return &fakeDriver{update: func(_ context.Context, _ Query, update Record) (Record, error) {
		*into = update
		return update, nil
	}}
}

func strTransform(field string, fn func(string) string) func(TransformParams) any {
	return func(p TransformParams) any {
		if s, ok := p.Data.(string); ok && p.Field == field {
			return fn(s)
		}
		return p.Data
	}
}

func userFields(fields map[string]string) db.Options {
	return db.Options{User: db.ModelOptions{Fields: fields}}
}

func userAdditional(fields ...db.Field) db.Options {
	return db.Options{User: db.ModelOptions{AdditionalFields: fields}}
}

func nullableRefPlugin(table, field string) db.Options {
	return db.Options{Plugins: [][]db.PluginTable{{{
		Key: table,
		Fields: []db.Field{{Name: field, Type: db.TypeString, Required: db.False,
			References: &db.Reference{Model: "user", Field: "id"}}},
	}}}}
}

func TestCreateAdapterHelper(t *testing.T) {
	ctx := context.Background()
	const adapterID = "test-adapter-id"
	adapter := e2eAdapter(t, e2eOpts{cfg: func(c *Config) { c.AdapterID = adapterID }})

	create := func(t *testing.T, ad Adapter, in CreateInput) Record {
		t.Helper()
		res, err := ad.Create(ctx, in)
		mustNoErr(t, err)
		return res
	}
	update := func(t *testing.T, ad Adapter, id any, data Record) Record {
		t.Helper()
		res, err := ad.Update(ctx, "user", []Where{{Field: "id", Value: id}}, data)
		mustNoErr(t, err)
		return res
	}

	t.Run("Should have the correct adapter id", func(t *testing.T) {
		if adapter.ID() != adapterID {
			t.Fatalf("id = %q", adapter.ID())
		}
	})

	t.Run("Should use the id generator if passed into the betterAuth config", func(t *testing.T) {
		ad := e2eAdapter(t, e2eOpts{opts: Options{GenerateID: func(string, int) (string, bool) {
			return "HARD-CODED-ID", true
		}}})
		res := create(t, ad, CreateInput{Model: "user", Data: Record{"name": "test-name"}})
		wantEqual(t, res["id"], "HARD-CODED-ID", "id")
	})

	t.Run("Should not generate an id if `advanced.database.generateId` is not defined or false", func(t *testing.T) {
		ad := e2eAdapter(t, e2eOpts{
			opts: Options{IDMode: IDNone},
			driver: &fakeDriver{create: func(_ context.Context, _, _ string, data Record) (Record, error) {
				if !undef(data, "id") {
					t.Errorf("data.id should not be defined, got %v", data["id"])
				}
				return data, nil
			}},
		})
		res := create(t, ad, CreateInput{Model: "user", Data: Record{"name": "test-name"}})
		if !undef(res, "id") {
			t.Fatalf("id should not be defined, got %v", res["id"])
		}
	})

	t.Run("Should generate UUIDs when `advanced.database.generateId` is set to 'uuid'", func(t *testing.T) {
		ad := e2eAdapter(t, e2eOpts{opts: Options{IDMode: IDUUID}})
		uuidRe := regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
		res := create(t, ad, CreateInput{Model: "user", Data: Record{"name": "test-name"}})
		id, ok := res["id"].(string)
		if !ok || !uuidRe.MatchString(id) {
			t.Fatalf("id %#v is not a uuid", res["id"])
		}
		ids := map[string]bool{}
		for i := 0; i < 10; i++ {
			r := create(t, ad, CreateInput{Model: "user", Data: Record{"name": "test-name-" + string(rune('0'+i))}})
			id, _ := r["id"].(string)
			if !uuidRe.MatchString(id) {
				t.Fatalf("id %q is not a uuid", id)
			}
			if ids[id] {
				t.Fatalf("duplicate id %q", id)
			}
			ids[id] = true
		}
		if len(ids) != 10 {
			t.Fatalf("ids = %d", len(ids))
		}
	})

	t.Run("Should preserve a forced UUID when the adapter supports native UUIDs", func(t *testing.T) {
		const existingID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
		ad := e2eAdapter(t, e2eOpts{
			cfg:  func(c *Config) { c.SupportsUUIDs = true },
			opts: Options{IDMode: IDUUID},
			driver: &fakeDriver{create: func(_ context.Context, _, _ string, data Record) (Record, error) {
				if data["id"] != existingID {
					t.Errorf("data.id = %#v", data["id"])
				}
				return data, nil
			}},
		})
		res := create(t, ad, CreateInput{Model: "user", Data: Record{"id": existingID, "name": "test-name"}, ForceAllowID: true})
		wantEqual(t, res["id"], existingID, "id")
	})

	// ---- create ----

	t.Run("create", func(t *testing.T) {
		t.Run("Should fill in the missing fields in the result", func(t *testing.T) {
			res := create(t, adapter, CreateInput{Model: "user", Data: Record{"name": "test-name"}})
			if _, ok := res["id"].(string); !ok {
				t.Fatalf("id = %#v", res["id"])
			}
			wantEqual(t, res["emailVerified"], false, "emailVerified")
			wantEqual(t, res["name"], "test-name", "name")
			if !undef(res, "email") || !undef(res, "image") {
				t.Fatalf("email/image should be undefined: %#v", res)
			}
			if _, ok := res["createdAt"].(time.Time); !ok {
				t.Fatalf("createdAt = %#v", res["createdAt"])
			}
			if _, ok := res["updatedAt"].(time.Time); !ok {
				t.Fatalf("updatedAt = %#v", res["updatedAt"])
			}
		})

		t.Run("should not return string for nullable foreign keys", func(t *testing.T) {
			ad := e2eAdapter(t, e2eOpts{schema: nullableRefPlugin("testModel", "nullableReference")})
			res := create(t, ad, CreateInput{Model: "testModel", Data: Record{"nullableReference": nil}})
			if v, ok := res["nullableReference"]; !ok || v != nil {
				t.Fatalf("nullableReference = %#v (present %v)", v, ok)
			}
			ad2 := e2eAdapter(t, e2eOpts{schema: nullableRefPlugin("testModel", "nullableReference"), opts: Options{IDMode: IDSerial}})
			res2 := create(t, ad2, CreateInput{Model: "testModel", Data: Record{"nullableReference": nil}})
			if v, ok := res2["nullableReference"]; !ok || v != nil {
				t.Fatalf("serial nullableReference = %#v (present %v)", v, ok)
			}
		})

		t.Run(`Should include an "id" in the result in all cases, unless "select" is used to exclude it`, func(t *testing.T) {
			res := create(t, adapter, CreateInput{Model: "user", Data: Record{"name": "test-name"}})
			if _, ok := res["id"].(string); !ok {
				t.Fatalf("id = %#v", res["id"])
			}
			withoutIDGeneration := e2eAdapter(t, e2eOpts{cfg: func(c *Config) { c.DisableIDGeneration = true }})
			res2 := create(t, withoutIDGeneration, CreateInput{Model: "user", Data: Record{"name": "test-name"}})
			if !undef(res2, "id") {
				t.Fatalf("id should be undefined, got %#v", res2["id"])
			}
			res3 := create(t, adapter, CreateInput{Model: "user", Data: Record{"name": "test-name"}, Select: []string{"name"}})
			if !has(res3, "name") || has(res3, "id") {
				t.Fatalf("select name: %#v", res3)
			}
		})

		t.Run(`Should receive a generated id during the call, unless "disableIdGeneration" is set to true`, func(t *testing.T) {
			var withID Record
			ad := e2eAdapter(t, e2eOpts{driver: captureCreate(&withID)})
			create(t, ad, CreateInput{Model: "user", Data: Record{"name": "test-name"}})
			if _, ok := withID["id"].(string); !ok {
				t.Fatalf("id = %#v", withID["id"])
			}
			var withoutID Record
			ad = e2eAdapter(t, e2eOpts{cfg: func(c *Config) { c.DisableIDGeneration = true }, driver: captureCreate(&withoutID)})
			create(t, ad, CreateInput{Model: "user", Data: Record{"name": "test-name"}})
			if withoutID == nil || !undef(withoutID, "id") {
				t.Fatalf("id should be undefined: %#v", withoutID)
			}
		})

		t.Run("Should not modify result null to string for id or fields referencing id", func(t *testing.T) {
			ad := e2eAdapter(t, e2eOpts{schema: nullableRefPlugin("testPluginTable", "testPluginField")})
			res := create(t, ad, CreateInput{Model: "testPluginTable", Data: Record{"testPluginField": nil}})
			if _, ok := res["id"].(string); !ok {
				t.Fatalf("id = %#v", res["id"])
			}
			if v, ok := res["testPluginField"]; !ok || v != nil {
				t.Fatalf("testPluginField = %#v", v)
			}
		})

		t.Run("Should modify boolean type to 1 or 0 if the DB doesn't support it. And expect the result to be transformed back to boolean", func(t *testing.T) {
			for _, tc := range []struct {
				in   bool
				want int64
			}{{true, 1}, {false, 0}} {
				var data Record
				ad := e2eAdapter(t, e2eOpts{cfg: func(c *Config) { c.SupportsBooleans = boolp(false) }, driver: captureCreate(&data)})
				res := create(t, ad, CreateInput{Model: "user", Data: Record{"emailVerified": tc.in}})
				if res["emailVerified"] != tc.in {
					t.Fatalf("result emailVerified = %#v, want %v", res["emailVerified"], tc.in)
				}
				if data["emailVerified"] != tc.want {
					t.Fatalf("stored emailVerified = %#v, want %d", data["emailVerified"], tc.want)
				}
			}
		})

		t.Run("Should modify string[] type to TEXT if the DB doesn't support it. And expect the result to be transformed back to string[]", func(t *testing.T) {
			var data Record
			ad := e2eAdapter(t, e2eOpts{
				cfg:    func(c *Config) { c.SupportsJSON = false },
				schema: userAdditional(db.Field{Name: "preferences", Type: db.TypeStringArray}),
				driver: captureCreate(&data),
			})
			prefs := []string{"medium", "large"}
			res := create(t, ad, CreateInput{Model: "user", Data: Record{"preferences": prefs}})
			wantEqual(t, res["preferences"], prefs, "result preferences")
			wantEqual(t, data["preferences"], `["medium","large"]`, "stored preferences")
		})

		t.Run("Should modify number[] type to TEXT if the DB doesn't support it. And expect the result to be transformed back to number[]", func(t *testing.T) {
			var data Record
			ad := e2eAdapter(t, e2eOpts{
				cfg:    func(c *Config) { c.SupportsJSON = false },
				schema: userAdditional(db.Field{Name: "preferences", Type: db.TypeNumberArray}),
				driver: captureCreate(&data),
			})
			prefs := []any{6, 7}
			res := create(t, ad, CreateInput{Model: "user", Data: Record{"preferences": prefs}})
			wantEqual(t, res["preferences"], prefs, "result preferences")
			wantEqual(t, data["preferences"], "[6,7]", "stored preferences")
		})

		t.Run("Should modify JSON type to TEXT if the DB doesn't support it. And expect the result to be transformed back to JSON", func(t *testing.T) {
			var data Record
			ad := e2eAdapter(t, e2eOpts{
				cfg:    func(c *Config) { c.SupportsJSON = false },
				schema: userAdditional(db.Field{Name: "preferences", Type: db.TypeJSON}),
				driver: captureCreate(&data),
			})
			prefs := jsonx.O("color", "blue", "size", "large")
			res := create(t, ad, CreateInput{Model: "user", Data: Record{"preferences": prefs}})
			wantEqual(t, res["preferences"], prefs, "result preferences")
			wantEqual(t, data["preferences"], `{"color":"blue","size":"large"}`, "stored preferences")
		})

		t.Run("Should modify date type to TEXT if the DB doesn't support it. And expect the result to be transformed back to date", func(t *testing.T) {
			testDate := time.Now()
			var data Record
			ad := e2eAdapter(t, e2eOpts{cfg: func(c *Config) { c.SupportsDates = boolp(false) }, driver: captureCreate(&data)})
			res := create(t, ad, CreateInput{Model: "user", Data: Record{"createdAt": testDate}})
			if _, ok := res["createdAt"].(time.Time); !ok {
				t.Fatalf("createdAt = %#v", res["createdAt"])
			}
			wantEqual(t, data["createdAt"], jsonx.ISOTime(testDate), "stored createdAt")
		})

		t.Run("Should allow custom transform input", func(t *testing.T) {
			var data Record
			ad := e2eAdapter(t, e2eOpts{
				cfg:    func(c *Config) { c.CustomTransformInput = strTransform("name", strings.ToUpper) },
				driver: captureCreate(&data),
			})
			res := create(t, ad, CreateInput{Model: "user", Data: Record{"name": "test-name"}})
			wantEqual(t, res["name"], "TEST-NAME", "result name")
			wantEqual(t, data["name"], "TEST-NAME", "stored name")
		})

		t.Run("Should allow custom transform output", func(t *testing.T) {
			var data Record
			ad := e2eAdapter(t, e2eOpts{
				cfg:    func(c *Config) { c.CustomTransformOutput = strTransform("name", strings.ToLower) },
				driver: captureCreate(&data),
			})
			res := create(t, ad, CreateInput{Model: "user", Data: Record{"name": "TEST-NAME"}})
			wantEqual(t, res["name"], "test-name", "result name")
			// Remains the same as the input because we're only transforming the output.
			wantEqual(t, data["name"], "TEST-NAME", "stored name")
		})

		t.Run("Should allow custom transform input and output", func(t *testing.T) {
			var data Record
			ad := e2eAdapter(t, e2eOpts{
				cfg: func(c *Config) {
					c.CustomTransformInput = strTransform("name", strings.ToUpper)
					c.CustomTransformOutput = strTransform("name", strings.ToLower)
				},
				driver: captureCreate(&data),
			})
			res := create(t, ad, CreateInput{Model: "user", Data: Record{"name": "TEST-NAME"}})
			wantEqual(t, res["name"], "test-name", "result name")
			wantEqual(t, data["name"], "TEST-NAME", "stored name")
		})

		t.Run("Should allow custom map input key transformation", func(t *testing.T) {
			var data Record
			ad := e2eAdapter(t, e2eOpts{
				cfg:    func(c *Config) { c.MapKeysTransformInput = map[string]string{"email": "email_address"} },
				driver: captureCreate(&data),
			})
			res := create(t, ad, CreateInput{Model: "user", Data: Record{"email": "test@test.com"}})
			if has(res, "email_address") {
				t.Fatalf("result has email_address: %#v", res)
			}
			// undefined: `email` was mapped to `email_address` on input but never mapped back.
			if !undef(res, "email") {
				t.Fatalf("email should be undefined, got %#v", res["email"])
			}
			wantEqual(t, data["email_address"], "test@test.com", "stored email_address")
		})

		t.Run("Should allow custom transform input to transform the where clause", func(t *testing.T) {
			var where []CleanedWhere
			ad := e2eAdapter(t, e2eOpts{
				cfg: func(c *Config) { c.MapKeysTransformInput = map[string]string{"id": "_id"} },
				driver: &fakeDriver{findOne: func(_ context.Context, q Query) (Record, error) {
					where = q.Where
					return Record{}, nil
				}},
			})
			_, err := ad.FindOne(ctx, FindOneInput{Model: "user", Where: []Where{{Field: "id", Value: "123"}}})
			mustNoErr(t, err)
			wantEqual(t, where[0].Field, "_id", "where[0].field")
		})

		t.Run("Should allow custom map output key transformation", func(t *testing.T) {
			var data Record
			ad := e2eAdapter(t, e2eOpts{
				cfg:    func(c *Config) { c.MapKeysTransformOutput = map[string]string{"email": "wrong_email_key"} },
				driver: captureCreate(&data),
			})
			res := create(t, ad, CreateInput{Model: "user", Data: Record{"email": "test@test.com"}})
			if has(res, "email") {
				t.Fatalf("result has email: %#v", res)
			}
			wantEqual(t, res["wrong_email_key"], "test@test.com", "result wrong_email_key")
			wantEqual(t, data["email"], "test@test.com", "stored email")
		})

		t.Run("Should allow custom map input and output key transformation", func(t *testing.T) {
			var data Record
			ad := e2eAdapter(t, e2eOpts{
				cfg: func(c *Config) {
					c.MapKeysTransformInput = map[string]string{"email": "email_address"}
					c.MapKeysTransformOutput = map[string]string{"email_address": "email"}
				},
				driver: captureCreate(&data),
			})
			res := create(t, ad, CreateInput{Model: "user", Data: Record{"email": "test@test.com"}})
			if has(res, "email_address") {
				t.Fatalf("result has email_address: %#v", res)
			}
			wantEqual(t, res["email"], "test@test.com", "result email")
			if has(data, "email") {
				t.Fatalf("stored data has email: %#v", data)
			}
			wantEqual(t, data["email_address"], "test@test.com", "stored email_address")
		})

		t.Run("Should expect the fields to be transformed into the correct field names if customized", func(t *testing.T) {
			var data Record
			ad := e2eAdapter(t, e2eOpts{schema: userFields(map[string]string{"email": "email_address"}), driver: captureCreate(&data)})
			res := create(t, ad, CreateInput{Model: "user", Data: Record{"email": "test@test.com"}})
			if has(res, "email_address") {
				t.Fatalf("result has email_address: %#v", res)
			}
			wantEqual(t, res["email"], "test@test.com", "result email")
			if has(data, "email") {
				t.Fatalf("stored data has email: %#v", data)
			}
			wantEqual(t, data["email_address"], "test@test.com", "stored email_address")
		})

		t.Run("Should expect the model to be transformed into the correct model name if customized", func(t *testing.T) {
			var model string
			ad := e2eAdapter(t, e2eOpts{
				schema: db.Options{User: db.ModelOptions{ModelName: "user_table"}},
				driver: &fakeDriver{create: func(_ context.Context, m, _ string, data Record) (Record, error) {
					model = m
					return data, nil
				}},
			})
			res := create(t, ad, CreateInput{Model: "user", Data: Record{"email": "test@test.com"}})
			if !has(res, "id") || !has(res, "email") {
				t.Fatalf("result: %#v", res)
			}
			wantEqual(t, model, "user_table", "model")
		})

		t.Run("Should expect the result to follow the schema", func(t *testing.T) {
			var data Record
			ad := e2eAdapter(t, e2eOpts{schema: userFields(map[string]string{"email": "email_address"}), driver: captureCreate(&data)})
			res := create(t, ad, CreateInput{Model: "user", Data: Record{"email": "test@test.com"}})
			for _, k := range []string{"email", "id", "createdAt", "updatedAt", "emailVerified"} {
				if !has(res, k) {
					t.Fatalf("result lacks %s: %#v", k, res)
				}
			}
			// name and image are undefined upstream (present keys with undefined values).
			if !undef(res, "name") || !undef(res, "image") {
				t.Fatalf("name/image should be undefined: %#v", res)
			}
			if has(res, "email_address") {
				t.Fatalf("result has email_address: %#v", res)
			}
			if has(data, "email") {
				t.Fatalf("stored data has email: %#v", data)
			}
			wantEqual(t, data["email_address"], "test@test.com", "stored email_address")
		})

		t.Run("Should expect the result to respect the select fields", func(t *testing.T) {
			ad := e2eAdapter(t, e2eOpts{schema: userFields(map[string]string{"email": "email_address"})})
			res := create(t, ad, CreateInput{Model: "user", Data: Record{
				"email":         "test@test.com",
				"name":          "test-name",
				"emailVerified": false,
				"image":         "test-image",
			}, Select: []string{"email"}})
			// __snapshots__/adapter-factory.test.ts.snap
			wantEqual(t, map[string]any(res), map[string]any{"email": "test@test.com"}, "result")
		})
	})

	// ---- update ----

	t.Run("update", func(t *testing.T) {
		t.Run("Should fill in the missing fields in the result", func(t *testing.T) {
			user := create(t, adapter, CreateInput{Model: "user", Data: Record{"name": "test-name"}})
			res := update(t, adapter, user["id"], Record{"name": "test-name-2"})
			// The driver echoes the update, so only the updated keys are defined; the other
			// schema keys are present-but-undefined upstream and absent here.
			wantEqual(t, res["name"], "test-name-2", "name")
			if _, ok := res["updatedAt"].(time.Time); !ok {
				t.Fatalf("updatedAt = %#v", res["updatedAt"])
			}
			for _, k := range []string{"id", "email", "emailVerified", "image", "createdAt"} {
				if !undef(res, k) {
					t.Fatalf("%s should be undefined: %#v", k, res)
				}
			}
		})

		t.Run(`Should include an "id" in the result in all cases`, func(t *testing.T) {
			user := create(t, adapter, CreateInput{Model: "user", Data: Record{"name": "test-name"}})
			res := update(t, adapter, user["id"], Record{"name": "test-name-2"})
			if res == nil {
				t.Fatal("update returned nil")
			}
			// upstream: the "id" key exists with an undefined value (the driver echoes the
			// update, which carries no id).
			if !undef(res, "id") {
				t.Fatalf("id = %#v", res["id"])
			}
		})

		t.Run("Should modify boolean type to 1 or 0 if the DB doesn't support it. And expect the result to be transformed back to boolean", func(t *testing.T) {
			for _, tc := range []struct {
				in   bool
				want int64
			}{{true, 1}, {false, 0}} {
				var data Record
				ad := e2eAdapter(t, e2eOpts{cfg: func(c *Config) { c.SupportsBooleans = boolp(false) }, driver: captureUpdate(&data)})
				user := create(t, ad, CreateInput{Model: "user", Data: Record{"emailVerified": !tc.in}})
				res := update(t, ad, user["id"], Record{"emailVerified": tc.in})
				if res["emailVerified"] != tc.in {
					t.Fatalf("result emailVerified = %#v, want %v", res["emailVerified"], tc.in)
				}
				if data["emailVerified"] != tc.want {
					t.Fatalf("stored emailVerified = %#v, want %d", data["emailVerified"], tc.want)
				}
			}
		})

		t.Run("Should modify JSON type to TEXT if the DB doesn't support it. And expect the result to be transformed back to JSON", func(t *testing.T) {
			var data Record
			ad := e2eAdapter(t, e2eOpts{
				cfg:    func(c *Config) { c.SupportsJSON = false },
				schema: userAdditional(db.Field{Name: "preferences", Type: db.TypeJSON}),
				driver: captureUpdate(&data),
			})
			prefs := jsonx.O("color", "blue", "size", "large")
			user := create(t, ad, CreateInput{Model: "user", Data: Record{"email": "test@test.com"}})
			res := update(t, ad, user["id"], Record{"preferences": prefs})
			wantEqual(t, res["preferences"], prefs, "result preferences")
			wantEqual(t, data["preferences"], `{"color":"blue","size":"large"}`, "stored preferences")
		})

		t.Run("Should modify date type to TEXT if the DB doesn't support it. And expect the result to be transformed back to date", func(t *testing.T) {
			testDate := time.Now()
			var data Record
			ad := e2eAdapter(t, e2eOpts{cfg: func(c *Config) { c.SupportsDates = boolp(false) }, driver: captureUpdate(&data)})
			user := create(t, ad, CreateInput{Model: "user", Data: Record{"email": "test@test.com"}})
			res := update(t, ad, user["id"], Record{"createdAt": testDate})
			if _, ok := res["createdAt"].(time.Time); !ok {
				t.Fatalf("createdAt = %#v", res["createdAt"])
			}
			wantEqual(t, data["createdAt"], jsonx.ISOTime(testDate), "stored createdAt")
		})

		t.Run("Should allow custom transform input", func(t *testing.T) {
			var data Record
			ad := e2eAdapter(t, e2eOpts{cfg: func(c *Config) { c.CustomTransformInput = strTransform("name", strings.ToUpper) }, driver: captureUpdate(&data)})
			user := create(t, ad, CreateInput{Model: "user", Data: Record{"name": "test-name"}})
			res := update(t, ad, user["id"], Record{"name": "test-name-2"})
			wantEqual(t, res["name"], "TEST-NAME-2", "result name")
			wantEqual(t, data["name"], "TEST-NAME-2", "stored name")
		})

		t.Run("Should allow custom transform output", func(t *testing.T) {
			var data Record
			ad := e2eAdapter(t, e2eOpts{cfg: func(c *Config) { c.CustomTransformOutput = strTransform("name", strings.ToLower) }, driver: captureUpdate(&data)})
			user := create(t, ad, CreateInput{Model: "user", Data: Record{"name": "TEST-NAME"}})
			res := update(t, ad, user["id"], Record{"name": "test-name-2"})
			wantEqual(t, res["name"], "test-name-2", "result name")
			wantEqual(t, data["name"], "test-name-2", "stored name")
		})

		t.Run("Should allow custom transform input and output", func(t *testing.T) {
			var data Record
			ad := e2eAdapter(t, e2eOpts{cfg: func(c *Config) {
				c.CustomTransformInput = strTransform("name", strings.ToUpper)
				c.CustomTransformOutput = strTransform("name", strings.ToLower)
			}, driver: captureUpdate(&data)})
			user := create(t, ad, CreateInput{Model: "user", Data: Record{"name": "test-name"}})
			res := update(t, ad, user["id"], Record{"name": "test-name-2"})
			wantEqual(t, res["name"], "test-name-2", "result name")
			wantEqual(t, data["name"], "TEST-NAME-2", "stored name")
		})

		t.Run("Should allow custom map input key transformation", func(t *testing.T) {
			var data Record
			ad := e2eAdapter(t, e2eOpts{cfg: func(c *Config) { c.MapKeysTransformInput = map[string]string{"email": "email_address"} }, driver: captureUpdate(&data)})
			user := create(t, ad, CreateInput{Model: "user", Data: Record{"email": "test@test.com"}})
			res := update(t, ad, user["id"], Record{"email": "test2@test.com"})
			if has(res, "email_address") || !undef(res, "email") {
				t.Fatalf("result: %#v", res)
			}
			wantEqual(t, data["email_address"], "test2@test.com", "stored email_address")
		})

		t.Run("Should allow custom map output key transformation", func(t *testing.T) {
			var data Record
			ad := e2eAdapter(t, e2eOpts{cfg: func(c *Config) { c.MapKeysTransformOutput = map[string]string{"email": "email_address"} }, driver: captureUpdate(&data)})
			user := create(t, ad, CreateInput{Model: "user", Data: Record{"email": "test@test.com"}})
			res := update(t, ad, user["id"], Record{"email": "test2@test.com"})
			if has(res, "email") {
				t.Fatalf("result has email: %#v", res)
			}
			wantEqual(t, res["email_address"], "test2@test.com", "result email_address")
			if has(data, "email_address") {
				t.Fatalf("stored update has email_address: %#v", data)
			}
			wantEqual(t, data["email"], "test2@test.com", "stored email")
		})

		t.Run("Should allow custom map input and output key transformation", func(t *testing.T) {
			var data Record
			ad := e2eAdapter(t, e2eOpts{cfg: func(c *Config) {
				c.MapKeysTransformInput = map[string]string{"email": "email_address"}
				c.MapKeysTransformOutput = map[string]string{"email_address": "email"}
			}, driver: captureUpdate(&data)})
			user := create(t, ad, CreateInput{Model: "user", Data: Record{"email": "test@test.com"}})
			res := update(t, ad, user["id"], Record{"email": "test2@test.com"})
			if has(res, "email_address") {
				t.Fatalf("result has email_address: %#v", res)
			}
			wantEqual(t, res["email"], "test2@test.com", "result email")
			if has(data, "email") {
				t.Fatalf("stored update has email: %#v", data)
			}
			wantEqual(t, data["email_address"], "test2@test.com", "stored email_address")
		})

		t.Run("Should expect the fields to be transformed into the correct field names if customized", func(t *testing.T) {
			var data Record
			ad := e2eAdapter(t, e2eOpts{schema: userFields(map[string]string{"email": "email_address"}), driver: captureUpdate(&data)})
			user := create(t, ad, CreateInput{Model: "user", Data: Record{"email": "test@test.com"}})
			res := update(t, ad, user["id"], Record{"email": "test2@test.com"})
			if has(res, "email_address") {
				t.Fatalf("result has email_address: %#v", res)
			}
			wantEqual(t, res["email"], "test2@test.com", "result email")
			if has(data, "email") {
				t.Fatalf("stored update has email: %#v", data)
			}
			wantEqual(t, data["email_address"], "test2@test.com", "stored email_address")
		})

		t.Run("Should expect not to receive an id even if disableIdGeneration is false in an update call", func(t *testing.T) {
			var data Record
			ad := e2eAdapter(t, e2eOpts{cfg: func(c *Config) { c.DisableIDGeneration = true }, driver: captureUpdate(&data)})
			user := create(t, ad, CreateInput{Model: "user", Data: Record{"email": "test@test.com"}})
			update(t, ad, user["id"], Record{"email": "test2@test.com"})
			if data == nil {
				t.Fatal("update was not called")
			}
			if has(data, "id") {
				t.Fatalf("update carries an id: %#v", data)
			}
		})
	})

	// ---- find ----

	t.Run("find", func(t *testing.T) {
		renamedUser := func() Record {
			return Record{
				"id":            "random-id-oudwduwbdouwbdu123b",
				"email_address": "test@test.com",
				"emailVerified": false,
				"createdAt":     time.Now(),
				"updatedAt":     time.Now(),
				"name":          "test-name",
			}
		}

		t.Run("findOne: Should transform the where clause according to the schema", func(t *testing.T) {
			var where []CleanedWhere
			ad := e2eAdapter(t, e2eOpts{
				schema: userFields(map[string]string{"email": "email_address"}),
				driver: &fakeDriver{findOne: func(_ context.Context, q Query) (Record, error) {
					where = q.Where
					return renamedUser(), nil
				}},
			})
			res, err := ad.FindOne(ctx, FindOneInput{Model: "user", Where: []Where{{Field: "email", Value: "test@test.com"}}})
			mustNoErr(t, err)
			if has(res, "email_address") {
				t.Fatalf("result has email_address: %#v", res)
			}
			wantEqual(t, res["email"], "test@test.com", "result email")
			wantEqual(t, where[0].Field, "email_address", "where[0].field")
		})

		t.Run("findMany: Should transform the where clause according to the schema", func(t *testing.T) {
			var where []CleanedWhere
			ad := e2eAdapter(t, e2eOpts{
				schema: userFields(map[string]string{"email": "email_address"}),
				driver: &fakeDriver{findMany: func(_ context.Context, q Query) ([]Record, error) {
					where = q.Where
					r := renamedUser()
					r["id"] = "random-id-eio1d1u12h33123ed"
					return []Record{r}, nil
				}},
			})
			res, err := ad.FindMany(ctx, FindManyInput{Model: "user", Where: []Where{{Field: "email", Value: "test@test.com"}}})
			mustNoErr(t, err)
			if has(res[0], "email_address") {
				t.Fatalf("result has email_address: %#v", res[0])
			}
			wantEqual(t, res[0]["email"], "test@test.com", "result email")
			wantEqual(t, where[0].Field, "email_address", "where[0].field")
		})

		serialUser := func() Record {
			return Record{
				"id":            int64(1),
				"email":         "test@test.com",
				"emailVerified": false,
				"createdAt":     time.Now(),
				"updatedAt":     time.Now(),
				"name":          "test-name",
			}
		}

		t.Run("findOne: Should receive an integer id in where clause if the user has enabled `serial`", func(t *testing.T) {
			var where []CleanedWhere
			ad := e2eAdapter(t, e2eOpts{
				opts: Options{IDMode: IDSerial},
				driver: &fakeDriver{findOne: func(_ context.Context, q Query) (Record, error) {
					where = q.Where
					return serialUser(), nil
				}},
			})
			res, err := ad.FindOne(ctx, FindOneInput{Model: "user", Where: []Where{{Field: "id", Value: "1"}}})
			mustNoErr(t, err)
			wantEqual(t, res["id"], "1", "result id")
			if _, isStr := res["id"].(string); !isStr {
				t.Fatalf("result id should be a string: %#v", res["id"])
			}
			wantEqual(t, where[0].Value, 1, "where[0].value")
			if _, isStr := where[0].Value.(string); isStr {
				t.Fatalf("where value should be a number: %#v", where[0].Value)
			}
		})

		t.Run("findMany: Should receive an integer id in where clause if the user has enabled `serial`", func(t *testing.T) {
			var where []CleanedWhere
			ad := e2eAdapter(t, e2eOpts{
				opts: Options{IDMode: IDSerial},
				driver: &fakeDriver{findMany: func(_ context.Context, q Query) ([]Record, error) {
					where = q.Where
					return []Record{serialUser()}, nil
				}},
			})
			res, err := ad.FindMany(ctx, FindManyInput{Model: "user", Where: []Where{{Field: "id", Value: "1"}}})
			mustNoErr(t, err)
			wantEqual(t, res[0]["id"], "1", "result id")
			wantEqual(t, where[0].Value, 1, "where[0].value")
			if _, isStr := where[0].Value.(string); isStr {
				t.Fatalf("where value should be a number: %#v", where[0].Value)
			}
		})
	})
}

func TestFallbackJoinOptionSystem(t *testing.T) {
	ctx := context.Background()
	joinsOn := Options{Joins: true}
	user := func(id, email, name string) Record {
		return Record{"id": id, "email": email, "emailVerified": false, "createdAt": time.Now(), "updatedAt": time.Now(), "name": name}
	}
	session := func(id, userID string) Record {
		return Record{"id": id, "userId": userID, "expiresAt": time.Now(), "createdAt": time.Now()}
	}

	t.Run("fallback when adapter returns flat rows (no join keys)", func(t *testing.T) {
		t.Run("findOne: Should handle forward joins (joined model has FK to base model) by making separate queries", func(t *testing.T) {
			type call struct{ method, model string }
			var calls []call
			ad := e2eAdapter(t, e2eOpts{opts: joinsOn, driver: &fakeDriver{
				findOne: func(_ context.Context, q Query) (Record, error) {
					calls = append(calls, call{"findOne", q.Model})
					if q.Model == "user" {
						return user("user-123", "test@test.com", "Test User"), nil
					}
					return nil, nil
				},
				findMany: func(_ context.Context, q Query) ([]Record, error) {
					calls = append(calls, call{"findMany", q.Model})
					if q.Model == "session" {
						return []Record{session("session-1", "user-123")}, nil
					}
					return []Record{}, nil
				},
			}})
			calls = nil
			res, err := ad.FindOne(ctx, FindOneInput{Model: "user", Where: []Where{{Field: "id", Value: "user-123"}},
				Join: map[string]Join{"session": {}}})
			mustNoErr(t, err)
			if len(calls) < 2 {
				t.Fatalf("calls = %v", calls)
			}
			var sawUser, sawSession bool
			for _, c := range calls {
				sawUser = sawUser || c.model == "user"
				sawSession = sawSession || c.model == "session"
			}
			if !sawUser || !sawSession {
				t.Fatalf("calls = %v", calls)
			}
			if !has(res, "id") || !has(res, "session") {
				t.Fatalf("result: %#v", res)
			}
		})

		t.Run("findMany: Should handle forward joins efficiently using IN operator", func(t *testing.T) {
			type call struct {
				method, model string
				where         []CleanedWhere
			}
			var calls []call
			ad := e2eAdapter(t, e2eOpts{opts: joinsOn, driver: &fakeDriver{
				findMany: func(_ context.Context, q Query) ([]Record, error) {
					calls = append(calls, call{"findMany", q.Model, q.Where})
					switch q.Model {
					case "user":
						return []Record{user("user-1", "test1@test.com", "User 1"), user("user-2", "test2@test.com", "User 2")}, nil
					case "session":
						return []Record{session("session-1", "user-1"), session("session-2", "user-2")}, nil
					}
					return []Record{}, nil
				},
			}})
			calls = nil
			res, err := ad.FindMany(ctx, FindManyInput{Model: "user", Where: []Where{}, Join: map[string]Join{"session": {}}})
			mustNoErr(t, err)
			var sessionCall *call
			for i := range calls {
				if calls[i].model == "session" {
					sessionCall = &calls[i]
					break
				}
			}
			if sessionCall == nil {
				t.Fatalf("no session query: %v", calls)
			}
			if sessionCall.where == nil {
				t.Fatal("session query has no where clause")
			}
			if len(res) == 0 {
				t.Fatal("no results")
			}
			for _, item := range res {
				if !has(item, "session") {
					t.Fatalf("item lacks session: %#v", item)
				}
			}
		})
	})

	t.Run("native join support (advanced.database.joins: true)", func(t *testing.T) {
		nested := func() Record {
			u := user("user-123", "test@test.com", "Test User")
			u["session"] = []Record{session("session-1", "user-123")}
			return u
		}

		t.Run("findOne: Should pass join to adapter and use nested data when present", func(t *testing.T) {
			var joinPassed map[string]JoinConfig
			ad := e2eAdapter(t, e2eOpts{opts: joinsOn, driver: &fakeDriver{
				findOne: func(_ context.Context, q Query) (Record, error) {
					joinPassed = q.Join
					return nested(), nil
				},
			}})
			res, err := ad.FindOne(ctx, FindOneInput{Model: "user", Where: []Where{{Field: "id", Value: "user-123"}},
				Join: map[string]Join{"session": {}}})
			mustNoErr(t, err)
			if joinPassed == nil {
				t.Fatal("join was not passed to the adapter")
			}
			if _, ok := joinPassed["session"]; !ok {
				t.Fatalf("join = %#v", joinPassed)
			}
			if !has(res, "session") {
				t.Fatalf("result: %#v", res)
			}
		})

		t.Run("findMany: Should pass join to adapter and use nested data when present", func(t *testing.T) {
			var joinPassed map[string]JoinConfig
			ad := e2eAdapter(t, e2eOpts{opts: joinsOn, driver: &fakeDriver{
				findMany: func(_ context.Context, q Query) ([]Record, error) {
					joinPassed = q.Join
					return []Record{nested()}, nil
				},
			}})
			res, err := ad.FindMany(ctx, FindManyInput{Model: "user", Where: []Where{}, Join: map[string]Join{"session": {}}})
			mustNoErr(t, err)
			if joinPassed == nil {
				t.Fatal("join was not passed to the adapter")
			}
			if _, ok := joinPassed["session"]; !ok {
				t.Fatalf("join = %#v", joinPassed)
			}
			if len(res) == 0 || !has(res[0], "session") {
				t.Fatalf("result: %#v", res)
			}
		})
	})

	t.Run("default behavior (joins disabled)", func(t *testing.T) {
		t.Run("Should not pass join to adapter by default", func(t *testing.T) {
			called := false
			var joinPassed map[string]JoinConfig
			ad := e2eAdapter(t, e2eOpts{driver: &fakeDriver{
				findOne: func(_ context.Context, q Query) (Record, error) {
					called = true
					joinPassed = q.Join
					return user("user-123", "test@test.com", "Test User"), nil
				},
				findMany: func(context.Context, Query) ([]Record, error) { return []Record{}, nil },
			}})
			_, err := ad.FindOne(ctx, FindOneInput{Model: "user", Where: []Where{{Field: "id", Value: "user-123"}},
				Join: map[string]Join{"session": {}}})
			mustNoErr(t, err)
			if !called || joinPassed != nil {
				t.Fatalf("join passed to the adapter: %#v", joinPassed)
			}
		})
	})
}
