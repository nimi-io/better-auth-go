package adaptertest

import (
	"math/rand/v2"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
)

// Port of packages/test-utils/src/adapter/suites/basic.ts

// NormalSuite is normalTestSuite.
var NormalSuite = CreateTestSuite("normal", SuiteConfig{}, func() []Test {
	return append([]Test{
		{Name: "init - tests", Fn: func(h *H) {
			h.True(idMode(h.Options()) != adapter.IDSerial, "generateId !== serial")
		}},
	}, normalTests()...)
})

// NormalTestNames returns the names of the normal suite tests (getNormalTestSuiteTests).
func NormalTestNames() []string {
	var out []string
	for _, t := range normalTests() {
		out = append(out, t.Name)
	}
	return out
}

// EnableJoinTests maps every join test of the normal suite to false, re-enabling them when
// combined with DisableAll (enableJoinTests).
func EnableJoinTests() map[string]bool {
	out := map[string]bool{}
	for _, name := range NormalTestNames() {
		if strings.Contains(name, "join") {
			out[name] = false
		}
	}
	return out
}

// ---- option fragments ----

func oneToOneTable(modelName string, field db.Field) ConfigMod {
	return func(c *betterauth.Config) {
		c.Plugins = append(c.Plugins, schemaPlugin("one-to-one-test", db.PluginTable{
			Key: "oneToOneTable", ModelName: modelName, Fields: []db.Field{field},
		}))
	}
}

func oneToOneIDRef(modelName string) ConfigMod {
	return oneToOneTable(modelName, db.Field{
		Name: "oneToOne", Type: db.TypeString, Required: db.True,
		References: &db.Reference{Model: "user", Field: "id"}, Unique: true,
	})
}

func numericField(next func() any) ConfigMod {
	return func(c *betterauth.Config) {
		u := ensureUser(c)
		u.AdditionalFields = append(u.AdditionalFields, db.Field{Name: "numericField", Type: db.TypeNumber, DefaultFunc: next})
	}
}

func defaultFieldsFields(required bool) []db.Field {
	return []db.Field{
		{Name: "testField", Type: db.TypeString, Required: db.Bool(required), DefaultValue: "test-value"},
		{Name: "cbDefaultValueField", Type: db.TypeString, Required: db.Bool(required), DefaultFunc: func() any { return "advanced-test-value" }},
	}
}

func defaultFieldsMod(c *betterauth.Config) {
	u := ensureUser(c)
	u.AdditionalFields = append(u.AdditionalFields, defaultFieldsFields(false)...)
	c.Plugins = append(c.Plugins, schemaPlugin("default-fields-test", db.PluginTable{Key: "testModel", Fields: defaultFieldsFields(false)}))
}

// organizationSchema is the schema of organization({ teams: { enabled: true } }).
func organizationSchema() []db.PluginTable {
	orgRef := &db.Reference{Model: "organization", Field: "id"}
	userRef := &db.Reference{Model: "user", Field: "id"}
	return []db.PluginTable{
		{Key: "organization", Fields: []db.Field{
			{Name: "name", Type: db.TypeString, Required: db.True, Sortable: true},
			{Name: "slug", Type: db.TypeString, Required: db.True, Unique: true, Sortable: true, Index: true},
			{Name: "logo", Type: db.TypeString, Required: db.False},
			{Name: "createdAt", Type: db.TypeDate, Required: db.True},
			{Name: "metadata", Type: db.TypeString, Required: db.False},
		}},
		{Key: "team", Fields: []db.Field{
			{Name: "name", Type: db.TypeString, Required: db.True},
			{Name: "memberCount", Type: db.TypeNumber, Required: db.True, DefaultValue: 0, Input: db.False, Returned: db.False},
			{Name: "organizationId", Type: db.TypeString, Required: db.True, References: orgRef, Index: true},
			{Name: "createdAt", Type: db.TypeDate, Required: db.True},
			{Name: "updatedAt", Type: db.TypeDate, Required: db.False, OnUpdate: func() any { return time.Now() }},
		}},
		{Key: "teamMember", Fields: []db.Field{
			{Name: "teamId", Type: db.TypeString, Required: db.True, References: &db.Reference{Model: "team", Field: "id"}, Index: true},
			{Name: "userId", Type: db.TypeString, Required: db.True, References: userRef, Index: true},
			{Name: "membershipKey", Type: db.TypeString, Required: db.False, Unique: true, Input: db.False, Returned: db.False},
			{Name: "createdAt", Type: db.TypeDate, Required: db.False},
		}},
		{Key: "member", Fields: []db.Field{
			{Name: "organizationId", Type: db.TypeString, Required: db.True, References: orgRef, Index: true},
			{Name: "userId", Type: db.TypeString, Required: db.True, References: userRef, Index: true},
			{Name: "role", Type: db.TypeString, Required: db.True, Sortable: true, DefaultValue: "member"},
			{Name: "createdAt", Type: db.TypeDate, Required: db.True},
		}},
		{Key: "invitation", Fields: []db.Field{
			{Name: "organizationId", Type: db.TypeString, Required: db.True, References: orgRef, Index: true},
			{Name: "email", Type: db.TypeString, Required: db.True, Sortable: true, Index: true},
			{Name: "role", Type: db.TypeString, Required: db.False, Sortable: true},
			{Name: "teamId", Type: db.TypeString, Required: db.False, Sortable: true},
			{Name: "status", Type: db.TypeString, Required: db.True, Sortable: true, DefaultValue: "pending"},
			{Name: "expiresAt", Type: db.TypeDate, Required: db.True},
			{Name: "createdAt", Type: db.TypeDate, Required: db.True, DefaultFunc: func() any { return time.Now() }},
			{Name: "inviterId", Type: db.TypeString, References: userRef, Required: db.True},
		}},
		{Key: "session", Fields: []db.Field{
			{Name: "activeOrganizationId", Type: db.TypeString, Required: db.False, Input: db.False},
			{Name: "activeTeamId", Type: db.TypeString, Required: db.False, Input: db.False},
		}},
	}
}

// ---- helpers ----

func sortedByID(rs []adapter.Record) []adapter.Record {
	out := append([]adapter.Record(nil), rs...)
	sort.SliceStable(out, func(i, j int) bool { return ID(out[i]) < ID(out[j]) })
	return out
}

func filterRecords(rs []adapter.Record, keep func(adapter.Record) bool) []adapter.Record {
	out := []adapter.Record{}
	for _, r := range rs {
		if keep(r) {
			out = append(out, r)
		}
	}
	return out
}

func findByID(rs []adapter.Record, id string) adapter.Record {
	for _, r := range rs {
		if ID(r) == id {
			return r
		}
	}
	return nil
}

func sortByNumeric(rs []adapter.Record) []adapter.Record {
	sort.SliceStable(rs, func(i, j int) bool { return Num(rs[i], "numericField") < Num(rs[j], "numericField") })
	return rs
}

func sliceRecords(rs []adapter.Record, from, to int) []adapter.Record {
	if from > len(rs) {
		from = len(rs)
	}
	if to > len(rs) {
		to = len(rs)
	}
	return append([]adapter.Record{}, rs[from:to]...)
}

// notFoundID is the id used to look up a missing record.
func notFoundID(h *H) string {
	if idMode(h.Options()) == adapter.IDUUID {
		return randomUUID()
	}
	return "100000"
}

func withUserID(h *H, model string, userID any) adapter.Record {
	return Merge(h.Generate(model), R{"userId": userID})
}

func or(field string, value any) adapter.Where {
	return adapter.Where{Field: field, Value: value, Connector: adapter.Or}
}

func op(field string, value any, o adapter.Operator) adapter.Where {
	return adapter.Where{Field: field, Value: value, Operator: o}
}

func joinAll(models ...string) map[string]adapter.Join {
	out := map[string]adapter.Join{}
	for _, m := range models {
		out[m] = adapter.Join{}
	}
	return out
}

// normalTests is getNormalTestSuiteTests.
func normalTests() []Test {
	createUser := func(h *H, extra ...R) adapter.Record {
		h.Helper()
		data := h.Generate("user")
		for _, e := range extra {
			data = Merge(data, e)
		}
		return h.Create(adapter.CreateInput{Model: "user", Data: data, ForceAllowID: true})
	}
	createWithUser := func(h *H, model string, userID any, extra ...R) adapter.Record {
		h.Helper()
		data := withUserID(h, model, userID)
		for _, e := range extra {
			data = Merge(data, e)
		}
		return h.Create(adapter.CreateInput{Model: model, Data: data, ForceAllowID: true})
	}
	createOneToOne := func(h *H, value any) adapter.Record {
		h.Helper()
		return h.Create(adapter.CreateInput{Model: "oneToOneTable", Data: R{"oneToOne": value}})
	}
	findUser := func(h *H, id any) adapter.Record {
		h.Helper()
		return h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("id", id)})
	}

	return []Test{
		{Name: "create - should create a model", Fn: func(h *H) {
			user := h.Generate("user")
			result := h.Create(adapter.CreateInput{Model: "user", Data: user, ForceAllowID: true})
			if m := idMode(h.Options()); m == adapter.IDSerial || m == adapter.IDUUID {
				user["id"] = result["id"]
			}
			h.IsString(result["id"])
			h.Equal(result, h.TransformGeneratedModel(user))
		}},
		{Name: "create - should always return an id", Fn: func(h *H) {
			user := Omit(h.Generate("user"), "id")
			res := h.Create(adapter.CreateInput{Model: "user", Data: user})
			_, ok := res["id"]
			h.True(ok, "result has id")
			h.IsString(res["id"])
		}},
		{Name: "create - should use generateId if provided", Fn: func(h *H) {
			id := "MOCK-ID"
			if g := h.CustomIDGenerator(); g != nil {
				if v := g(); v != "" {
					id = v
				}
			}
			h.ModifyOptions(func(c *betterauth.Config) {
				ensureDB(c).GenerateIDFunc = func(string, int) (string, bool) { return id, true }
			}, false)
			user := Omit(h.Generate("user"), "id")
			res := h.Create(adapter.CreateInput{Model: "user", Data: user})
			want := id
			if f := h.TransformIDOutput(); f != nil {
				want = f(id)
			}
			h.Equal(res["id"], want)
			findResult := findUser(h, res["id"])
			h.Equal(findResult, res)
		}},
		{
			Name: "create - should return null for nullable foreign keys",
			MigrateBetterAuth: func(c *betterauth.Config) {
				c.Plugins = append(c.Plugins, schemaPlugin("nullable-test", db.PluginTable{Key: "testModel", Fields: []db.Field{
					{Name: "nullableReference", Type: db.TypeString, References: &db.Reference{Field: "id", Model: "user"}, Required: db.False},
				}}))
			},
			Fn: func(h *H) {
				res := h.Create(adapter.CreateInput{Model: "testModel", Data: R{"nullableReference": nil}, ForceAllowID: true})
				h.FieldNull(res, "nullableReference")
			},
		},
		{Name: "create - should apply default values to fields", Fn: func(h *H) {
			h.ModifyOptions(func(c *betterauth.Config) {
				u := ensureUser(c)
				u.AdditionalFields = append(u.AdditionalFields,
					db.Field{Name: "testField", Type: db.TypeString, DefaultValue: "test-value"},
					db.Field{Name: "cbDefaultValueField", Type: db.TypeString, DefaultFunc: func() any { return "advanced-test-value" }})
				c.Plugins = append(c.Plugins, schemaPlugin("default-fields-test", db.PluginTable{Key: "testModel", Fields: []db.Field{
					{Name: "testField", Type: db.TypeString, DefaultValue: "test-value"},
					{Name: "cbDefaultValueField", Type: db.TypeString, DefaultFunc: func() any { return "advanced-test-value" }},
				}}))
			}, true)
			result := h.Create(adapter.CreateInput{Model: "testModel", Data: R{}})
			h.True(result["id"] != nil, "id defined")
			h.IsString(result["id"])
			h.Equal(result["testField"], "test-value")
			h.Equal(result["cbDefaultValueField"], "advanced-test-value")
			userResult := createUser(h)
			h.NotNull(userResult)
			h.Equal(userResult["testField"], "test-value")
			h.Equal(userResult["cbDefaultValueField"], "advanced-test-value")
		}},
		{Name: "findOne - should find a model", Fn: func(h *H) {
			user := h.InsertRandom("user")[0]
			result := findUser(h, user["id"])
			h.Equal(result, user)
		}},
		{Name: "findOne - should not apply defaultValue if value not found", Fn: func(h *H) {
			h.ModifyOptions(defaultFieldsMod, true)
			first := h.Create(adapter.CreateInput{Model: "testModel", Data: R{"testField": nil, "cbDefaultValueField": nil}})
			second := createUser(h, R{"testField": nil, "cbDefaultValueField": nil})
			result := h.FindOne(adapter.FindOneInput{Model: "testModel", Where: Where("id", first["id"])})
			h.NotNull(result)
			h.FieldNull(result, "testField")
			h.FieldNull(result, "cbDefaultValueField")
			resultTwo := h.FindMany(adapter.FindManyInput{Model: "user", Where: Where("id", second["id"])})
			h.True(resultTwo != nil, "resultTwo not null")
			h.Len(resultTwo, 1)
			h.FieldNull(resultTwo[0], "testField")
			h.FieldNull(resultTwo[0], "cbDefaultValueField")
		}},
		{Name: "findOne - should find a model using a reference field", Fn: func(h *H) {
			rows := h.InsertRandom("session")
			user, session := rows[0], rows[1]
			result := h.FindOne(adapter.FindOneInput{Model: "session", Where: Where("userId", user["id"])})
			h.Equal(result, session)
		}},
		{Name: "findOne - should not throw on record not found", Fn: func(h *H) {
			result := findUser(h, notFoundID(h))
			h.Null(result)
		}},
		{Name: "findOne - should find a model without id", Fn: func(h *H) {
			user := h.InsertRandom("user")[0]
			result := h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("email", user["email"])})
			h.Equal(result, user)
		}},
		{Name: "findOne - should find a model with join", Fn: func(h *H) {
			var users, sessions, accounts []adapter.Record
			for range 3 {
				users = append(users, createUser(h))
				userID := users[0]["id"]
				sessions = append(sessions, createWithUser(h, "session", userID))
				accounts = append(accounts, createWithUser(h, "account", userID))
			}
			result := h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("id", users[0]["id"]),
				Join: joinAll("session", "account")})
			h.NotNull(result)
			got := Merge(result, R{
				"session": sortedByID(h.Array(result["session"])),
				"account": sortedByID(h.Array(result["account"])),
			})
			h.Equal(got, Merge(users[0], R{"session": sortedByID(sessions), "account": sortedByID(accounts)}))
		}},
		{Name: "findOne - should find a model with modified field name", Fn: func(h *H) {
			h.ModifyOptions(func(c *betterauth.Config) {
				ensureUser(c).Fields = map[string]string{"email": "email_address"}
			}, true)
			user := h.InsertRandom("user")[0]
			result := h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("email", user["email"])})
			h.Equal(result, user)
			h.Equal(result["email"], user["email"])
		}},
		{Name: "findOne - should find a model with modified model name", Fn: func(h *H) {
			h.ModifyOptions(func(c *betterauth.Config) { ensureUser(c).ModelName = "user_custom" }, true)
			user := h.InsertRandom("user")[0]
			h.NotNull(user)
			_, hasID := user["id"]
			_, hasName := user["name"]
			h.True(hasID && hasName, "user has id and name")
			result := h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("email", user["email"])})
			h.Equal(result, user)
			h.Equal(result["email"], user["email"])
		}},
		{Name: "findOne - should find a model with additional fields", Fn: func(h *H) {
			h.ModifyOptions(func(c *betterauth.Config) {
				u := ensureUser(c)
				u.AdditionalFields = append(u.AdditionalFields, db.Field{Name: "customField", Type: db.TypeString,
					Input: db.False, Required: db.True, DefaultValue: "default-value"})
			}, true)
			user := h.InsertRandom("user")[0]
			_, ok := user["customField"]
			h.True(ok, "user has customField")
			h.Equal(user["customField"], "default-value")
			result := h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("customField", user["customField"])})
			h.Equal(result, user)
			h.Equal(result["customField"], "default-value")
		}},
		{Name: "findOne - should select fields", Fn: func(h *H) {
			user := h.InsertRandom("user")[0]
			result := h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("id", user["id"]), Select: []string{"email", "name"}})
			h.Equal(result, R{"email": user["email"], "name": user["name"]})
		}},
		{Name: "findOne - should select fields with one-to-many join", Fn: func(h *H) {
			user := createUser(h)
			session := createWithUser(h, "session", user["id"])
			result := h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("id", user["id"]),
				Select: []string{"email", "name"}, Join: joinAll("session")})
			h.NotNull(result)
			h.Equal(result["email"], user["email"])
			h.Equal(result["name"], user["name"])
			sessions := h.Array(result["session"])
			h.Len(sessions, 1)
			h.Equal(sessions[0], session)
		}},
		{Name: "findOne - should select fields with one-to-one join", Fn: func(h *H) {
			h.ModifyOptions(oneToOneIDRef(""), true)
			user := createUser(h)
			oneToOne := createOneToOne(h, user["id"])
			result := h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("id", user["id"]),
				Select: []string{"email", "name"}, Join: joinAll("oneToOneTable")})
			h.NotNull(result)
			h.Equal(result["email"], user["email"])
			h.Equal(result["name"], user["name"])
			h.True(result["oneToOneTable"] != nil, "oneToOneTable defined")
			h.Equal(h.Object(result["oneToOneTable"]), oneToOne)
		}},
		{Name: "findOne - should select fields with multiple joins", Fn: func(h *H) {
			user := createUser(h)
			session := createWithUser(h, "session", user["id"])
			account := createWithUser(h, "account", user["id"])
			result := h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("id", user["id"]),
				Select: []string{"email", "name"}, Join: joinAll("session", "account")})
			h.NotNull(result)
			h.Equal(result["email"], user["email"])
			h.Equal(result["name"], user["name"])
			sessions := h.Array(result["session"])
			h.Len(sessions, 1)
			h.Equal(sessions[0], session)
			accounts := h.Array(result["account"])
			h.Len(accounts, 1)
			h.Equal(accounts[0], account)
		}},
		{Name: "findOne - should find model with date field", Fn: func(h *H) {
			user := h.InsertRandom("user")[0]
			result := h.FindOne(adapter.FindOneInput{Model: "user", Where: []W{op("createdAt", user["createdAt"], adapter.Eq)}})
			h.Equal(result, user)
			_, isDate := result["createdAt"].(time.Time)
			h.True(isDate, "createdAt should be a time.Time, got %T", result["createdAt"])
			h.Equal(result["createdAt"], user["createdAt"])
		}},
		{Name: "findOne - should perform backwards joins", Fn: func(h *H) {
			user := createUser(h)
			session := createWithUser(h, "session", user["id"])
			result := h.FindOne(adapter.FindOneInput{Model: "session", Where: Where("token", session["token"]), Join: joinAll("user")})
			h.Equal(result, Merge(session, R{"user": user}))
		}},
		{Name: "findOne - should return an object for one-to-one joins", Fn: func(h *H) {
			h.ModifyOptions(oneToOneIDRef(""), true)
			users := Firsts(h.InsertRandomN("user", 2))
			oneToOne := createOneToOne(h, users[0]["id"])
			createOneToOne(h, users[1]["id"])
			result := h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("id", users[0]["id"]), Join: joinAll("oneToOneTable")})
			h.Equal(result, Merge(users[0], R{"oneToOneTable": oneToOne}))
		}},
		{Name: "findOne - should return an array for one-to-many joins", Fn: func(h *H) {
			user := createUser(h)
			session := createWithUser(h, "session", user["id"])
			result := h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("id", user["id"]), Join: joinAll("session")})
			h.Equal(result, Merge(user, R{"session": []adapter.Record{session}}))
		}},
		{Name: "findOne - should work with both one-to-one and one-to-many joins", Fn: func(h *H) {
			h.ModifyOptions(oneToOneIDRef(""), true)
			users := Firsts(h.InsertRandomN("user", 2))
			oneToOne := createOneToOne(h, users[0]["id"])
			now := time.Now().UnixMilli()
			session1 := createWithUser(h, "session", users[0]["id"], R{"createdAt": time.UnixMilli(now - 3000).UTC()})
			session2 := createWithUser(h, "session", users[0]["id"], R{"createdAt": time.UnixMilli(now - 1000).UTC()})
			result := h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("id", users[0]["id"]),
				Join: joinAll("oneToOneTable", "session")})
			h.NotNull(result)
			if sessions, ok := result["session"].([]adapter.Record); ok && len(sessions) > 0 {
				sorted := append([]adapter.Record(nil), sessions...)
				sort.SliceStable(sorted, func(i, j int) bool { return Time(sorted[i], "createdAt").Before(Time(sorted[j], "createdAt")) })
				result["session"] = sorted
			}
			h.Equal(result, Merge(users[0], R{"oneToOneTable": oneToOne, "session": []adapter.Record{session1, session2}}))
		}},
		{Name: "findOne - should return null for failed base model lookup that has joins", Fn: func(h *H) {
			h.ModifyOptions(oneToOneIDRef("one_to_one_table"), true)
			result := h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("id", notFoundID(h)),
				Join: joinAll("session", "account", "oneToOneTable")})
			h.Null(result)
		}},
		{Name: "findOne - should join a model with modified field name", Fn: func(h *H) {
			h.ModifyOptions(func(c *betterauth.Config) {
				ensureUser(c).Fields = map[string]string{"email": "email_address"}
				oneToOneTable("one_to_one_table", db.Field{
					Name: "oneToOne", Type: db.TypeString, Required: db.True,
					References: &db.Reference{Field: "email", Model: "user"}, Unique: true, FieldName: "one_to_one",
				})(c)
			}, true)
			user := createUser(h)
			oneToOne := createOneToOne(h, user["email"])
			result := h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("email", user["email"]), Join: joinAll("oneToOneTable")})
			h.Equal(result, Merge(user, R{"oneToOneTable": oneToOne}))
		}},
		{Name: "findMany - should find many models", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 3))
			result := h.FindMany(adapter.FindManyInput{Model: "user"})
			h.Equal(h.SortModels(result), h.SortModels(users))
		}},
		{Name: "findMany - should find many models with date fields", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 3))
			sort.SliceStable(users, func(i, j int) bool { return Time(users[i], "createdAt").After(Time(users[j], "createdAt")) })
			youngestUser := users[0]
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{op("createdAt", youngestUser["createdAt"], adapter.Lt)}})
			h.Equal(h.SortModels(result), h.SortModels(filterRecords(users, func(u R) bool {
				return Time(u, "createdAt").Before(Time(youngestUser, "createdAt"))
			})))
		}},
		{Name: "findMany - should find many models with join", Fn: func(h *H) {
			var expected []adapter.Record
			for i := 0; i < 10; i++ {
				var extra []R
				if i < 3 {
					extra = append(extra, R{"name": "join-user-" + strconv.Itoa(i)})
				}
				user := createUser(h, extra...)
				var sessions, accounts []adapter.Record
				for range 3 {
					sessions = append(sessions, createWithUser(h, "session", user["id"]))
				}
				for range 3 {
					accounts = append(accounts, createWithUser(h, "account", user["id"]))
				}
				if i < 3 {
					expected = append(expected, Merge(user, R{"session": sessions, "account": accounts}))
				}
			}
			result := h.FindMany(adapter.FindManyInput{Model: "user",
				Where: []W{op("name", "join-user", adapter.StartsWith)}, Join: joinAll("session", "account")})
			normalizeJoined := func(rs []adapter.Record) []adapter.Record {
				out := sortedByID(rs)
				for i, x := range out {
					out[i] = Merge(x, R{
						"session": sortedByID(h.Array(x["session"])),
						"account": sortedByID(h.Array(x["account"])),
					})
				}
				return out
			}
			h.Equal(normalizeJoined(result), normalizeJoined(expected))
		}},
		{Name: "findMany - should find many with join and limit", Fn: func(h *H) {
			for range 5 {
				user := createUser(h)
				for range 3 {
					createWithUser(h, "session", user["id"])
				}
			}
			result := h.FindMany(adapter.FindManyInput{Model: "user", Join: joinAll("session"), Limit: 2})
			h.Len(result, 2)
			for _, user := range result {
				h.Len(h.Array(user["session"]), 3)
			}
		}},
		{Name: "findMany - should select fields", Fn: func(h *H) {
			var expected []R
			for _, rows := range h.InsertRandomN("user", 3) {
				expected = append(expected, R{"id": rows[0]["id"], "email": rows[0]["email"]})
			}
			sel := []string{"id", "email"}
			ids := make([]any, len(expected))
			for i, r := range expected {
				ids[i] = r["id"]
			}
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{op("id", ids, adapter.In)}, Select: sel})
			h.Equal(len(result), len(expected))
			matches := false
			for _, r := range expected {
				if ID(r) == ID(result[0]) && r["email"] == result[0]["email"] {
					matches = true
				}
			}
			onlySelected := true
			for k, v := range result[0] {
				if !Contains(sel, k) && v != nil {
					onlySelected = false
				}
			}
			h.True(matches && onlySelected, "result[0] should only contain the selected fields of an inserted user: %s", Format(result[0]))
		}},
		{Name: "findMany - should select fields with one-to-many join", Fn: func(h *H) {
			user := createUser(h)
			session := createWithUser(h, "session", user["id"])
			results := h.FindMany(adapter.FindManyInput{Model: "user", Where: Where("id", user["id"]),
				Select: []string{"email", "name"}, Join: joinAll("session")})
			h.True(len(results) > 0, "result defined")
			result := results[0]
			h.Equal(result["email"], user["email"])
			h.Equal(result["name"], user["name"])
			sessions := h.Array(result["session"])
			h.Len(sessions, 1)
			h.Equal(sessions[0], session)
		}},
		{Name: "findMany - should select fields with one-to-one join", Fn: func(h *H) {
			h.ModifyOptions(oneToOneIDRef(""), true)
			user := createUser(h)
			oneToOne := createOneToOne(h, user["id"])
			results := h.FindMany(adapter.FindManyInput{Model: "user", Where: Where("id", user["id"]),
				Select: []string{"email", "name"}, Join: joinAll("oneToOneTable")})
			h.True(len(results) > 0, "result defined")
			result := results[0]
			h.Equal(result["email"], user["email"])
			h.Equal(result["name"], user["name"])
			h.True(result["oneToOneTable"] != nil, "oneToOneTable defined")
			h.Equal(h.Object(result["oneToOneTable"]), oneToOne)
		}},
		{Name: "findMany - should select fields with multiple joins", Fn: func(h *H) {
			user := createUser(h)
			session := createWithUser(h, "session", user["id"])
			account := createWithUser(h, "account", user["id"])
			results := h.FindMany(adapter.FindManyInput{Model: "user", Where: Where("id", user["id"]),
				Select: []string{"email", "name"}, Join: joinAll("session", "account")})
			h.True(len(results) > 0, "result defined")
			result := results[0]
			h.Equal(result["email"], user["email"])
			h.Equal(result["name"], user["name"])
			sessions := h.Array(result["session"])
			h.Len(sessions, 1)
			h.Equal(sessions[0], session)
			accounts := h.Array(result["account"])
			h.Len(accounts, 1)
			h.Equal(accounts[0], account)
		}},
		{Name: "findMany - should find many with join and offset", Fn: func(h *H) {
			for i := 0; i < 5; i++ {
				user := createUser(h, R{"name": "user-" + pad2(i)})
				for range 2 {
					createWithUser(h, "session", user["id"])
				}
			}
			result := h.FindMany(adapter.FindManyInput{Model: "user", Join: joinAll("session"), Offset: 2})
			h.Equal(len(result), 3)
		}},
		{Name: "findMany - should find many with join and sortBy", Fn: func(h *H) {
			n := -1
			h.ModifyOptions(numericField(func() any { n++; return n }), true)
			for range 5 {
				user := createUser(h)
				for range 2 {
					createWithUser(h, "session", user["id"])
				}
			}
			result := h.FindMany(adapter.FindManyInput{Model: "user", Join: joinAll("session"),
				SortBy: &adapter.SortBy{Field: "numericField", Direction: "desc"}})
			h.True(len(result) > 0, "results")
			h.True(Num(result[0], "numericField") > Num(result[len(result)-1], "numericField"),
				"first numericField should be greater than the last: %v vs %v", result[0]["numericField"], result[len(result)-1]["numericField"])
			for _, user := range result {
				h.True(len(h.Array(user["session"])) > 0, "user should have sessions")
			}
		}},
		{Name: "findMany - should find many with join and where clause", Fn: func(h *H) {
			for i := 0; i < 5; i++ {
				name := "other-user-" + strconv.Itoa(i)
				if i < 2 {
					name = "target-user-" + strconv.Itoa(i)
				}
				user := createUser(h, R{"name": name})
				for range 2 {
					createWithUser(h, "session", user["id"])
				}
			}
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{op("name", "target-user", adapter.StartsWith)}, Join: joinAll("session")})
			h.Len(result, 2)
			for _, user := range result {
				h.True(strings.HasPrefix(Str(user, "name"), "target-user"), "name prefix")
				h.Len(h.Array(user["session"]), 2)
			}
		}},
		{Name: "findMany - should find many with join, where, limit, and offset", Fn: func(h *H) {
			for i := 0; i < 10; i++ {
				user := createUser(h, R{"name": "target-" + pad2(i)})
				for range 2 {
					createWithUser(h, "session", user["id"])
				}
			}
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{op("name", "target", adapter.StartsWith)},
				Join: joinAll("session"), Limit: 3, Offset: 2})
			h.Len(result, 3)
			for _, user := range result {
				h.Len(h.Array(user["session"]), 2)
			}
		}},
		{Name: "findMany - should find many with one-to-one join", Fn: func(h *H) {
			h.ModifyOptions(oneToOneIDRef(""), true)
			users := Firsts(h.InsertRandomN("user", 3))
			for _, user := range users {
				createOneToOne(h, user["id"])
			}
			result := h.FindMany(adapter.FindManyInput{Model: "user", Join: joinAll("oneToOneTable")})
			withJoin := filterRecords(result, func(r R) bool { return r["oneToOneTable"] != nil && h.Object(r["oneToOneTable"]) != nil })
			h.Len(withJoin, 3)
			for _, user := range withJoin {
				o := h.Object(user["oneToOneTable"])
				h.Equal(o["oneToOne"], user["id"])
			}
		}},
		{Name: "findMany - should find many with both one-to-one and one-to-many joins", Fn: func(h *H) {
			h.ModifyOptions(oneToOneIDRef(""), true)
			users := Firsts(h.InsertRandomN("user", 2))
			for _, user := range users {
				createOneToOne(h, user["id"])
				for range 2 {
					createWithUser(h, "session", user["id"])
				}
			}
			result := h.FindMany(adapter.FindManyInput{Model: "user", Join: joinAll("oneToOneTable", "session")})
			withBoth := filterRecords(result, func(r R) bool {
				return h.Object(r["oneToOneTable"]) != nil && len(h.Array(r["session"])) > 0
			})
			h.True(len(withBoth) >= 2, "at least 2 users with both joins, got %d", len(withBoth))
			for _, user := range withBoth {
				h.True(h.Object(user["oneToOneTable"]) != nil, "oneToOneTable defined")
				h.True(len(h.Array(user["session"])) > 0, "sessions")
			}
		}},
		{Name: "findMany - should return an empty array when no models are found", Fn: func(h *H) {
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: Where("id", notFoundID(h))})
			h.Equal(result, []adapter.Record{})
		}},
		{Name: "findMany - should return empty array when base records don't exist with joins", Fn: func(h *H) {
			h.ModifyOptions(oneToOneIDRef(""), true)
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: Where("id", notFoundID(h)),
				Join: joinAll("session", "account", "oneToOneTable")})
			h.Equal(result, []adapter.Record{})
		}},
		{Name: "findMany - should find many models with starts_with operator", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 3))
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{op("name", "user", adapter.StartsWith)}})
			h.Equal(h.SortModels(result), h.SortModels(users))
		}},
		{Name: "findMany - starts_with should not interpret regex patterns", Fn: func(h *H) {
			literal := createUser(h, R{"name": ".*danger"})
			h.InsertRandomN("user", 3)
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{op("name", ".*", adapter.StartsWith)}})
			h.Equal(len(result), 1)
			h.Equal(ID(result[0]), ID(literal))
			h.True(strings.HasPrefix(Str(result[0], "name"), ".*"), "name prefix")
		}},
		{Name: "findMany - ends_with should not interpret regex patterns", Fn: func(h *H) {
			literal := createUser(h, R{"name": "danger.*"})
			h.InsertRandomN("user", 3)
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{op("name", ".*", adapter.EndsWith)}})
			h.Equal(len(result), 1)
			h.Equal(ID(result[0]), ID(literal))
			h.True(strings.HasSuffix(Str(result[0], "name"), ".*"), "name suffix")
		}},
		{Name: "findMany - contains should not interpret regex patterns", Fn: func(h *H) {
			literal := createUser(h, R{"name": "prefix-.*-suffix"})
			h.InsertRandomN("user", 3)
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{op("name", ".*", adapter.Contains)}})
			h.Equal(len(result), 1)
			h.Equal(ID(result[0]), ID(literal))
			h.True(strings.Contains(Str(result[0], "name"), ".*"), "name contains")
		}},
		{Name: "findMany - should find many models with ends_with operator", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 3))
			for _, user := range users {
				res := h.Update("user", Where("id", user["id"]), R{"name": strings.ToLower(Str(user, "name"))})
				if res == nil {
					h.Fatal("No result")
				}
				user["name"] = res["name"]
				user["updatedAt"] = res["updatedAt"]
			}
			name0 := Str(users[0], "name")
			endsWith := name0[len(name0)-1:]
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{op("name", endsWith, adapter.EndsWith)}})
			expected := h.SortModels(filterRecords(users, func(u R) bool { return strings.HasSuffix(Str(u, "name"), endsWith) }))
			if len(result) != len(expected) {
				h.Logf("Result length: %d\n%s\nExpected result length: %d - key: %q\n%s", len(result), Format(h.SortModels(result)), len(expected), endsWith, Format(expected))
			}
			h.Equal(h.SortModels(result), expected)
		}},
		{Name: "findMany - should find many models with contains operator", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 3))
			h.True(strings.Contains(Str(users[0], "email"), "@email.com"), "email contains @email.com")
			// all emails contains `@email.com` from `insertRandom`
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{op("email", "mail", adapter.Contains)}})
			h.Equal(h.SortModels(result), h.SortModels(users))
		}},
		{Name: "findMany - should handle multiple where conditions with different operators", Fn: func(h *H) {
			// upstream spreads the un-awaited generate("user") promise, so only name and
			// email are passed
			for _, data := range []R{
				{"name": "john doe", "email": "john@example.com"},
				{"name": "jane smith", "email": "jane@gmail.com"},
			} {
				h.Create(adapter.CreateInput{Model: "user", Data: data, ForceAllowID: true})
			}
			and := func(field string, value any, o adapter.Operator) W {
				return W{Field: field, Value: value, Operator: o, Connector: adapter.And}
			}
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{
				and("email", "john@example.com", adapter.Eq), and("name", "john", adapter.Contains)}})
			h.Equal(len(result), 1)
			h.Equal(result[0]["email"], "john@example.com")
			h.Equal(result[0]["name"], "john doe")
			result2 := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{
				and("email", "gmail", adapter.Contains), and("name", "jane", adapter.Contains)}})
			h.Equal(len(result2), 1)
			h.Equal(result2[0]["email"], "jane@gmail.com")
			h.Equal(result2[0]["name"], "jane smith")
			result3 := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{
				and("email", "john", adapter.StartsWith), and("name", "john", adapter.Contains)}})
			h.Equal(len(result3), 1)
			h.Equal(result3[0]["email"], "john@example.com")
			h.Equal(result3[0]["name"], "john doe")
		}},
		{Name: "findMany - should find many models with contains operator (using symbol)", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 3))
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{op("email", "@", adapter.Contains)}})
			h.Equal(h.SortModels(result), h.SortModels(users))
		}},
		{Name: "findMany - should find many models with eq operator", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 3))
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{op("email", users[0]["email"], adapter.Eq)}})
			h.Equal(h.SortModels(result), h.SortModels([]adapter.Record{users[0]}))
		}},
		{Name: "findMany - should find many models with ne operator", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 3))
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{op("email", users[0]["email"], adapter.Ne)}})
			h.Equal(h.SortModels(result), h.SortModels(append([]adapter.Record(nil), users[1:]...)))
		}},
		{Name: "findMany - should find many models with gt operator", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 3))
			sort.SliceStable(users, func(i, j int) bool { return Time(users[i], "createdAt").Before(Time(users[j], "createdAt")) })
			oldestUser := users[0]
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{op("createdAt", oldestUser["createdAt"], adapter.Gt)}})
			expected := h.SortModels(filterRecords(users, func(u R) bool { return Time(u, "createdAt").After(Time(oldestUser, "createdAt")) }))
			h.True(len(result) != 0, "result should not be empty")
			h.Equal(h.SortModels(result), expected)
		}},
		{Name: "findMany - should find many models with gte operator", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 3))
			sort.SliceStable(users, func(i, j int) bool { return Time(users[i], "createdAt").After(Time(users[j], "createdAt")) })
			oldestUser := users[0]
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{op("createdAt", oldestUser["createdAt"], adapter.Gte)}})
			expected := filterRecords(users, func(u R) bool { return !Time(u, "createdAt").Before(Time(oldestUser, "createdAt")) })
			h.True(len(result) != 0, "result should not be empty")
			h.Equal(h.SortModels(result), h.SortModels(expected))
		}},
		{Name: "findMany - should find many models with lte operator", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 3))
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{op("createdAt", users[0]["createdAt"], adapter.Lte)}})
			expected := filterRecords(users, func(u R) bool { return !Time(u, "createdAt").After(Time(users[0], "createdAt")) })
			h.Equal(h.SortModels(result), h.SortModels(expected))
		}},
		{Name: "findMany - should find many models with lt operator", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 3))
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{op("createdAt", users[0]["createdAt"], adapter.Lt)}})
			expected := filterRecords(users, func(u R) bool { return Time(u, "createdAt").Before(Time(users[0], "createdAt")) })
			h.Equal(h.SortModels(result), h.SortModels(expected))
		}},
		{Name: "findMany - should find many models with in operator", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 3))
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{op("id", []any{users[0]["id"], users[1]["id"]}, adapter.In)}})
			expected := filterRecords(users, func(u R) bool { return ID(u) == ID(users[0]) || ID(u) == ID(users[1]) })
			h.Equal(h.SortModels(result), h.SortModels(expected))
		}},
		{Name: "findMany - should find many models with not_in operator", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 3))
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{op("id", []any{users[0]["id"], users[1]["id"]}, adapter.NotIn)}})
			h.Equal(h.SortModels(result), []adapter.Record{users[2]})
		}},
		{Name: "findMany - should find many models with sortBy", Fn: func(h *H) {
			n := -1
			h.ModifyOptions(numericField(func() any { v := n; n++; return v }), true)
			users := Firsts(h.InsertRandomN("user", 5))
			result := h.FindMany(adapter.FindManyInput{Model: "user", SortBy: &adapter.SortBy{Field: "numericField", Direction: "asc"}})
			var expected, got []float64
			for _, u := range users {
				expected = append(expected, Num(u, "numericField"))
			}
			sort.Float64s(expected)
			for _, r := range result {
				got = append(got, Num(r, "numericField"))
			}
			if !DeepEqual(got, expected) {
				h.Logf("result: %v\nexpected result: %v", IDs(result), expected)
			}
			h.Equal(got, expected)
			if idMode(h.Options()) == adapter.IDSerial {
				_, err := strconv.ParseFloat(ID(users[0]), 64)
				h.True(err == nil, "Number(users[0].id) should not be NaN")
			}
		}},
		{Name: "findMany - should find many models with limit", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 3))
			result := h.FindMany(adapter.FindManyInput{Model: "user", Limit: 2})
			h.Equal(len(result), 2)
			// upstream: expect(users.find((x) => x.id === result[0]!.id)).not.toBeNull()
			_ = findByID(users, ID(result[0]))
		}},
		{Name: "findMany - should find many models with offset", Fn: func(h *H) {
			count := 10
			h.InsertRandomN("user", count)
			result := h.FindMany(adapter.FindManyInput{Model: "user", Offset: 2})
			h.Equal(len(result), count-2)
		}},
		{Name: "findMany - should find many models with limit and offset", Fn: func(h *H) {
			h.InsertRandomN("user", 5)
			result := h.FindMany(adapter.FindManyInput{Model: "user", Limit: 2, Offset: 2})
			h.Equal(len(result), 2)
			for _, user := range result {
				for _, k := range []string{"id", "name", "email"} {
					_, ok := user[k]
					h.True(ok, "user should have property %s", k)
				}
			}
		}},
		{Name: "findMany - should find many models with sortBy and offset", Fn: func(h *H) {
			n := -1
			h.ModifyOptions(numericField(func() any { v := n; n++; return v }), true)
			users := Firsts(h.InsertRandomN("user", 5))
			result := h.FindMany(adapter.FindManyInput{Model: "user", SortBy: &adapter.SortBy{Field: "numericField", Direction: "asc"}, Offset: 2})
			h.Len(result, 3)
			h.Equal(result, sliceRecords(sortByNumeric(users), 2, len(users)))
		}},
		{Name: "findMany - should find many models with sortBy and limit", Fn: func(h *H) {
			n := -1
			h.ModifyOptions(numericField(func() any { v := n; n++; return v }), true)
			users := Firsts(h.InsertRandomN("user", 5))
			result := h.FindMany(adapter.FindManyInput{Model: "user", SortBy: &adapter.SortBy{Field: "numericField", Direction: "asc"}, Limit: 2})
			h.Equal(result, sliceRecords(sortByNumeric(users), 0, 2))
		}},
		{Name: "findMany - should find many models with sortBy and limit and offset", Fn: func(h *H) {
			n := -1
			h.ModifyOptions(numericField(func() any { v := n; n++; return v }), true)
			users := Firsts(h.InsertRandomN("user", 5))
			result := h.FindMany(adapter.FindManyInput{Model: "user", SortBy: &adapter.SortBy{Field: "numericField", Direction: "asc"}, Limit: 2, Offset: 2})
			h.Equal(len(result), 2)
			h.Equal(result, sliceRecords(sortByNumeric(users), 2, 4))
		}},
		{Name: "findMany - should find many models with sortBy and limit and offset and where", Fn: func(h *H) {
			n := -1
			h.ModifyOptions(numericField(func() any { v := n; n++; return v }), true)
			users := Firsts(h.InsertRandomN("user", 10))
			for i, user := range users {
				if i < 5 {
					continue
				}
				result := h.Update("user", Where("id", user["id"]), R{"name": Str(user, "name") + "-last"})
				if result == nil {
					h.Fatal("No result")
				}
				users[i]["name"] = result["name"]
				users[i]["updatedAt"] = result["updatedAt"]
			}
			result := h.FindMany(adapter.FindManyInput{Model: "user", SortBy: &adapter.SortBy{Field: "numericField", Direction: "asc"},
				Limit: 2, Offset: 2, Where: []W{op("name", "last", adapter.EndsWith)}})
			expected := sliceRecords(sortByNumeric(filterRecords(users, func(u R) bool { return strings.HasSuffix(Str(u, "name"), "last") })), 2, 4)
			if len(result) != 2 || !DeepEqual(result, expected) {
				h.Logf("results: %v\nexpected results: %v", IDs(result), IDs(expected))
			}
			h.Equal(len(result), 2)
			h.Equal(result, expected)
		}},
		{Name: "update - should update a model", Fn: func(h *H) {
			user := h.InsertRandom("user")[0]
			result := h.Update("user", Where("id", user["id"]), R{"name": "test-name"})
			expected := Merge(user, R{"name": "test-name"})
			h.NotNull(result)
			result["updatedAt"] = user["updatedAt"]
			h.Equal(result, expected)
			findResult := findUser(h, user["id"])
			h.NotNull(findResult)
			findResult["updatedAt"] = user["updatedAt"]
			h.Equal(findResult, expected)
		}},
		{Name: "update - should return null when where is empty", Fn: func(h *H) {
			result := h.Update("user", []W{}, R{"name": "test-name"})
			h.Null(result)
		}},
		{Name: "updateMany - should update all models when where is empty", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 3))
			h.UpdateMany("user", []W{}, R{"name": "test-name"})
			result := h.SortModels(h.FindMany(adapter.FindManyInput{Model: "user"}))
			sortedUsers := h.SortModels(users)
			expected := make([]adapter.Record, len(sortedUsers))
			for i, u := range sortedUsers {
				var updatedAt any
				if i < len(result) {
					updatedAt = result[i]["updatedAt"]
				}
				expected[i] = Merge(u, R{"name": "test-name", "updatedAt": updatedAt})
			}
			h.Equal(result, expected)
		}},
		{Name: "updateMany - should update many models with a specific where", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 3))
			h.UpdateMany("user", Where("id", users[0]["id"]), R{"name": "test-name"})
			result := findUser(h, users[0]["id"])
			h.NotNull(result)
			h.Equal(result, Merge(users[0], R{"name": "test-name", "updatedAt": result["updatedAt"]}))
		}},
		{Name: "updateMany - should update many models with a multiple where", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 3))
			h.UpdateMany("user", []W{or("id", users[0]["id"]), or("id", users[1]["id"])}, R{"name": "test-name"})
			result := findUser(h, users[0]["id"])
			h.NotNull(result)
			h.Equal(result, Merge(users[0], R{"name": "test-name", "updatedAt": result["updatedAt"]}))
		}},
		{Name: "incrementOne - guarded set transition returns the row on a matching guard and null on a guard miss", Fn: func(h *H) {
			transitionUser := h.InsertRandom("user")[0]
			image := "https://example.com/avatar.png"
			won := h.IncrementOne(adapter.IncrementInput{Model: "user",
				Where:     Where("id", transitionUser["id"], "name", transitionUser["name"]),
				Increment: map[string]float64{}, Set: R{"image": image}})
			h.NotNull(won)
			h.Equal(won["image"], image)
			lost := h.IncrementOne(adapter.IncrementInput{Model: "user",
				Where:     Where("id", transitionUser["id"], "name", "name-that-does-not-match"),
				Increment: map[string]float64{}, Set: R{"image": "https://example.com/should-not-apply.png"}})
			h.Null(lost)
			after := findUser(h, transitionUser["id"])
			h.NotNull(after)
			h.Equal(after["image"], image)
		}},
		{Name: "delete - should delete a model", Fn: func(h *H) {
			user := h.InsertRandom("user")[0]
			h.Delete("user", Where("id", user["id"])...)
			h.Null(findUser(h, user["id"]))
		}},
		{Name: "delete - should not throw on record not found", Fn: func(h *H) {
			err := h.Adapter.Delete(h.Ctx, "user", Where("id", notFoundID(h)))
			h.True(err == nil, "delete should not fail: %v", err)
		}},
		{Name: "delete - should delete by non-unique field", Fn: func(h *H) {
			verification := h.InsertRandom("verification")[0]
			h.Delete("verification", Where("identifier", verification["identifier"])...)
			result := h.FindOne(adapter.FindOneInput{Model: "verification", Where: Where("identifier", verification["identifier"])})
			h.Null(result)
		}},
		{Name: "deleteMany - should delete many models", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 3))
			h.DeleteMany("user", or("id", users[0]["id"]), or("id", users[1]["id"]))
			result := h.FindMany(adapter.FindManyInput{Model: "user"})
			h.Equal(h.SortModels(result), h.SortModels(append([]adapter.Record(nil), users[2:]...)))
		}},
		{Name: "deleteMany - starts_with should not interpret regex patterns", Fn: func(h *H) {
			literal := createUser(h, R{"name": ".*danger"})
			normalUsers := Firsts(h.InsertRandomN("user", 3))
			h.DeleteMany("user", op("name", ".*", adapter.StartsWith))
			h.Null(findUser(h, literal["id"]))
			for _, user := range normalUsers {
				h.NotNull(findUser(h, user["id"]))
			}
		}},
		{Name: "deleteMany - ends_with should not interpret regex patterns", Fn: func(h *H) {
			literal := createUser(h, R{"name": "danger.*"})
			normalUsers := Firsts(h.InsertRandomN("user", 3))
			h.DeleteMany("user", op("name", ".*", adapter.EndsWith))
			h.Null(findUser(h, literal["id"]))
			for _, user := range normalUsers {
				h.NotNull(findUser(h, user["id"]))
			}
		}},
		{Name: "deleteMany - contains should not interpret regex patterns", Fn: func(h *H) {
			literal := createUser(h, R{"name": "prefix-.*-suffix"})
			normalUsers := Firsts(h.InsertRandomN("user", 3))
			h.DeleteMany("user", op("name", ".*", adapter.Contains))
			h.Null(findUser(h, literal["id"]))
			for _, user := range normalUsers {
				h.NotNull(findUser(h, user["id"]))
			}
		}},
		{Name: "deleteMany - should delete many models with numeric values", Fn: func(h *H) {
			i := 0
			h.ModifyOptions(numericField(func() any { v := i; i++; return v }), true)
			users := Firsts(h.InsertRandomN("user", 3))
			h.Equal(users[0]["numericField"], 0)
			h.Equal(users[1]["numericField"], 1)
			h.Equal(users[2]["numericField"], 2)
			h.DeleteMany("user", op("numericField", users[0]["numericField"], adapter.Gt))
			result := h.FindMany(adapter.FindManyInput{Model: "user"})
			h.Equal(result, []adapter.Record{users[0]})
		}},
		{Name: "deleteMany - should delete many models with boolean values", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 3))
			h.UpdateMany("user", []W{}, R{"emailVerified": true})
			h.Update("user", Where("id", users[1]["id"]), R{"emailVerified": false})
			h.DeleteMany("user", Where("emailVerified", true)...)
			result := h.FindMany(adapter.FindManyInput{Model: "user"})
			h.Len(result, 1)
			h.True(findByID(result, ID(users[0])) == nil, "users[0] should be deleted")
			h.True(findByID(result, ID(users[1])) != nil, "users[1] should remain")
			h.True(findByID(result, ID(users[2])) == nil, "users[2] should be deleted")
		}},
		{Name: "count - should count many models", Fn: func(h *H) {
			users := h.InsertRandomN("user", 15)
			result := h.Count("user")
			h.Equal(result, len(users))
		}},
		{Name: "count - should return 0 with no rows to count", Fn: func(h *H) {
			h.Equal(h.Count("user"), 0)
		}},
		{Name: "count - should count with where clause", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 15))
			result := h.Count("user", or("id", users[2]["id"]), or("id", users[3]["id"]))
			h.Equal(result, 2)
		}},
		{Name: "update - should correctly return record when updating a field used in where clause", Fn: func(h *H) {
			user := h.InsertRandom("user")[0]
			originalEmail := user["email"]
			result := h.Update("user", Where("email", originalEmail), R{"email": "newemail@example.com"})
			h.NotNull(result)
			h.Equal(result["email"], "newemail@example.com")
			h.Equal(ID(result), ID(user))
			foundUser := h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("email", "newemail@example.com")})
			h.NotNull(foundUser)
			h.Equal(ID(foundUser), ID(user))
			oldUser := h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("email", originalEmail)})
			h.Null(oldUser)
		}},
		{Name: "update - should handle updating multiple fields including where clause field", Fn: func(h *H) {
			user := h.InsertRandom("user")[0]
			result := h.Update("user", Where("email", user["email"]), R{
				"email": "updated@example.com", "name": "Updated Name", "emailVerified": true})
			h.NotNull(result)
			h.Equal(result["email"], "updated@example.com")
			h.Equal(result["name"], "Updated Name")
			h.Equal(result["emailVerified"], true)
			h.Equal(ID(result), ID(user))
		}},
		{Name: "update - should work when updated field is not in where clause", Fn: func(h *H) {
			user := h.InsertRandom("user")[0]
			result := h.Update("user", Where("email", user["email"]), R{"name": "Updated Name Only"})
			h.NotNull(result)
			h.Equal(result["name"], "Updated Name Only")
			h.Equal(result["email"], user["email"]) // Should remain unchanged
			h.Equal(ID(result), ID(user))
		}},
		{Name: "findOne - backwards join should only return single record not array", Fn: func(h *H) {
			user := createUser(h)
			session := createWithUser(h, "session", user["id"])
			result := h.FindOne(adapter.FindOneInput{Model: "session", Where: Where("id", session["id"]), Join: joinAll("user")})
			h.NotNull(result)
			joined := h.Object(result["user"], "result.user should not be an array")
			h.NotNull(joined)
			h.Equal(ID(joined), ID(user))
		}},
		{Name: "findMany - backwards join should only return single record not array", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 2))
			for _, user := range users {
				createWithUser(h, "session", user["id"])
			}
			result := h.FindMany(adapter.FindManyInput{Model: "session", Join: joinAll("user")})
			for _, session := range result {
				joined := h.Object(session["user"], "session.user should not be an array")
				h.NotNull(joined)
				h.True(joined["id"] != nil, "session.user.id defined")
			}
		}},
		{Name: "findOne - backwards join with modified field name (session base, users-table join)", Fn: func(h *H) {
			h.ModifyOptions(func(c *betterauth.Config) { ensureUser(c).ModelName = "user_table" }, true)
			user := createUser(h)
			session := createWithUser(h, "session", user["id"])
			result := h.FindOne(adapter.FindOneInput{Model: "session", Where: Where("id", session["id"]), Join: joinAll("user")})
			h.Equal(result, Merge(session, R{"user": user}))
			joined := h.Object(result["user"], "result.user should not be an array")
			h.NotNull(joined)
			h.Equal(ID(joined), ID(user))
		}},
		{Name: "findOne - multiple joins should return result even when some joined tables have no matching rows", Fn: func(h *H) {
			h.ModifyOptions(func(c *betterauth.Config) {
				c.Plugins = append(c.Plugins, schemaPlugin("organization", organizationSchema()...))
			}, true)
			user := createUser(h)
			org := h.Create(adapter.CreateInput{Model: "organization", Data: R{
				"name": "Test Organization", "slug": "test-org-" + strconv.FormatFloat(rand.Float64(), 'f', -1, 64), "createdAt": jsNow(),
			}, ForceAllowID: true})
			h.Create(adapter.CreateInput{Model: "member", Data: R{
				"organizationId": org["id"], "userId": user["id"], "role": "owner", "createdAt": jsNow(),
			}, ForceAllowID: true})
			h.Create(adapter.CreateInput{Model: "team", Data: R{
				"name": "Test Team", "organizationId": org["id"], "createdAt": jsNow(),
			}, ForceAllowID: true})
			result := h.FindOne(adapter.FindOneInput{Model: "organization", Where: Where("id", org["id"]),
				Join: joinAll("member", "team", "invitation")})
			h.NotNull(result)
			h.Equal(ID(result), ID(org))
			h.Equal(result["name"], "Test Organization")
			members := h.Array(result["member"])
			h.Len(members, 1)
			h.Equal(members[0]["userId"], user["id"])
			h.Equal(members[0]["role"], "owner")
			teams := h.Array(result["team"])
			h.Len(teams, 1)
			h.Equal(teams[0]["name"], "Test Team")
			h.Len(h.Array(result["invitation"]), 0)
		}},
		{Name: "findOne - should be able to perform a limited join", Fn: func(h *H) {
			user := createUser(h)
			for range 5 {
				createWithUser(h, "session", user["id"])
			}
			result := h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("id", user["id"]),
				Join: map[string]adapter.Join{"session": {Limit: 2}}})
			h.NotNull(result)
			sessions := h.Array(result["session"])
			h.Len(sessions, 2)
			h.Equal(sessions[0]["userId"], user["id"])
		}},
		{Name: "findOne - should be able to perform a complex limited join", Fn: func(h *H) {
			user := createUser(h)
			for range 5 {
				createWithUser(h, "session", user["id"])
				createWithUser(h, "account", user["id"])
			}
			result := h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("id", user["id"]),
				Join: map[string]adapter.Join{"session": {Limit: 2}, "account": {Limit: 3}}})
			h.NotNull(result)
			h.Len(h.Array(result["session"]), 2)
			h.Len(h.Array(result["account"]), 3)
		}},
		{Name: "findMany - should be able to perform a limited join", Fn: func(h *H) {
			var users []adapter.Record
			for range 5 {
				users = append(users, createUser(h))
			}
			for _, user := range users {
				for range 5 {
					createWithUser(h, "session", user["id"])
				}
			}
			result := h.FindMany(adapter.FindManyInput{Model: "user", Join: map[string]adapter.Join{"session": {Limit: 2}}})
			h.Len(result, 5)
			for _, user := range result {
				sessions := h.Array(user["session"])
				h.Len(sessions, 2)
				h.Equal(sessions[0]["userId"], user["id"])
			}
		}},
		{Name: "findMany - should be able to perform a complex limited join", Fn: func(h *H) {
			for range 5 {
				user := createUser(h)
				for range 5 {
					createWithUser(h, "session", user["id"])
					createWithUser(h, "account", user["id"])
				}
			}
			result := h.FindMany(adapter.FindManyInput{Model: "user",
				Join:  map[string]adapter.Join{"session": {Limit: 2}, "account": {Limit: 3}},
				Limit: 2, Offset: 2})
			h.Len(result, 2)
			for _, user := range result {
				sessions := h.Array(user["session"])
				h.Len(sessions, 2)
				h.Equal(sessions[0]["userId"], user["id"])
				accounts := h.Array(user["account"])
				h.Len(accounts, 3)
				h.Equal(accounts[0]["userId"], user["id"])
			}
		}},
		{Name: "findOne - should return null for one-to-one join when joined record doesn't exist", Fn: func(h *H) {
			h.ModifyOptions(oneToOneIDRef(""), true)
			user := createUser(h)
			result := h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("id", user["id"]), Join: joinAll("oneToOneTable")})
			h.NotNull(result)
			h.Equal(ID(result), ID(user))
			h.FieldNull(result, "oneToOneTable")
		}},
		{Name: "findMany - should return null for one-to-one join when joined records don't exist", Fn: func(h *H) {
			h.ModifyOptions(oneToOneIDRef(""), true)
			userWithJoin := createUser(h)
			oneToOne := createOneToOne(h, userWithJoin["id"])
			userWithoutJoin := createUser(h)
			result := h.FindMany(adapter.FindManyInput{Model: "user",
				Where: []W{or("id", userWithJoin["id"]), or("id", userWithoutJoin["id"])}, Join: joinAll("oneToOneTable")})
			h.Equal(len(result), 2)
			withJoin := findByID(result, ID(userWithJoin))
			withoutJoin := findByID(result, ID(userWithoutJoin))
			h.NotNull(withJoin)
			joined := h.Object(withJoin["oneToOneTable"])
			h.NotNull(joined)
			h.Equal(ID(joined), ID(oneToOne))
			h.NotNull(withoutJoin)
			h.FieldNull(withoutJoin, "oneToOneTable")
		}},
		{Name: "findMany - should return empty array for one-to-many join when joined records don't exist", Fn: func(h *H) {
			userWithSessions := createUser(h)
			session1 := createWithUser(h, "session", userWithSessions["id"])
			session2 := createWithUser(h, "session", userWithSessions["id"])
			userWithoutSessions := createUser(h)
			result := h.FindMany(adapter.FindManyInput{Model: "user",
				Where: []W{or("id", userWithSessions["id"]), or("id", userWithoutSessions["id"])}, Join: joinAll("session")})
			h.Equal(len(result), 2)
			withSessions := findByID(result, ID(userWithSessions))
			withoutSessions := findByID(result, ID(userWithoutSessions))
			h.NotNull(withSessions)
			sessions := h.Array(withSessions["session"])
			h.Len(sessions, 2)
			h.True(findByID(sessions, ID(session1)) != nil, "session1 joined")
			h.True(findByID(sessions, ID(session2)) != nil, "session2 joined")
			h.NotNull(withoutSessions)
			h.Len(h.Array(withoutSessions["session"]), 0)
		}},
		{Name: "findMany - should handle mixed joins correctly when some are missing", Fn: func(h *H) {
			h.ModifyOptions(oneToOneIDRef(""), true)
			user1 := createUser(h)
			oneToOne1 := createOneToOne(h, user1["id"])
			session1 := createWithUser(h, "session", user1["id"])
			user2 := createUser(h)
			oneToOne2 := createOneToOne(h, user2["id"])
			user3 := createUser(h)
			session3 := createWithUser(h, "session", user3["id"])
			user4 := createUser(h)
			result := h.FindMany(adapter.FindManyInput{Model: "user",
				Where: []W{or("id", user1["id"]), or("id", user2["id"]), or("id", user3["id"]), or("id", user4["id"])},
				Join:  joinAll("oneToOneTable", "session")})
			h.Equal(len(result), 4)

			result1 := findByID(result, ID(user1))
			h.NotNull(result1)
			h.Equal(ID(h.Object(result1["oneToOneTable"])), ID(oneToOne1))
			s1 := h.Array(result1["session"])
			h.Len(s1, 1)
			h.Equal(ID(s1[0]), ID(session1))

			result2 := findByID(result, ID(user2))
			h.NotNull(result2)
			h.Equal(ID(h.Object(result2["oneToOneTable"])), ID(oneToOne2))
			h.Len(h.Array(result2["session"]), 0)

			result3 := findByID(result, ID(user3))
			h.NotNull(result3)
			h.FieldNull(result3, "oneToOneTable")
			s3 := h.Array(result3["session"])
			h.Len(s3, 1)
			h.Equal(ID(s3[0]), ID(session3))

			result4 := findByID(result, ID(user4))
			h.NotNull(result4)
			h.FieldNull(result4, "oneToOneTable")
			h.Len(h.Array(result4["session"]), 0)
		}},
		{
			Name: "create - should support arrays",
			MigrateBetterAuth: func(c *betterauth.Config) {
				c.Plugins = append(c.Plugins, schemaPlugin("string-arrays-test", db.PluginTable{Key: "testModel", Fields: []db.Field{
					{Name: "stringArray", Type: db.TypeStringArray, Required: db.True},
					{Name: "numberArray", Type: db.TypeNumberArray, Required: db.True},
				}}))
			},
			Fn: func(h *H) {
				result := h.Create(adapter.CreateInput{Model: "testModel", Data: R{
					"stringArray": []any{"1", "2", "3"}, "numberArray": []any{1, 2, 3}}})
				h.Equal(result["stringArray"], []any{"1", "2", "3"})
				h.Equal(result["numberArray"], []any{1, 2, 3})
				findResult := h.FindOne(adapter.FindOneInput{Model: "testModel", Where: Where("id", result["id"])})
				h.Equal(findResult, result)
				h.Equal(findResult["stringArray"], []any{"1", "2", "3"})
				h.Equal(findResult["numberArray"], []any{1, 2, 3})
			},
		},
		{
			Name: "create - should support json",
			MigrateBetterAuth: func(c *betterauth.Config) {
				c.Plugins = append(c.Plugins, schemaPlugin("json-test", db.PluginTable{Key: "testModel", Fields: []db.Field{
					{Name: "json", Type: db.TypeJSON, Required: db.True},
				}}))
			},
			Fn: func(h *H) {
				result := h.Create(adapter.CreateInput{Model: "testModel", Data: R{"json": map[string]any{"foo": "bar"}}})
				h.Equal(result["json"], map[string]any{"foo": "bar"})
				findResult := h.FindOne(adapter.FindOneInput{Model: "testModel", Where: Where("id", result["id"])})
				h.Equal(findResult, result)
				h.Equal(findResult["json"], map[string]any{"foo": "bar"})
				h.Log(Format(findResult))
			},
		},
		{Name: "update - should support multiple where conditions under AND connector with unique field", Fn: func(h *H) {
			user := h.InsertRandom("user")[0]
			result := h.Update("user", Where("email", user["email"], "id", user["id"]), R{"name": "Updated Name"})
			h.NotNull(result)
			h.Equal(result["name"], "Updated Name")
			h.Equal(result["email"], user["email"])
			h.Equal(ID(result), ID(user))
		}},
		{Name: "findMany - eq operator with null value (single condition) should use IS NULL", Fn: func(h *H) {
			withNull := createUser(h, R{"image": nil})
			withImage := createUser(h, R{"image": "https://example.com/avatar.png"})
			nullIDs := IDs(h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{op("image", nil, adapter.Eq)}}))
			h.True(Contains(nullIDs, ID(withNull)), "eq null should contain the null user")
			h.True(!Contains(nullIDs, ID(withImage)), "eq null should not contain the user with image")
			notNullIDs := IDs(h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{op("image", nil, adapter.Ne)}}))
			h.True(!Contains(notNullIDs, ID(withNull)), "ne null should not contain the null user")
			h.True(Contains(notNullIDs, ID(withImage)), "ne null should contain the user with image")
		}},
		{Name: "findMany - eq and ne operators with null value in AND group should use IS NULL / IS NOT NULL", Fn: func(h *H) {
			nullVerified := createUser(h, R{"image": nil, "emailVerified": true})
			nullUnverified := createUser(h, R{"image": nil, "emailVerified": false})
			imageVerified := createUser(h, R{"image": "https://example.com/avatar.png", "emailVerified": true})
			and := func(field string, value any, o adapter.Operator) W {
				return W{Field: field, Value: value, Operator: o, Connector: adapter.And}
			}
			eqIDs := IDs(h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{
				and("image", nil, adapter.Eq), and("emailVerified", true, "")}}))
			h.True(Contains(eqIDs, ID(nullVerified)), "eq: nullVerified")
			h.True(!Contains(eqIDs, ID(nullUnverified)), "eq: not nullUnverified")
			h.True(!Contains(eqIDs, ID(imageVerified)), "eq: not imageVerified")
			neIDs := IDs(h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{
				and("image", nil, adapter.Ne), and("emailVerified", true, "")}}))
			h.True(!Contains(neIDs, ID(nullVerified)), "ne: not nullVerified")
			h.True(!Contains(neIDs, ID(nullUnverified)), "ne: not nullUnverified")
			h.True(Contains(neIDs, ID(imageVerified)), "ne: imageVerified")
		}},
		{Name: "findMany - eq and ne operators with null value in OR group should use IS NULL / IS NOT NULL", Fn: func(h *H) {
			withNull := createUser(h, R{"image": nil})
			targetImage := createUser(h, R{"image": "https://example.com/target.png"})
			otherImage := createUser(h, R{"image": "https://example.com/other.png"})
			orOp := func(field string, value any, o adapter.Operator) W {
				return W{Field: field, Value: value, Operator: o, Connector: adapter.Or}
			}
			eqIDs := IDs(h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{
				orOp("image", nil, adapter.Eq), orOp("email", targetImage["email"], "")}}))
			h.True(Contains(eqIDs, ID(withNull)), "eq: withNull")
			h.True(Contains(eqIDs, ID(targetImage)), "eq: targetImage")
			h.True(!Contains(eqIDs, ID(otherImage)), "eq: not otherImage")
			neIDs := IDs(h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{
				orOp("image", nil, adapter.Ne), orOp("email", withNull["email"], "")}}))
			h.True(Contains(neIDs, ID(withNull)), "ne: withNull (matched by email OR clause)")
			h.True(Contains(neIDs, ID(targetImage)), "ne: targetImage")
			h.True(Contains(neIDs, ID(otherImage)), "ne: otherImage")
		}},
		{Name: "update - should return updated record when where condition uses null value", Fn: func(h *H) {
			withNull := createUser(h, R{"image": nil})
			result := h.Update("user", []W{{Field: "id", Value: withNull["id"]}, op("image", nil, adapter.Eq)}, R{"name": "null-where-updated"})
			h.NotNull(result)
			h.Equal(ID(result), ID(withNull))
			h.Equal(result["name"], "null-where-updated")
		}},
		{Name: "update - should return null when a multi-predicate where matches no row", Fn: func(h *H) {
			user := h.InsertRandom("user")[0]
			verified, _ := user["emailVerified"].(bool)
			winner := h.Update("user", Where("id", user["id"], "emailVerified", verified), R{"emailVerified": !verified})
			h.NotNull(winner)
			h.Equal(ID(winner), ID(user))
			h.Equal(winner["emailVerified"], !verified)
			loser := h.Update("user", Where("id", user["id"], "emailVerified", verified), R{"emailVerified": verified})
			h.Null(loser)
			after := findUser(h, user["id"])
			h.NotNull(after)
			h.Equal(after["emailVerified"], !verified)
		}},
	}
}

func pad2(i int) string {
	s := strconv.Itoa(i)
	if len(s) < 2 {
		s = "0" + s
	}
	return s
}
