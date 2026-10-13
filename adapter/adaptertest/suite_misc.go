package adaptertest

import (
	"context"
	"errors"
	"regexp"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/db"
)

// ensureUser returns cfg.User, allocating it when nil.
func ensureUser(c *betterauth.Config) *betterauth.UserConfig {
	if c.User == nil {
		c.User = &betterauth.UserConfig{}
	}
	return c.User
}

// ensureDB returns cfg.Advanced.Database, allocating it when nil.
func ensureDB(c *betterauth.Config) *betterauth.DatabaseAdvancedConfig {
	if c.Advanced == nil {
		c.Advanced = &betterauth.AdvancedConfig{}
	}
	if c.Advanced.Database == nil {
		c.Advanced.Database = &betterauth.DatabaseAdvancedConfig{}
	}
	return c.Advanced.Database
}

func idMode(c *betterauth.Config) adapter.IDMode {
	if c.Advanced == nil || c.Advanced.Database == nil {
		return adapter.IDDefault
	}
	return c.Advanced.Database.GenerateID
}

// schemaPlugin returns a plugin that only contributes schema.
func schemaPlugin(id string, tables ...db.PluginTable) *betterauth.Plugin {
	return &betterauth.Plugin{ID: id, Schema: tables}
}

// ---- transactions.ts ----

// TransactionsSuite is transactionsTestSuite.
var TransactionsSuite = CreateTestSuite("transactions", SuiteConfig{}, func() []Test {
	return []Test{
		{Name: "transaction - should rollback failing transaction", Fn: func(h *H) {
			if !h.sr.r.supportsTransactions() {
				h.Skipf("Skipping test: %s does not support transactions", h.Adapter.ID())
				return
			}
			user1 := h.Generate("user")
			user2 := h.Generate("user")
			simulated := errors.New("Simulated failure")
			err := h.Adapter.Transaction(h.Ctx, func(ctx context.Context, tx adapter.Adapter) error {
				if _, err := tx.Create(ctx, adapter.CreateInput{Model: "user", Data: user1, ForceAllowID: true}); err != nil {
					return err
				}
				users, err := tx.FindMany(ctx, adapter.FindManyInput{Model: "user"})
				if err != nil {
					return err
				}
				h.Len(users, 1)
				return simulated
				// unreachable upstream: tx.create({ model: "user", data: user2 })
			})
			_ = user2
			if !errors.Is(err, simulated) {
				h.Fatalf("expected transaction to reject with %q, got %v", simulated, err)
			}
			result := h.FindMany(adapter.FindManyInput{Model: "user"})
			h.HardCleanup()
			h.Equal(len(result), 0)
		}},
	}
})

// ---- joins.ts / number-id.ts / uuid.ts ----

func normalTestsWithout(name string) []Test {
	var out []Test
	for _, t := range normalTests() {
		if t.Name != name {
			out = append(out, t)
		}
	}
	return out
}

// JoinsSuite is joinsTestSuite: the normal tests with native joins enabled.
var JoinsSuite = CreateTestSuite("joins", SuiteConfig{
	DefaultOptions: func(c *betterauth.Config) { ensureDB(c).Joins = true },
	AlwaysMigrate:  true,
	PrefixTests:    "joins",
}, func() []Test {
	return append([]Test{
		{Name: "init - tests", Fn: func(h *H) {
			opts := h.Options()
			h.True(opts.Advanced != nil && opts.Advanced.Database != nil && opts.Advanced.Database.Joins, "advanced.database.joins")
		}},
	}, normalTestsWithout("create - should use generateId if provided")...)
})

// NumberIDSuite is numberIdTestSuite: the normal tests with serial ids.
var NumberIDSuite = CreateTestSuite("number-id", SuiteConfig{
	DefaultOptions: func(c *betterauth.Config) { ensureDB(c).GenerateID = adapter.IDSerial },
	AlwaysMigrate:  true,
	PrefixTests:    "number-id",
}, func() []Test {
	return append([]Test{
		{Name: "init - tests", Fn: func(h *H) {
			h.True(idMode(h.Options()) == adapter.IDSerial, "generateId === serial")
		}},
		{Name: "create - should return a number id", Fn: func(h *H) {
			user := h.Generate("user")
			res := h.Create(adapter.CreateInput{Model: "user", Data: user, ForceAllowID: true})
			_, ok := res["id"]
			h.True(ok, "result has id")
			h.IsString(res["id"])
			n, ok := adapter.ToFloat(res["id"])
			h.True(ok && n > 0, "Number(res.id) > 0, got %v", res["id"])
		}},
	}, normalTestsWithout("create - should use generateId if provided")...)
})

var uuidRegex = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// UUIDSuite is uuidTestSuite: the normal tests with uuid ids.
var UUIDSuite = CreateTestSuite("uuid", SuiteConfig{
	DefaultOptions:    func(c *betterauth.Config) { ensureDB(c).GenerateID = adapter.IDUUID },
	PrefixTests:       "uuid",
	AlwaysMigrate:     true,
	CustomIDGenerator: bacrypto.RandomUUID,
}, func() []Test {
	return append([]Test{
		{Name: "init - tests", Fn: func(h *H) {
			h.True(idMode(h.Options()) == adapter.IDUUID, "generateId === uuid")
		}},
		{Name: "create - should return a uuid", Fn: func(h *H) {
			user := h.Generate("user")
			res := h.Create(adapter.CreateInput{Model: "user", Data: Omit(user, "id")})
			_, ok := res["id"]
			h.True(ok, "result has id")
			h.IsString(res["id"])
			h.True(uuidRegex.MatchString(ID(res)), "id %q should be a uuid", ID(res))
			h.Log(Format(res))
		}},
		{Name: "findOne - should find a model using a uuid", Fn: func(h *H) {
			user := Omit(h.Generate("user"), "id")
			res := h.Create(adapter.CreateInput{Model: "user", Data: user})
			result := h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("id", res["id"])})
			h.True(uuidRegex.MatchString(ID(result)), "id %q should be a uuid", ID(result))
			h.Equal(result, res)
		}},
	}, normalTestsWithout("create - should use generateId if provided")...)
})

// ---- case-insensitive.ts ----

func insensitive(field string, value any, op adapter.Operator) adapter.Where {
	return adapter.Where{Field: field, Value: value, Operator: op, Insensitive: true}
}

// CaseInsensitiveSuite is caseInsensitiveTestSuite.
var CaseInsensitiveSuite = CreateTestSuite("case-insensitive", SuiteConfig{}, func() []Test {
	createUser := func(h *H, email, name string) adapter.Record {
		return h.Create(adapter.CreateInput{Model: "user", Data: Merge(h.Generate("user"), R{"email": email, "name": name}), ForceAllowID: true})
	}
	return []Test{
		{Name: "findOne - eq with mode insensitive should match regardless of case", Fn: func(h *H) {
			user := createUser(h, "TestUser@Example.COM", "CaseTest")
			result := h.FindOne(adapter.FindOneInput{Model: "user", Where: []W{insensitive("email", "testuser@example.com", adapter.Eq)}})
			h.NotNull(result)
			h.Equal(ID(result), ID(user))
			h.Equal(result["email"], "TestUser@Example.COM")
		}},
		{Name: "findOne - eq with mode sensitive (default) should not match different case", Fn: func(h *H) {
			createUser(h, "ExactCase@Test.com", "ExactCase")
			result := h.FindOne(adapter.FindOneInput{Model: "user", Where: []W{{Field: "email", Value: "exactcase@test.com", Operator: adapter.Eq}}})
			h.Null(result)
		}},
		{Name: "findMany - eq with mode insensitive", Fn: func(h *H) {
			user := createUser(h, "FindMany@EQ.Test", "FindManyEQ")
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{insensitive("email", "findmany@eq.test", adapter.Eq)}})
			h.Len(result, 1)
			h.Equal(ID(result[0]), ID(user))
		}},
		{Name: "findMany - ne with mode insensitive", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 3))
			excludeUser := createUser(h, "ExcludeMe@NE.Test", "ExcludeMe")
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{insensitive("email", "excludeme@ne.test", adapter.Ne)}})
			ids := IDs(result)
			h.True(!Contains(ids, ID(excludeUser)), "result should not contain the excluded user")
			h.True(Contains(ids, ID(users[0])), "result should contain users[0]")
		}},
		{Name: "findMany - in with mode insensitive", Fn: func(h *H) {
			user := createUser(h, "InArray@Test.COM", "InArray")
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{insensitive("email",
				[]any{"other@test.com", "inarray@test.com", "third@test.com"}, adapter.In)}})
			h.Len(result, 1)
			h.Equal(ID(result[0]), ID(user))
		}},
		{Name: "findMany - not_in with mode insensitive", Fn: func(h *H) {
			users := Firsts(h.InsertRandomN("user", 2))
			excludeUser := createUser(h, "NotIn@Exclude.Test", "NotIn")
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{insensitive("email", []any{"notin@exclude.test"}, adapter.NotIn)}})
			ids := IDs(result)
			h.True(!Contains(ids, ID(excludeUser)), "result should not contain the excluded user")
			h.True(Contains(ids, ID(users[0])), "result should contain users[0]")
		}},
		{Name: "findMany - contains with mode insensitive", Fn: func(h *H) {
			user := createUser(h, "prefixCONTAINSsuffix@test.com", "Contains")
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{insensitive("email", "containssuffix", adapter.Contains)}})
			h.True(len(result) >= 1, "at least one result")
			h.True(Contains(IDs(result), ID(user)), "result should contain the user")
		}},
		{Name: "findMany - starts_with with mode insensitive", Fn: func(h *H) {
			user := createUser(h, "STARTSwith@test.com", "StartsWith")
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{insensitive("email", "starts", adapter.StartsWith)}})
			h.True(len(result) >= 1, "at least one result")
			h.True(Contains(IDs(result), ID(user)), "result should contain the user")
		}},
		{Name: "findMany - ends_with with mode insensitive", Fn: func(h *H) {
			user := createUser(h, "user@ENDSWITH.Com", "EndsWith")
			result := h.FindMany(adapter.FindManyInput{Model: "user", Where: []W{insensitive("email", "endswith.com", adapter.EndsWith)}})
			h.True(len(result) >= 1, "at least one result")
			h.True(Contains(IDs(result), ID(user)), "result should contain the user")
		}},
		{Name: "count - with mode insensitive", Fn: func(h *H) {
			createUser(h, "CountTest@Case.INSENSITIVE", "CountTest")
			result := h.Count("user", insensitive("email", "counttest@case.insensitive", adapter.Eq))
			h.True(result >= 1, "count >= 1, got %d", result)
		}},
		{Name: "update - where with mode insensitive", Fn: func(h *H) {
			user := createUser(h, "UpdateWhere@Insensitive.Test", "BeforeUpdate")
			result := h.Update("user", []W{insensitive("email", "updatewhere@insensitive.test", adapter.Eq)}, R{"name": "AfterUpdate"})
			h.NotNull(result)
			h.Equal(result["name"], "AfterUpdate")
			h.Equal(ID(result), ID(user))
		}},
		{Name: "deleteMany - where with mode insensitive", Fn: func(h *H) {
			keepUser := h.InsertRandom("user")[0]
			deleteUser := createUser(h, "DeleteMany@Case.INSENSITIVE", "ToDelete")
			h.DeleteMany("user", insensitive("email", "deletemany@case.insensitive", adapter.Eq))
			h.Null(h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("id", deleteUser["id"])}))
			h.NotNull(h.FindOne(adapter.FindOneInput{Model: "user", Where: Where("id", keepUser["id"])}))
		}},
	}
})
