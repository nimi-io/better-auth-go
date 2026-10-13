package mongodb

import (
	"errors"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/db"
)

// Unit tests of the query builders and the where-clause translation (no database needed).

func customOf(t *testing.T, a adapter.Adapter) *mongoAdapter {
	t.Helper()
	c, ok := a.(interface{ Custom() adapter.CustomAdapter })
	if !ok {
		t.Fatal("adapter does not expose Custom()")
	}
	switch m := c.Custom().(type) {
	case *mongoAdapter:
		return m
	case *txAdapter:
		return m.mongoAdapter
	}
	t.Fatalf("unexpected custom adapter %T", c.Custom())
	return nil
}

func offlineAdapter(t *testing.T, opts adapter.Options) *mongoAdapter {
	t.Helper()
	if opts.Schema == nil {
		opts.Schema = schemaOf(db.Options{RateLimitInDatabase: true, Session: db.ModelOptions{Fields: map[string]string{"userId": "user_id"}}})
	}
	return customOf(t, mustAdapter(t, New(nil, Config{}), opts))
}

func TestEscapeForMongoRegex(t *testing.T) {
	cases := map[string]string{
		"a.b*c+d?e^f$g{h}i(j)k|l[m]n\\o": `a\.b\*c\+d\?e\^f\$g\{h\}i\(j\)k\|l\[m\]n\\o`,
		"plain-text_@":                   "plain-text_@",
		"":                               "",
	}
	for in, want := range cases {
		if got := EscapeForMongoRegex(in, 0); got != want {
			t.Errorf("escape(%q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("a", 300)
	if got := EscapeForMongoRegex(long, 0); len(got) != 256 {
		t.Errorf("default max length: %d", len(got))
	}
	if got := EscapeForMongoRegex("abc.def", 4); got != `abc\.` {
		t.Errorf("custom max length: %q", got)
	}
	// slice() counts UTF-16 code units
	if got := EscapeForMongoRegex("😀😀", 3); got != "😀�" {
		t.Errorf("utf-16 slice: %q", got)
	}
	if got := escapeAny(42); got != "" {
		t.Errorf("non-string: %q", got)
	}
}

func TestInsensitiveQueryBuilders(t *testing.T) {
	cases := []struct {
		got  bson.D
		want string
	}{
		{insensitiveEq("email", "A.b"), `{"email":{"$regex":"^A\\.b$","$options":"i"}}`},
		{insensitiveIn("email", []string{"a", "b"}), `{"$or":[{"email":{"$regex":"^a$","$options":"i"}},{"email":{"$regex":"^b$","$options":"i"}}]}`},
		{insensitiveIn("email", nil), `{"$expr":{"$eq":[1,0]}}`},
		{insensitiveNotIn("email", []string{"a"}), `{"$nor":[{"email":{"$regex":"^a$","$options":"i"}}]}`},
		{insensitiveNotIn("email", nil), `{}`},
		{insensitiveNe("email", "x"), `{"email":{"$not":{"$regex":"^x$","$options":"i"}}}`},
		{insensitiveContains("name", "a+"), `{"name":{"$regex":".*a\\+.*","$options":"i"}}`},
		{insensitiveStartsWith("name", "a"), `{"name":{"$regex":"^a","$options":"i"}}`},
		{insensitiveEndsWith("name", "a"), `{"name":{"$regex":"a$","$options":"i"}}`},
	}
	for _, c := range cases {
		if got := extJSON(t, toBSON(c.got)); got != c.want {
			t.Errorf("got %s\nwant %s", got, c.want)
		}
	}
}

func TestConvertWhereClause(t *testing.T) {
	a := offlineAdapter(t, adapter.Options{})
	const hex = "507f1f77bcf86cd799439011"
	cw := func(field string, value any, op adapter.Operator, conn adapter.Connector, insensitive bool) adapter.CleanedWhere {
		if op == "" {
			op = adapter.Eq
		}
		if conn == "" {
			conn = adapter.And
		}
		return adapter.CleanedWhere{Field: field, Value: value, Operator: op, Connector: conn, Insensitive: insensitive}
	}
	cases := []struct {
		name  string
		model string
		where []adapter.CleanedWhere
		want  string
	}{
		{"empty", "user", nil, `{}`},
		{"eq", "user", []adapter.CleanedWhere{cw("email", "a@b.c", "", "", false)}, `{"email":"a@b.c"}`},
		{"eq id → ObjectId", "user", []adapter.CleanedWhere{cw("_id", hex, "", "", false)}, `{"_id":{"$oid":"` + hex + `"}}`},
		{"eq invalid id stays string", "user", []adapter.CleanedWhere{cw("_id", "not-an-id", "", "", false)}, `{"_id":"not-an-id"}`},
		{"eq null", "user", []adapter.CleanedWhere{cw("image", nil, "", "", false)}, `{"image":null}`},
		{"renamed FK → ObjectId", "session", []adapter.CleanedWhere{cw("user_id", hex, "", "", false)}, `{"user_id":{"$oid":"` + hex + `"}}`},
		{"in ids", "user", []adapter.CleanedWhere{cw("_id", []string{hex, "x"}, adapter.In, "", false)}, `{"_id":{"$in":[{"$oid":"` + hex + `"},"x"]}}`},
		{"not_in", "user", []adapter.CleanedWhere{cw("name", []any{"a", "b"}, adapter.NotIn, "", false)}, `{"name":{"$nin":["a","b"]}}`},
		{"in scalar", "user", []adapter.CleanedWhere{cw("name", "a", adapter.In, "", false)}, `{"name":{"$in":["a"]}}`},
		{"gt/gte/lt/lte", "rateLimit", []adapter.CleanedWhere{
			cw("count", int64(1), adapter.Gt, "", false), cw("count", 2.5, adapter.Gte, "", false),
			cw("count", int64(3), adapter.Lt, "", false), cw("count", int64(1)<<40, adapter.Lte, "", false)},
			`{"$and":[{"count":{"$gt":1}},{"count":{"$gte":2.5}},{"count":{"$lt":3}},{"count":{"$lte":1.099511627776E+12}}]}`},
		{"ne", "user", []adapter.CleanedWhere{cw("name", "x", adapter.Ne, "", false)}, `{"name":{"$ne":"x"}}`},
		{"contains", "user", []adapter.CleanedWhere{cw("name", "a.b", adapter.Contains, "", false)}, `{"name":{"$regex":".*a\\.b.*"}}`},
		{"starts_with", "user", []adapter.CleanedWhere{cw("name", "(a", adapter.StartsWith, "", false)}, `{"name":{"$regex":"^\\(a"}}`},
		{"ends_with", "user", []adapter.CleanedWhere{cw("name", "a$", adapter.EndsWith, "", false)}, `{"name":{"$regex":"a\\$$"}}`},
		{"contains non-string", "user", []adapter.CleanedWhere{cw("name", 5, adapter.Contains, "", false)}, `{"name":{"$regex":".*.*"}}`},
		{"uppercase operator", "user", []adapter.CleanedWhere{cw("name", "x", "NE", "", false)}, `{"name":{"$ne":"x"}}`},
		{"insensitive eq", "user", []adapter.CleanedWhere{cw("email", "A@B.C", "", "", true)}, `{"email":{"$regex":"^A@B\\.C$","$options":"i"}}`},
		{"insensitive in", "user", []adapter.CleanedWhere{cw("email", []string{"A"}, adapter.In, "", true)}, `{"$or":[{"email":{"$regex":"^A$","$options":"i"}}]}`},
		{"insensitive empty in", "user", []adapter.CleanedWhere{cw("email", []string{}, adapter.In, "", true)}, `{"$expr":{"$eq":[1,0]}}`},
		{"insensitive not_in", "user", []adapter.CleanedWhere{cw("email", []string{"A"}, adapter.NotIn, "", true)}, `{"$nor":[{"email":{"$regex":"^A$","$options":"i"}}]}`},
		{"insensitive ne", "user", []adapter.CleanedWhere{cw("email", "A", adapter.Ne, "", true)}, `{"email":{"$not":{"$regex":"^A$","$options":"i"}}}`},
		{"insensitive contains", "user", []adapter.CleanedWhere{cw("email", "A", adapter.Contains, "", true)}, `{"email":{"$regex":".*A.*","$options":"i"}}`},
		{"insensitive mixed array is sensitive", "user", []adapter.CleanedWhere{cw("name", []any{"A", 1}, adapter.In, "", true)}, `{"name":{"$in":["A",1]}}`},
		{"insensitive ignored for ids", "user", []adapter.CleanedWhere{cw("_id", hex, "", "", true)}, `{"_id":{"$oid":"` + hex + `"}}`},
		{"insensitive ignored for id references", "session", []adapter.CleanedWhere{cw("user_id", "abc", "", "", true)}, `{"user_id":"abc"}`},
		{"single OR is returned as is", "user", []adapter.CleanedWhere{cw("name", "a", "", adapter.Or, false)}, `{"name":"a"}`},
		{"AND + OR", "user", []adapter.CleanedWhere{
			cw("name", "a", "", adapter.And, false), cw("email", "x", "", adapter.Or, false), cw("email", "y", "", adapter.Or, false)},
			`{"$and":[{"name":"a"}],"$or":[{"email":"x"},{"email":"y"}]}`},
		{"only OR", "user", []adapter.CleanedWhere{cw("name", "a", "", adapter.Or, false), cw("name", "b", "", adapter.Or, false)},
			`{"$or":[{"name":"a"},{"name":"b"}]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := a.convertWhere(c.where, c.model)
			if err != nil {
				t.Fatal(err)
			}
			if s := extJSON(t, toBSON(got)); s != c.want {
				t.Fatalf("got  %s\nwant %s", s, c.want)
			}
		})
	}
}

func TestConvertWhereErrors(t *testing.T) {
	a := offlineAdapter(t, adapter.Options{})
	_, err := a.convertWhere([]adapter.CleanedWhere{{Field: "name", Value: "x", Operator: "like", Connector: adapter.And}}, "user")
	var me *MongoAdapterError
	if !errors.As(err, &me) || me.Code != "UNSUPPORTED_OPERATOR" || me.Error() != "Unsupported operator: like" {
		t.Fatalf("err %v", err)
	}
	_, err = a.convertWhere([]adapter.CleanedWhere{{Field: "_id", Value: 42, Operator: adapter.Eq, Connector: adapter.And}}, "user")
	if !errors.As(err, &me) || me.Code != "INVALID_ID" || me.Error() != "Invalid id value" {
		t.Fatalf("err %v", err)
	}
	_, err = a.convertWhere([]adapter.CleanedWhere{{Field: "_id", Value: []any{"x", 42}, Operator: adapter.In, Connector: adapter.And}}, "user")
	if !errors.As(err, &me) || me.Code != "INVALID_ID" {
		t.Fatalf("err %v", err)
	}
	if _, err := a.convertWhere([]adapter.CleanedWhere{{Field: "nope", Value: 1, Operator: adapter.Eq}}, "user"); err == nil {
		t.Fatal("unknown field should fail")
	}
}

func TestConvertWhereCustomIDGeneratorKeepsStrings(t *testing.T) {
	a := offlineAdapter(t, adapter.Options{GenerateID: func(string, int) (string, bool) { return "custom", true }})
	got, err := a.convertWhere([]adapter.CleanedWhere{{Field: "_id", Value: "507f1f77bcf86cd799439011", Operator: adapter.Eq, Connector: adapter.And}}, "user")
	if err != nil {
		t.Fatal(err)
	}
	if s := extJSON(t, got); s != `{"_id":"507f1f77bcf86cd799439011"}` {
		t.Fatalf("got %s", s)
	}
	// with a custom generator even non-string ids are passed through
	if _, err := a.convertWhere([]adapter.CleanedWhere{{Field: "_id", Value: 42, Operator: adapter.Eq, Connector: adapter.And}}, "user"); err != nil {
		t.Fatal(err)
	}
}

func TestConvertWhereUUIDMode(t *testing.T) {
	a := offlineAdapter(t, adapter.Options{IDMode: adapter.IDUUID})
	const u = "550e8400-e29b-41d4-a716-446655440000"
	got, err := a.convertWhere([]adapter.CleanedWhere{
		{Field: "_id", Value: u, Operator: adapter.Eq, Connector: adapter.And},
		{Field: "_id", Value: "550e8400e29b41d4a716446655440000", Operator: adapter.Ne, Connector: adapter.And},
		{Field: "_id", Value: "507f1f77bcf86cd799439011", Operator: adapter.Ne, Connector: adapter.And},
	}, "user")
	if err != nil {
		t.Fatal(err)
	}
	const bin = `{"$binary":{"base64":"VQ6EAOKbQdSnFkRmVUQAAA==","subType":"04"}}`
	want := `{"$and":[{"_id":` + bin + `},{"_id":{"$ne":` + bin + `}},{"_id":{"$ne":"507f1f77bcf86cd799439011"}}]}`
	if s := extJSON(t, got); s != want {
		t.Fatalf("got  %s\nwant %s", s, want)
	}
}

func TestTransformInputAndOutput(t *testing.T) {
	ids := idCodec{}
	ref := db.Field{Name: "userId", References: &db.Reference{Model: "user", Field: "id"}}
	optRef := db.Field{Name: "parentId", References: &db.Reference{Model: "user", Field: "id"}}
	reqRef := ref
	reqRef.Required = db.True
	const hex = "507f1f77bcf86cd799439011"
	in := func(data any, field string, attr db.Field, action string) any {
		return transformInput(ids, adapter.TransformParams{Data: data, Field: field, Attr: attr, Action: action})
	}
	if v, ok := in(hex, "_id", db.Field{}, "create").(bson.ObjectID); !ok || v.Hex() != hex {
		t.Fatalf("create id: %v", v)
	}
	if v, ok := in(hex, "userId", ref, "update").(bson.ObjectID); !ok || v.Hex() != hex {
		t.Fatalf("update FK: %v", v)
	}
	if v := in(hex, "userId", ref, "findOne"); v != hex {
		t.Fatalf("findOne should not convert: %v", v)
	}
	if v := in("invalid", "_id", db.Field{}, "create"); v != "invalid" {
		t.Fatalf("invalid string kept: %v", v)
	}
	if v := in(hex, "name", db.Field{Name: "name"}, "create"); v != hex {
		t.Fatalf("plain field converted: %v", v)
	}
	arr := in([]string{hex, "x"}, "userId", ref, "create").([]any)
	if _, ok := arr[0].(bson.ObjectID); !ok || arr[1] != "x" {
		t.Fatalf("array: %v", arr)
	}
	if v := in(nil, "parentId", optRef, "create"); v != nil {
		t.Fatalf("optional nil FK: %v", v)
	}
	if v := in(nil, "userId", reqRef, "update"); v != nil {
		t.Fatalf("update nil: %v", v)
	}
	if _, ok := in(nil, "userId", reqRef, "create").(bson.ObjectID); !ok {
		t.Fatal("required FK without a value gets a fresh ObjectId on create (upstream behaviour)")
	}
	custom := idCodec{custom: true}
	if v := transformInput(custom, adapter.TransformParams{Data: hex, Field: "_id", Action: "create"}); v != hex {
		t.Fatalf("custom generator: %v", v)
	}
	// output
	oidv, _ := bson.ObjectIDFromHex(hex)
	if v := transformOutput(adapter.TransformParams{Data: oidv, Field: "id"}); v != hex {
		t.Fatalf("output id: %v", v)
	}
	if v := transformOutput(adapter.TransformParams{Data: []any{oidv, "x"}, Field: "userId", Attr: ref}).([]any); v[0] != hex || v[1] != "x" {
		t.Fatalf("output array: %v", v)
	}
	if v := transformOutput(adapter.TransformParams{Data: oidv, Field: "other", Attr: db.Field{}}); v != oidv {
		t.Fatalf("non-id field converted: %v", v)
	}
}

func TestToBSONMatchesJSNumberEncoding(t *testing.T) {
	cases := []struct {
		in   any
		want bson.Type
	}{
		{int64(5), bson.TypeInt32}, {5.0, bson.TypeInt32}, {int64(1) << 40, bson.TypeDouble},
		{1.5, bson.TypeDouble}, {int64(-2147483648), bson.TypeInt32}, {int64(2147483648), bson.TypeDouble},
		{int(7), bson.TypeInt32},
	}
	for _, c := range cases {
		b, err := bson.Marshal(bson.D{{Key: "v", Value: toBSON(c.in)}})
		if err != nil {
			t.Fatal(err)
		}
		if got := bson.Raw(b).Lookup("v").Type; got != c.want {
			t.Errorf("%T(%v) → %v, want %v", c.in, c.in, got, c.want)
		}
	}
}

func TestIndexNames(t *testing.T) {
	name, err := databaseIndexName("directory_user", []string{"connection_id", "external_id"}, "", true)
	if err != nil || name != "directory_user_connection_id_external_id_uidx" {
		t.Fatalf("%q %v", name, err)
	}
	long := strings.Repeat("a", 40)
	name, _ = databaseIndexName(long, []string{long}, "", false)
	generated := long + "_" + long + "_idx"
	want := generated[:63-len("_"+stableIndexNameHash(generated)+"_idx")] + "_" + stableIndexNameHash(generated) + "_idx"
	if name != want || len(name) != 63 {
		t.Fatalf("long name %q (%d)", name, len(name))
	}
	// FNV-1a reference value for "a"
	if h := stableIndexNameHash("a"); h != "e40c292c" {
		t.Fatalf("hash %s", h)
	}
	for _, bad := range []string{" ", "1abc", "a-b", strings.Repeat("x", 64)} {
		if _, err := databaseIndexName("t", []string{"c"}, bad, false); err == nil {
			t.Errorf("name %q should be rejected", bad)
		}
	}
	tbl := &db.Table{Key: "x", Fields: []db.Field{{Name: "a", Type: db.TypeString, FieldName: "a_col"}, {Name: "j", Type: db.TypeJSON}},
		Indexes: []db.Index{{Fields: []string{"a"}}, {Fields: []string{"a"}}}}
	idx, err := resolveTableIndexes(tbl, "x")
	if err != nil || len(idx) != 1 || idx[0].Columns[0] != "a_col" || idx[0].Name != "x_a_col_idx" {
		t.Fatalf("%v %v", idx, err)
	}
	for _, bad := range [][]string{{}, {"a", "a"}, {"j"}, {"missing"}} {
		tbl.Indexes = []db.Index{{Fields: bad}}
		if _, err := resolveTableIndexes(tbl, "x"); err == nil {
			t.Errorf("fields %v should be rejected", bad)
		}
	}
	tbl.Indexes = []db.Index{{Fields: []string{"a"}, Name: "same"}, {Fields: []string{"a"}, Name: "SAME", Unique: true}}
	if _, err := resolveTableIndexes(tbl, "x"); err == nil {
		t.Error("conflicting index names should be rejected")
	}
}

func TestUniqueIndexRejectsOptionalFields(t *testing.T) {
	tbl := &db.Table{Key: "thing", ModelName: "thing", Fields: []db.Field{
		{Name: "a", Type: db.TypeString, Required: db.False},
		{Name: "b", Type: db.TypeString},
	}, Indexes: []db.Index{{Fields: []string{"a", "b"}, Unique: true}}}
	_, err := resolveTableIndexes(tbl, "thing")
	if err == nil || !strings.Contains(err.Error(), "can only include required fields") {
		t.Fatalf("got %v", err)
	}
	tbl.Fields[0].Required = nil // unset counts as required, like upstream
	if _, err := resolveTableIndexes(tbl, "thing"); err != nil {
		t.Fatal(err)
	}
}
