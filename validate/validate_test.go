package validate

import "testing"

// Expected messages were captured from zod@4.5.4 (see e2e/scripts and the PR notes).
func TestZodCompatibleMessages(t *testing.T) {
	cases := []struct {
		name   string
		schema Schema
		value  any
		want   string
	}{
		{"str-undef", Object(F("a", String())), map[string]any{}, "[body.a] Invalid input: expected string, received undefined"},
		{"str-num", Object(F("a", String())), map[string]any{"a": 1.0}, "[body.a] Invalid input: expected string, received number"},
		{"str-null", Object(F("a", String())), map[string]any{"a": nil}, "[body.a] Invalid input: expected string, received null"},
		{"str-arr", Object(F("a", String())), map[string]any{"a": []any{}}, "[body.a] Invalid input: expected string, received array"},
		{"str-obj", Object(F("a", String())), map[string]any{"a": map[string]any{}}, "[body.a] Invalid input: expected string, received object"},
		{"obj-undef", Object(F("a", String())), Undefined, "[body] Invalid input: expected object, received undefined"},
		{"obj-null", Object(F("a", String())), nil, "[body] Invalid input: expected object, received null"},
		{"obj-arr", Object(F("a", String())), []any{}, "[body] Invalid input: expected object, received array"},
		{"email", Object(F("a", Email())), map[string]any{"a": "bad"}, "[body.a] Invalid email address"},
		{"email-undef", Object(F("a", Email())), map[string]any{}, "[body.a] Invalid input: expected string, received undefined"},
		{"nonempty", Object(F("a", String().NonEmpty())), map[string]any{"a": ""}, "[body.a] Too small: expected string to have >=1 characters"},
		{"bool", Object(F("a", Boolean())), map[string]any{"a": "true"}, "[body.a] Invalid input: expected boolean, received string"},
		{"num", Object(F("a", Number())), map[string]any{"a": "1"}, "[body.a] Invalid input: expected number, received string"},
		{"arr", Object(F("a", Array(String()))), map[string]any{"a": "x"}, "[body.a] Invalid input: expected array, received string"},
		{"arr-item", Object(F("a", Array(String()))), map[string]any{"a": []any{"x", 1.0}}, "[body.a.1] Invalid input: expected string, received number"},
		{"record", Record(Any()), []any{}, "[body] Invalid input: expected record, received array"},
		{"strict", StrictObject(F("a", String())), map[string]any{"a": "x", "b": 1.0, "c": 2.0}, `[body] Unrecognized keys: "b", "c"`},
		{"union", Union(StrictObject(F("accountId", String())), StrictObject(F("useAccountCookie", Literal(true)))), map[string]any{}, "[body] Invalid input"},
		{"union2", Union(
			StrictObject(F("accountId", String()), F("userId", Optional(String()))),
			StrictObject(F("useAccountCookie", Literal(true)), F("userId", Optional(String())))),
			map[string]any{"accountId": "x", "foo": 1.0}, `[body] Unrecognized key: "foo"`},
		{"literal", Object(F("a", Literal(true))), map[string]any{"a": false}, "[body.a] Invalid input: expected true"},
		{"enum", Object(F("a", Enum("github", "google"))), map[string]any{"a": "x"}, `[body.a] Invalid option: expected one of "github"|"google"`},
		{"and", And(Object(F("name", String()), F("email", Email())), Record(Any())), map[string]any{"email": "x"},
			"[body.name] Invalid input: expected string, received undefined; [body.email] Invalid email address"},
		{"and-undef", And(Object(F("name", String())), Record(Any())), Undefined,
			"[body] Invalid input: expected object, received undefined; [body] Invalid input: expected record, received undefined"},
		{"int", Object(F("a", Number().Int())), map[string]any{"a": 1.5}, "[body.a] Invalid input: expected int, received number"},
		{"min", Object(F("a", String().Min(3))), map[string]any{"a": "x"}, "[body.a] Too small: expected string to have >=3 characters"},
		{"max", Object(F("a", String().Max(3))), map[string]any{"a": "xxxxx"}, "[body.a] Too big: expected string to have <=3 characters"},
		{"nummin", Object(F("a", Number().Min(3))), map[string]any{"a": 1.0}, "[body.a] Too small: expected number to be >=3"},
	}
	for _, c := range cases {
		_, issues := Validate(c.schema, c.value)
		if got := FormatIssues(issues, "body"); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

func TestSuccessfulOutputs(t *testing.T) {
	out, issues := Validate(Optional(Object(F("a", Optional(String())))), Undefined)
	if issues != nil || out != nil {
		t.Fatalf("optional undefined: %v %v", out, issues)
	}
	out, _ = Validate(Object(F("d", Optional(CoerceBoolean()))), map[string]any{"d": "false"})
	if out.(map[string]any)["d"] != true {
		t.Fatal("coerce.boolean should treat \"false\" as true")
	}
	out, _ = Validate(Object(F("r", Default(Boolean(), true))), map[string]any{})
	if out.(map[string]any)["r"] != true {
		t.Fatal("default not applied")
	}
	out, _ = Validate(Object(F("a", String())), map[string]any{"a": "x", "extra": 1.0})
	if _, ok := out.(map[string]any)["extra"]; ok {
		t.Fatal("unknown keys should be stripped")
	}
}

func TestEmailRegex(t *testing.T) {
	cases := map[string]bool{"a@b.co": true, "a@b.c": false, "A.B@x.io": true, "a..b@x.io": false,
		".a@x.io": false, "a.@x.io": false, "a+b@x-y.io": true, "ü@x.io": false, "a@x_y.io": false,
		"a@[1.1.1.1]": false, "test@localhost": false}
	for e, want := range cases {
		if IsEmail(e) != want {
			t.Errorf("%s: want %v", e, want)
		}
	}
}
