package validate

import "testing"

func TestZodExtras(t *testing.T) {
	if out, is := Validate(Describe(String(), "d"), "x"); len(is) > 0 || out != "x" {
		t.Fatal("describe")
	}
	if Inspect(Describe(String(), "d")).Description != "d" {
		t.Fatal("inspect describe")
	}
	if _, is := Validate(Nullable(String()), nil); len(is) > 0 {
		t.Fatal("nullable null")
	}
	if _, is := Validate(Object(F("a", Nullable(String()))), map[string]any{}); len(is) == 0 {
		t.Fatal("nullable rejects undefined")
	}
	if out, _ := Validate(Object(F("a", Prefault(String(), "p"))), map[string]any{}); out.(map[string]any)["a"] != "p" {
		t.Fatal("prefault")
	}
	if out, _ := Validate(Object(F("a", Catch(String(), "c"))), map[string]any{"a": 1.0}); out.(map[string]any)["a"] != "c" {
		t.Fatal("catch")
	}
	_, is := Validate(Object(F("a", NonOptional(Optional(String())))), map[string]any{})
	if len(is) != 1 || is[0].Message != "Invalid input: expected nonoptional, received undefined" {
		t.Fatalf("nonoptional %v", is)
	}
	_, is = Validate(Object(F("a", UndefinedValue())), map[string]any{"a": "x"})
	if len(is) != 1 || is[0].Message != "Invalid input: expected undefined, received string" {
		t.Fatalf("undefined %v", is)
	}
	if _, is := Validate(RecordOf(String().Min(2), Boolean()), map[string]any{"a": true}); len(is) == 0 {
		t.Fatal("record key")
	}
	if out, _ := Validate(Preprocess(func(v any) any { return "x" }, String()), 1.0); out != "x" {
		t.Fatal("preprocess")
	}
	if Inspect(Unknown()).Kind != KindUnknown || Inspect(Void()).Kind != KindVoid || Inspect(NullValue()).Kind != KindNull {
		t.Fatal("kinds")
	}
	if Inspect(Nullish(String())).Kind != KindNullable || Inspect(Default(String(), "x")).Kind != KindDefault {
		t.Fatal("wrapper kinds")
	}
}
