package jsonx

import (
	"math"
	"testing"
	"time"
)

func TestMarshalNumbersMatchJavaScript(t *testing.T) {
	a, b := 0.1, 0.2
	// Expected output captured from Node.js JSON.stringify.
	vals := []any{0.0, math.Copysign(0, -1), 1.0, 1.5, -2.25, 1e21, 1e20, 123456789012345680000.0,
		1e-6, 1e-7, 0.000001234, 1736000000000.0, a + b, 5e-324, 1.7976931348623157e308,
		9007199254740992.0, 100.0, 1e100}
	got, err := Stringify(vals)
	if err != nil {
		t.Fatal(err)
	}
	want := `[0,0,1,1.5,-2.25,1e+21,100000000000000000000,123456789012345680000,0.000001,1e-7,0.000001234,1736000000000,0.30000000000000004,5e-324,1.7976931348623157e+308,9007199254740992,100,1e+100]`
	if got != want {
		t.Fatalf("numbers\n got %s\nwant %s", got, want)
	}
}

func TestMarshalStringEscapingMatchesJavaScript(t *testing.T) {
	got, _ := Stringify("a\"b\\c\n\t\u0001\u001f\u007f<>&  é😀")
	want := "\"a\\\"b\\\\c\\n\\t\\u0001\\u001f\u007f<>&  é😀\""
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestMarshalTimeIsISOWithMillis(t *testing.T) {
	got, _ := Stringify(time.UnixMilli(1736000000123))
	if got != `"2025-01-04T14:13:20.123Z"` {
		t.Fatalf("got %s", got)
	}
}

func TestObjectOrderAndUndefined(t *testing.T) {
	o := O("b", 1, "a", Undefined, "c", []any{Undefined, nil})
	o.Set("b", 2) // keeps position
	got, _ := Stringify(o)
	if got != `{"b":2,"c":[null,null]}` {
		t.Fatalf("got %s", got)
	}
}

func TestParseRoundTripPreservesOrder(t *testing.T) {
	in := `{"z":1,"a":{"y":true,"b":[1,"x",null]},"m":"2024-01-01T00:00:00Z"}`
	v, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := Stringify(v)
	if out != in {
		t.Fatalf("roundtrip\n got %s\nwant %s", out, in)
	}
	// safeJSONParse revives ISO strings, so re-stringifying normalises to millisecond precision.
	revived, _ := Stringify(ReviveDates(v))
	if revived != `{"z":1,"a":{"y":true,"b":[1,"x",null]},"m":"2024-01-01T00:00:00.000Z"}` {
		t.Fatalf("revived %s", revived)
	}
}

func TestParseDuplicateKeysKeepFirstPositionLastValue(t *testing.T) {
	v, err := Parse([]byte(`{"a":1,"b":2,"a":3}`))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := Stringify(v)
	if out != `{"a":3,"b":2}` {
		t.Fatalf("got %s", out)
	}
}

func TestJSSubstringUTF16(t *testing.T) {
	s := "a😀b"
	if EncodeUTF16Length(s) != 4 {
		t.Fatalf("len %d", EncodeUTF16Length(s))
	}
	if JSSubstring(s, 0, 3) != "a😀" {
		t.Fatalf("substring %q", JSSubstring(s, 0, 3))
	}
}
