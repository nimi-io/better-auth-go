package adapter

import (
	"testing"

	"github.com/nimi-io/better-auth-go/db"
)

type hexID [2]byte

func (h hexID) Hex() string    { return "0a0b" }
func (h hexID) String() string { return `ObjectID("0a0b")` }

func TestToStringPrefersHex(t *testing.T) {
	if got := ToString(hexID{}); got != "0a0b" {
		t.Fatalf("got %q", got)
	}
}

func TestFactoryEncodesJSONLikeJavaScript(t *testing.T) {
	f := &factory{cfg: Config{}}
	got := f.encodeValue(db.Field{Name: "meta", Type: db.TypeJSON}, map[string]any{"a": "<b>&"})
	if got != `{"a":"<b>&"}` {
		t.Fatalf("json: %v", got)
	}
	got = f.encodeValue(db.Field{Name: "tags", Type: db.TypeStringArray}, []string{"x<y"})
	if got != `["x<y"]` {
		t.Fatalf("array: %v", got)
	}
}
