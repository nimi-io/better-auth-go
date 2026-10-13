package oauthprovider

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/nimi-io/better-auth-go/jsonx"
)

// Shared helpers of the mx-prefixed ports.

// mxJSON round-trips v through JSON (jsonx-aware) into plain Go values.
func mxJSON(t *testing.T, v any) any {
	t.Helper()
	raw, err := jsonx.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

// mxExpectJSON asserts that got equals want after a JSON round trip of both.
func mxExpectJSON(t *testing.T, got, want any) {
	t.Helper()
	g, w := mxJSON(t, got), mxJSON(t, want)
	if !reflect.DeepEqual(g, w) {
		t.Fatalf("got %v, want %v", g, w)
	}
}

func mxStrPtr(s string) *string { return &s }

func mxBoolPtr(b bool) *bool { return &b }
