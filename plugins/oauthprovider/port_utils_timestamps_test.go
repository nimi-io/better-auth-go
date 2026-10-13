package oauthprovider

import (
	"math"
	"testing"
	"time"
)

// Port of utils/timestamps.test.ts.

func TestMx_NormalizeTimestampValue(t *testing.T) {
	t.Run("parses epoch-millis text values", func(t *testing.T) {
		result := normalizeTimestampValue("1774295570569.0")
		if result == nil || result.UnixMilli() != 1774295570569 {
			t.Fatalf("got %v", result)
		}
	})
	t.Run("returns undefined for invalid values", func(t *testing.T) {
		for _, v := range []any{"not-a-date", math.NaN(), 9e15, "9e15"} {
			if r := normalizeTimestampValue(v); r != nil {
				t.Fatalf("%v: expected nil, got %v", v, r)
			}
		}
	})
}

func TestMx_ResolveSessionAuthTime(t *testing.T) {
	t.Run("reads createdAt from direct session objects", func(t *testing.T) {
		r := resolveSessionAuthTime(map[string]any{"createdAt": "1774295570569.0"})
		if r == nil || r.UnixMilli() != 1774295570569 {
			t.Fatalf("got %v", r)
		}
	})
	t.Run("reads created_at from nested session payloads", func(t *testing.T) {
		r := resolveSessionAuthTime(map[string]any{"session": map[string]any{"created_at": float64(1774295570569)}})
		if r == nil || r.UnixMilli() != 1774295570569 {
			t.Fatalf("got %v", r)
		}
	})
	t.Run("normalizes direct Date values", func(t *testing.T) {
		d := time.UnixMilli(1774295570569)
		r := resolveSessionAuthTime(d)
		if r == nil || r.UnixMilli() != 1774295570569 {
			t.Fatalf("got %v", r)
		}
	})
	t.Run("does not fall back to updatedAt timestamps", func(t *testing.T) {
		direct := resolveSessionAuthTime(map[string]any{"updatedAt": float64(1774295570569)})
		nested := resolveSessionAuthTime(map[string]any{"session": map[string]any{"updated_at": "1774295570569.0"}})
		if direct != nil || nested != nil {
			t.Fatalf("got %v %v", direct, nested)
		}
	})
}
