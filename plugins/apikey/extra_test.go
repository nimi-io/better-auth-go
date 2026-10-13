package apikey

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Go-specific tests (not in the upstream suite): cross-implementation hashing, options
// without upstream test coverage, schema and metadata.

func TestDefaultKeyHasherMatchesTypeScript(t *testing.T) {
	raw, err := os.ReadFile("testdata/hash-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx []struct{ Key, Hash string }
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	if len(fx) == 0 {
		t.Fatal("no fixtures")
	}
	for _, f := range fx {
		if got := DefaultKeyHasher(f.Key); got != f.Hash {
			t.Fatalf("hash(%q) = %s, want %s", f.Key, got, f.Hash)
		}
	}
}

// A key hashed by the TypeScript plugin and inserted directly into the database verifies.
func TestVerifyKeyCreatedByTypeScript(t *testing.T) {
	raw, _ := os.ReadFile("testdata/hash-fixtures.json")
	var fx []struct{ Key, Hash string }
	_ = json.Unmarshal(raw, &fx)
	inst := newInstance(t, Options{}, nil)
	s := inst.signInWithTestUser()
	f := fx[3]
	inst.dbCreateKey(rawKey(s.userID, "ts", f.Hash))
	r := inst.verify(map[string]any{"key": f.Key})
	eq(t, r["valid"], true)
}

func TestDefaultKeyGenerator(t *testing.T) {
	k, _ := DefaultKeyGenerator(64, "pre_")
	eq(t, len(k), 68)
	eq(t, strings.HasPrefix(k, "pre_"), true)
	for _, c := range k[4:] {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			t.Fatalf("unexpected character %q", c)
		}
	}
}

func TestCustomHeadersGetterAndGenerator(t *testing.T) {
	t.Run("custom header list", func(t *testing.T) {
		in := newInstance(t, Options{Configuration: Configuration{EnableSessionForAPIKeys: true,
			APIKeyHeaders: []string{"x-first", "authorization-key"}}}, nil)
		s := in.signInWithTestUser()
		k := in.createKey(map[string]any{"userId": s.userID}, nil)
		h := http.Header{}
		h.Set("authorization-key", str(k["key"]))
		sess, err := in.auth.API.GetSession(t.Context(), h)
		if err != nil || sess == nil {
			t.Fatalf("expected session: %v", err)
		}
		h = http.Header{}
		h.Set("x-api-key", str(k["key"]))
		sess, _ = in.auth.API.GetSession(t.Context(), h)
		if sess != nil {
			t.Fatal("default header must be ignored")
		}
	})
	t.Run("custom getter", func(t *testing.T) {
		in := newInstance(t, Options{Configuration: Configuration{EnableSessionForAPIKeys: true,
			CustomAPIKeyGetter: func(ctx *betterauth.EndpointContext) string {
				return strings.TrimPrefix(ctx.GetHeader("Authorization"), "ApiKey ")
			}}}, nil)
		s := in.signInWithTestUser()
		k := in.createKey(map[string]any{"userId": s.userID}, nil)
		h := http.Header{}
		h.Set("Authorization", "ApiKey "+str(k["key"]))
		res := in.http("GET", "/api-key/list", nil, h)
		m := expectOK(t, res)
		if len(listIDs(m)) != 1 {
			t.Fatalf("expected the key list: %v", m)
		}
	})
	t.Run("short key is forbidden", func(t *testing.T) {
		in := newInstance(t, Options{Configuration: Configuration{EnableSessionForAPIKeys: true}}, nil)
		h := http.Header{}
		h.Set("x-api-key", "short")
		res := in.http("GET", "/get-session", nil, h)
		expectStatus(t, res, 403, "INVALID_API_KEY")
	})
	t.Run("custom key generator", func(t *testing.T) {
		in := newInstance(t, Options{Configuration: Configuration{DefaultPrefix: "gen_",
			CustomKeyGenerator: func(length int, prefix string) (string, error) {
				return prefix + strings.Repeat("k", length), nil
			}}}, nil)
		s := in.signInWithTestUser()
		k := in.createKey(map[string]any{"userId": s.userID}, nil)
		eq(t, k["key"], "gen_"+strings.Repeat("k", 64))
		eq(t, k["start"], "gen_kk")
	})
}

func TestDeleteAllExpiredAPIKeys(t *testing.T) {
	in := newInstance(t, Options{Configuration: Configuration{KeyExpiration: &KeyExpiration{DefaultExpiresIn: Float(60 * 60 * 24)}}}, nil)
	s := in.signInWithTestUser()
	k := in.createKey(map[string]any{"userId": s.userID}, nil)
	notNil(t, k["expiresAt"])
	in.advance(48 * time.Hour)
	defer in.useRealTimers()
	r := in.mustCall("deleteAllExpiredApiKeys", nil, nil)
	eq(t, r["success"], true)
	isNil(t, r["error"])
	row, _ := in.p.dbFindOne(in.ctx(), "id", str(k["id"]))
	if row != nil {
		t.Fatal("expired key not deleted")
	}
	// server-only endpoints are not routed
	eq(t, in.http("POST", "/api-key/verify", map[string]any{"key": "x"}, nil).Status, 404)
}

func TestSchemaAndMetadata(t *testing.T) {
	p, _ := newPlugin(Options{Schema: &SchemaOptions{ModelName: "api_keys", Fields: map[string]string{"referenceId": "owner_id"}}})
	tables := p.tables()
	eq(t, tables[0].Key, "apikey")
	eq(t, tables[0].ModelName, "api_keys")
	for _, f := range tables[0].Fields {
		if f.Name == "referenceId" {
			eq(t, f.FieldName, "owner_id")
		}
		if f.Name == "rateLimitMax" {
			eq(t, f.DefaultValue, float64(10))
		}
	}
	pl := p.build()
	for _, ep := range pl.Endpoints {
		if ep.ServerOnly {
			continue
		}
		if _, ok := ep.Metadata["openapi"].(*jsonx.Object); !ok {
			t.Fatalf("%s: missing openapi metadata", ep.Key)
		}
	}
	// renamed table and column work end to end
	in := newInstance(t, Options{Schema: &SchemaOptions{ModelName: "api_keys", Fields: map[string]string{"referenceId": "owner_id"}}}, nil)
	s := in.signInWithTestUser()
	k := in.createKey(map[string]any{"userId": s.userID}, nil)
	eq(t, in.verify(map[string]any{"key": k["key"]})["valid"], true)
}
