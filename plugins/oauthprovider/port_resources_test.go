package oauthprovider

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
)

// Port of resources.test.ts.

// rsLogger captures log lines per level.
type rsLogger struct {
	mu    sync.Mutex
	lines map[string][]string
}

func (l *rsLogger) add(level, msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lines == nil {
		l.lines = map[string][]string{}
	}
	if len(args) > 0 {
		msg += " " + fmt.Sprint(args...)
	}
	l.lines[level] = append(l.lines[level], msg)
}
func (l *rsLogger) Debug(msg string, args ...any) { l.add("debug", msg, args...) }
func (l *rsLogger) Info(msg string, args ...any)  { l.add("info", msg, args...) }
func (l *rsLogger) Warn(msg string, args ...any)  { l.add("warn", msg, args...) }
func (l *rsLogger) Error(msg string, args ...any) { l.add("error", msg, args...) }
func (l *rsLogger) get(level string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines[level]...)
}

func rsStrPtr(s string) *string { return &s }
func rsIntPtr(i int) *int       { return &i }

// rsBoot mirrors bootWithResourcesOption: a fresh instance whose seed state is reset and
// re-run after migrations.
func rsBoot(t *testing.T, opts Options, logger *rsLogger) *testEnv {
	t.Helper()
	eo := envOptions{}
	if logger != nil {
		eo.mutate = func(c *betterauth.Config) { c.Logger = logger }
	}
	env := newEnv(t, opts, eo)
	ResetSeedStateForTests(env.plugin)
	ac := env.auth.Context()
	o, err := pluginOptions(ac)
	if err != nil {
		t.Fatal(err)
	}
	if err := seedResourcesOnce(context.Background(), ac, o); err != nil {
		t.Fatal(err)
	}
	return env
}

func rsReadResource(env *testEnv, identifier string) adapter.Record {
	return env.findOne(modelResource, eq("identifier", identifier))
}

func rsResolved(t *testing.T, opts Options) *resolved {
	t.Helper()
	o, err := resolveOptions(opts)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func rsNum(v any) any {
	if v == nil {
		return nil
	}
	f, ok := adapter.ToFloat(v)
	if !ok {
		return v
	}
	return f
}

func TestRs_CollectResourceInputs(t *testing.T) {
	// Go's Options.Resources is already []ResourceInput: the string -> {identifier}
	// conversion of collectResourceInputs happens at the type level (the caller writes
	// ResourceInput{Identifier: ...}). The ported cases check the resolved inputs.
	t.Run("does not warn when resources is used", func(t *testing.T) {
		logger := &rsLogger{}
		rsBoot(t, Options{Resources: []ResourceInput{{Identifier: "https://api.example.com"}}}, logger)
		if w := logger.get("warn"); len(w) != 0 {
			t.Fatal(w)
		}
	})
	t.Run("converts string entries in resources to identifier-only inputs", func(t *testing.T) {
		o := rsResolved(t, Options{Resources: []ResourceInput{{Identifier: "https://a"}, {Identifier: "https://b", AccessTokenTTL: rsIntPtr(60)}}})
		want := []ResourceInput{{Identifier: "https://a"}, {Identifier: "https://b", AccessTokenTTL: rsIntPtr(60)}}
		if !reflect.DeepEqual(o.Resources, want) {
			t.Fatal(o.Resources)
		}
	})
	t.Run("preserves configured resource order", func(t *testing.T) {
		o := rsResolved(t, Options{Resources: []ResourceInput{{Identifier: "https://first"}, {Identifier: "https://second", AccessTokenTTL: rsIntPtr(300)}}})
		if len(o.Resources) != 2 || o.Resources[0].Identifier != "https://first" || o.Resources[1].Identifier != "https://second" ||
			*o.Resources[1].AccessTokenTTL != 300 {
			t.Fatal(o.Resources)
		}
	})
	t.Run("returns empty array when no resource config is provided", func(t *testing.T) {
		o := rsResolved(t, Options{})
		if len(o.Resources) != 0 {
			t.Fatal(o.Resources)
		}
	})
}

func TestRs_SeedResources(t *testing.T) {
	t.Run("seeds nothing when no resource config is set", func(t *testing.T) {
		env := rsBoot(t, Options{}, nil)
		if r := rsReadResource(env, "https://nope.example.com"); r != nil {
			t.Fatal(r)
		}
	})
	t.Run("seeds string-form `resources` entries with plugin defaults", func(t *testing.T) {
		env := rsBoot(t, Options{Resources: []ResourceInput{{Identifier: "https://api.example.com"}}}, nil)
		r := rsReadResource(env, "https://api.example.com")
		if r == nil || r["identifier"] != "https://api.example.com" || r["name"] != "https://api.example.com" ||
			r["disabled"] != false || rsNum(r["policyVersion"]) != float64(1) || r["accessTokenTtl"] != nil ||
			r["signingAlgorithm"] != nil || r["allowedScopes"] != nil {
			t.Fatal(r)
		}
	})
	t.Run("seeds object-form `resources` entries with explicit policy", func(t *testing.T) {
		env := rsBoot(t, Options{Resources: []ResourceInput{{Identifier: "https://api.example.com/admin", Name: rsStrPtr("Admin API"),
			AccessTokenTTL: rsIntPtr(300), AllowedScopes: []string{"admin:read", "admin:write"}, SigningAlgorithm: rsStrPtr("EdDSA")}}}, nil)
		r := rsReadResource(env, "https://api.example.com/admin")
		if r == nil || r["name"] != "Admin API" || rsNum(r["accessTokenTtl"]) != float64(300) ||
			!reflect.DeepEqual(recStrings(r, "allowedScopes"), []string{"admin:read", "admin:write"}) || r["signingAlgorithm"] != "EdDSA" {
			t.Fatal(r)
		}
	})
	t.Run("logs the enforcePerClientResources resolution at init", func(t *testing.T) {
		logger := &rsLogger{}
		rsBoot(t, Options{Resources: []ResourceInput{{Identifier: "https://api.example.com"}}}, logger)
		all := strings.Join(logger.get("info"), "\n")
		if !strings.Contains(all, "enforcePerClientResources resolved to true") || !strings.Contains(all, "default") {
			t.Fatal(all)
		}
	})
	t.Run("insertOnly (default) preserves existing rows when re-seeded", func(t *testing.T) {
		id := "https://api.example.com/insert-only"
		env := rsBoot(t, Options{Resources: []ResourceInput{{Identifier: id, Name: rsStrPtr("Original")}}}, nil)
		env.update(modelResource, adapter.Record{"name": "Admin edited"}, eq("identifier", id))
		if err := seedResources(context.Background(), env.auth.Context(),
			rsResolved(t, Options{Resources: []ResourceInput{{Identifier: id, Name: rsStrPtr("Config rename attempt")}}})); err != nil {
			t.Fatal(err)
		}
		if r := rsReadResource(env, id); r["name"] != "Admin edited" {
			t.Fatal(r)
		}
	})
	t.Run("merge mode updates only specified fields on existing rows", func(t *testing.T) {
		id := "https://api.example.com/merge"
		env := rsBoot(t, Options{Resources: []ResourceInput{{Identifier: id, Name: rsStrPtr("Original"), AccessTokenTTL: rsIntPtr(600),
			AllowedScopes: []string{"a", "b"}}}}, nil)
		if err := seedResources(context.Background(), env.auth.Context(),
			rsResolved(t, Options{Resources: []ResourceInput{{Identifier: id, AccessTokenTTL: rsIntPtr(120)}}, ResourceSeedMode: "merge"})); err != nil {
			t.Fatal(err)
		}
		r := rsReadResource(env, id)
		if r["name"] != "Original" || rsNum(r["accessTokenTtl"]) != float64(120) || !reflect.DeepEqual(recStrings(r, "allowedScopes"), []string{"a", "b"}) {
			t.Fatal(r)
		}
	})
	t.Run("overwrite mode replaces every field on existing rows", func(t *testing.T) {
		id := "https://api.example.com/overwrite"
		env := rsBoot(t, Options{Resources: []ResourceInput{{Identifier: id, Name: rsStrPtr("Original"), AccessTokenTTL: rsIntPtr(600),
			AllowedScopes: []string{"a", "b"}}}}, nil)
		if err := seedResources(context.Background(), env.auth.Context(),
			rsResolved(t, Options{Resources: []ResourceInput{{Identifier: id, AccessTokenTTL: rsIntPtr(120)}}, ResourceSeedMode: "overwrite"})); err != nil {
			t.Fatal(err)
		}
		r := rsReadResource(env, id)
		if r["name"] != id || rsNum(r["accessTokenTtl"]) != float64(120) || r["allowedScopes"] != nil {
			t.Fatal(r)
		}
	})
}

func TestRs_GetResourceCache(t *testing.T) {
	t.Run("returns the row from the DB when cache is not opt-in", func(t *testing.T) {
		id := "https://api.example.com/uncached"
		env := rsBoot(t, Options{Resources: []ResourceInput{{Identifier: id}}}, nil)
		ctx := &betterauth.EndpointContext{Auth: env.auth.Context()}
		r, err := getResource(ctx, rsResolved(t, Options{Resources: []ResourceInput{{Identifier: id}}}), id)
		if err != nil || r == nil || r.Identifier != id {
			t.Fatal(r, err)
		}
	})
	t.Run("caches when identifier is in cachedResources", func(t *testing.T) {
		id := "https://api.example.com/cached"
		env := rsBoot(t, Options{Resources: []ResourceInput{{Identifier: id}}, CachedResources: []string{id}}, nil)
		ctx := &betterauth.EndpointContext{Auth: env.auth.Context()}
		o := rsResolved(t, Options{Resources: []ResourceInput{{Identifier: id}}, CachedResources: []string{id}})
		defer o.resourceCache.invalidate("")
		first, err := getResource(ctx, o, id)
		if err != nil || first == nil || first.Identifier != id {
			t.Fatal(first, err)
		}
		env.update(modelResource, adapter.Record{"name": "Mutated externally"}, eq("identifier", id))
		second, _ := getResource(ctx, o, id)
		if second.Name != id {
			t.Fatal(second.Name)
		}
		o.resourceCache.invalidate(id)
		third, _ := getResource(ctx, o, id)
		if third.Name != "Mutated externally" {
			t.Fatal(third.Name)
		}
	})
}
