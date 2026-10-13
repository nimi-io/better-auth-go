package scim

// Port of upstream scim-group-list-query.test.ts ("SCIM Group collection queries").

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
)

// glqCountingAdapter is createQueryCountingAdapter: it counts findMany calls per model.
type glqCountingAdapter struct {
	adapter.Adapter
	mu    sync.Mutex
	calls map[string]int
}

func (a *glqCountingAdapter) FindMany(ctx context.Context, in adapter.FindManyInput) ([]adapter.Record, error) {
	a.mu.Lock()
	a.calls[in.Model]++
	a.mu.Unlock()
	return a.Adapter.FindMany(ctx, in)
}

func (a *glqCountingAdapter) count(model string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls[model]
}

func (a *glqCountingAdapter) reset() {
	a.mu.Lock()
	a.calls = map[string]int{}
	a.mu.Unlock()
}

func glqNewEnv(t *testing.T) (*testEnv, *glqCountingAdapter) {
	t.Helper()
	counter := &glqCountingAdapter{calls: map[string]int{}}
	e := newEnv(t, Options{Connections: []ConnectionOptions{staticConnection("workforce", "test-scim-token")}},
		envOptions{mutate: func(cfg *betterauth.Config) {
			inner := cfg.Database
			cfg.Database = func(o adapter.Options) (adapter.Adapter, error) {
				a, err := inner(o)
				if err != nil {
					return nil, err
				}
				counter.Adapter = a
				return counter, nil
			}
		}})
	return e, counter
}

func TestGroupListQuery_SCIMGroupCollectionQueries(t *testing.T) {
	headers := bearer("test-scim-token")

	t.Run("loads one page of Group memberships and Users in batches", func(t *testing.T) {
		e, queries := glqNewEnv(t)
		ada := e.mustCall("createSCIMUser", betterauth.CallInput{Headers: headers, Body: map[string]any{"schemas": []any{SchemaUser}, "userName": "ada@example.com"}})
		grace := e.mustCall("createSCIMUser", betterauth.CallInput{Headers: headers, Body: map[string]any{"schemas": []any{SchemaUser}, "userName": "grace@example.com"}})
		e.mustCall("createSCIMGroup", betterauth.CallInput{Headers: headers, Body: map[string]any{
			"schemas": []any{SchemaGroup}, "displayName": "Engineering",
			"members": []any{map[string]any{"value": ada["id"]}, map[string]any{"value": grace["id"]}},
		}})
		// Groups are listed by orderKey (creation millisecond + random suffix); keep the two
		// creations in distinct milliseconds so the upstream [2, 1] order is deterministic.
		time.Sleep(2 * time.Millisecond)
		e.mustCall("createSCIMGroup", betterauth.CallInput{Headers: headers, Body: map[string]any{
			"schemas": []any{SchemaGroup}, "displayName": "Research",
			"members": []any{map[string]any{"value": grace["id"]}},
		}})
		queries.reset()

		page := e.mustCall("listSCIMGroups", betterauth.CallInput{Headers: headers})
		resources, _ := page["Resources"].([]any)
		if len(resources) != 2 {
			t.Fatalf("Resources = %v", page["Resources"])
		}
		var lens []int
		for _, r := range resources {
			m, _ := r.(map[string]any)["members"].([]any)
			lens = append(lens, len(m))
		}
		if fmt.Sprint(lens) != "[2 1]" {
			t.Fatalf("member counts = %v", lens)
		}
		if n := queries.count("scimGroupMember"); n != 1 {
			t.Fatalf("scimGroupMember findMany calls = %d, want 1", n)
		}
		if n := queries.count("scimUser"); n != 1 {
			t.Fatalf("scimUser findMany calls = %d, want 1", n)
		}
	})

	t.Run("rejects an over-limit Group in a batched collection response", func(t *testing.T) {
		e, _ := glqNewEnv(t)
		overLimit := e.mustCall("createSCIMGroup", betterauth.CallInput{Headers: headers, Body: map[string]any{"schemas": []any{SchemaGroup}, "displayName": "Over limit"}})
		e.mustCall("createSCIMGroup", betterauth.CallInput{Headers: headers, Body: map[string]any{"schemas": []any{SchemaGroup}, "displayName": "Within limit"}})
		createdAt := time.Now()
		for i := 0; i < 1_001; i++ {
			e.insert("scimGroupMember", adapter.Record{
				"id":            fmt.Sprintf("membership-%d", i),
				"connectionId":  "workforce",
				"groupId":       overLimit["id"],
				"scimUserId":    fmt.Sprintf("user-%d", i),
				"membershipKey": fmt.Sprintf("membership-key-%d", i),
				"createdAt":     createdAt,
			})
		}
		_, ae := e.call("listSCIMGroups", betterauth.CallInput{Headers: headers})
		if ae == nil {
			t.Fatal("expected error")
		}
		if ae.StatusCode != 500 {
			t.Fatalf("status = %d", ae.StatusCode)
		}
		rapMatchObject(t, errBody(ae), `{"status":"500"}`)
	})
}
