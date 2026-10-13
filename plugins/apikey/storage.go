package apikey

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

const storageConcurrency = 10

func storageKeyByHashedKey(h string) string { return "api-key:" + h }
func storageKeyByID(id string) string       { return "api-key:by-id:" + id }
func storageKeyByReferenceID(r string) string {
	return "api-key:by-ref:" + r
}

// serializeAPIKey is JSON.stringify({...apiKey, dates as ISO strings}).
func serializeAPIKey(k *APIKey) string {
	o := k.object()
	for _, f := range []string{"createdAt", "updatedAt", "expiresAt", "lastRefillAt", "lastRequest"} {
		v, _ := o.Get(f)
		if t, ok := v.(time.Time); ok {
			o.Set(f, jsonx.ISOTime(t))
		}
	}
	s, _ := jsonx.Stringify(o)
	return s
}

func deserializeAPIKey(data string, ok bool) *APIKey {
	if !ok || data == "" {
		return nil
	}
	v, err := jsonx.Parse([]byte(data))
	if err != nil {
		return nil
	}
	obj, isObj := v.(*jsonx.Object)
	if !isObj {
		return nil
	}
	return keyFromRecord(obj)
}

func (p *plugin) storageFor(ctx *betterauth.EndpointContext, c *config) betterauth.SecondaryStorage {
	if c.CustomStorage != nil {
		return c.CustomStorage
	}
	return ctx.Auth.SecondaryStorage
}

func (p *plugin) ttlFor(k *APIKey) time.Duration {
	if k.ExpiresAt != nil {
		secs := math.Floor(float64(k.ExpiresAt.Sub(p.now()).Milliseconds()) / 1000)
		if secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return 0
}

func (p *plugin) getFromStorage(ctx context.Context, st betterauth.SecondaryStorage, key string) (*APIKey, error) {
	data, ok, err := st.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	return deserializeAPIKey(data, ok), nil
}

// keyedLocks serializes read-modify-write cycles on a reference list (refListLocks).
var keyedLocks = struct {
	mu    sync.Mutex
	locks map[string]*keyedLock
}{locks: map[string]*keyedLock{}}

type keyedLock struct {
	mu   sync.Mutex
	refs int
}

func withRefListLock(key string, fn func() error) error {
	keyedLocks.mu.Lock()
	l := keyedLocks.locks[key]
	if l == nil {
		l = &keyedLock{}
		keyedLocks.locks[key] = l
	}
	l.refs++
	keyedLocks.mu.Unlock()
	l.mu.Lock()
	defer func() {
		l.mu.Unlock()
		keyedLocks.mu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(keyedLocks.locks, key)
		}
		keyedLocks.mu.Unlock()
	}()
	return fn()
}

func parseIDList(data string, ok bool) ([]string, bool) {
	if !ok || data == "" {
		return nil, false
	}
	var ids []string
	if err := json.Unmarshal([]byte(data), &ids); err != nil {
		return nil, false
	}
	return ids, true
}

func modifyRefList(ctx context.Context, st betterauth.SecondaryStorage, refKey string, modify func([]string) []string) error {
	return withRefListLock(refKey, func() error {
		data, ok, err := st.Get(ctx, refKey)
		if err != nil {
			return err
		}
		ids, _ := parseIDList(data, ok)
		next := modify(ids)
		if len(next) == 0 {
			return st.Delete(ctx, refKey)
		}
		b, _ := jsonx.Stringify(next)
		return st.Set(ctx, refKey, b, 0)
	})
}

// parallel runs fns concurrently and returns the first error.
func parallel(fns ...func() error) error {
	var wg sync.WaitGroup
	errs := make([]error, len(fns))
	for i, fn := range fns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = fn()
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// mapConcurrent runs fn over items with bounded concurrency, preserving order.
func mapConcurrent[T, R any](items []T, limit int, fn func(T) (R, error)) ([]R, error) {
	out := make([]R, len(items))
	errs := make([]error, len(items))
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i, it := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			out[i], errs[i] = fn(it)
		}()
	}
	wg.Wait()
	return out, errors.Join(errs...)
}

func (p *plugin) setInStorage(ctx context.Context, k *APIKey, st betterauth.SecondaryStorage, ttl time.Duration, c *config) error {
	serialized := serializeAPIKey(k)
	refKey := storageKeyByReferenceID(k.ReferenceID)
	if c.FallbackToDatabase {
		return parallel(
			func() error { return st.Set(ctx, storageKeyByHashedKey(k.Key), serialized, ttl) },
			func() error { return st.Set(ctx, storageKeyByID(k.ID), serialized, ttl) },
			func() error { return st.Delete(ctx, refKey) },
		)
	}
	if err := parallel(
		func() error { return st.Set(ctx, storageKeyByHashedKey(k.Key), serialized, ttl) },
		func() error { return st.Set(ctx, storageKeyByID(k.ID), serialized, ttl) },
	); err != nil {
		return err
	}
	return modifyRefList(ctx, st, refKey, func(ids []string) []string {
		if slices.Contains(ids, k.ID) {
			return ids
		}
		return append(ids, k.ID)
	})
}

func (p *plugin) deleteFromStorage(ctx context.Context, k *APIKey, st betterauth.SecondaryStorage, c *config) error {
	refKey := storageKeyByReferenceID(k.ReferenceID)
	if c.FallbackToDatabase {
		return parallel(
			func() error { return st.Delete(ctx, storageKeyByHashedKey(k.Key)) },
			func() error { return st.Delete(ctx, storageKeyByID(k.ID)) },
			func() error { return st.Delete(ctx, refKey) },
		)
	}
	return parallel(
		func() error { return st.Delete(ctx, storageKeyByHashedKey(k.Key)) },
		func() error { return st.Delete(ctx, storageKeyByID(k.ID)) },
		func() error {
			return modifyRefList(ctx, st, refKey, func(ids []string) []string {
				return slices.DeleteFunc(slices.Clone(ids), func(id string) bool { return id == k.ID })
			})
		},
	)
}

func (p *plugin) dbFindOne(ctx *betterauth.EndpointContext, field, value string) (*APIKey, error) {
	rec, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: TableName,
		Where: []adapter.Where{{Field: field, Value: value}}})
	if err != nil || rec == nil {
		return nil, err
	}
	return keyFromRecord(rec), nil
}

// lookup implements getApiKey / getApiKeyById of adapter.ts (field "key" or "id").
func (p *plugin) lookup(ctx *betterauth.EndpointContext, field, value string, c *config) (*APIKey, error) {
	st := p.storageFor(ctx, c)
	storageKey := storageKeyByHashedKey(value)
	if field == "id" {
		storageKey = storageKeyByID(value)
	}
	switch {
	case c.storage == StorageDatabase:
		return p.dbFindOne(ctx, field, value)
	case c.storage == StorageSecondary && c.FallbackToDatabase:
		if st != nil {
			cached, err := p.getFromStorage(ctx.Context(), st, storageKey)
			if err != nil {
				return nil, err
			}
			if cached != nil {
				return cached, nil
			}
		}
		k, err := p.dbFindOne(ctx, field, value)
		if err != nil {
			return nil, err
		}
		if k != nil && st != nil {
			if err := p.setInStorage(ctx.Context(), k, st, p.ttlFor(k), c); err != nil {
				return nil, err
			}
		}
		return k, nil
	case c.storage == StorageSecondary:
		if st == nil {
			return nil, nil
		}
		return p.getFromStorage(ctx.Context(), st, storageKey)
	}
	return p.dbFindOne(ctx, field, value)
}

func (p *plugin) getByHash(ctx *betterauth.EndpointContext, hashed string, c *config) (*APIKey, error) {
	return p.lookup(ctx, "key", hashed, c)
}

func (p *plugin) getByID(ctx *betterauth.EndpointContext, id string, c *config) (*APIKey, error) {
	return p.lookup(ctx, "id", id, c)
}

var errNoSecondaryStorage = errors.New("Secondary storage is required when storage mode is 'secondary-storage'")

// setKey writes the key to secondary storage (setApiKey; no-op for database storage).
func (p *plugin) setKey(ctx *betterauth.EndpointContext, k *APIKey, c *config) error {
	if c.storage != StorageSecondary {
		return nil
	}
	st := p.storageFor(ctx, c)
	if st == nil {
		return errNoSecondaryStorage
	}
	return p.setInStorage(ctx.Context(), k, st, p.ttlFor(k), c)
}

// deleteKey removes the key from secondary storage (deleteApiKey of adapter.ts).
func (p *plugin) deleteKey(ctx *betterauth.EndpointContext, k *APIKey, c *config) error {
	if c.storage != StorageSecondary {
		return nil
	}
	st := p.storageFor(ctx, c)
	if st == nil {
		return errNoSecondaryStorage
	}
	return p.deleteFromStorage(ctx.Context(), k, st, c)
}

type listOptions struct {
	sortBy        string
	sortDirection string
}

func compareValues(a, b any) int {
	switch x := a.(type) {
	case time.Time:
		if y, ok := b.(time.Time); ok {
			return x.Compare(y)
		}
	case string:
		if y, ok := b.(string); ok {
			switch {
			case x < y:
				return -1
			case x > y:
				return 1
			}
			return 0
		}
	case float64:
		if y, ok := b.(float64); ok {
			switch {
			case x < y:
				return -1
			case x > y:
				return 1
			}
			return 0
		}
	case bool:
		if y, ok := b.(bool); ok {
			switch {
			case !x && y:
				return -1
			case x && !y:
				return 1
			}
			return 0
		}
	}
	if c, ok := adapter.Compare(a, b); ok {
		return c
	}
	return 0
}

// sortKeys is applySortingAndPagination without pagination (the route paginates).
func sortKeys(keys []*APIKey, o listOptions) []*APIKey {
	out := slices.Clone(keys)
	if o.sortBy == "" {
		return out
	}
	asc := o.sortDirection != "desc"
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].get(o.sortBy), out[j].get(o.sortBy)
		var c int
		switch {
		case a == nil && b == nil:
			c = 0
		case a == nil:
			c = -1
		case b == nil:
			c = 1
		default:
			c = compareValues(a, b)
		}
		if !asc {
			c = -c
		}
		return c < 0
	})
	return out
}

func (p *plugin) dbList(ctx *betterauth.EndpointContext, referenceID string, o listOptions) ([]*APIKey, error) {
	in := adapter.FindManyInput{Model: TableName, Where: []adapter.Where{{Field: "referenceId", Value: referenceID}}}
	if o.sortBy != "" {
		dir := o.sortDirection
		if dir == "" {
			dir = "asc"
		}
		in.SortBy = &adapter.SortBy{Field: o.sortBy, Direction: dir}
	}
	recs, err := ctx.Auth.Adapter.FindMany(ctx.Context(), in)
	if err != nil {
		return nil, err
	}
	out := make([]*APIKey, 0, len(recs))
	for _, r := range recs {
		out = append(out, keyFromRecord(r))
	}
	return out, nil
}

func (p *plugin) keysByIDs(ctx context.Context, st betterauth.SecondaryStorage, ids []string) ([]*APIKey, error) {
	res, err := mapConcurrent(ids, storageConcurrency, func(id string) (*APIKey, error) {
		return p.getFromStorage(ctx, st, storageKeyByID(id))
	})
	if err != nil {
		return nil, err
	}
	out := make([]*APIKey, 0, len(res))
	for _, k := range res {
		if k != nil {
			out = append(out, k)
		}
	}
	return out, nil
}

// list implements listApiKeys of adapter.ts (pagination is applied by the route).
func (p *plugin) list(ctx *betterauth.EndpointContext, referenceID string, c *config, o listOptions) ([]*APIKey, error) {
	st := p.storageFor(ctx, c)
	switch {
	case c.storage == StorageDatabase:
		return p.dbList(ctx, referenceID, o)
	case c.storage == StorageSecondary && c.FallbackToDatabase:
		refKey := storageKeyByReferenceID(referenceID)
		if st != nil {
			data, ok, err := st.Get(ctx.Context(), refKey)
			if err != nil {
				return nil, err
			}
			ids, _ := parseIDList(data, ok)
			if len(ids) > 0 {
				keys, err := p.keysByIDs(ctx.Context(), st, ids)
				if err != nil {
					return nil, err
				}
				return sortKeys(keys, o), nil
			}
		}
		keys, err := p.dbList(ctx, referenceID, o)
		if err != nil {
			return nil, err
		}
		if st != nil && len(keys) > 0 {
			if _, err := mapConcurrent(keys, storageConcurrency, func(k *APIKey) (struct{}, error) {
				return struct{}{}, p.setInStorage(ctx.Context(), k, st, p.ttlFor(k), c)
			}); err != nil {
				return nil, err
			}
			ids := make([]string, len(keys))
			for i, k := range keys {
				ids[i] = k.ID
			}
			b, _ := jsonx.Stringify(ids)
			if err := st.Set(ctx.Context(), refKey, b, 0); err != nil {
				return nil, err
			}
		}
		return keys, nil
	case c.storage == StorageSecondary:
		if st == nil {
			return nil, nil
		}
		data, ok, err := st.Get(ctx.Context(), storageKeyByReferenceID(referenceID))
		if err != nil {
			return nil, err
		}
		ids, valid := parseIDList(data, ok)
		if !valid {
			return nil, nil
		}
		keys, err := p.keysByIDs(ctx.Context(), st, ids)
		if err != nil {
			return nil, err
		}
		return sortKeys(keys, o), nil
	}
	return p.dbList(ctx, referenceID, o)
}

// migrateMetadata rewrites double-stringified metadata when the key lives in the database
// (migrateDoubleStringifiedMetadata) and returns the parsed metadata.
func (p *plugin) migrateMetadata(ctx *betterauth.EndpointContext, k *APIKey, c *config) any {
	parsed := parseDoubleStringifiedMetadata(k.Metadata)
	if needsMetadataMigration(k.Metadata) && (c.storage == StorageDatabase || c.FallbackToDatabase) {
		if _, err := ctx.Auth.Adapter.Update(ctx.Context(), TableName,
			[]adapter.Where{{Field: "id", Value: k.ID}}, adapter.Record{"metadata": parsed}); err != nil {
			ctx.Auth.Logger.Warn("Failed to migrate double-stringified metadata for API key "+k.ID+":", err)
		}
	}
	return parsed
}

// batchMigrateMetadata is batchMigrateLegacyMetadata.
func (p *plugin) batchMigrateMetadata(ctx *betterauth.EndpointContext, keys []*APIKey, c *config) {
	if c.storage != StorageDatabase && !c.FallbackToDatabase {
		return
	}
	var todo []*APIKey
	for _, k := range keys {
		if needsMetadataMigration(k.Metadata) {
			todo = append(todo, k)
		}
	}
	if len(todo) == 0 {
		return
	}
	var wg sync.WaitGroup
	for _, k := range todo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			parsed := parseDoubleStringifiedMetadata(k.Metadata)
			if _, err := ctx.Auth.Adapter.Update(ctx.Context(), TableName,
				[]adapter.Where{{Field: "id", Value: k.ID}}, adapter.Record{"metadata": parsed}); err != nil {
				ctx.Auth.Logger.Warn("Failed to migrate double-stringified metadata for API key "+k.ID+":", err)
			}
		}()
	}
	wg.Wait()
}
