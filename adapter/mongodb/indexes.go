package mongodb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"unicode/utf16"
	"unicode/utf8"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/nimi-io/better-auth-go/db"
)

// This file ports resolveDatabaseTableIndexes (packages/core/src/db/database-index.ts) and the
// ensureModelIndexes logic of mongodb-adapter.ts: table-level indexes declared in the schema
// are created lazily, once per definition, before the first write to a collection.

const (
	maxIndexNameBytes = 63
	maxIndexFields    = 16
)

var indexNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// resolvedIndex is a table index with physical column names and its database name.
type resolvedIndex struct {
	Columns []string
	Name    string
	Unique  bool
}

// stableIndexNameHash is the 32-bit FNV-1a hash over the UTF-16 code units of value.
func stableIndexNameHash(value string) string {
	hash := uint32(0x811c9dc5)
	for _, u := range utf16.Encode([]rune(value)) {
		hash ^= uint32(u)
		hash *= 0x01000193
	}
	return fmt.Sprintf("%08x", hash)
}

func truncateUTF8(value string, maxBytes int) string {
	n := 0
	for i, r := range value {
		w := utf8.RuneLen(r)
		if w < 0 {
			w = 3
		}
		if n+w > maxBytes {
			return value[:i]
		}
		n += w
	}
	return value
}

// sliceUTF16End drops the last n UTF-16 code units of s (s.slice(0, -n)).
func sliceUTF16End(s string, n int) string {
	units := utf16.Encode([]rune(s))
	if n >= len(units) {
		return ""
	}
	return string(utf16.Decode(units[:len(units)-n]))
}

// databaseIndexName ports getDatabaseIndexName.
func databaseIndexName(tableName string, columns []string, name string, unique bool) (string, error) {
	if name != "" {
		if strings.TrimSpace(name) == "" {
			return "", errors.New("Database index names must contain at least one visible character.")
		}
		if !indexNamePattern.MatchString(name) {
			return "", errors.New("Database index names must start with a letter or underscore and contain only letters, numbers, and underscores.")
		}
		if len(name) > maxIndexNameBytes {
			return "", fmt.Errorf("Database index names must be at most %d UTF-8 bytes.", maxIndexNameBytes)
		}
		return name, nil
	}
	kind := "idx"
	if unique {
		kind = "uidx"
	}
	generated := tableName + "_" + strings.Join(columns, "_") + "_" + kind
	if len(generated) <= maxIndexNameBytes {
		return generated, nil
	}
	suffix := "_" + stableIndexNameHash(generated) + "_" + kind
	return truncateUTF8(sliceUTF16End(generated, len(kind)+1), maxIndexNameBytes-len(suffix)) + suffix, nil
}

// resolveTableIndexes ports resolveDatabaseTableIndexes for one table.
func resolveTableIndexes(t *db.Table, tableName string) ([]resolvedIndex, error) {
	field := func(name string) (db.Field, bool) {
		for _, f := range t.Fields {
			if f.Name == name {
				return f, true
			}
		}
		return db.Field{}, false
	}
	resolved := make([]resolvedIndex, 0, len(t.Indexes))
	for _, idx := range t.Indexes {
		if len(idx.Fields) == 0 {
			return nil, fmt.Errorf("Index on table %q must include at least one field.", tableName)
		}
		if len(idx.Fields) > maxIndexFields {
			return nil, fmt.Errorf("Index on table %q can include at most %d fields so it works across supported databases.", tableName, maxIndexFields)
		}
		seen := map[string]bool{}
		for _, f := range idx.Fields {
			if seen[f] {
				return nil, fmt.Errorf("Index on table %q contains the same field more than once.", tableName)
			}
			seen[f] = true
		}
		if idx.Unique {
			for _, name := range idx.Fields {
				if f, ok := field(name); ok && f.IsOptional() {
					return nil, fmt.Errorf("Unique index on table %q can only include required fields so its behavior is consistent across databases.", tableName)
				}
			}
		}
		for _, name := range idx.Fields {
			if f, ok := field(name); ok {
				switch f.Type {
				case db.TypeJSON, db.TypeStringArray, db.TypeNumberArray:
					return nil, fmt.Errorf("Index on table %q references field %q, whose type is not portably indexable.", tableName, name)
				}
			}
		}
		columns := make([]string, len(idx.Fields))
		colSeen := map[string]bool{}
		for i, name := range idx.Fields {
			f, ok := field(name)
			if !ok {
				return nil, fmt.Errorf("Index on table %q references unknown field %q.", tableName, name)
			}
			columns[i] = f.Column()
			colSeen[strings.ToLower(columns[i])] = true
		}
		if len(colSeen) != len(columns) {
			return nil, fmt.Errorf("Index on table %q resolves more than one field to the same database column.", tableName)
		}
		name, err := databaseIndexName(tableName, columns, idx.Name, idx.Unique)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, resolvedIndex{Columns: columns, Name: name, Unique: idx.Unique})
	}
	definitions := map[string]string{}
	out := make([]resolvedIndex, 0, len(resolved))
	for _, idx := range resolved {
		def, _ := json.Marshal([]any{idx.Columns, idx.Unique})
		key := strings.ToLower(idx.Name)
		if existing, ok := definitions[key]; ok {
			if existing != string(def) {
				return nil, fmt.Errorf("Database index name %q identifies more than one index on table %q.", idx.Name, tableName)
			}
			continue
		}
		definitions[key] = string(def)
		out = append(out, idx)
	}
	return out, nil
}

// createIndexFunc creates one index on a collection.
type createIndexFunc func(ctx context.Context, coll *mongo.Collection, keys bson.D, name string, unique bool) error

func defaultCreateIndex(ctx context.Context, coll *mongo.Collection, keys bson.D, name string, unique bool) error {
	_, err := coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    keys,
		Options: options.Index().SetName(name).SetUnique(unique),
	})
	return err
}

// indexRegistry deduplicates index creation across every adapter instance created by one
// New call (indexSetupByDefinition upstream). Failed setups are forgotten so they are retried.
type indexRegistry struct {
	mu     sync.Mutex
	setups map[string]*indexSetup
	create createIndexFunc
}

type indexSetup struct {
	done chan struct{}
	err  error
}

func newIndexRegistry() *indexRegistry {
	return &indexRegistry{setups: map[string]*indexSetup{}, create: defaultCreateIndex}
}

func (r *indexRegistry) ensure(ctx context.Context, database *mongo.Database, model string, indexes []resolvedIndex) error {
	for _, idx := range indexes {
		fields := make([]string, len(idx.Columns))
		keys := make(bson.D, len(idx.Columns))
		for i, c := range idx.Columns {
			if c == "id" {
				c = "_id"
			}
			fields[i] = c
			keys[i] = bson.E{Key: c, Value: int32(1)}
		}
		defBytes, _ := json.Marshal([]any{model, idx.Name, fields, idx.Unique})
		def := string(defBytes)

		r.mu.Lock()
		setup, ok := r.setups[def]
		if !ok {
			setup = &indexSetup{done: make(chan struct{})}
			r.setups[def] = setup
		}
		r.mu.Unlock()

		if ok {
			select {
			case <-setup.done:
			case <-ctx.Done():
				return ctx.Err()
			}
			if setup.err != nil {
				return setup.err
			}
			continue
		}
		err := r.create(ctx, database.Collection(model), keys, idx.Name, idx.Unique)
		setup.err = err
		close(setup.done)
		if err != nil {
			r.mu.Lock()
			if r.setups[def] == setup {
				delete(r.setups, def)
			}
			r.mu.Unlock()
			return err
		}
	}
	return nil
}
