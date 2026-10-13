package migration

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/nimi-io/better-auth-go/db"
)

// This file ports the parts of packages/core/src/db/database-index.ts and
// packages/better-auth/src/db/get-schema.ts that getMigrations relies on: the physical schema
// (tables keyed by model name, fields keyed by column name) with resolved indexes.

const (
	maxDatabaseIndexNameBytes = 63
	maxDatabaseIndexFields    = 16
)

// SchemaError is a schema or index definition problem (BetterAuthError upstream). It is
// distinct from *UnsafeMigrationError.
type SchemaError struct{ Message string }

func (e *SchemaError) Error() string { return e.Message }

func schemaErrorf(format string, args ...any) error {
	return &SchemaError{Message: fmt.Sprintf(format, args...)}
}

// resolvedIndex is a table-level index with physical column names (ResolvedDBTableIndex).
type resolvedIndex struct {
	Columns []string
	Name    string
	Unique  bool
}

// physField is a field of the physical schema: the column name and its attributes, with
// references rewritten to the referenced table's model name (getSchema).
type physField struct {
	Column string
	Field  db.Field
}

// physTable is a table of the physical schema (an entry of getSchema's result).
type physTable struct {
	Name              string
	Fields            []physField
	Indexes           []resolvedIndex
	Order             int // 0 means unordered (Infinity upstream)
	DisableMigrations bool
}

func (t *physTable) field(column string) (db.Field, bool) {
	for _, f := range t.Fields {
		if f.Column == column {
			return f.Field, true
		}
	}
	return db.Field{}, false
}

// setField assigns a field by column name with JavaScript object-spread semantics: an
// existing key keeps its position.
func (t *physTable) setField(column string, f db.Field) {
	for i := range t.Fields {
		if t.Fields[i].Column == column {
			t.Fields[i].Field = f
			return
		}
	}
	t.Fields = append(t.Fields, physField{Column: column, Field: f})
}

// physicalSchema ports getSchema: it keys tables by model name and fields by column name,
// merges logical tables that share a model name and attaches the resolved indexes.
func physicalSchema(schema *db.Schema) ([]*physTable, error) {
	indexesByTable, err := resolveDatabaseSchemaIndexes(schema)
	if err != nil {
		return nil, err
	}
	var out []*physTable
	byName := map[string]*physTable{}
	for _, t := range schema.Tables {
		var fields []physField
		set := func(column string, f db.Field) {
			for i := range fields {
				if fields[i].Column == column {
					fields[i].Field = f
					return
				}
			}
			fields = append(fields, physField{Column: column, Field: f})
		}
		for _, f := range t.Fields {
			if f.References != nil {
				if ref := schema.Table(f.References.Model); ref != nil {
					r := *f.References
					r.Model = modelName(ref)
					f.References = &r
				}
			}
			set(f.Column(), f)
		}
		name := modelName(t)
		if existing, ok := byName[name]; ok {
			for _, f := range fields {
				existing.setField(f.Column, f.Field)
			}
			if t.DisableMigrations {
				existing.DisableMigrations = true
			}
			continue
		}
		pt := &physTable{Name: name, Fields: fields, Order: t.Order, DisableMigrations: t.DisableMigrations}
		byName[name] = pt
		out = append(out, pt)
	}
	for _, pt := range out {
		if idx, ok := indexesByTable[pt.Name]; ok {
			pt.Indexes = idx
		}
	}
	return out, nil
}

func modelName(t *db.Table) string {
	if t.ModelName != "" {
		return t.ModelName
	}
	return t.Key
}

// portableIdentifierKey is getPortableDatabaseIdentifierKey.
func portableIdentifierKey(identifier string) string { return strings.ToLower(identifier) }

// stableIndexNameHash is getStableIndexNameHash: 32-bit FNV-1a over UTF-16 code units.
func stableIndexNameHash(value string) string {
	hash := uint32(0x811c9dc5)
	for _, unit := range utf16.Encode([]rune(value)) {
		hash ^= uint32(unit)
		hash *= 0x01000193
	}
	return fmt.Sprintf("%08x", hash)
}

func truncateUTF8(value string, maxBytes int) string {
	var b strings.Builder
	n := 0
	for _, r := range value {
		l := utf8.RuneLen(r)
		if l < 0 {
			l = 3
		}
		if n+l > maxBytes {
			break
		}
		b.WriteRune(r)
		n += l
	}
	return b.String()
}

var indexNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// databaseIndexName is getDatabaseIndexName.
func databaseIndexName(tableName string, fields []string, name *string, unique bool) (string, error) {
	if name != nil {
		n := *name
		if strings.TrimSpace(n) == "" {
			return "", schemaErrorf("Database index names must contain at least one visible character.")
		}
		if !indexNamePattern.MatchString(n) {
			return "", schemaErrorf("Database index names must start with a letter or underscore and contain only letters, numbers, and underscores.")
		}
		if len(n) > maxDatabaseIndexNameBytes {
			return "", schemaErrorf("Database index names must be at most %d UTF-8 bytes.", maxDatabaseIndexNameBytes)
		}
		return n, nil
	}
	kind := "idx"
	if unique {
		kind = "uidx"
	}
	generated := tableName + "_" + strings.Join(fields, "_") + "_" + kind
	if len(generated) <= maxDatabaseIndexNameBytes {
		return generated, nil
	}
	suffix := "_" + stableIndexNameHash(generated) + "_" + kind
	// generatedName.slice(0, -kind.length - 1): kind is ASCII, so a byte slice is exact.
	base := generated[:len(generated)-len(kind)-1]
	return truncateUTF8(base, maxDatabaseIndexNameBytes-len(suffix)) + suffix, nil
}

// fieldIndexName is getDatabaseFieldIndexName.
func fieldIndexName(tableName, column string, unique bool) string {
	n, _ := databaseIndexName(tableName, []string{column}, nil, unique)
	return n
}

type indexSource struct {
	tableName string
	fields    []db.Field // logical fields, object-spread merged
	indexes   []db.Index
}

func (s *indexSource) field(name string) (db.Field, bool) {
	for _, f := range s.fields {
		if f.Name == name {
			return f, true
		}
	}
	return db.Field{}, false
}

func mergeLogicalFields(dst []db.Field, src []db.Field) []db.Field {
	for _, f := range src {
		replaced := false
		for i := range dst {
			if dst[i].Name == f.Name {
				dst[i] = f
				replaced = true
				break
			}
		}
		if !replaced {
			dst = append(dst, f)
		}
	}
	return dst
}

// resolveDatabaseSchemaIndexes ports resolveDatabaseSchemaIndexes (as called by
// getAuthTablesWithResolvedIndexes): tables with migrations disabled are skipped.
func resolveDatabaseSchemaIndexes(schema *db.Schema) (map[string][]resolvedIndex, error) {
	var order []string
	merged := map[string]*indexSource{}
	for _, t := range schema.Tables {
		if t.DisableMigrations {
			continue
		}
		name := modelName(t)
		if existing, ok := merged[name]; ok {
			if len(existing.indexes) > 0 || len(t.Indexes) > 0 {
				return nil, schemaErrorf("Database schema resolves more than one indexed logical table to %q. Define table-level indexes through one logical schema key instead of aliasing multiple keys to the same database table.", name)
			}
			existing.fields = mergeLogicalFields(existing.fields, t.Fields)
			continue
		}
		src := &indexSource{tableName: name, fields: mergeLogicalFields(nil, t.Fields)}
		src.indexes = append(src.indexes, t.Indexes...)
		merged[name] = src
		order = append(order, name)
	}

	tableNamesByIdentifier := map[string]string{}
	for _, name := range order {
		tableNamesByIdentifier[portableIdentifierKey(name)] = name
	}
	fieldIndexOwnerByName := map[string]string{}
	for _, name := range order {
		src := merged[name]
		for _, f := range src.fields {
			if !f.Index && !f.Unique {
				continue
			}
			indexName := fieldIndexName(src.tableName, f.Column(), f.Unique)
			key := portableIdentifierKey(indexName)
			if _, ok := tableNamesByIdentifier[key]; ok {
				return nil, schemaErrorf("Database index name %q conflicts with a table name. Index and table names must be unique across the schema.", indexName)
			}
			if owner, ok := fieldIndexOwnerByName[key]; ok {
				return nil, schemaErrorf("Database field-level index name %q is used by both table %q and table %q.", indexName, owner, src.tableName)
			}
			fieldIndexOwnerByName[key] = src.tableName
		}
	}

	out := map[string][]resolvedIndex{}
	indexOwnerByName := map[string]string{}
	for _, name := range order {
		src := merged[name]
		resolved, err := resolveDatabaseTableIndexes(src)
		if err != nil {
			return nil, err
		}
		out[src.tableName] = resolved
		for _, index := range resolved {
			key := portableIdentifierKey(index.Name)
			if _, ok := tableNamesByIdentifier[key]; ok {
				return nil, schemaErrorf("Database index name %q conflicts with a table name. Index and table names must be unique across the schema.", index.Name)
			}
			if owner, ok := fieldIndexOwnerByName[key]; ok {
				return nil, schemaErrorf("Database index name %q is already reserved by field-level index metadata on table %q. Remove the duplicate table-level index or give it a distinct name.", index.Name, owner)
			}
			if owner, ok := indexOwnerByName[key]; ok && owner != src.tableName {
				return nil, schemaErrorf("Database index name %q is used by both table %q and table %q. Index names must be unique across the schema.", index.Name, owner, src.tableName)
			}
			indexOwnerByName[key] = src.tableName
		}
	}
	return out, nil
}

// resolveDatabaseTableIndexes ports resolveDatabaseTableIndexes.
func resolveDatabaseTableIndexes(src *indexSource) ([]resolvedIndex, error) {
	table := src.tableName
	var resolved []resolvedIndex
	for _, index := range src.indexes {
		if len(index.Fields) == 0 {
			return nil, schemaErrorf("Index on table %q must include at least one field.", table)
		}
		if len(index.Fields) > maxDatabaseIndexFields {
			return nil, schemaErrorf("Index on table %q can include at most %d fields so it works across supported databases.", table, maxDatabaseIndexFields)
		}
		seen := map[string]bool{}
		for _, f := range index.Fields {
			if seen[f] {
				return nil, schemaErrorf("Index on table %q contains the same field more than once.", table)
			}
			seen[f] = true
		}
		if index.Unique {
			for _, name := range index.Fields {
				if f, ok := src.field(name); ok && f.IsOptional() {
					return nil, schemaErrorf("Unique index on table %q can only include required fields so its behavior is consistent across databases.", table)
				}
			}
		}
		for _, name := range index.Fields {
			if f, ok := src.field(name); ok {
				switch f.Type {
				case db.TypeJSON, db.TypeStringArray, db.TypeNumberArray:
					return nil, schemaErrorf("Index on table %q references field %q, whose type is not portably indexable.", table, name)
				}
			}
		}
		columns := make([]string, 0, len(index.Fields))
		for _, name := range index.Fields {
			f, ok := src.field(name)
			if !ok {
				return nil, schemaErrorf("Index on table %q references unknown field %q.", table, name)
			}
			columns = append(columns, f.Column())
		}
		portable := map[string]bool{}
		for _, c := range columns {
			portable[portableIdentifierKey(c)] = true
		}
		if len(portable) != len(columns) {
			return nil, schemaErrorf("Index on table %q resolves more than one field to the same database column.", table)
		}
		var namePtr *string
		if index.Name != "" {
			n := index.Name
			namePtr = &n
		}
		name, err := databaseIndexName(table, columns, namePtr, index.Unique)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, resolvedIndex{Columns: columns, Name: name, Unique: index.Unique})
	}
	definitionsByName := map[string]string{}
	var out []resolvedIndex
	for _, index := range resolved {
		def, _ := json.Marshal([]any{index.Columns, index.Unique})
		key := portableIdentifierKey(index.Name)
		if existing, ok := definitionsByName[key]; ok {
			if existing != string(def) {
				return nil, schemaErrorf("Database index name %q identifies more than one index on table %q.", index.Name, table)
			}
			continue
		}
		definitionsByName[key] = string(def)
		out = append(out, index)
	}
	return out, nil
}

// indexStringLength is getDatabaseIndexStringLength for the bounded dialects (MySQL and
// SQL Server); ok is false when the column is in no table-level index.
func indexStringLength(t *physTable, column string, d boundedDialect) (int, bool) {
	var containing []resolvedIndex
	for _, index := range t.Indexes {
		for _, c := range index.Columns {
			if c == column {
				containing = append(containing, index)
				break
			}
		}
	}
	if len(containing) == 0 {
		return 0, false
	}
	budget, bytesPerChar, length := 1700, 1, 255
	if d == boundedMySQL {
		budget, bytesPerChar, length = 3072, 4, 191
	}
	for _, index := range containing {
		stringColumns := 0
		for _, c := range index.Columns {
			if f, ok := t.field(c); ok && isStringType(f.Type) {
				stringColumns++
			}
		}
		if stringColumns == 0 {
			continue
		}
		nonString := (len(index.Columns) - stringColumns) * 16
		safe := max(1, budget-nonString) / bytesPerChar / stringColumns
		length = min(length, safe)
	}
	return length, true
}

type boundedDialect int

const (
	boundedMySQL boundedDialect = iota
	boundedMSSQL
)

func isStringType(t db.FieldType) bool { return t == db.TypeString || t == db.TypeEnum }
