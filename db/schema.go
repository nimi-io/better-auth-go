// Package db describes the Better Auth database schema: field and table definitions,
// plugin schemas, and the default auth tables (user, session, account, verification,
// rateLimit). It mirrors packages/core/src/db (get-tables.ts, type.ts).
package db

import (
	"fmt"
	"time"
)

// FieldType is the logical type of a column.
type FieldType string

// Field types (DBFieldType).
const (
	TypeString      FieldType = "string"
	TypeNumber      FieldType = "number"
	TypeBoolean     FieldType = "boolean"
	TypeDate        FieldType = "date"
	TypeJSON        FieldType = "json"
	TypeStringArray FieldType = "string[]"
	TypeNumberArray FieldType = "number[]"
	// TypeEnum is a string restricted to Field.Enum values (Array<LiteralString> upstream).
	TypeEnum FieldType = "enum"
)

// OnDelete actions for references.
const (
	OnDeleteNoAction   = "no action"
	OnDeleteRestrict   = "restrict"
	OnDeleteCascade    = "cascade"
	OnDeleteSetNull    = "set null"
	OnDeleteSetDefault = "set default"
)

// Reference is a foreign key.
type Reference struct {
	Model    string
	Field    string
	OnDelete string
}

// Field is a column definition (DBFieldAttribute). Name is the logical key used by Better
// Auth; FieldName is the physical column name (defaults to Name).
type Field struct {
	Name string
	Type FieldType
	Enum []string
	// Required is tri-state like upstream's `required`: nil (unset) makes the column NOT NULL
	// in migrations but leaves the field optional in input validation; use True / False to
	// set it explicitly. See IsRequired, NotNull and IsOptional.
	Required  *bool
	FieldName string
	// Returned=false hides the field from API output (returned: false upstream).
	Returned *bool
	// Input=false rejects the field in user input (input: false upstream).
	Input *bool
	// DefaultValue is a static default; DefaultFunc is called when set (takes precedence).
	DefaultValue any
	DefaultFunc  func() any
	// OnUpdate supplies a value on every update when none is given.
	OnUpdate        func() any
	TransformInput  func(any) (any, error)
	TransformOutput func(any) (any, error)
	// Validator validates user input for this field; return an error message on failure.
	Validator  func(any) (any, error)
	References *Reference
	Unique     bool
	BigInt     bool
	Sortable   bool
	Index      bool
}

// IsRequired reports `required === true` (input validation, defaults on create).
func (f Field) IsRequired() bool { return f.Required != nil && *f.Required }

// NotNull reports `required !== false`: unset or true (migrations create NOT NULL columns).
func (f Field) NotNull() bool { return f.Required == nil || *f.Required }

// IsOptional reports `required === false`.
func (f Field) IsOptional() bool { return f.Required != nil && !*f.Required }

// Bool returns a pointer to b (for Field.Required, Returned and Input).
func Bool(b bool) *bool { return &b }

// IsReturned reports whether the field appears in API output.
func (f Field) IsReturned() bool { return f.Returned == nil || *f.Returned }

// IsInput reports whether the field may be set from user input.
func (f Field) IsInput() bool { return f.Input == nil || *f.Input }

// HasDefault reports whether the field has a default value.
func (f Field) HasDefault() bool { return f.DefaultFunc != nil || f.DefaultValue != nil }

// Default evaluates the default value.
func (f Field) Default() any {
	if f.DefaultFunc != nil {
		return f.DefaultFunc()
	}
	return f.DefaultValue
}

// Column returns the physical column name.
func (f Field) Column() string {
	if f.FieldName != "" {
		return f.FieldName
	}
	return f.Name
}

// Index is a table index.
type Index struct {
	Fields []string
	Name   string
	Unique bool
}

// Table is a model definition.
type Table struct {
	// Key is the logical model key ("user", "session", ...).
	Key string
	// ModelName is the physical table/collection name.
	ModelName         string
	Fields            []Field
	Indexes           []Index
	DisableMigrations bool
	Order             int
}

// Field returns the field with the given logical name (or physical column name).
func (t *Table) Field(name string) (Field, bool) {
	for _, f := range t.Fields {
		if f.Name == name {
			return f, true
		}
	}
	for _, f := range t.Fields {
		if f.FieldName == name {
			return f, true
		}
	}
	return Field{}, false
}

// Schema is an ordered set of tables.
type Schema struct {
	Tables []*Table
}

// Table looks a table up by logical key.
func (s *Schema) Table(key string) *Table {
	for _, t := range s.Tables {
		if t.Key == key {
			return t
		}
	}
	return nil
}

// Clone returns a deep copy of the table list (fields copied by value).
func (s *Schema) Clone() *Schema {
	out := &Schema{}
	for _, t := range s.Tables {
		c := *t
		c.Fields = append([]Field(nil), t.Fields...)
		c.Indexes = append([]Index(nil), t.Indexes...)
		out.Tables = append(out.Tables, &c)
	}
	return out
}

// PluginTable is a table (or extension of a core table) declared by a plugin.
type PluginTable struct {
	// Key is the logical model key. Using "user", "session", "account" or "verification"
	// extends the core table with extra fields.
	Key              string
	ModelName        string
	Fields           []Field
	Indexes          []Index
	DisableMigration bool
}

// ModelOptions are the per-model options (modelName / fields / additionalFields).
type ModelOptions struct {
	ModelName string
	// Fields renames logical fields to physical column names.
	Fields map[string]string
	// AdditionalFields adds custom columns.
	AdditionalFields []Field
}

// Options carries the parts of the auth configuration that shape the schema.
type Options struct {
	User, Session, Account, Verification ModelOptions
	RateLimit                            ModelOptions
	Plugins                              [][]PluginTable
	HasSecondaryStorage                  bool
	StoreSessionInDatabase               bool
	StoreVerificationInDatabase          bool
	RateLimitInDatabase                  bool
}

func boolPtr(b bool) *bool { return &b }

// False is a convenience pointer for Field.Returned / Field.Input.
var False = boolPtr(false)

// True is a convenience pointer.
var True = boolPtr(true)

func now() any { return time.Now() }

// mergeFields appends or replaces fields by name, keeping the position of existing names
// (the semantics of JavaScript object spread).
func mergeFields(base []Field, extra ...[]Field) []Field {
	out := append([]Field(nil), base...)
	for _, list := range extra {
		for _, f := range list {
			replaced := false
			for i := range out {
				if out[i].Name == f.Name {
					out[i] = f
					replaced = true
					break
				}
			}
			if !replaced {
				out = append(out, f)
			}
		}
	}
	return out
}

func mergeIndexes(a, b []Index) []Index {
	out := append([]Index(nil), a...)
	seen := map[string]bool{}
	key := func(i Index) string { return fmt.Sprintf("%s|%v|%v", i.Name, i.Fields, i.Unique) }
	for _, i := range out {
		seen[key(i)] = true
	}
	for _, i := range b {
		if !seen[key(i)] {
			seen[key(i)] = true
			out = append(out, i)
		}
	}
	return out
}

func col(o ModelOptions, name string) string {
	if v, ok := o.Fields[name]; ok && v != "" {
		return v
	}
	return name
}

func orDefault(s, d string) string {
	if s != "" {
		return s
	}
	return d
}

// GetAuthTables builds the full schema (getAuthTables in core/db/get-tables.ts).
func GetAuthTables(o Options) *Schema {
	// Merge plugin tables by key, in plugin order.
	type merged struct {
		key       string
		fields    []Field
		indexes   []Index
		modelName string
		disable   bool
	}
	var order []string
	pluginTables := map[string]*merged{}
	for _, plugin := range o.Plugins {
		for _, pt := range plugin {
			m, ok := pluginTables[pt.Key]
			if !ok {
				m = &merged{key: pt.Key}
				pluginTables[pt.Key] = m
				order = append(order, pt.Key)
			}
			m.fields = mergeFields(m.fields, pt.Fields)
			m.indexes = mergeIndexes(m.indexes, pt.Indexes)
			m.modelName = orDefault(pt.ModelName, pt.Key)
			if pt.DisableMigration {
				m.disable = true
			}
		}
	}
	pluginFields := func(key string) ([]Field, []Index) {
		if m, ok := pluginTables[key]; ok {
			return m.fields, m.indexes
		}
		return nil, nil
	}

	s := &Schema{}

	uf, ui := pluginFields("user")
	s.Tables = append(s.Tables, &Table{
		Key: "user", ModelName: orDefault(o.User.ModelName, "user"), Indexes: ui, Order: 1,
		Fields: mergeFields([]Field{
			{Name: "name", Type: TypeString, Required: True, FieldName: col(o.User, "name"), Sortable: true},
			{Name: "email", Type: TypeString, Unique: true, Required: True, FieldName: col(o.User, "email"), Sortable: true},
			{Name: "emailVerified", Type: TypeBoolean, DefaultValue: false, Required: True, FieldName: col(o.User, "emailVerified"), Input: False},
			{Name: "image", Type: TypeString, Required: False, FieldName: col(o.User, "image")},
			{Name: "createdAt", Type: TypeDate, DefaultFunc: now, Required: True, FieldName: col(o.User, "createdAt")},
			{Name: "updatedAt", Type: TypeDate, DefaultFunc: now, OnUpdate: now, Required: True, FieldName: col(o.User, "updatedAt")},
		}, uf, o.User.AdditionalFields),
	})

	if !o.HasSecondaryStorage || o.StoreSessionInDatabase {
		sf, si := pluginFields("session")
		s.Tables = append(s.Tables, &Table{
			Key: "session", ModelName: orDefault(o.Session.ModelName, "session"), Indexes: si, Order: 2,
			Fields: mergeFields([]Field{
				{Name: "expiresAt", Type: TypeDate, Required: True, FieldName: col(o.Session, "expiresAt")},
				{Name: "token", Type: TypeString, Required: True, FieldName: col(o.Session, "token"), Unique: true},
				{Name: "createdAt", Type: TypeDate, Required: True, FieldName: col(o.Session, "createdAt"), DefaultFunc: now},
				{Name: "updatedAt", Type: TypeDate, Required: True, FieldName: col(o.Session, "updatedAt"), OnUpdate: now},
				{Name: "ipAddress", Type: TypeString, Required: False, FieldName: col(o.Session, "ipAddress")},
				{Name: "userAgent", Type: TypeString, Required: False, FieldName: col(o.Session, "userAgent")},
				{Name: "userId", Type: TypeString, FieldName: col(o.Session, "userId"),
					References: &Reference{Model: "user", Field: "id", OnDelete: OnDeleteCascade}, Required: True, Index: true},
			}, sf, o.Session.AdditionalFields),
		})
	}

	af, ai := pluginFields("account")
	s.Tables = append(s.Tables, &Table{
		Key: "account", ModelName: orDefault(o.Account.ModelName, "account"), Indexes: ai, Order: 3,
		Fields: mergeFields([]Field{
			{Name: "accountId", Type: TypeString, Required: True, FieldName: col(o.Account, "accountId")},
			{Name: "providerId", Type: TypeString, Required: True, FieldName: col(o.Account, "providerId")},
			{Name: "userId", Type: TypeString, References: &Reference{Model: "user", Field: "id", OnDelete: OnDeleteCascade},
				Required: True, FieldName: col(o.Account, "userId"), Index: true},
			{Name: "accessToken", Type: TypeString, Returned: False, Required: False, FieldName: col(o.Account, "accessToken")},
			{Name: "refreshToken", Type: TypeString, Returned: False, Required: False, FieldName: col(o.Account, "refreshToken")},
			{Name: "idToken", Type: TypeString, Returned: False, Required: False, FieldName: col(o.Account, "idToken")},
			{Name: "accessTokenExpiresAt", Type: TypeDate, Returned: False, Required: False, FieldName: col(o.Account, "accessTokenExpiresAt")},
			{Name: "refreshTokenExpiresAt", Type: TypeDate, Returned: False, Required: False, FieldName: col(o.Account, "refreshTokenExpiresAt")},
			{Name: "scope", Type: TypeString, Required: False, FieldName: col(o.Account, "scope")},
			{Name: "password", Type: TypeString, Returned: False, Required: False, FieldName: col(o.Account, "password")},
			{Name: "createdAt", Type: TypeDate, Required: True, FieldName: col(o.Account, "createdAt"), DefaultFunc: now},
			{Name: "updatedAt", Type: TypeDate, Required: True, FieldName: col(o.Account, "updatedAt"), OnUpdate: now},
		}, af, o.Account.AdditionalFields),
	})

	if !o.HasSecondaryStorage || o.StoreVerificationInDatabase {
		vf, vi := pluginFields("verification")
		s.Tables = append(s.Tables, &Table{
			Key: "verification", ModelName: orDefault(o.Verification.ModelName, "verification"), Indexes: vi, Order: 4,
			Fields: mergeFields([]Field{
				{Name: "identifier", Type: TypeString, Required: True, FieldName: col(o.Verification, "identifier"), Index: true},
				{Name: "value", Type: TypeString, Required: True, FieldName: col(o.Verification, "value")},
				{Name: "expiresAt", Type: TypeDate, Required: True, FieldName: col(o.Verification, "expiresAt")},
				{Name: "createdAt", Type: TypeDate, Required: True, DefaultFunc: now, FieldName: col(o.Verification, "createdAt")},
				{Name: "updatedAt", Type: TypeDate, Required: True, DefaultFunc: now, OnUpdate: now, FieldName: col(o.Verification, "updatedAt")},
			}, vf, o.Verification.AdditionalFields),
		})
	}

	for _, key := range order {
		switch key {
		case "user", "session", "account", "verification":
			continue
		}
		m := pluginTables[key]
		s.Tables = append(s.Tables, &Table{
			Key: key, ModelName: m.modelName, Fields: m.fields, Indexes: m.indexes, DisableMigrations: m.disable,
		})
	}

	if o.RateLimitInDatabase {
		s.Tables = append(s.Tables, &Table{
			Key: "rateLimit", ModelName: orDefault(o.RateLimit.ModelName, "rateLimit"),
			Fields: []Field{
				{Name: "key", Type: TypeString, Unique: true, Required: True, FieldName: col(o.RateLimit, "key")},
				{Name: "count", Type: TypeNumber, Required: True, FieldName: col(o.RateLimit, "count")},
				{Name: "lastRequest", Type: TypeNumber, BigInt: true, Required: True, FieldName: col(o.RateLimit, "lastRequest"),
					DefaultFunc: func() any { return time.Now().UnixMilli() }},
			},
		})
	}
	return s
}
