// Package adapter defines the generic database adapter used by Better Auth, modeled on
// packages/core/src/db/adapter. Database drivers implement the low-level [CustomAdapter]
// (physical table/column names, cleaned where clauses) and wrap it with [NewFactory], which
// provides the high-level [Adapter] Better Auth calls with logical model/field names.
package adapter

import (
	"context"

	"github.com/nimi-io/better-auth-go/db"
)

// Record is a database row keyed by field name.
type Record = map[string]any

// Operator is a where-clause operator.
type Operator string

// Operators (whereOperators upstream).
const (
	Eq         Operator = "eq"
	Ne         Operator = "ne"
	Lt         Operator = "lt"
	Lte        Operator = "lte"
	Gt         Operator = "gt"
	Gte        Operator = "gte"
	In         Operator = "in"
	NotIn      Operator = "not_in"
	Contains   Operator = "contains"
	StartsWith Operator = "starts_with"
	EndsWith   Operator = "ends_with"
)

// Connector joins where clauses.
type Connector string

// Connectors.
const (
	And Connector = "AND"
	Or  Connector = "OR"
)

// Where is a single condition. Zero values default to Operator "eq", Connector "AND" and
// case-sensitive matching.
type Where struct {
	Field     string
	Value     any
	Operator  Operator
	Connector Connector
	// Insensitive selects case-insensitive string matching (mode: "insensitive").
	Insensitive bool
}

// CleanedWhere is a Where with defaults applied and the physical field name resolved.
type CleanedWhere struct {
	Field       string
	Value       any
	Operator    Operator
	Connector   Connector
	Insensitive bool
}

// SortBy orders findMany results.
type SortBy struct {
	Field     string
	Direction string // "asc" or "desc"
}

// Join requests related rows of another model. A zero Limit uses the default limit.
type Join struct {
	Limit int
}

// JoinConfig is the resolved join passed to a CustomAdapter when native joins are enabled.
type JoinConfig struct {
	// ModelKey is the logical key of the joined model.
	ModelKey string
	// From is the physical column on the base model, To on the joined model.
	From, To string
	Limit    int
	// Relation is "one-to-one" or "one-to-many".
	Relation string
}

// CreateInput is the input of Adapter.Create.
type CreateInput struct {
	Model        string
	Data         Record
	Select       []string
	ForceAllowID bool
}

// FindOneInput is the input of Adapter.FindOne.
type FindOneInput struct {
	Model  string
	Where  []Where
	Select []string
	Join   map[string]Join
}

// FindManyInput is the input of Adapter.FindMany.
type FindManyInput struct {
	Model  string
	Where  []Where
	Limit  int
	Offset int
	SortBy *SortBy
	Select []string
	Join   map[string]Join
}

// IncrementInput is the input of Adapter.IncrementOne.
type IncrementInput struct {
	Model     string
	Where     []Where
	Increment map[string]float64
	Set       Record
}

// Adapter is the database API Better Auth uses (DBAdapter upstream). Model and field names
// are logical names ("user", "emailVerified"); renames are resolved by the factory.
type Adapter interface {
	ID() string
	Create(ctx context.Context, in CreateInput) (Record, error)
	// FindOne returns nil, nil when nothing matches.
	FindOne(ctx context.Context, in FindOneInput) (Record, error)
	FindMany(ctx context.Context, in FindManyInput) ([]Record, error)
	Count(ctx context.Context, model string, where []Where) (int64, error)
	// Update updates the first matching row and returns it (nil when none matched).
	Update(ctx context.Context, model string, where []Where, update Record) (Record, error)
	UpdateMany(ctx context.Context, model string, where []Where, update Record) (int64, error)
	Delete(ctx context.Context, model string, where []Where) error
	DeleteMany(ctx context.Context, model string, where []Where) (int64, error)
	// ConsumeOne atomically deletes and returns one matching row.
	ConsumeOne(ctx context.Context, model string, where []Where) (Record, error)
	// IncrementOne atomically increments numeric fields (and sets others) on one matching row.
	IncrementOne(ctx context.Context, in IncrementInput) (Record, error)
	// Transaction runs fn inside a transaction when the driver supports it. The context
	// passed to fn carries the transactional adapter (see Current).
	Transaction(ctx context.Context, fn func(ctx context.Context, tx Adapter) error) error
	// Schema returns the resolved schema.
	Schema() *db.Schema
}

// Query is the input of CustomAdapter read operations.
type Query struct {
	Model    string // physical model name
	ModelKey string // logical model key
	Where    []CleanedWhere
	Select   []string
	Limit    int
	Offset   int
	SortBy   *SortBy // Field is the physical column name
	// Join is set only when native joins are enabled; keys are physical model names.
	Join map[string]JoinConfig
}

// CustomAdapter is implemented by database drivers. All names are physical.
type CustomAdapter interface {
	Create(ctx context.Context, model, modelKey string, data Record) (Record, error)
	FindOne(ctx context.Context, q Query) (Record, error)
	FindMany(ctx context.Context, q Query) ([]Record, error)
	Count(ctx context.Context, q Query) (int64, error)
	Update(ctx context.Context, q Query, update Record) (Record, error)
	UpdateMany(ctx context.Context, q Query, update Record) (int64, error)
	Delete(ctx context.Context, q Query) error
	DeleteMany(ctx context.Context, q Query) (int64, error)
}

// ConsumeOner is an optional native ConsumeOne.
type ConsumeOner interface {
	ConsumeOne(ctx context.Context, q Query) (Record, error)
}

// IncrementOner is an optional native IncrementOne.
type IncrementOner interface {
	IncrementOne(ctx context.Context, q Query, increment map[string]float64, set Record) (Record, error)
}

// Transactor is an optional native transaction implementation. fn receives a CustomAdapter
// bound to the transaction.
type Transactor interface {
	Transaction(ctx context.Context, fn func(ctx context.Context, tx CustomAdapter) error) error
}

// Config describes driver capabilities (DBAdapterFactoryConfig).
type Config struct {
	AdapterID          string
	AdapterName        string
	UsePlural          bool
	SupportsNumericIDs *bool
	SupportsUUIDs      bool
	SupportsJSON       bool
	SupportsDates      *bool
	SupportsBooleans   *bool
	SupportsArrays     bool
	// DisableIDGeneration leaves id generation to the database.
	DisableIDGeneration bool
	// CustomIDGenerator overrides the default id generator.
	CustomIDGenerator func(model string) string
	// MapKeysTransformInput / Output rename keys (e.g. "id" ↔ "_id" for MongoDB).
	MapKeysTransformInput  map[string]string
	MapKeysTransformOutput map[string]string
	// CustomTransformInput / Output adjust individual values.
	CustomTransformInput  func(p TransformParams) any
	CustomTransformOutput func(p TransformParams) any
}

// TransformParams is passed to custom value transforms.
type TransformParams struct {
	Data   any
	Field  string // physical field name
	Attr   db.Field
	Action string
	Model  string // physical model name
}

// IDMode selects id generation.
type IDMode string

// ID generation modes (advanced.database.generateId).
const (
	IDDefault IDMode = ""
	IDUUID    IDMode = "uuid"
	IDSerial  IDMode = "serial"
	// IDNone leaves ids entirely to the database (generateId: false).
	IDNone IDMode = "none"
)

// Options are passed by Better Auth when instantiating an adapter.
type Options struct {
	Schema *db.Schema
	IDMode IDMode
	// GenerateID, when set, overrides id generation. Return ok=false to let the database
	// generate the id.
	GenerateID           func(model string, size int) (id string, ok bool)
	DefaultFindManyLimit int
	// Joins enables native joins; otherwise joins are emulated with extra queries.
	Joins  bool
	Logger Logger
}

// Logger receives adapter warnings.
type Logger interface {
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// Factory instantiates an adapter for a given schema.
type Factory func(opts Options) (Adapter, error)
