// Package mongodb is the MongoDB adapter for Better Auth, a port of @better-auth/mongo-adapter
// (packages/mongo-adapter) on top of go.mongodb.org/mongo-driver/v2.
//
// Documents are stored exactly as the TypeScript adapter stores them, so a Go and a Node.js
// server can share one database:
//
//   - collections are named after the (optionally pluralised) model names;
//   - the id is stored in _id as an ObjectId (a BSON UUID when generateId is "uuid", the
//     generated string when a custom id generator is configured);
//   - fields referencing another model's id (session.userId, account.userId, ...) are stored
//     with the same type as _id;
//   - dates are BSON dates, booleans BSON booleans, string[]/number[] BSON arrays, JSON
//     fields JSON strings, and numbers int32 when they are 32-bit integers, double otherwise
//     (the encoding of the Node.js driver).
//
// The adapter has no migrations. Table-level indexes declared in the schema are created on
// first write, like upstream.
package mongodb

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/nimi-io/better-auth-go/adapter"
)

// MongoAdapterError is returned for invalid ids and unsupported operators.
type MongoAdapterError struct {
	// Code is "INVALID_ID" or "UNSUPPORTED_OPERATOR".
	Code    string
	Message string
}

func (e *MongoAdapterError) Error() string { return e.Message }

// DebugLogOptions selects which methods are logged (the object form of debugLogs upstream).
type DebugLogOptions struct {
	Create, Update, UpdateMany, FindOne, FindMany bool
	Delete, DeleteMany, ConsumeOne, IncrementOne  bool
	Count                                         bool
	// LogCondition, when set, must return true for anything to be logged.
	LogCondition func() bool
}

func (o *DebugLogOptions) enabled(method string) bool {
	if o.LogCondition != nil && !o.LogCondition() {
		return false
	}
	switch method {
	case "create":
		return o.Create
	case "update":
		return o.Update
	case "updateMany":
		return o.UpdateMany
	case "findOne":
		return o.FindOne
	case "findMany":
		return o.FindMany
	case "delete":
		return o.Delete
	case "deleteMany":
		return o.DeleteMany
	case "consumeOne":
		return o.ConsumeOne
	case "incrementOne":
		return o.IncrementOne
	case "count":
		return o.Count
	}
	return true
}

// Config mirrors MongoDBAdapterConfig.
type Config struct {
	// Client enables transactions (sessions must be started on the client that owns the
	// database). Without a client, Transaction runs its callback without a transaction.
	Client *mongo.Client
	// Transaction enables transactions when Client is set; nil means true.
	Transaction *bool
	// UsePlural pluralises collection names ("users", "sessions", ...).
	UsePlural bool
	// DebugLogs logs every operation; DebugLogOptions logs only the selected methods.
	DebugLogs       bool
	DebugLogOptions *DebugLogOptions
	// Logger receives debug logs (slog.Default() when nil).
	Logger *slog.Logger
}

// New returns a MongoDB adapter factory (mongodbAdapter(db, config)).
func New(database *mongo.Database, cfg Config) adapter.Factory {
	return newFactory(database, cfg, newIndexRegistry())
}

func newFactory(database *mongo.Database, cfg Config, indexes *indexRegistry) adapter.Factory {
	return func(opts adapter.Options) (adapter.Adapter, error) {
		ids := idCodec{uuid: opts.IDMode == adapter.IDUUID, custom: opts.GenerateID != nil}
		useTx := cfg.Client != nil && (cfg.Transaction == nil || *cfg.Transaction)
		notNumeric := false
		fcfg := adapter.Config{
			AdapterID:             "mongodb-adapter",
			AdapterName:           "MongoDB Adapter",
			UsePlural:             cfg.UsePlural,
			SupportsArrays:        true,
			SupportsNumericIDs:    &notNumeric,
			MapKeysTransformInput: map[string]string{"id": "_id"},
			// Upstream also sets mapKeysTransformOutput {_id: "id"}. The shared Go factory
			// then drops the id whenever a select list is given (it only keeps the "_id"
			// key when the select names "_id", while callers select "id"; upstream gets
			// away with it because transformInput mutates the schema to contain "id").
			// The driver therefore renames _id → id itself (see normalizeOutput).
			CustomTransformInput:  func(p adapter.TransformParams) any { return transformInput(ids, p) },
			CustomTransformOutput: transformOutput,
			CustomIDGenerator:     func(string) string { return bson.NewObjectID().Hex() },
		}
		return adapter.NewFactory(fcfg, func(opts adapter.Options, h adapter.Helpers) (adapter.CustomAdapter, error) {
			base := &mongoAdapter{
				db:      database,
				cfg:     cfg,
				opts:    opts,
				h:       h,
				ids:     ids,
				indexes: indexes,
				shared:  &sharedState{resolved: map[string][]resolvedIndex{}},
			}
			if useTx {
				return &txAdapter{mongoAdapter: base}, nil
			}
			return base, nil
		})(opts)
	}
}

// transformInput ports customTransformInput: on create/update, ids and id references are
// converted to ObjectId (or BSON UUID).
func transformInput(ids idCodec, p adapter.TransformParams) any {
	isRef := p.Attr.References != nil && p.Attr.References.Field == "id"
	if p.Field != "_id" && !isRef {
		return p.Data
	}
	if ids.custom {
		return p.Data
	}
	if p.Action != "create" && p.Action != "update" {
		return p.Data
	}
	data := p.Data
	if ids.isInstance(data) {
		return data
	}
	if s, ok := data.(string); ok {
		if id, ok := ids.coerce(s); ok {
			return id
		}
		return s
	}
	if _, isStrings := data.([]string); isStrings || isSlice(data) {
		arr, _ := adapter.ToSlice(data)
		out := make([]any, len(arr))
		for i, v := range arr {
			out[i] = v
			if s, ok := v.(string); ok {
				if id, ok := ids.coerce(s); ok {
					out[i] = id
				}
			}
		}
		return out
	}
	if isRef && !p.Attr.IsRequired() && data == nil {
		return nil
	}
	if p.Action == "update" {
		return data
	}
	return ids.generate()
}

func isSlice(v any) bool {
	_, ok := adapter.ToSlice(v)
	return ok
}

// transformOutput ports customTransformOutput.
func transformOutput(p adapter.TransformParams) any {
	if p.Field == "id" || (p.Attr.References != nil && p.Attr.References.Field == "id") {
		return idToString(p.Data)
	}
	return p.Data
}

// sharedState is shared between an adapter and the transactional adapters derived from it
// (resolvedIndexesByModel upstream).
type sharedState struct {
	mu       sync.Mutex
	resolved map[string][]resolvedIndex
}

type mongoAdapter struct {
	db      *mongo.Database
	cfg     Config
	opts    adapter.Options
	h       adapter.Helpers
	ids     idCodec
	indexes *indexRegistry
	shared  *sharedState
	session *mongo.Session
}

// txAdapter is a mongoAdapter that supports transactions (adapter.Transactor).
type txAdapter struct{ *mongoAdapter }

// Transaction runs fn in a MongoDB transaction: the session is committed when fn returns nil
// and aborted otherwise.
func (t *txAdapter) Transaction(ctx context.Context, fn func(ctx context.Context, tx adapter.CustomAdapter) error) (err error) {
	sess, err := t.cfg.Client.StartSession()
	if err != nil {
		return err
	}
	defer sess.EndSession(context.WithoutCancel(ctx))
	if err := sess.StartTransaction(); err != nil {
		return err
	}
	inner := *t.mongoAdapter
	inner.session = sess
	committed := false
	defer func() {
		if committed {
			return
		}
		_ = sess.AbortTransaction(context.WithoutCancel(ctx))
		if r := recover(); r != nil {
			panic(r)
		}
	}()
	if err := fn(ctx, &inner); err != nil {
		return err
	}
	if err := sess.CommitTransaction(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

// opCtx binds the transaction session (if any) to ctx.
func (a *mongoAdapter) opCtx(ctx context.Context) context.Context {
	if a.session != nil {
		return mongo.NewSessionContext(ctx, a.session)
	}
	return ctx
}

func (a *mongoAdapter) coll(model string) *mongo.Collection { return a.db.Collection(model) }

// ---- debug logs ----

func (a *mongoAdapter) debug(method, action, model string, data any) {
	if !a.cfg.DebugLogs && a.cfg.DebugLogOptions == nil {
		return
	}
	if a.cfg.DebugLogOptions != nil && !a.cfg.DebugLogOptions.enabled(method) {
		return
	}
	logger := a.cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Info("[MongoDB Adapter] "+method+" "+action, "model", model, "data", debugValue(data))
}

// debugValue renders BSON documents as relaxed extended JSON for logs.
func debugValue(v any) any {
	switch v.(type) {
	case bson.D, bson.A:
		b, err := bson.MarshalExtJSON(bson.D{{Key: "v", Value: v}}, false, false)
		if err == nil {
			return string(b[len(`{"v":`) : len(b)-1])
		}
	}
	return v
}

// ---- indexes ----

func (a *mongoAdapter) modelIndexes(model, modelKey string) ([]resolvedIndex, error) {
	a.shared.mu.Lock()
	defer a.shared.mu.Unlock()
	if idx, ok := a.shared.resolved[model]; ok {
		return idx, nil
	}
	var idx []resolvedIndex
	t, _ := a.h.Table(modelKey)
	if t != nil && !t.DisableMigrations {
		var err error
		idx, err = resolveIndexes(t, model)
		if err != nil {
			return nil, err
		}
	}
	a.shared.resolved[model] = idx
	return idx, nil
}

// resolveIndexes is a variable so tests can observe how often indexes are resolved.
var resolveIndexes = resolveTableIndexes

// ensureModelIndexes creates the table-level indexes of a model before the first write.
// Index creation never runs inside the transaction session.
func (a *mongoAdapter) ensureModelIndexes(ctx context.Context, model, modelKey string) error {
	idx, err := a.modelIndexes(model, modelKey)
	if err != nil {
		return err
	}
	if len(idx) == 0 {
		return nil
	}
	return a.indexes.ensure(ctx, a.db, model, idx)
}

// ---- document helpers ----

// orderedDoc converts a record to a document with _id first followed by the schema field
// order (the key order the TypeScript adapter produces).
func (a *mongoAdapter) orderedDoc(modelKey string, data adapter.Record) bson.D {
	doc := make(bson.D, 0, len(data))
	used := map[string]bool{}
	add := func(k string) {
		if v, ok := data[k]; ok && !used[k] {
			used[k] = true
			doc = append(doc, bson.E{Key: k, Value: toBSON(v)})
		}
	}
	add("_id")
	if t, _ := a.h.Table(modelKey); t != nil {
		for _, f := range t.Fields {
			add(f.Column())
		}
	}
	rest := make([]string, 0)
	for k := range data {
		if !used[k] {
			rest = append(rest, k)
		}
	}
	sortStrings(rest)
	for _, k := range rest {
		add(k)
	}
	return doc
}

// normalizeOutput converts a decoded document into a Record, renames _id to id and renders
// the id and id reference fields of the model (and of joined models) as strings.
func (a *mongoAdapter) normalizeOutput(modelKey string, doc any, join map[string]adapter.JoinConfig) adapter.Record {
	rec, ok := fromBSON(doc).(adapter.Record)
	if !ok {
		return nil
	}
	a.stringifyIDs(modelKey, rec)
	for joined, jc := range join {
		switch t := rec[joined].(type) {
		case adapter.Record:
			a.stringifyIDs(jc.ModelKey, t)
		case []any:
			for _, x := range t {
				if r, ok := x.(adapter.Record); ok {
					a.stringifyIDs(jc.ModelKey, r)
				}
			}
		}
	}
	return rec
}

// stringifyIDs renames _id to id (mapKeysTransformOutput) and applies the id conversion of
// customTransformOutput in the driver. The shared
// factory stringifies id references with fmt-style String() before calling
// CustomTransformOutput, which would render an ObjectId as `ObjectID("…")`, so the
// conversion has to happen here.
func (a *mongoAdapter) stringifyIDs(modelKey string, rec adapter.Record) {
	if v, ok := rec["_id"]; ok {
		delete(rec, "_id")
		rec["id"] = idToString(v)
	}
	t, _ := a.h.Table(modelKey)
	if t == nil {
		return
	}
	for _, f := range t.Fields {
		if f.References != nil && f.References.Field == "id" {
			if v, ok := rec[f.Column()]; ok {
				rec[f.Column()] = idToString(v)
			}
		}
	}
}

func (a *mongoAdapter) filter(q adapter.Query) (bson.D, error) {
	if q.Where == nil {
		return bson.D{}, nil
	}
	f, err := a.convertWhere(q.Where, q.ModelKey)
	if err != nil {
		return nil, err
	}
	return toBSON(f).(bson.D), nil
}

// ---- CustomAdapter ----

func (a *mongoAdapter) Create(ctx context.Context, model, modelKey string, data adapter.Record) (adapter.Record, error) {
	a.debug("create", "Parsed Input", model, data)
	if err := a.ensureModelIndexes(ctx, model, modelKey); err != nil {
		return nil, err
	}
	doc := a.orderedDoc(modelKey, data)
	res, err := a.coll(model).InsertOne(a.opCtx(ctx), doc)
	if err != nil {
		return nil, err
	}
	out := adapter.Record{"_id": res.InsertedID}
	for _, e := range doc {
		out[e.Key] = e.Value
	}
	rec := a.normalizeOutput(modelKey, out, nil)
	a.debug("create", "DB Result", model, rec)
	return rec, nil
}

func (a *mongoAdapter) lookupStages(q adapter.Query, findOne bool) (bson.A, error) {
	var stages bson.A
	for _, joinedModel := range sortedJoinKeys(q.Join) {
		jc := q.Join[joinedModel]
		joinKey := jc.ModelKey
		if joinKey == "" {
			joinKey = joinedModel
		}
		localField, err := a.h.FieldName(q.ModelKey, jc.From)
		if err != nil {
			return nil, err
		}
		foreignField, err := a.h.FieldName(joinKey, jc.To)
		if err != nil {
			return nil, err
		}
		if localField == "id" {
			localField = "_id"
		}
		if foreignField == "id" {
			foreignField = "_id"
		}
		var unique, shouldLimit bool
		if findOne {
			// schema[modelKey].fields[on.to]: looked up by logical name only.
			if t, _ := a.h.Table(joinKey); t != nil {
				for _, f := range t.Fields {
					if f.Name == jc.To {
						unique = f.Unique
					}
				}
			}
			shouldLimit = !unique
		} else {
			if attr, err := a.h.FieldAttributes(joinKey, jc.To); err == nil {
				unique = attr.Unique
			}
			shouldLimit = jc.Relation != "one-to-one"
		}
		limit := jc.Limit
		if limit == 0 {
			limit = a.opts.DefaultFindManyLimit
			if limit == 0 {
				limit = 100
			}
		}
		if shouldLimit && limit > 0 {
			stages = append(stages, bson.D{{Key: "$lookup", Value: bson.D{
				{Key: "from", Value: joinedModel},
				{Key: "let", Value: bson.D{{Key: "localFieldValue", Value: "$" + localField}}},
				{Key: "pipeline", Value: bson.A{
					bson.D{{Key: "$match", Value: bson.D{{Key: "$expr", Value: bson.D{
						{Key: "$eq", Value: bson.A{"$" + foreignField, "$$localFieldValue"}},
					}}}}},
					bson.D{{Key: "$limit", Value: limit}},
				}},
				{Key: "as", Value: joinedModel},
			}}})
		} else {
			stages = append(stages, bson.D{{Key: "$lookup", Value: bson.D{
				{Key: "from", Value: joinedModel},
				{Key: "localField", Value: localField},
				{Key: "foreignField", Value: foreignField},
				{Key: "as", Value: joinedModel},
			}}})
		}
		if unique {
			stages = append(stages, bson.D{{Key: "$unwind", Value: bson.D{
				{Key: "path", Value: "$" + joinedModel},
				{Key: "preserveNullAndEmptyArrays", Value: true},
			}}})
		}
	}
	return stages, nil
}

func sortedJoinKeys(m map[string]adapter.JoinConfig) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	return keys
}

func (a *mongoAdapter) projection(q adapter.Query) (bson.D, error) {
	proj := bson.D{}
	seen := map[string]bool{}
	for _, s := range q.Select {
		name, err := a.h.FieldName(q.ModelKey, s)
		if err != nil {
			return nil, err
		}
		if !seen[name] {
			seen[name] = true
			proj = append(proj, bson.E{Key: name, Value: int32(1)})
		}
	}
	for _, joined := range sortedJoinKeys(q.Join) {
		if !seen[joined] {
			seen[joined] = true
			proj = append(proj, bson.E{Key: joined, Value: int32(1)})
		}
	}
	return proj, nil
}

func (a *mongoAdapter) pipeline(q adapter.Query, findOne bool) (bson.A, error) {
	match, err := a.filter(q)
	if err != nil {
		return nil, err
	}
	pipeline := bson.A{bson.D{{Key: "$match", Value: match}}}
	lookups, err := a.lookupStages(q, findOne)
	if err != nil {
		return nil, err
	}
	pipeline = append(pipeline, lookups...)
	if len(q.Select) > 0 {
		proj, err := a.projection(q)
		if err != nil {
			return nil, err
		}
		pipeline = append(pipeline, bson.D{{Key: "$project", Value: proj}})
	}
	if findOne {
		pipeline = append(pipeline, bson.D{{Key: "$limit", Value: int32(1)}})
		return toBSON(pipeline).(bson.A), nil
	}
	if q.SortBy != nil {
		field, err := a.h.FieldName(q.ModelKey, q.SortBy.Field)
		if err != nil {
			return nil, err
		}
		dir := int32(1)
		if q.SortBy.Direction == "desc" {
			dir = -1
		}
		pipeline = append(pipeline, bson.D{{Key: "$sort", Value: bson.D{{Key: field, Value: dir}}}})
	}
	if q.Offset > 0 {
		pipeline = append(pipeline, bson.D{{Key: "$skip", Value: q.Offset}})
	}
	if q.Limit > 0 {
		pipeline = append(pipeline, bson.D{{Key: "$limit", Value: q.Limit}})
	}
	return toBSON(pipeline).(bson.A), nil
}

func (a *mongoAdapter) aggregate(ctx context.Context, model string, pipeline bson.A) ([]bson.D, error) {
	cur, err := a.coll(model).Aggregate(a.opCtx(ctx), pipeline)
	if err != nil {
		return nil, err
	}
	var docs []bson.D
	if err := cur.All(a.opCtx(ctx), &docs); err != nil {
		return nil, err
	}
	return docs, nil
}

func (a *mongoAdapter) FindOne(ctx context.Context, q adapter.Query) (adapter.Record, error) {
	pipeline, err := a.pipeline(q, true)
	if err != nil {
		return nil, err
	}
	a.debug("findOne", "Pipeline", q.Model, pipeline)
	docs, err := a.aggregate(ctx, q.Model, pipeline)
	if err != nil {
		return nil, err
	}
	if len(docs) == 0 {
		return nil, nil
	}
	rec := a.normalizeOutput(q.ModelKey, docs[0], q.Join)
	a.debug("findOne", "DB Result", q.Model, rec)
	return rec, nil
}

func (a *mongoAdapter) FindMany(ctx context.Context, q adapter.Query) ([]adapter.Record, error) {
	pipeline, err := a.pipeline(q, false)
	if err != nil {
		return nil, err
	}
	a.debug("findMany", "Pipeline", q.Model, pipeline)
	docs, err := a.aggregate(ctx, q.Model, pipeline)
	if err != nil {
		return nil, err
	}
	out := make([]adapter.Record, 0, len(docs))
	for _, d := range docs {
		out = append(out, a.normalizeOutput(q.ModelKey, d, q.Join))
	}
	a.debug("findMany", "DB Result", q.Model, out)
	return out, nil
}

func (a *mongoAdapter) Count(ctx context.Context, q adapter.Query) (int64, error) {
	match, err := a.filter(q)
	if err != nil {
		return 0, err
	}
	pipeline := bson.A{bson.D{{Key: "$match", Value: match}}, bson.D{{Key: "$count", Value: "total"}}}
	a.debug("count", "Pipeline", q.Model, pipeline)
	docs, err := a.aggregate(ctx, q.Model, pipeline)
	if err != nil {
		return 0, err
	}
	if len(docs) == 0 {
		return 0, nil
	}
	rec, _ := fromBSON(docs[0]).(adapter.Record)
	n, _ := adapter.ToInt64(rec["total"])
	a.debug("count", "DB Result", q.Model, n)
	return n, nil
}

func (a *mongoAdapter) setDoc(modelKey string, values adapter.Record) bson.D {
	return a.orderedDoc(modelKey, values)
}

func decodeSingle(res *mongo.SingleResult) (bson.D, error) {
	var doc bson.D
	if err := res.Decode(&doc); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, err
	}
	return doc, nil
}

func (a *mongoAdapter) Update(ctx context.Context, q adapter.Query, values adapter.Record) (adapter.Record, error) {
	if err := a.ensureModelIndexes(ctx, q.Model, q.ModelKey); err != nil {
		return nil, err
	}
	clause, err := a.filter(q)
	if err != nil {
		return nil, err
	}
	update := bson.D{{Key: "$set", Value: a.setDoc(q.ModelKey, values)}}
	a.debug("update", "Parsed Input", q.Model, bson.A{clause, update})
	doc, err := decodeSingle(a.coll(q.Model).FindOneAndUpdate(a.opCtx(ctx), clause, update,
		options.FindOneAndUpdate().SetReturnDocument(options.After)))
	if err != nil || doc == nil {
		return nil, err
	}
	rec := a.normalizeOutput(q.ModelKey, doc, nil)
	a.debug("update", "DB Result", q.Model, rec)
	return rec, nil
}

func (a *mongoAdapter) UpdateMany(ctx context.Context, q adapter.Query, values adapter.Record) (int64, error) {
	if err := a.ensureModelIndexes(ctx, q.Model, q.ModelKey); err != nil {
		return 0, err
	}
	clause, err := a.filter(q)
	if err != nil {
		return 0, err
	}
	update := bson.D{{Key: "$set", Value: a.setDoc(q.ModelKey, values)}}
	a.debug("updateMany", "Parsed Input", q.Model, bson.A{clause, update})
	res, err := a.coll(q.Model).UpdateMany(a.opCtx(ctx), clause, update)
	if err != nil {
		return 0, err
	}
	a.debug("updateMany", "DB Result", q.Model, res.ModifiedCount)
	return res.ModifiedCount, nil
}

func (a *mongoAdapter) Delete(ctx context.Context, q adapter.Query) error {
	clause, err := a.filter(q)
	if err != nil {
		return err
	}
	a.debug("delete", "Parsed Input", q.Model, clause)
	_, err = a.coll(q.Model).DeleteOne(a.opCtx(ctx), clause)
	return err
}

func (a *mongoAdapter) DeleteMany(ctx context.Context, q adapter.Query) (int64, error) {
	clause, err := a.filter(q)
	if err != nil {
		return 0, err
	}
	a.debug("deleteMany", "Parsed Input", q.Model, clause)
	res, err := a.coll(q.Model).DeleteMany(a.opCtx(ctx), clause)
	if err != nil {
		return 0, err
	}
	a.debug("deleteMany", "DB Result", q.Model, res.DeletedCount)
	return res.DeletedCount, nil
}

// ConsumeOne atomically deletes and returns one matching document (findOneAndDelete).
func (a *mongoAdapter) ConsumeOne(ctx context.Context, q adapter.Query) (adapter.Record, error) {
	clause, err := a.filter(q)
	if err != nil {
		return nil, err
	}
	a.debug("consumeOne", "Parsed Input", q.Model, clause)
	doc, err := decodeSingle(a.coll(q.Model).FindOneAndDelete(a.opCtx(ctx), clause))
	if err != nil || doc == nil {
		return nil, err
	}
	rec := a.normalizeOutput(q.ModelKey, doc, nil)
	a.debug("consumeOne", "DB Result", q.Model, rec)
	return rec, nil
}

// IncrementOne atomically applies $inc (and $set) to one matching document and returns it
// after the update.
func (a *mongoAdapter) IncrementOne(ctx context.Context, q adapter.Query, increment map[string]float64, set adapter.Record) (adapter.Record, error) {
	if err := a.ensureModelIndexes(ctx, q.Model, q.ModelKey); err != nil {
		return nil, err
	}
	clause, err := a.filter(q)
	if err != nil {
		return nil, err
	}
	update := bson.D{}
	if len(increment) > 0 {
		keys := make([]string, 0, len(increment))
		for k := range increment {
			keys = append(keys, k)
		}
		sortStrings(keys)
		inc := bson.D{}
		for _, k := range keys {
			inc = append(inc, bson.E{Key: k, Value: jsNumber(increment[k])})
		}
		update = append(update, bson.E{Key: "$inc", Value: inc})
	}
	if len(set) > 0 {
		update = append(update, bson.E{Key: "$set", Value: a.setDoc(q.ModelKey, set)})
	}
	a.debug("incrementOne", "Parsed Input", q.Model, bson.A{clause, update})
	var doc bson.D
	if len(update) == 0 {
		doc, err = decodeSingle(a.coll(q.Model).FindOne(a.opCtx(ctx), clause))
	} else {
		doc, err = decodeSingle(a.coll(q.Model).FindOneAndUpdate(a.opCtx(ctx), clause, update,
			options.FindOneAndUpdate().SetReturnDocument(options.After)))
	}
	if err != nil || doc == nil {
		return nil, err
	}
	rec := a.normalizeOutput(q.ModelKey, doc, nil)
	a.debug("incrementOne", "DB Result", q.Model, rec)
	return rec, nil
}

// compile-time checks
var (
	_ adapter.CustomAdapter = (*mongoAdapter)(nil)
	_ adapter.ConsumeOner   = (*mongoAdapter)(nil)
	_ adapter.IncrementOner = (*mongoAdapter)(nil)
	_ adapter.Transactor    = (*txAdapter)(nil)
)
