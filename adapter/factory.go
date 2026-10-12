package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Helpers expose schema name resolution to drivers.
type Helpers struct {
	Schema  *db.Schema
	Options Options
	f       *factory
}

// ModelName returns the physical model name for a logical (or physical) model.
func (h Helpers) ModelName(model string) (string, error) { return h.f.getModelName(model) }

// DefaultModelName returns the logical model key.
func (h Helpers) DefaultModelName(model string) (string, error) {
	return h.f.getDefaultModelName(model)
}

// FieldName returns the physical column for a logical field.
func (h Helpers) FieldName(model, field string) (string, error) {
	return h.f.getFieldName(model, field)
}

// DefaultFieldName returns the logical field name for a physical or logical name.
func (h Helpers) DefaultFieldName(model, field string) (string, error) {
	return h.f.getDefaultFieldName(model, field)
}

// FieldAttributes returns the field definition (including the synthetic id field).
func (h Helpers) FieldAttributes(model, field string) (db.Field, error) {
	return h.f.getFieldAttributes(model, field)
}

// Table returns the logical table for a model (logical or physical name).
func (h Helpers) Table(model string) (*db.Table, error) {
	key, err := h.f.getDefaultModelName(model)
	if err != nil {
		return nil, err
	}
	return h.Schema.Table(key), nil
}

// UseNumberID reports whether ids are serial numbers.
func (h Helpers) UseNumberID() bool { return h.Options.IDMode == IDSerial }

// Builder creates a driver-level adapter for the resolved schema.
type Builder func(opts Options, h Helpers) (CustomAdapter, error)

// NewFactory wraps a driver with the shared transform layer (createAdapterFactory).
func NewFactory(cfg Config, build Builder) Factory {
	return func(opts Options) (Adapter, error) {
		if opts.Schema == nil {
			return nil, errors.New("adapter: schema is required")
		}
		if cfg.AdapterName == "" {
			cfg.AdapterName = cfg.AdapterID
		}
		if opts.IDMode == IDSerial && cfg.SupportsNumericIDs != nil && !*cfg.SupportsNumericIDs {
			return nil, fmt.Errorf("[%s] Your database or database adapter does not support numeric ids. Please disable \"useNumberId\" in your config.", cfg.AdapterName)
		}
		if opts.DefaultFindManyLimit == 0 {
			opts.DefaultFindManyLimit = 100
		}
		f := &factory{cfg: cfg, opts: opts, schema: opts.Schema}
		custom, err := build(opts, Helpers{Schema: opts.Schema, Options: opts, f: f})
		if err != nil {
			return nil, err
		}
		f.custom = custom
		return f, nil
	}
}

type factory struct {
	cfg    Config
	opts   Options
	schema *db.Schema
	custom CustomAdapter
}

func (f *factory) supportsDates() bool { return f.cfg.SupportsDates == nil || *f.cfg.SupportsDates }
func (f *factory) supportsBooleans() bool {
	return f.cfg.SupportsBooleans == nil || *f.cfg.SupportsBooleans
}
func (f *factory) useNumberID() bool { return f.opts.IDMode == IDSerial }

func (f *factory) ID() string            { return f.cfg.AdapterID }
func (f *factory) Schema() *db.Schema    { return f.schema }
func (f *factory) Custom() CustomAdapter { return f.custom }

// ---- name resolution ----

func (f *factory) getDefaultModelName(model string) (string, error) {
	resolve := func(candidate string) string {
		if f.schema.Table(candidate) != nil {
			return candidate
		}
		for _, t := range f.schema.Tables {
			if t.ModelName == candidate {
				return t.Key
			}
		}
		return ""
	}
	if f.cfg.UsePlural && strings.HasSuffix(model, "s") {
		if m := resolve(model[:len(model)-1]); m != "" {
			return m, nil
		}
	}
	if m := resolve(model); m != "" {
		return m, nil
	}
	return "", fmt.Errorf("Model \"%s\" not found in schema", model)
}

func (f *factory) getModelName(model string) (string, error) {
	key, err := f.getDefaultModelName(model)
	if err != nil {
		return "", err
	}
	t := f.schema.Table(key)
	name := model
	if t.ModelName != model {
		name = t.ModelName
	}
	if f.cfg.UsePlural {
		return name + "s", nil
	}
	return name, nil
}

func (f *factory) getDefaultFieldName(model, field string) (string, error) {
	if field == "id" || field == "_id" {
		return "id", nil
	}
	key, err := f.getDefaultModelName(model)
	if err != nil {
		return "", err
	}
	t := f.schema.Table(key)
	for _, fl := range t.Fields {
		if fl.Name == field {
			return field, nil
		}
	}
	for _, fl := range t.Fields {
		if fl.FieldName == field {
			return fl.Name, nil
		}
	}
	return "", fmt.Errorf("Field %s not found in model %s", field, key)
}

func (f *factory) getFieldName(model, field string) (string, error) {
	key, err := f.getDefaultModelName(model)
	if err != nil {
		return "", err
	}
	name, err := f.getDefaultFieldName(key, field)
	if err != nil {
		return "", err
	}
	if name == "id" {
		return "id", nil
	}
	fl, _ := f.schema.Table(key).Field(name)
	return fl.Column(), nil
}

func (f *factory) idField() db.Field {
	t := db.TypeString
	if f.useNumberID() {
		t = db.TypeNumber
	}
	return db.Field{Name: "id", Type: t, Required: true}
}

func (f *factory) getFieldAttributes(model, field string) (db.Field, error) {
	key, err := f.getDefaultModelName(model)
	if err != nil {
		return db.Field{}, err
	}
	name, err := f.getDefaultFieldName(key, field)
	if err != nil {
		return db.Field{}, err
	}
	if name == "id" {
		return f.idField(), nil
	}
	fl, _ := f.schema.Table(key).Field(name)
	return fl, nil
}

func (f *factory) mappedInputKey(field string) string {
	if v, ok := f.cfg.MapKeysTransformInput[field]; ok && v != "" {
		return v
	}
	return ""
}

// ---- id generation ----

var uuidRegex = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func (f *factory) shouldGenerateID(forceAllowID bool) bool {
	switch {
	case f.cfg.DisableIDGeneration:
		return false
	case f.useNumberID() && !forceAllowID:
		return false
	case f.opts.IDMode == IDUUID:
		return !f.cfg.SupportsUUIDs
	case f.opts.IDMode == IDNone:
		return false
	}
	return true
}

func (f *factory) generateID(modelKey string) (string, bool) {
	if f.cfg.DisableIDGeneration || f.opts.IDMode == IDNone || f.opts.IDMode == IDSerial {
		return "", false
	}
	if f.opts.GenerateID != nil {
		return f.opts.GenerateID(modelKey, 0)
	}
	if f.opts.IDMode == IDUUID {
		return bacrypto.RandomUUID(), true
	}
	if f.cfg.CustomIDGenerator != nil {
		return f.cfg.CustomIDGenerator(modelKey), true
	}
	return bacrypto.GenerateID(), true
}

// transformID applies the idField input transform.
func (f *factory) transformID(value any, present, forceAllowID bool, modelKey string) (any, bool) {
	gen := f.shouldGenerateID(forceAllowID)
	if !present && gen {
		if id, ok := f.generateID(modelKey); ok {
			value, present = id, true
		}
	}
	if !present || isFalsy(value) {
		return nil, false
	}
	if f.useNumberID() {
		n, err := strconv.ParseFloat(ToString(value), 64)
		if err != nil {
			return nil, false
		}
		return toNumber(n), true
	}
	if f.opts.IDMode == IDUUID {
		if gen && !forceAllowID {
			return value, true
		}
		if f.cfg.DisableIDGeneration {
			return nil, false
		}
		if s, ok := value.(string); ok && forceAllowID {
			if uuidRegex.MatchString(s) {
				return s, true
			}
			if f.opts.Logger != nil {
				f.opts.Logger.Warn("[Adapter Factory] - Invalid UUID value for field `id` provided when `forceAllowId` is true. Generating a new UUID.")
			}
		}
		if f.cfg.SupportsUUIDs {
			return nil, false
		}
		return bacrypto.RandomUUID(), true
	}
	return value, true
}

func isFalsy(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case bool:
		return !t
	case float64:
		return t == 0
	case int:
		return t == 0
	case int64:
		return t == 0
	}
	return false
}

// ---- transforms ----

func (f *factory) transformInput(data Record, modelKey, action string, forceAllowID bool) (Record, error) {
	t := f.schema.Table(modelKey)
	out := Record{}
	physModel, _ := f.getModelName(modelKey)
	// id first (it is the last key upstream, but order of a Go map is irrelevant)
	if action == "create" {
		v, present := data["id"]
		if !forceAllowID {
			present = false
		}
		if id, ok := f.transformID(v, present, forceAllowID, modelKey); ok {
			key := "id"
			if m := f.mappedInputKey("id"); m != "" {
				key = m
			}
			if f.cfg.CustomTransformInput != nil {
				id = f.cfg.CustomTransformInput(TransformParams{Data: id, Field: key, Attr: f.idField(), Action: action, Model: physModel})
			}
			if id != nil {
				out[key] = id
			}
		}
	} else if v, ok := data["id"]; ok && action != "update" {
		out["id"] = v
	}
	for _, fl := range t.Fields {
		value, present := data[fl.Name]
		newName := fl.Column()
		if m := f.mappedInputKey(fl.Name); m != "" {
			newName = m
		}
		if !present && ((!fl.HasDefault() && fl.TransformInput == nil && !(action == "update" && fl.OnUpdate != nil)) ||
			(action == "update" && fl.OnUpdate == nil)) {
			continue
		}
		if fl.Type == db.TypeDate {
			if s, ok := value.(string); ok {
				if tm, ok := jsonx.ParseJSDate(s); ok {
					value = tm
				}
			}
		}
		// withApplyDefault
		switch action {
		case "update":
			if !present && fl.OnUpdate != nil {
				value, present = fl.OnUpdate(), true
			}
		case "create":
			if (!present || (fl.Required && value == nil)) && fl.HasDefault() {
				value, present = fl.Default(), true
			}
		}
		if fl.TransformInput != nil {
			var arg any
			if present {
				arg = value
			}
			nv, err := fl.TransformInput(arg)
			if err != nil {
				return nil, err
			}
			value, present = nv, nv != nil || present
		}
		if !present {
			continue
		}
		value = f.encodeValue(fl, value)
		if f.cfg.CustomTransformInput != nil {
			value = f.cfg.CustomTransformInput(TransformParams{Data: value, Field: newName, Attr: fl, Action: action, Model: physModel})
		}
		out[newName] = value
	}
	return out, nil
}

// encodeValue converts a Go value to the representation the driver supports.
func (f *factory) encodeValue(fl db.Field, value any) any {
	if value == nil {
		return nil
	}
	if fl.References != nil && fl.References.Field == "id" && f.useNumberID() {
		if arr, ok := value.([]any); ok {
			out := make([]any, len(arr))
			for i, x := range arr {
				if x != nil {
					n, _ := strconv.ParseFloat(ToString(x), 64)
					out[i] = toNumber(n)
				}
			}
			return out
		}
		n, _ := strconv.ParseFloat(ToString(value), 64)
		return toNumber(n)
	}
	switch fl.Type {
	case db.TypeJSON:
		if !f.cfg.SupportsJSON {
			if _, isStr := value.(string); !isStr {
				b, err := json.Marshal(jsonx.ToPlain(value))
				if err == nil {
					return string(b)
				}
			}
		}
	case db.TypeStringArray, db.TypeNumberArray:
		if !f.cfg.SupportsArrays {
			if _, isStr := value.(string); !isStr {
				b, err := json.Marshal(value)
				if err == nil {
					return string(b)
				}
			}
		}
	case db.TypeDate:
		if tm, ok := value.(time.Time); ok {
			tm = tm.UTC().Truncate(time.Millisecond)
			if !f.supportsDates() {
				return jsonx.ISOTime(tm)
			}
			return tm
		}
	case db.TypeBoolean:
		if b, ok := value.(bool); ok && !f.supportsBooleans() {
			if b {
				return int64(1)
			}
			return int64(0)
		}
	case db.TypeNumber:
		if fv, ok := ToFloat(value); ok {
			return toNumber(fv)
		}
	}
	return value
}

func (f *factory) outputKey(originalKey string) string {
	for k, v := range f.cfg.MapKeysTransformOutput {
		if v == originalKey {
			return k
		}
	}
	return originalKey
}

func (f *factory) transformSingleOutput(rec Record, modelKey string, sel []string) Record {
	if rec == nil {
		return nil
	}
	t := f.schema.Table(modelKey)
	physModel, _ := f.getModelName(modelKey)
	out := Record{}
	contains := func(k string) bool {
		if len(sel) == 0 {
			return true
		}
		for _, s := range sel {
			if s == k {
				return true
			}
		}
		return false
	}
	idKey := "id"
	for k, v := range f.cfg.MapKeysTransformOutput {
		if v == "id" {
			idKey = k
		}
	}
	fields := append(append([]db.Field(nil), t.Fields...), db.Field{Name: idKey, Type: f.idField().Type})
	for _, fl := range fields {
		if !contains(fl.Name) {
			continue
		}
		originalKey := fl.Column()
		value, present := rec[f.outputKey(originalKey)]
		if fl.TransformOutput != nil {
			nv, err := fl.TransformOutput(value)
			if err == nil {
				value = nv
			}
		}
		newName := fl.Name
		if m, ok := f.cfg.MapKeysTransformOutput[fl.Name]; ok {
			newName = m
		}
		if originalKey == "id" || (fl.References != nil && fl.References.Field == "id") {
			if value != nil {
				value = ToString(value)
			}
		} else {
			value = f.decodeValue(fl, value)
		}
		if f.cfg.CustomTransformOutput != nil {
			value = f.cfg.CustomTransformOutput(TransformParams{Data: value, Field: newName, Attr: fl, Model: physModel})
		}
		if !present && value == nil {
			continue
		}
		out[newName] = value
	}
	return out
}

func (f *factory) decodeValue(fl db.Field, value any) any {
	if value == nil {
		return nil
	}
	switch fl.Type {
	case db.TypeJSON:
		switch t := value.(type) {
		case string:
			var v any
			if err := json.Unmarshal([]byte(t), &v); err == nil {
				return v
			}
			return nil
		case []byte:
			var v any
			if err := json.Unmarshal(t, &v); err == nil {
				return v
			}
		}
	case db.TypeStringArray, db.TypeNumberArray:
		switch t := value.(type) {
		case string:
			var v []any
			if err := json.Unmarshal([]byte(t), &v); err == nil {
				return v
			}
			return nil
		case []string:
			out := make([]any, len(t))
			for i, x := range t {
				out[i] = x
			}
			return out
		}
	case db.TypeDate:
		if tm, ok := ToTime(value); ok {
			return tm.UTC().Truncate(time.Millisecond)
		}
	case db.TypeBoolean:
		switch t := value.(type) {
		case bool:
			return t
		case int64:
			return t == 1
		case float64:
			return t == 1
		case int:
			return t == 1
		case []byte:
			return len(t) > 0 && t[0] == 1 || string(t) == "1"
		}
	case db.TypeNumber:
		if fv, ok := ToFloat(value); ok {
			return toNumber(fv)
		}
	case db.TypeString, db.TypeEnum:
		if b, ok := value.([]byte); ok {
			return string(b)
		}
	}
	return value
}

// toNumber normalises a float to int64 when it is integral.
func toNumber(f float64) any {
	if f == math.Trunc(f) && math.Abs(f) < 1<<53 {
		return int64(f)
	}
	return f
}

func (f *factory) transformWhere(modelKey string, where []Where, action string) ([]CleanedWhere, error) {
	if where == nil {
		return nil, nil
	}
	physModel, _ := f.getModelName(modelKey)
	out := make([]CleanedWhere, 0, len(where))
	for _, w := range where {
		op := w.Operator
		if op == "" {
			op = Eq
		}
		conn := w.Connector
		if conn == "" {
			conn = And
		}
		if op == In || op == NotIn {
			if _, ok := toAnySlice(w.Value); !ok {
				return nil, errors.New("Value must be an array")
			}
		}
		defField, err := f.getDefaultFieldName(modelKey, w.Field)
		if err != nil {
			return nil, err
		}
		fieldName := f.mappedInputKey(defField)
		if fieldName == "" {
			fieldName, _ = f.getFieldName(modelKey, defField)
		}
		attr, _ := f.getFieldAttributes(modelKey, defField)
		value := w.Value
		if defField == "id" || (attr.References != nil && attr.References.Field == "id") {
			if f.useNumberID() {
				if arr, ok := toAnySlice(value); ok {
					nv := make([]any, len(arr))
					for i, x := range arr {
						n, _ := strconv.ParseFloat(ToString(x), 64)
						nv[i] = toNumber(n)
					}
					value = nv
				} else {
					n, _ := strconv.ParseFloat(ToString(value), 64)
					value = toNumber(n)
				}
			}
		}
		if attr.Type == db.TypeDate {
			if tm, ok := value.(time.Time); ok {
				tm = tm.UTC().Truncate(time.Millisecond)
				if !f.supportsDates() {
					value = jsonx.ISOTime(tm)
				} else {
					value = tm
				}
			}
		}
		if attr.Type == db.TypeBoolean {
			if s, ok := value.(string); ok {
				value = s == "true"
			}
			if b, ok := value.(bool); ok && !f.supportsBooleans() {
				if b {
					value = int64(1)
				} else {
					value = int64(0)
				}
			}
		}
		if attr.Type == db.TypeNumber {
			switch t := value.(type) {
			case string:
				if strings.TrimSpace(t) != "" {
					if n, err := strconv.ParseFloat(strings.TrimSpace(t), 64); err == nil {
						value = toNumber(n)
					}
				}
			case float64:
				value = toNumber(t)
			case int:
				value = int64(t)
			default:
				if arr, ok := toAnySlice(value); ok {
					parsed := make([]any, len(arr))
					all := true
					for i, x := range arr {
						s, isStr := x.(string)
						if !isStr || strings.TrimSpace(s) == "" {
							if fv, ok := ToFloat(x); ok {
								parsed[i] = toNumber(fv)
								continue
							}
							all = false
							break
						}
						n, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
						if err != nil {
							all = false
							break
						}
						parsed[i] = toNumber(n)
					}
					if all {
						value = parsed
					}
				}
			}
		}
		if attr.Type == db.TypeJSON && !f.cfg.SupportsJSON {
			switch value.(type) {
			case map[string]any, []any, *jsonx.Object:
				b, err := json.Marshal(jsonx.ToPlain(value))
				if err != nil {
					return nil, fmt.Errorf("Failed to stringify JSON value for field %s", fieldName)
				}
				value = string(b)
			}
		}
		if f.cfg.CustomTransformInput != nil {
			value = f.cfg.CustomTransformInput(TransformParams{Data: value, Field: fieldName, Attr: attr, Action: action, Model: physModel})
		}
		out = append(out, CleanedWhere{Field: fieldName, Value: value, Operator: op, Connector: conn, Insensitive: w.Insensitive})
	}
	return out, nil
}

// ---- joins ----

type resolvedJoin struct {
	modelName string // physical
	cfg       JoinConfig
}

func (f *factory) transformJoin(baseModel string, join map[string]Join, sel []string) ([]resolvedJoin, []string, error) {
	if len(join) == 0 {
		return nil, sel, nil
	}
	baseKey, err := f.getDefaultModelName(baseModel)
	if err != nil {
		return nil, nil, err
	}
	var out []resolvedJoin
	// deterministic order
	models := make([]string, 0, len(join))
	for m := range join {
		models = append(models, m)
	}
	sortStrings(models)
	for _, model := range models {
		spec := join[model]
		joinKey, err := f.getDefaultModelName(model)
		if err != nil {
			return nil, nil, err
		}
		type fk struct {
			name string
			attr db.Field
		}
		var fks []fk
		for _, fl := range f.schema.Table(joinKey).Fields {
			if fl.References != nil {
				if rk, err := f.getDefaultModelName(fl.References.Model); err == nil && rk == baseKey {
					fks = append(fks, fk{fl.Name, fl})
				}
			}
		}
		forward := true
		if len(fks) == 0 {
			for _, fl := range f.schema.Table(baseKey).Fields {
				if fl.References != nil {
					if rk, err := f.getDefaultModelName(fl.References.Model); err == nil && rk == joinKey {
						fks = append(fks, fk{fl.Name, fl})
					}
				}
			}
			forward = false
		}
		if len(fks) == 0 {
			return nil, nil, fmt.Errorf("No foreign key found for model %s and base model %s while performing join operation.", model, baseModel)
		}
		if len(fks) > 1 {
			return nil, nil, fmt.Errorf("Multiple foreign keys found for model %s and base model %s while performing join operation. Only one foreign key is supported.", model, baseModel)
		}
		key, attr := fks[0].name, fks[0].attr
		var from, to, required string
		if forward {
			required = attr.References.Field
			from, _ = f.getFieldName(baseKey, required)
			to, _ = f.getFieldName(joinKey, key)
		} else {
			required = key
			from, _ = f.getFieldName(baseKey, required)
			to, _ = f.getFieldName(joinKey, attr.References.Field)
		}
		if len(sel) > 0 {
			found := false
			for _, s := range sel {
				if s == required {
					found = true
				}
			}
			if !found {
				sel = append(sel, required)
			}
		}
		unique := to == "id" || attr.Unique
		limit := f.opts.DefaultFindManyLimit
		if unique {
			limit = 1
		} else if spec.Limit > 0 {
			limit = spec.Limit
		}
		rel := "one-to-many"
		if unique {
			rel = "one-to-one"
		}
		physName, _ := f.getModelName(model)
		out = append(out, resolvedJoin{modelName: physName, cfg: JoinConfig{ModelKey: joinKey, From: from, To: to, Limit: limit, Relation: rel}})
	}
	return out, sel, nil
}

func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

func joinMap(js []resolvedJoin) map[string]JoinConfig {
	if len(js) == 0 {
		return nil
	}
	m := map[string]JoinConfig{}
	for _, j := range js {
		m[j.modelName] = j.cfg
	}
	return m
}

func (f *factory) transformOutput(ctx context.Context, custom CustomAdapter, rec Record, modelKey string, sel []string, joins []resolvedJoin) (Record, error) {
	if rec == nil {
		return nil, nil
	}
	out := f.transformSingleOutput(rec, modelKey, sel)
	for _, j := range joins {
		var joined any
		if f.opts.Joins {
			joined = rec[j.modelName]
		} else {
			// fallback join: query the related model directly
			baseField, _ := f.getDefaultFieldName(modelKey, j.cfg.From)
			value := out[baseField]
			if value == nil {
				joined = nil
			} else {
				where, err := f.transformWhere(j.cfg.ModelKey, []Where{{Field: j.cfg.To, Value: value}}, "findOne")
				if err != nil {
					return nil, err
				}
				q := Query{Model: j.modelName, ModelKey: j.cfg.ModelKey, Where: where}
				if j.cfg.Relation == "one-to-one" {
					r, err := custom.FindOne(ctx, q)
					if err != nil {
						return nil, err
					}
					if r != nil {
						joined = r
					}
				} else {
					q.Limit = j.cfg.Limit
					rs, err := custom.FindMany(ctx, q)
					if err != nil {
						return nil, err
					}
					arr := make([]any, len(rs))
					for i, r := range rs {
						arr[i] = r
					}
					joined = arr
				}
			}
		}
		if j.cfg.Relation == "one-to-one" {
			var item Record
			switch t := joined.(type) {
			case Record:
				item = t
			case []any:
				if len(t) > 0 {
					item, _ = t[0].(Record)
				}
			case []Record:
				if len(t) > 0 {
					item = t[0]
				}
			}
			if item == nil {
				out[j.cfg.ModelKey] = nil
			} else {
				out[j.cfg.ModelKey] = f.transformSingleOutput(item, j.cfg.ModelKey, nil)
			}
		} else {
			items := []Record{}
			switch t := joined.(type) {
			case []any:
				for _, x := range t {
					if r, ok := x.(Record); ok {
						items = append(items, f.transformSingleOutput(r, j.cfg.ModelKey, nil))
					}
				}
			case []Record:
				for _, r := range t {
					items = append(items, f.transformSingleOutput(r, j.cfg.ModelKey, nil))
				}
			case Record:
				items = append(items, f.transformSingleOutput(t, j.cfg.ModelKey, nil))
			}
			out[j.cfg.ModelKey] = items
		}
	}
	return out, nil
}

// ---- Adapter implementation ----

func (f *factory) current(ctx context.Context) CustomAdapter {
	if tx, ok := ctx.Value(customTxKey{f}).(CustomAdapter); ok {
		return tx
	}
	return f.custom
}

func (f *factory) Create(ctx context.Context, in CreateInput) (Record, error) {
	key, err := f.getDefaultModelName(in.Model)
	if err != nil {
		return nil, err
	}
	model, _ := f.getModelName(key)
	data := in.Data
	if _, hasID := data["id"]; hasID && !in.ForceAllowID {
		if f.opts.Logger != nil {
			f.opts.Logger.Warn(fmt.Sprintf("[%s] - You are trying to create a record with an id. This is not allowed as we handle id generation for you, unless you pass in the `forceAllowId` parameter. The id will be ignored.", f.cfg.AdapterName))
		}
	}
	tdata, err := f.transformInput(data, key, "create", in.ForceAllowID)
	if err != nil {
		return nil, err
	}
	custom := f.current(ctx)
	res, err := custom.Create(ctx, model, key, tdata)
	if err != nil {
		return nil, err
	}
	return f.transformOutput(ctx, custom, res, key, in.Select, nil)
}

func (f *factory) Update(ctx context.Context, modelIn string, where []Where, update Record) (Record, error) {
	key, err := f.getDefaultModelName(modelIn)
	if err != nil {
		return nil, err
	}
	model, _ := f.getModelName(key)
	cw, err := f.transformWhere(key, where, "update")
	if err != nil {
		return nil, err
	}
	if len(cw) == 0 {
		return nil, nil
	}
	data, err := f.transformInput(update, key, "update", false)
	if err != nil {
		return nil, err
	}
	custom := f.current(ctx)
	res, err := custom.Update(ctx, Query{Model: model, ModelKey: key, Where: cw}, data)
	if err != nil {
		return nil, err
	}
	return f.transformOutput(ctx, custom, res, key, nil, nil)
}

func (f *factory) UpdateMany(ctx context.Context, modelIn string, where []Where, update Record) (int64, error) {
	key, err := f.getDefaultModelName(modelIn)
	if err != nil {
		return 0, err
	}
	model, _ := f.getModelName(key)
	cw, err := f.transformWhere(key, where, "updateMany")
	if err != nil {
		return 0, err
	}
	data, err := f.transformInput(update, key, "update", false)
	if err != nil {
		return 0, err
	}
	return f.current(ctx).UpdateMany(ctx, Query{Model: model, ModelKey: key, Where: cw}, data)
}

func (f *factory) FindOne(ctx context.Context, in FindOneInput) (Record, error) {
	key, err := f.getDefaultModelName(in.Model)
	if err != nil {
		return nil, err
	}
	model, _ := f.getModelName(key)
	cw, err := f.transformWhere(key, in.Where, "findOne")
	if err != nil {
		return nil, err
	}
	joins, sel, err := f.transformJoin(key, in.Join, append([]string(nil), in.Select...))
	if err != nil {
		return nil, err
	}
	q := Query{Model: model, ModelKey: key, Where: cw, Select: f.physicalSelect(key, sel)}
	if f.opts.Joins {
		q.Join = joinMap(joins)
	}
	custom := f.current(ctx)
	res, err := custom.FindOne(ctx, q)
	if err != nil || res == nil {
		return nil, err
	}
	return f.transformOutput(ctx, custom, res, key, sel, joins)
}

func (f *factory) physicalSelect(key string, sel []string) []string {
	if len(sel) == 0 {
		return nil
	}
	out := make([]string, 0, len(sel))
	for _, s := range sel {
		n, err := f.getFieldName(key, s)
		if err != nil {
			n = s
		}
		if m := f.mappedInputKey(s); m != "" {
			n = m
		}
		out = append(out, n)
	}
	return out
}

func (f *factory) FindMany(ctx context.Context, in FindManyInput) ([]Record, error) {
	key, err := f.getDefaultModelName(in.Model)
	if err != nil {
		return nil, err
	}
	model, _ := f.getModelName(key)
	limit := in.Limit
	if limit == 0 {
		limit = f.opts.DefaultFindManyLimit
	}
	cw, err := f.transformWhere(key, in.Where, "findMany")
	if err != nil {
		return nil, err
	}
	joins, sel, err := f.transformJoin(key, in.Join, append([]string(nil), in.Select...))
	if err != nil {
		return nil, err
	}
	q := Query{Model: model, ModelKey: key, Where: cw, Limit: limit, Offset: in.Offset, Select: f.physicalSelect(key, sel)}
	if in.SortBy != nil {
		col, err := f.getFieldName(key, in.SortBy.Field)
		if err != nil {
			return nil, err
		}
		dir := strings.ToLower(in.SortBy.Direction)
		if dir != "desc" {
			dir = "asc"
		}
		q.SortBy = &SortBy{Field: col, Direction: dir}
	}
	if f.opts.Joins {
		q.Join = joinMap(joins)
	}
	custom := f.current(ctx)
	res, err := custom.FindMany(ctx, q)
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(res))
	for _, r := range res {
		t, err := f.transformOutput(ctx, custom, r, key, sel, joins)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

func (f *factory) Count(ctx context.Context, modelIn string, where []Where) (int64, error) {
	key, err := f.getDefaultModelName(modelIn)
	if err != nil {
		return 0, err
	}
	model, _ := f.getModelName(key)
	cw, err := f.transformWhere(key, where, "count")
	if err != nil {
		return 0, err
	}
	return f.current(ctx).Count(ctx, Query{Model: model, ModelKey: key, Where: cw})
}

func (f *factory) Delete(ctx context.Context, modelIn string, where []Where) error {
	key, err := f.getDefaultModelName(modelIn)
	if err != nil {
		return err
	}
	model, _ := f.getModelName(key)
	cw, err := f.transformWhere(key, where, "delete")
	if err != nil {
		return err
	}
	return f.current(ctx).Delete(ctx, Query{Model: model, ModelKey: key, Where: cw})
}

func (f *factory) DeleteMany(ctx context.Context, modelIn string, where []Where) (int64, error) {
	key, err := f.getDefaultModelName(modelIn)
	if err != nil {
		return 0, err
	}
	model, _ := f.getModelName(key)
	cw, err := f.transformWhere(key, where, "deleteMany")
	if err != nil {
		return 0, err
	}
	return f.current(ctx).DeleteMany(ctx, Query{Model: model, ModelKey: key, Where: cw})
}

func (f *factory) ConsumeOne(ctx context.Context, modelIn string, where []Where) (Record, error) {
	key, err := f.getDefaultModelName(modelIn)
	if err != nil {
		return nil, err
	}
	model, _ := f.getModelName(key)
	cw, err := f.transformWhere(key, where, "consumeOne")
	if err != nil {
		return nil, err
	}
	custom := f.current(ctx)
	q := Query{Model: model, ModelKey: key, Where: cw}
	var res Record
	if c, ok := custom.(ConsumeOner); ok {
		res, err = c.ConsumeOne(ctx, q)
	} else {
		res, err = f.fallbackConsumeOne(ctx, custom, q)
	}
	if err != nil || res == nil {
		return nil, err
	}
	return f.transformOutput(ctx, custom, res, key, nil, nil)
}

func (f *factory) IncrementOne(ctx context.Context, in IncrementInput) (Record, error) {
	if len(in.Increment) == 0 && len(in.Set) == 0 {
		return nil, errors.New("incrementOne requires a non-empty `increment` or `set`; both were empty.")
	}
	key, err := f.getDefaultModelName(in.Model)
	if err != nil {
		return nil, err
	}
	model, _ := f.getModelName(key)
	cw, err := f.transformWhere(key, in.Where, "incrementOne")
	if err != nil {
		return nil, err
	}
	inc := map[string]float64{}
	for field, delta := range in.Increment {
		col := f.mappedInputKey(field)
		if col == "" {
			col, err = f.getFieldName(key, field)
			if err != nil {
				return nil, err
			}
		}
		inc[col] = delta
	}
	var set Record
	if len(in.Set) > 0 {
		set, err = f.transformInput(in.Set, key, "update", false)
		if err != nil {
			return nil, err
		}
	}
	if len(inc) == 0 && len(set) == 0 {
		return nil, errors.New("incrementOne resolved to an empty update: every increment/set field was unknown to the schema or transformed away.")
	}
	custom := f.current(ctx)
	q := Query{Model: model, ModelKey: key, Where: cw}
	var res Record
	if c, ok := custom.(IncrementOner); ok {
		res, err = c.IncrementOne(ctx, q, inc, set)
	} else {
		res, err = f.fallbackIncrementOne(ctx, custom, q, inc, set)
	}
	if err != nil || res == nil {
		return nil, err
	}
	return f.transformOutput(ctx, custom, res, key, nil, nil)
}

type customTxKey struct{ f *factory }

func (f *factory) Transaction(ctx context.Context, fn func(ctx context.Context, tx Adapter) error) error {
	t, ok := f.current(ctx).(Transactor)
	if !ok {
		return fn(ctx, f)
	}
	return t.Transaction(ctx, func(txCtx context.Context, tx CustomAdapter) error {
		txCtx = context.WithValue(txCtx, customTxKey{f}, tx)
		return fn(txCtx, f)
	})
}

// ---- atomic fallbacks (atomic-fallback.ts) ----

func isScalar(v any) bool {
	switch v.(type) {
	case nil, string, bool, float64, float32, int, int64, int32, time.Time:
		return true
	}
	return false
}

func (f *factory) snapshotGuard(row Record, fields []string, q Query) ([]CleanedWhere, error) {
	idCol := "id"
	if m := f.mappedInputKey("id"); m != "" {
		idCol = m
	}
	idVal, ok := row[idCol]
	if !ok || idVal == nil {
		return nil, fmt.Errorf("Adapter \"%s\" must return the row id for atomic fallbacks.", f.cfg.AdapterID)
	}
	idWhere := CleanedWhere{Field: idCol, Value: idVal, Operator: Eq, Connector: And}
	hasOr := false
	for _, w := range q.Where {
		if w.Connector == Or {
			hasOr = true
		}
	}
	var guard []CleanedWhere
	if hasOr {
		guard = []CleanedWhere{idWhere}
	} else {
		guard = append(append([]CleanedWhere(nil), q.Where...), idWhere)
	}
	seen := map[string]bool{}
	for _, field := range fields {
		if seen[field] || field == idCol {
			continue
		}
		seen[field] = true
		v := row[field]
		if !isScalar(v) {
			continue
		}
		guard = append(guard, CleanedWhere{Field: field, Value: v, Operator: Eq, Connector: And})
	}
	return guard, nil
}

func (f *factory) fallbackConsumeOne(ctx context.Context, custom CustomAdapter, q Query) (Record, error) {
	row, err := custom.FindOne(ctx, q)
	if err != nil || row == nil {
		return nil, err
	}
	var fields []string
	for k := range row {
		fields = append(fields, k)
	}
	for _, w := range q.Where {
		fields = append(fields, w.Field)
	}
	guard, err := f.snapshotGuard(row, fields, q)
	if err != nil {
		return nil, err
	}
	n, err := custom.DeleteMany(ctx, Query{Model: q.Model, ModelKey: q.ModelKey, Where: guard})
	if err != nil {
		return nil, err
	}
	if n == 1 {
		return row, nil
	}
	return nil, nil
}

func (f *factory) fallbackIncrementOne(ctx context.Context, custom CustomAdapter, q Query, inc map[string]float64, set Record) (Record, error) {
	var fields []string
	for _, w := range q.Where {
		fields = append(fields, w.Field)
	}
	for k := range inc {
		fields = append(fields, k)
	}
	for k := range set {
		fields = append(fields, k)
	}
	for attempt := 0; attempt < 5; attempt++ {
		row, err := custom.FindOne(ctx, q)
		if err != nil || row == nil {
			return nil, err
		}
		update := Record{}
		for k, v := range set {
			update[k] = v
		}
		for field, delta := range inc {
			cur := 0.0
			if v := row[field]; v != nil {
				fv, ok := ToFloat(v)
				if !ok {
					return nil, fmt.Errorf("Adapter \"%s\" must return finite numeric counter values or null for atomic increments.", f.cfg.AdapterID)
				}
				cur = fv
			}
			update[field] = toNumber(cur + delta)
		}
		guard, err := f.snapshotGuard(row, fields, q)
		if err != nil {
			return nil, err
		}
		n, err := custom.UpdateMany(ctx, Query{Model: q.Model, ModelKey: q.ModelKey, Where: guard}, update)
		if err != nil {
			return nil, err
		}
		if n == 1 {
			out := Record{}
			for k, v := range row {
				out[k] = v
			}
			for k, v := range update {
				out[k] = v
			}
			return out, nil
		}
	}
	return nil, fmt.Errorf("Adapter \"%s\" could not complete an atomic increment due to contention. Retry the operation or implement incrementOne natively.", f.cfg.AdapterID)
}
