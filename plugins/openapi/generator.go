package openapi

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// MetadataKey is the Endpoint.Metadata key holding an endpoint's OpenAPI overrides
// (metadata.openapi upstream): description, operationId, tags, parameters, requestBody and
// responses, as maps / *jsonx.Object / any JSON-marshalable value.
const MetadataKey = "openapi"

// BodySchemaMetadataKey is an Endpoint.Metadata key holding a validate.Schema used as the
// documented request body for endpoints that validate their body themselves (Body nil),
// e.g. to report validation errors in a custom format.
const BodySchemaMetadataKey = "openapiBodySchema"

// coreTable holds the metadata.openapi blocks of the core endpoints
// (packages/better-auth/src/api/routes/*.ts), keyed by endpoint key, plus the zod
// .meta({description}) texts of their body and query schemas, keyed by
// "body" or "query.<param>" and a "/"-separated JSON path inside the converted schema.
//
//go:embed core_openapi.json
var coreTableJSON []byte

type coreEntry struct {
	OpenAPI      *jsonx.Object
	Descriptions map[string]string
	// Schemas replaces converted schema nodes whose Go validators are opaque functions
	// (validate.Custom) with the schema upstream derives from its zod definition.
	Schemas map[string]*jsonx.Object
}

var (
	coreOnce  sync.Once
	coreTable map[string]coreEntry
)

func loadCoreTable() map[string]coreEntry {
	coreOnce.Do(func() {
		coreTable = map[string]coreEntry{}
		v, err := jsonx.Parse(coreTableJSON)
		if err != nil {
			panic("openapi: invalid core_openapi.json: " + err.Error())
		}
		root := v.(*jsonx.Object)
		for _, k := range root.Keys() {
			raw, _ := root.Get(k)
			entry := raw.(*jsonx.Object)
			ce := coreEntry{Descriptions: map[string]string{}, Schemas: map[string]*jsonx.Object{}}
			if sc, ok := entry.Get("schemas"); ok {
				if so, ok := sc.(*jsonx.Object); ok {
					for _, p := range so.Keys() {
						x, _ := so.Get(p)
						ce.Schemas[p], _ = x.(*jsonx.Object)
					}
				}
			}
			if o, ok := entry.Get("openapi"); ok {
				ce.OpenAPI, _ = o.(*jsonx.Object)
			}
			if d, ok := entry.Get("descriptions"); ok {
				if do, ok := d.(*jsonx.Object); ok {
					for _, p := range do.Keys() {
						s, _ := do.Get(p)
						ce.Descriptions[p], _ = s.(string)
					}
				}
			}
			coreTable[k] = ce
		}
	})
	return coreTable
}

// toOrdered converts any JSON-marshalable value into ordered jsonx values (a deep copy).
func toOrdered(v any) any {
	if v == nil {
		return nil
	}
	b, err := jsonx.Marshal(v)
	if err != nil {
		b, err = json.Marshal(v)
		if err != nil {
			return nil
		}
	}
	out, err := jsonx.Parse(b)
	if err != nil {
		return nil
	}
	return out
}

func deepClone(v any) any {
	switch t := v.(type) {
	case *jsonx.Object:
		c := jsonx.NewObject()
		for _, k := range t.Keys() {
			x, _ := t.Get(k)
			c.Set(k, deepClone(x))
		}
		return c
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = deepClone(x)
		}
		return out
	}
	return v
}

// endpointOpenAPI returns the endpoint's metadata.openapi block (nil when absent). Core
// endpoints without one fall back to the ported upstream table.
func endpointOpenAPI(ep *betterauth.Endpoint, core bool) *jsonx.Object {
	if ep.Metadata != nil {
		if v, ok := ep.Metadata[MetadataKey]; ok && v != nil {
			if o, ok := toOrdered(v).(*jsonx.Object); ok {
				return o
			}
		}
	}
	if core {
		if e, ok := loadCoreTable()[ep.Key]; ok && e.OpenAPI != nil {
			return deepClone(e.OpenAPI).(*jsonx.Object)
		}
	}
	return nil
}

func objGet(o *jsonx.Object, key string) any {
	if o == nil {
		return nil
	}
	v, _ := o.Get(key)
	return v
}

func isServerOnly(ep *betterauth.Endpoint) bool {
	if ep.ServerOnly {
		return true
	}
	if ep.Metadata != nil {
		if b, ok := ep.Metadata["SERVER_ONLY"].(bool); ok && b {
			return true
		}
	}
	return false
}

func unwrapDescribedSchema(s validate.Schema) validate.Schema {
	for {
		info := validate.Inspect(s)
		if info.Kind != validate.KindDescribed {
			return s
		}
		s = info.Inner
	}
}

func getParameters(ep *betterauth.Endpoint, meta *jsonx.Object, ov *coreEntry) []any {
	var params []any
	if p, ok := objGet(meta, "parameters").([]any); ok {
		params = append(params, p...)
		return params
	}
	if ep.Query == nil {
		return params
	}
	info := validate.Inspect(unwrapDescribedSchema(ep.Query))
	if info.Kind != validate.KindObject {
		return params
	}
	for _, f := range info.Fields {
		schema := toOpenAPISchema(f.Schema)
		applyOverlay(schema, ov, "query."+f.Name)
		params = append(params, jsonx.O("name", f.Name, "in", "query", "schema", schema))
	}
	return params
}

func getPathParameters(path string, params []any) []any {
	existing := map[string]bool{}
	for _, p := range params {
		if o, ok := p.(*jsonx.Object); ok {
			in, _ := objGet(o, "in").(string)
			name, _ := objGet(o, "name").(string)
			existing[in+":"+name] = true
		}
	}
	var out []any
	for _, part := range strings.Split(path, "/") {
		if !strings.HasPrefix(part, ":") {
			continue
		}
		name := part[1:]
		if existing["path:"+name] {
			continue
		}
		out = append(out, jsonx.O("name", name, "in", "path", "required", true, "schema", jsonx.O("type", "string")))
	}
	return out
}

// lookupPath walks a "/"-separated path of object keys and array indexes.
func lookupPath(root any, rest string) (parent any, last string, node any) {
	node = root
	if rest == "" {
		return nil, "", node
	}
	segs := strings.Split(rest, "/")
	for i, seg := range segs {
		parent, last = node, seg
		switch n := node.(type) {
		case *jsonx.Object:
			node, _ = n.Get(seg)
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(n) {
				return nil, "", nil
			}
			node = n[idx]
		default:
			return nil, "", nil
		}
		if node == nil && i < len(segs)-1 {
			return nil, "", nil
		}
	}
	return parent, last, node
}

func relPath(p, prefix string) (string, bool) {
	if p == prefix {
		return "", true
	}
	if strings.HasPrefix(p, prefix+"/") {
		return p[len(prefix)+1:], true
	}
	return "", false
}

// applyOverlay applies the core table's schema replacements and descriptions (recorded
// at "/"-separated paths below prefix) to a converted schema.
func applyOverlay(schema *jsonx.Object, ov *coreEntry, prefix string) {
	if ov == nil {
		return
	}
	for p, repl := range ov.Schemas {
		rest, ok := relPath(p, prefix)
		if !ok || rest == "" || repl == nil {
			continue
		}
		parent, last, node := lookupPath(schema, rest)
		if po, isObj := parent.(*jsonx.Object); isObj && node != nil {
			po.Set(last, deepClone(repl))
		}
	}
	for p, d := range ov.Descriptions {
		rest, ok := relPath(p, prefix)
		if !ok {
			continue
		}
		_, _, node := lookupPath(schema, rest)
		if o, isObj := node.(*jsonx.Object); isObj && o != nil && !o.Has("description") {
			o.Set("description", d)
		}
	}
}

func getRequestBody(ep *betterauth.Endpoint, meta *jsonx.Object, ov *coreEntry) *jsonx.Object {
	if rb, ok := objGet(meta, "requestBody").(*jsonx.Object); ok {
		return rb
	}
	body := ep.Body
	if body == nil && ep.Metadata != nil {
		if s, ok := ep.Metadata[BodySchemaMetadataKey].(validate.Schema); ok {
			body = s
		}
	}
	if body == nil {
		return nil
	}
	schema := toOpenAPISchema(body)
	applyOverlay(schema, ov, "body")
	return jsonx.O("required", !schemaAcceptsUndefined(body),
		"content", jsonx.O("application/json", jsonx.O("schema", schema)))
}

var userInputBodyPaths = map[string]bool{"/sign-up/email": true, "/update-user": true}

func dbFieldToRequestBodyProperty(f db.Field) *jsonx.Object {
	switch f.Type {
	case db.TypeDate:
		return jsonx.O("type", "string", "format", "date-time")
	case db.TypeJSON:
		return jsonx.NewObject()
	case db.TypeStringArray:
		return jsonx.O("type", "array", "items", jsonx.O("type", "string"))
	case db.TypeNumberArray:
		return jsonx.O("type", "array", "items", jsonx.O("type", "number"))
	case db.TypeEnum:
		values := make([]any, len(f.Enum))
		for i, v := range f.Enum {
			values[i] = v
		}
		return jsonx.O("type", "string", "enum", values)
	}
	s := jsonx.O("type", string(f.Type))
	if f.DefaultFunc == nil && f.DefaultValue != nil {
		s.Set("default", f.DefaultValue)
	}
	return s
}

type namedFields struct {
	order  []string
	fields map[string]db.Field
}

func (n *namedFields) add(f db.Field) {
	if n.fields == nil {
		n.fields = map[string]db.Field{}
	}
	if _, ok := n.fields[f.Name]; !ok {
		n.order = append(n.order, f.Name)
	}
	n.fields[f.Name] = f
}

func userInputRequestBodyFields(cfg *betterauth.Config, plugins []*betterauth.Plugin) (*jsonx.Object, []string) {
	var nf namedFields
	if cfg.User != nil {
		for _, f := range cfg.User.AdditionalFields {
			nf.add(f)
		}
	}
	for _, p := range plugins {
		for _, t := range p.Schema {
			if t.Key != "user" {
				continue
			}
			for _, f := range t.Fields {
				nf.add(f)
			}
		}
	}
	props := jsonx.NewObject()
	var required []string
	for _, name := range nf.order {
		f := nf.fields[name]
		if !f.IsInput() {
			continue
		}
		props.Set(name, dbFieldToRequestBodyProperty(f))
		if f.IsRequired() && !f.HasDefault() {
			required = append(required, name)
		}
	}
	return props, required
}

func applyUserInputFields(path string, rb *jsonx.Object, cfg *betterauth.Config, plugins []*betterauth.Plugin) *jsonx.Object {
	if !userInputBodyPaths[path] {
		return rb
	}
	inputProps, inputRequired := userInputRequestBodyFields(cfg, plugins)
	if inputProps.Len() == 0 {
		return rb
	}
	var existing *jsonx.Object
	if rb != nil {
		if c, ok := objGet(rb, "content").(*jsonx.Object); ok {
			if aj, ok := objGet(c, "application/json").(*jsonx.Object); ok {
				existing, _ = objGet(aj, "schema").(*jsonx.Object)
			}
		}
	}
	props := jsonx.NewObject()
	if ep, ok := objGet(existing, "properties").(*jsonx.Object); ok {
		props = ep.Clone()
	}
	for _, k := range inputProps.Keys() {
		if !props.Has(k) {
			v, _ := inputProps.Get(k)
			props.Set(k, v)
		}
	}
	var required []any
	seen := map[any]bool{}
	if r, ok := objGet(existing, "required").([]any); ok {
		for _, x := range r {
			if !seen[x] {
				seen[x] = true
				required = append(required, x)
			}
		}
	}
	if path == "/sign-up/email" {
		for _, k := range inputRequired {
			if props.Has(k) && !seen[k] {
				seen[k] = true
				required = append(required, k)
			}
		}
	}
	schema := jsonx.NewObject()
	if existing != nil {
		schema = existing.Clone()
	}
	if !schema.Has("type") || objGet(schema, "type") == nil {
		schema.Set("type", "object")
	}
	schema.Set("properties", props)
	if len(required) > 0 {
		schema.Set("required", required)
	}
	out := jsonx.NewObject()
	if rb != nil {
		out = rb.Clone()
	}
	out.Set("content", jsonx.O("application/json", jsonx.O("schema", schema)))
	return out
}

func defaultResponses(over *jsonx.Object) *jsonx.Object {
	msg := func(required bool) *jsonx.Object {
		s := jsonx.O("type", "object", "properties", jsonx.O("message", jsonx.O("type", "string")))
		if required {
			s.Set("required", []any{"message"})
		}
		return jsonx.O("application/json", jsonx.O("schema", s))
	}
	out := jsonx.O(
		"400", jsonx.O("content", msg(true), "description", "Bad Request. Usually due to missing parameters, or invalid parameters."),
		"401", jsonx.O("content", msg(true), "description", "Unauthorized. Due to missing or invalid authentication."),
		"403", jsonx.O("content", msg(false), "description", "Forbidden. You do not have permission to access this resource or to perform this action."),
		"404", jsonx.O("content", msg(false), "description", "Not Found. The requested resource was not found."),
		"429", jsonx.O("content", msg(false), "description", "Too Many Requests. You have exceeded the rate limit. Try again later."),
		"500", jsonx.O("content", msg(false), "description", "Internal Server Error. This is a problem with the server that you cannot fix."),
	)
	if over != nil {
		for _, k := range over.Keys() {
			v, _ := over.Get(k)
			out.Set(k, deepClone(v))
		}
	}
	return out
}

func toOpenAPIPath(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if strings.HasPrefix(p, ":") {
			parts[i] = "{" + p[1:] + "}"
		}
	}
	return strings.Join(parts, "/")
}

func operationID(id string, method string, used map[string]bool) any {
	if id == "" {
		return nil
	}
	if !used[id] {
		used[id] = true
		return id
	}
	m := strings.ToUpper(method)
	suffix := m[:1] + strings.ToLower(m[1:])
	candidate := id + suffix
	for i := 2; used[candidate]; i++ {
		candidate = id + suffix + strconv.Itoa(i)
	}
	used[candidate] = true
	return candidate
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func getFieldSchema(f db.Field) *jsonx.Object {
	var s *jsonx.Object
	switch f.Type {
	case db.TypeStringArray:
		s = jsonx.O("type", "array", "items", jsonx.O("type", "string"))
	case db.TypeNumberArray:
		s = jsonx.O("type", "array", "items", jsonx.O("type", "number"))
	case db.TypeDate:
		s = jsonx.O("type", "string", "format", "date-time")
	case db.TypeEnum:
		values := make([]any, len(f.Enum))
		for i, v := range f.Enum {
			values[i] = v
		}
		s = jsonx.O("type", values)
	default:
		s = jsonx.O("type", string(f.Type))
	}
	if f.DefaultFunc == nil && f.DefaultValue != nil {
		s.Set("default", f.DefaultValue)
	}
	if !f.IsInput() {
		s.Set("readOnly", true)
	}
	return s
}

func modelSchemas(cfg *betterauth.Config) *jsonx.Object {
	c := *cfg
	sess := betterauth.SessionConfig{}
	if cfg.Session != nil {
		sess = *cfg.Session
	}
	sess.StoreSessionInDatabase = true // the session table is always documented
	c.Session = &sess
	schema := betterauth.GetSchema(c)
	out := jsonx.NewObject()
	for _, t := range schema.Tables {
		props := jsonx.O("id", jsonx.O("type", "string", "readOnly", true))
		required := []any{"id"}
		seen := map[string]bool{"id": true}
		for _, f := range t.Fields {
			props.Set(f.Name, getFieldSchema(f))
			if f.IsRequired() && f.IsReturned() && !seen[f.Name] {
				seen[f.Name] = true
				required = append(required, f.Name)
			}
		}
		out.Set(capitalize(t.Key), jsonx.O("type", "object", "properties", props, "required", required))
	}
	return out
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

type pathItems struct {
	order []string
	items map[string]*jsonx.Object
}

func (p *pathItems) set(path, method string, op *jsonx.Object) {
	if p.items == nil {
		p.items = map[string]*jsonx.Object{}
	}
	item, ok := p.items[path]
	if !ok {
		item = jsonx.NewObject()
		p.items[path] = item
		p.order = append(p.order, path)
	}
	item.Set(method, op)
}

func stringsFrom(v any) []any {
	if arr, ok := v.([]any); ok {
		return arr
	}
	return nil
}

func buildOperation(tags []any, meta *jsonx.Object, method string, used map[string]bool, params []any) *jsonx.Object {
	op := jsonx.O("tags", tags)
	if d := objGet(meta, "description"); d != nil {
		op.Set("description", d)
	}
	id, _ := objGet(meta, "operationId").(string)
	if oid := operationID(id, method, used); oid != nil {
		op.Set("operationId", oid)
	}
	op.Set("security", []any{jsonx.O("bearerAuth", []any{})})
	if params == nil {
		params = []any{}
	}
	op.Set("parameters", deepClone(params))
	return op
}

// Generate builds the OpenAPI document for an auth context (generator upstream).
func Generate(ac *betterauth.AuthContext) *jsonx.Object {
	cfg := ac.Options
	plugins := ac.Plugins()
	var paths pathItems
	used := map[string]bool{}
	baseKeys := map[string]bool{}
	core := betterauth.OpenAPICoreEndpoints()
	for _, ep := range core {
		if ep.Key != "" {
			baseKeys[ep.Key] = true
		}
	}
	table := loadCoreTable()
	for _, ep := range core {
		if ep.Path == "" || containsString(cfg.DisabledPaths, ep.Path) || isServerOnly(ep) {
			continue
		}
		meta := endpointOpenAPI(ep, true)
		var ov *coreEntry
		if e, ok := table[ep.Key]; ok && (ep.Metadata == nil || ep.Metadata[MetadataKey] == nil) {
			ov = &e
		}
		path := toOpenAPIPath(ep.Path)
		params := getParameters(ep, meta, ov)
		params = append(params, getPathParameters(ep.Path, params)...)
		tags := append([]any{"Default"}, stringsFrom(objGet(meta, "tags"))...)
		respOver, _ := objGet(meta, "responses").(*jsonx.Object)
		for _, m := range ep.Methods {
			if m != "GET" && m != "DELETE" {
				continue
			}
			op := buildOperation(deepClone(tags).([]any), meta, m, used, params)
			op.Set("responses", defaultResponses(respOver))
			paths.set(path, strings.ToLower(m), op)
		}
		for _, m := range ep.Methods {
			if m != "POST" && m != "PATCH" && m != "PUT" {
				continue
			}
			body := applyUserInputFields(ep.Path, getRequestBody(ep, meta, ov), cfg, plugins)
			op := buildOperation(deepClone(tags).([]any), meta, m, used, params)
			if body != nil {
				op.Set("requestBody", deepClone(body))
			} else {
				op.Set("requestBody", jsonx.O("content", jsonx.O("application/json",
					jsonx.O("schema", jsonx.O("type", "object", "properties", jsonx.NewObject())))))
			}
			op.Set("responses", defaultResponses(respOver))
			paths.set(path, strings.ToLower(m), op)
		}
	}
	for _, p := range plugins {
		if p.ID == "open-api" {
			continue
		}
		for _, ep := range p.Endpoints {
			if ep.Key != "" && baseKeys[ep.Key] {
				continue
			}
			if ep.Path == "" || containsString(cfg.DisabledPaths, ep.Path) || isServerOnly(ep) {
				continue
			}
			meta := endpointOpenAPI(ep, false)
			path := toOpenAPIPath(ep.Path)
			params := getParameters(ep, meta, nil)
			params = append(params, getPathParameters(ep.Path, params)...)
			tags := stringsFrom(objGet(meta, "tags"))
			if objGet(meta, "tags") == nil {
				tags = []any{capitalize(p.ID)}
			}
			respOver, _ := objGet(meta, "responses").(*jsonx.Object)
			for _, m := range ep.Methods {
				if m != "GET" && m != "DELETE" {
					continue
				}
				op := buildOperation(deepClone(tags).([]any), meta, m, used, params)
				op.Set("responses", defaultResponses(respOver))
				paths.set(path, strings.ToLower(m), op)
			}
			for _, m := range ep.Methods {
				if m != "POST" && m != "PATCH" && m != "PUT" {
					continue
				}
				op := buildOperation(deepClone(tags).([]any), meta, m, used, params)
				if body := getRequestBody(ep, meta, nil); body != nil {
					op.Set("requestBody", deepClone(body))
				}
				op.Set("responses", defaultResponses(respOver))
				paths.set(path, strings.ToLower(m), op)
			}
		}
	}
	pathsObj := jsonx.NewObject()
	for _, p := range paths.order {
		pathsObj.Set(p, paths.items[p])
	}
	components := jsonx.O("schemas", modelSchemas(cfg), "securitySchemes", jsonx.O(
		"apiKeyCookie", jsonx.O("type", "apiKey", "in", "cookie", "name", "apiKeyCookie",
			"description", "API Key authentication via cookie"),
		"bearerAuth", jsonx.O("type", "http", "scheme", "bearer", "description", "Bearer token authentication"),
	))
	doc := jsonx.O(
		"openapi", "3.1.1",
		"info", jsonx.O("title", "Better Auth", "description", "API Reference for your Better Auth Instance", "version", "1.1.0"),
		"components", components,
		"security", []any{jsonx.O("apiKeyCookie", []any{}, "bearerAuth", []any{})},
		"servers", []any{jsonx.O("url", ac.BaseURL)},
		"tags", []any{jsonx.O("name", "Default", "description",
			"Default endpoints that are included with Better Auth by default. These endpoints are not part of any plugin.")},
		"paths", pathsObj,
	)
	return jsOrder(doc).(*jsonx.Object)
}

var arrayIndexKey = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// jsOrder reorders object keys like JavaScript does: integer-like keys first (ascending),
// then the remaining keys in insertion order.
func jsOrder(v any) any {
	switch t := v.(type) {
	case *jsonx.Object:
		var ints []int
		var rest []string
		for _, k := range t.Keys() {
			if arrayIndexKey.MatchString(k) && len(k) < 10 {
				n, _ := strconv.Atoi(k)
				ints = append(ints, n)
			} else {
				rest = append(rest, k)
			}
		}
		for i := 1; i < len(ints); i++ {
			for j := i; j > 0 && ints[j] < ints[j-1]; j-- {
				ints[j], ints[j-1] = ints[j-1], ints[j]
			}
		}
		out := jsonx.NewObject()
		for _, n := range ints {
			k := strconv.Itoa(n)
			x, _ := t.Get(k)
			out.Set(k, jsOrder(x))
		}
		for _, k := range rest {
			x, _ := t.Get(k)
			out.Set(k, jsOrder(x))
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = jsOrder(x)
		}
		return out
	}
	return v
}
