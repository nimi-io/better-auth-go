package scim

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/nimi-io/better-auth-go/jsonx"
)

// ---- resource-schema-registry.ts ----

// resourceType is "User" or "Group".
type resourceType string

const (
	resourceUser  resourceType = "User"
	resourceGroup resourceType = "Group"
)

func coreSchemaID(rt resourceType) string {
	if rt == resourceGroup {
		return SchemaGroup
	}
	return SchemaUser
}

// stripCoreAttributePrefix is stripSCIMCoreAttributePrefix.
func stripCoreAttributePrefix(rt resourceType, attributePath string) string {
	prefix := coreSchemaID(rt) + ":"
	if strings.HasPrefix(jsLower(attributePath), jsLower(prefix)) {
		return attributePath[len(prefix):]
	}
	return attributePath
}

type schemaDescriptor struct {
	id                 string
	canonicalAttribute string
	responseAttribute  string
	aliases            []pathAlias
}

type pathAlias struct{ path, relativePath string }

func schemaDescriptors(rt resourceType) []schemaDescriptor {
	if rt == resourceGroup {
		return []schemaDescriptor{{id: SchemaGroup}}
	}
	// Sorted by id length (descending): the Enterprise extension URN is longer.
	return []schemaDescriptor{
		{id: SchemaEnterpriseUser, canonicalAttribute: "enterprise", responseAttribute: SchemaEnterpriseUser,
			aliases: []pathAlias{{path: "manager", relativePath: "manager"}}},
		{id: SchemaUser},
	}
}

func resolveAttributePath(rt resourceType, attributePath string, mapAttr func(schemaDescriptor) string) string {
	normalized := jsLower(attributePath)
	for _, d := range schemaDescriptors(rt) {
		mapped := mapAttr(d)
		for _, a := range d.aliases {
			na := jsLower(a.path)
			if normalized != na && !strings.HasPrefix(normalized, na+".") {
				continue
			}
			suffix := attributePath[len(a.path):]
			if mapped != "" {
				return mapped + "." + a.relativePath + suffix
			}
			return a.relativePath + suffix
		}
		nid := jsLower(d.id)
		if normalized == nid {
			if mapped != "" {
				return mapped
			}
			return attributePath
		}
		if !strings.HasPrefix(normalized, nid+":") {
			continue
		}
		rel := attributePath[len(d.id)+1:]
		if mapped != "" {
			return mapped + "." + rel
		}
		return rel
	}
	return attributePath
}

func resolveResponseAttributePath(rt resourceType, p string) string {
	return resolveAttributePath(rt, p, func(d schemaDescriptor) string { return d.responseAttribute })
}

func resolveCanonicalAttributePath(rt resourceType, p string) string {
	return resolveAttributePath(rt, p, func(d schemaDescriptor) string { return d.canonicalAttribute })
}

// ---- collection-query.ts ----

type equalityFilter struct {
	attribute string
	value     string
}

type classicPagination struct {
	startIndex int
	offset     int
	count      int
}

type attributeProjection struct {
	mode       string // default, include, exclude
	attributes map[string]bool
	order      []string
}

type queryError struct {
	code      string
	parameter string
	scimType  string
	detail    string
}

type collectionQuery struct {
	filters    []equalityFilter
	pagination classicPagination
	projection attributeProjection
}

// queryInput is SCIMCollectionQueryInput.
type queryInput struct {
	filter                         *string
	startIndex, count              any
	attributes, excludedAttributes any
}

func queryInputFrom(q map[string]any) queryInput {
	in := queryInput{startIndex: undef, count: undef, attributes: undef, excludedAttributes: undef}
	if q == nil {
		return in
	}
	if v, ok := q["filter"].(string); ok {
		in.filter = &v
	}
	if v, ok := q["startIndex"]; ok {
		in.startIndex = v
	}
	if v, ok := q["count"]; ok {
		in.count = v
	}
	if v, ok := q["attributes"]; ok {
		in.attributes = v
	}
	if v, ok := q["excludedAttributes"]; ok {
		in.excludedAttributes = v
	}
	return in
}

var integerPattern = regexp.MustCompile(`^-?\d+$`)

func parseInteger(input any, parameter string) (*int, *queryError) {
	if input == nil || isUndef(input) {
		return nil, nil
	}
	parsed := math.NaN()
	switch t := input.(type) {
	case float64:
		parsed = t
	case int:
		parsed = float64(t)
	case int64:
		parsed = float64(t)
	case string:
		s := jsTrim(t)
		if integerPattern.MatchString(s) {
			if f, err := strconv.ParseFloat(s, 64); err == nil {
				parsed = f
			}
		}
	}
	if math.IsNaN(parsed) || math.IsInf(parsed, 0) || parsed != math.Trunc(parsed) || math.Abs(parsed) > 9007199254740991 {
		if parameter == "startIndex" {
			return nil, &queryError{"invalid-start-index", parameter, errInvalidValue, "startIndex must be an integer"}
		}
		return nil, &queryError{"invalid-count", parameter, errInvalidValue, "count must be an integer"}
	}
	n := int(parsed)
	return &n, nil
}

func parseClassicPagination(startIndex, count any) (classicPagination, *queryError) {
	si, err := parseInteger(startIndex, "startIndex")
	if err != nil {
		return classicPagination{}, err
	}
	c, err := parseInteger(count, "count")
	if err != nil {
		return classicPagination{}, err
	}
	start := 1
	if si != nil {
		start = *si
	}
	if start < 1 {
		start = 1
	}
	cnt := MaxPageSize
	if c != nil {
		cnt = *c
	}
	if cnt < 0 {
		cnt = 0
	}
	if cnt > MaxPageSize {
		cnt = MaxPageSize
	}
	return classicPagination{startIndex: start, offset: start - 1, count: cnt}, nil
}

var (
	workEmailFilterPattern = regexp.MustCompile(`(?i)^emails\[\s*type\s+eq\s+"work"\s*\]\.value$`)
	filterAttributePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*)?$`)
)

func canonicalizeFilterAttribute(rt resourceType, attribute string) string {
	normalized := stripCoreAttributePrefix(rt, attribute)
	if workEmailFilterPattern.MatchString(normalized) {
		if rt == resourceUser {
			return "emails.work.value"
		}
		return ""
	}
	if !filterAttributePattern.MatchString(normalized) {
		return ""
	}
	switch jsLower(normalized) {
	case "id":
		return "id"
	case "externalid":
		return "externalId"
	case "username":
		if rt == resourceUser {
			return "userName"
		}
	case "emails.value":
		if rt == resourceUser {
			return "emails.value"
		}
	case "displayname":
		if rt == resourceGroup {
			return "displayName"
		}
	}
	return ""
}

type topLevelWord struct {
	start, end int
	value      string
}

func invalidFilterSyntax(detail string) *queryError {
	return &queryError{"invalid-filter-syntax", "filter", errInvalidFilter, detail}
}

func isASCIILetter(c rune) bool { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') }

// jsIsSpace is /\s/.
func jsIsSpace(r rune) bool { return isJSWhitespace(r) || unicode.Is(unicode.Zs, r) }

// scanFilterTopLevel works on UTF-16-free rune indices (filters are matched as runes).
func scanFilterTopLevel(filter []rune) ([]topLevelWord, *queryError) {
	var words []topLevelWord
	depth := 0
	quoted, escaped := false, false
	for i := 0; i < len(filter); i++ {
		c := filter[i]
		if quoted {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == '"' {
				quoted = false
			}
			continue
		}
		if c == '"' {
			quoted = true
			continue
		}
		if c == '[' {
			depth++
			continue
		}
		if c == ']' {
			if depth == 0 {
				return nil, invalidFilterSyntax("filter contains malformed quotes or brackets")
			}
			depth--
			continue
		}
		if depth != 0 || !isASCIILetter(c) {
			continue
		}
		start := i
		for i+1 < len(filter) && isASCIILetter(filter[i+1]) {
			i++
		}
		end := i + 1
		words = append(words, topLevelWord{start: start, end: end, value: string(filter[start:end])})
	}
	if quoted || depth != 0 {
		return nil, invalidFilterSyntax("filter contains malformed quotes or brackets")
	}
	return words, nil
}

func surroundedBySpace(filter []rune, w topLevelWord) bool {
	if w.start-1 < 0 || w.end >= len(filter) {
		return false
	}
	return jsIsSpace(filter[w.start-1]) && jsIsSpace(filter[w.end])
}

func parseEqualityFilter(rt resourceType, filter string) (*equalityFilter, *queryError) {
	if jsTrim(filter) == "" {
		return nil, nil
	}
	f := []rune(jsTrim(filter))
	words, qerr := scanFilterTopLevel(f)
	if qerr != nil {
		return nil, qerr
	}
	var rawAttribute, rawOperator, rawValue string
	found := false
	for _, word := range words {
		if !surroundedBySpace(f, word) {
			continue
		}
		a := jsTrim(string(f[:word.start]))
		v := jsTrim(string(f[word.end:]))
		if a == "" || v == "" {
			continue
		}
		rawAttribute, rawOperator, rawValue, found = a, word.value, v, true
		break
	}
	if !found {
		return nil, invalidFilterSyntax(`filter must use the form attribute eq "value"`)
	}
	if jsLower(rawOperator) != "eq" {
		return nil, &queryError{"unsupported-filter-operator", "filter", errInvalidFilter, "filter operator " + rawOperator + " is not supported"}
	}
	attribute := canonicalizeFilterAttribute(rt, rawAttribute)
	if attribute == "" {
		return nil, &queryError{"unsupported-filter-attribute", "filter", errInvalidFilter,
			"filter attribute " + rawAttribute + " is not supported for " + string(rt)}
	}
	value, err := parseJSON([]byte(rawValue))
	if err != nil || !isJSONParseable(rawValue) {
		return nil, &queryError{"invalid-filter-value", "filter", errInvalidFilter, "filter equality value must be a valid quoted JSON string"}
	}
	s, ok := value.(string)
	if !ok {
		return nil, &queryError{"invalid-filter-value", "filter", errInvalidFilter, "filter equality value must be a quoted string"}
	}
	return &equalityFilter{attribute: attribute, value: s}, nil
}

// isJSONParseable rejects inputs Go's decoder tolerates but JSON.parse does not.
func isJSONParseable(s string) bool {
	t := strings.TrimFunc(s, func(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == '\r' })
	return t != ""
}

func splitFilterConjunction(filter string) ([]string, *queryError) {
	f := []rune(filter)
	words, qerr := scanFilterTopLevel(f)
	if qerr != nil {
		return nil, qerr
	}
	var expressions []string
	start := 0
	for _, word := range words {
		if jsLower(word.value) == "and" && surroundedBySpace(f, word) {
			expr := jsTrim(string(f[start:word.start]))
			if expr == "" {
				return nil, invalidFilterSyntax("filter contains an invalid conjunction")
			}
			expressions = append(expressions, expr)
			start = word.end
		}
	}
	final := jsTrim(string(f[start:]))
	if final == "" {
		return nil, invalidFilterSyntax("filter contains an invalid conjunction")
	}
	if len(expressions) >= 10 {
		return nil, invalidFilterSyntax("filter supports at most 10 equality expressions")
	}
	return append(expressions, final), nil
}

func parseFilter(rt resourceType, filter *string) ([]equalityFilter, *queryError) {
	if filter == nil || jsTrim(*filter) == "" {
		return nil, nil
	}
	exprs, qerr := splitFilterConjunction(*filter)
	if qerr != nil {
		return nil, qerr
	}
	var out []equalityFilter
	for _, e := range exprs {
		f, qerr := parseEqualityFilter(rt, e)
		if qerr != nil {
			return nil, qerr
		}
		if f != nil {
			out = append(out, *f)
		}
	}
	return out, nil
}

var noWhitespace = regexp.MustCompile(`^\S+$`)

func normalizeAttributeList(rt resourceType, input any, parameter string) (map[string]bool, []string, *queryError) {
	if input == nil || isUndef(input) {
		return nil, nil, nil
	}
	var values []string
	switch t := input.(type) {
	case string:
		values = []string{t}
	case []any:
		for _, x := range t {
			s, _ := x.(string)
			values = append(values, s)
		}
	case []string:
		values = t
	}
	if len(values) == 0 {
		return nil, nil, nil
	}
	set := map[string]bool{}
	var order []string
	for _, v := range values {
		if jsTrim(v) == "" {
			continue
		}
		for _, part := range strings.Split(v, ",") {
			attr := jsTrim(part)
			if attr == "" || !noWhitespace.MatchString(attr) || strings.ContainsFunc(attr, jsIsSpace) {
				return nil, nil, &queryError{"invalid-attribute-list", parameter, errInvalidValue,
					parameter + " must be a comma-separated list of attribute paths"}
			}
			n := jsLower(resolveResponseAttributePath(rt, attr))
			if !set[n] {
				set[n] = true
				order = append(order, n)
			}
		}
	}
	if len(set) == 0 {
		return nil, nil, nil
	}
	return set, order, nil
}

// parseAttributeProjection is parseSCIMAttributeProjection.
func parseAttributeProjection(rt resourceType, attributes, excluded any) (attributeProjection, *queryError) {
	inc, incOrder, qerr := normalizeAttributeList(rt, attributes, "attributes")
	if qerr != nil {
		return attributeProjection{}, qerr
	}
	exc, excOrder, qerr := normalizeAttributeList(rt, excluded, "excludedAttributes")
	if qerr != nil {
		return attributeProjection{}, qerr
	}
	if inc != nil && exc != nil {
		return attributeProjection{}, &queryError{"conflicting-attribute-projection", "attributes", errInvalidValue,
			"attributes and excludedAttributes cannot be used together"}
	}
	if inc != nil {
		return attributeProjection{mode: "include", attributes: inc, order: incOrder}, nil
	}
	if exc != nil {
		return attributeProjection{mode: "exclude", attributes: exc, order: excOrder}, nil
	}
	return attributeProjection{mode: "default"}, nil
}

// parseCollectionQuery is parseSCIMCollectionQuery.
func parseCollectionQuery(rt resourceType, in queryInput) (collectionQuery, *queryError) {
	p, qerr := parseClassicPagination(in.startIndex, in.count)
	if qerr != nil {
		return collectionQuery{}, qerr
	}
	filters, qerr := parseFilter(rt, in.filter)
	if qerr != nil {
		return collectionQuery{}, qerr
	}
	proj, qerr := parseAttributeProjection(rt, in.attributes, in.excludedAttributes)
	if qerr != nil {
		return collectionQuery{}, qerr
	}
	return collectionQuery{filters: filters, pagination: p, projection: proj}, nil
}

// ---- resource-attribute-projection.ts ----

type pathNode struct {
	selected bool
	children map[string]*pathNode
}

func newPathNode() *pathNode { return &pathNode{children: map[string]*pathNode{}} }

func createPathTree(paths []string, resourceAttributeNames []string) *pathNode {
	root := newPathNode()
	names := append([]string{}, resourceAttributeNames...)
	// stable sort by length descending
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && len(names[j]) > len(names[j-1]); j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	for _, p := range paths {
		root2 := ""
		for _, n := range names {
			ln := jsLower(n)
			if p == ln || strings.HasPrefix(p, ln+".") {
				root2 = n
				break
			}
		}
		rel := p
		if root2 != "" {
			rel = strings.TrimPrefix(p[len(root2):], ".")
		}
		var segments []string
		if root2 != "" {
			segments = append(segments, root2)
		}
		if rel != "" {
			segments = append(segments, strings.Split(rel, ".")...)
		}
		node := root
		for _, s := range segments {
			ns := jsLower(s)
			child := node.children[ns]
			if child == nil {
				child = newPathNode()
				node.children[ns] = child
			}
			node = child
		}
		node.selected = true
	}
	return root
}

func includeSelected(value any, node *pathNode) (any, bool) {
	if node.selected {
		return value, true
	}
	if arr, ok := value.([]any); ok {
		var items []any
		for _, it := range arr {
			if v, ok := includeSelected(it, node); ok {
				items = append(items, v)
			}
		}
		if len(items) > 0 {
			return items, true
		}
		return nil, false
	}
	o, ok := value.(*jsonx.Object)
	if !ok {
		return nil, false
	}
	out := jsonx.NewObject()
	for _, k := range o.Keys() {
		child := node.children[jsLower(k)]
		if child == nil {
			continue
		}
		cv, _ := o.Get(k)
		if v, ok := includeSelected(cv, child); ok {
			out.Set(k, v)
		}
	}
	if out.Len() > 0 {
		return out, true
	}
	return nil, false
}

func excludeSelected(value any, node *pathNode) (any, bool) {
	if node.selected {
		return nil, false
	}
	if arr, ok := value.([]any); ok {
		items := []any{}
		for _, it := range arr {
			if v, ok := excludeSelected(it, node); ok {
				items = append(items, v)
			}
		}
		return items, true
	}
	if isDateValue(value) {
		// A Date is a record without own enumerable properties.
		return jsonx.NewObject(), true
	}
	o, ok := value.(*jsonx.Object)
	if !ok {
		return value, true
	}
	out := jsonx.NewObject()
	for _, k := range o.Keys() {
		cv, _ := o.Get(k)
		child := node.children[jsLower(k)]
		if child == nil {
			out.Set(k, cv)
			continue
		}
		if v, ok := excludeSelected(cv, child); ok {
			out.Set(k, v)
		}
	}
	return out, true
}

// projectResourceAttributes is projectSCIMResourceAttributes.
func projectResourceAttributes(resource *jsonx.Object, p attributeProjection) *jsonx.Object {
	if p.mode == "default" || p.mode == "" {
		return resource.Clone()
	}
	tree := createPathTree(p.order, resource.Keys())
	out := jsonx.O("schemas", objGet(resource, "schemas"), "id", objGet(resource, "id"))
	for _, k := range resource.Keys() {
		lk := jsLower(k)
		if lk == "schemas" || lk == "id" {
			continue
		}
		v, _ := resource.Get(k)
		node := tree.children[lk]
		if p.mode == "include" {
			if node == nil {
				continue
			}
			if sv, ok := includeSelected(v, node); ok {
				out.Set(k, sv)
			}
			continue
		}
		if node == nil {
			out.Set(k, v)
			continue
		}
		if sv, ok := excludeSelected(v, node); ok {
			out.Set(k, sv)
		}
	}
	return out
}

func isDateValue(v any) bool {
	switch v.(type) {
	case time.Time, *time.Time:
		return true
	}
	return false
}
