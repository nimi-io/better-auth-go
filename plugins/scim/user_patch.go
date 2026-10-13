package scim

import (
	"regexp"
	"sort"
	"strings"

	"github.com/nimi-io/better-auth-go/jsonx"
)

// patchOperation is one validated PatchOp operation.
type patchOperation struct {
	Op    string
	Path  *string
	Value any // undef when absent
}

func readPatchOperations(body *jsonx.Object) []patchOperation {
	var ops []patchOperation
	for _, x := range getArr(body, "Operations") {
		o, ok := x.(*jsonx.Object)
		if !ok {
			continue
		}
		op := patchOperation{Op: getStr(o, "op"), Value: objGet(o, "value")}
		if p, ok := getOptStr(o, "path"); ok {
			op.Path = &p
		}
		ops = append(ops, op)
	}
	return ops
}

var (
	emailTypeValuePath    = regexp.MustCompile(`(?i)^emails\s*\[\s*type\s+eq\s+"([^"]+)"\s*\]\s*\.\s*value$`)
	emailPrimaryValuePath = regexp.MustCompile(`(?i)^emails\s*\[\s*primary\s+eq\s+"?true"?\s*\]\s*\.\s*value$`)
	scimValuePath         = regexp.MustCompile(`(?i)^([A-Za-z$][\w$-]*)\s*\[\s*type\s+eq\s+"([^"]+)"\s*\](?:\s*\.\s*([A-Za-z$][\w$-]*))?$`)
	scimPrimaryValuePath  = regexp.MustCompile(`(?i)^([A-Za-z$][\w$-]*)\s*\[\s*primary\s+eq\s+"?(true|false)"?\s*\](?:\s*\.\s*([A-Za-z$][\w$-]*))?$`)
	patchEmailSchema      = zObj(
		zf("value", scimEmailValueSchema),
		zf("primary", zOpt(zBoolean{})),
		zf("type", zOpt(zStr().trim().min(1))),
	)
	patchEmailListSchema = zArr(patchEmailSchema).min(1).max(20)
)

// userPatchState is SCIMUserPatchState.
type userPatchState struct {
	UserName        string
	PrimaryEmail    string
	Emails          []canonicalEmail
	DisplayName     string
	FormattedName   string
	GivenName       *string
	FamilyName      *string
	MiddleName      *string
	HonorificPrefix *string
	HonorificSuffix *string
	ExternalID      *string
	Active          bool
	Attributes      *jsonx.Object
}

// patchError is used for control flow within the patch engine.
type patchError struct{ err error }

func throwPatch(status, detail, scimType string) {
	panic(patchError{err: scimErr(status, detail, scimType)})
}

func invalidPatchValue(detail string) { throwPatch("BAD_REQUEST", detail, errInvalidValue) }

func rejectReadOnlyAttribute(attribute string) {
	throwPatch("BAD_REQUEST", attribute+" is read-only", errMutability)
}

func unsupportedPath(path string) {
	throwPatch("BAD_REQUEST", "User PATCH path "+path+" is not supported", errInvalidPath)
}

func createComparableValue(v any) any {
	switch t := v.(type) {
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = createComparableValue(x)
		}
		return out
	case *jsonx.Object:
		keys := []string{}
		for _, k := range t.Keys() {
			x, _ := t.Get(k)
			if !isUndef(x) {
				keys = append(keys, k)
			}
		}
		sort.SliceStable(keys, func(i, j int) bool { return localeLess(keys[i], keys[j]) })
		o := jsonx.NewObject()
		for _, k := range keys {
			x, _ := t.Get(k)
			o.Set(k, createComparableValue(x))
		}
		return o
	}
	return v
}

func localeLess(a, b string) bool { return localeCompare(a, b) < 0 }

func strPtrEq(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func optStr(o *jsonx.Object, key string) *string {
	if s, ok := getOptStr(o, key); ok {
		return &s
	}
	return nil
}

// userPatchChangesState is scimUserPatchChangesState.
func userPatchChangesState(u *scimUserRow, s *userPatchState) (bool, error) {
	attrs, err := readUserAttributes(u)
	if err != nil {
		return false, err
	}
	name, _ := getObj(attrs, "name")
	ext := u.ExternalID
	return u.UserName != s.UserName ||
		u.PrimaryEmail != s.PrimaryEmail ||
		mustStringify(createComparableValue(objGet(attrs, "emails"))) != mustStringify(createComparableValue(emailsToAny(s.Emails))) ||
		u.DisplayName != s.DisplayName ||
		getStr(name, "formatted") != s.FormattedName ||
		!strPtrEq(optStr(name, "givenName"), s.GivenName) ||
		!strPtrEq(optStr(name, "familyName"), s.FamilyName) ||
		!strPtrEq(optStr(name, "middleName"), s.MiddleName) ||
		!strPtrEq(optStr(name, "honorificPrefix"), s.HonorificPrefix) ||
		!strPtrEq(optStr(name, "honorificSuffix"), s.HonorificSuffix) ||
		!strPtrEq(ext, s.ExternalID) ||
		u.Active != s.Active ||
		mustStringify(createComparableValue(attrs)) != mustStringify(createComparableValue(s.Attributes)), nil
}

func unwrapSinglePatchValue(v any) any {
	if arr, ok := v.([]any); ok && len(arr) == 1 {
		return arr[0]
	}
	return v
}

func readNonEmptyString(v any, attribute string) string {
	s, ok := unwrapSinglePatchValue(v).(string)
	if !ok || jsTrim(s) == "" {
		invalidPatchValue(attribute + " must be a non-empty string")
	}
	return jsTrim(s)
}

func readEmail(v any) string {
	out, issues := zParse(scimEmailValueSchema, v)
	if len(issues) > 0 {
		invalidPatchValue("emails.value must be an email")
	}
	return jsLower(out.(string))
}

func readEmailValues(v any) []inputEmail {
	out, issues := zParse(patchEmailListSchema, v)
	if len(issues) > 0 {
		invalidPatchValue("emails must contain between 1 and 20 valid emails")
	}
	return readInputEmails(out)
}

func inputEmailTupleKey(e inputEmail) string { return emailTupleKey(e.Type, e.Value) }

func hasUniqueDefinedInputTypes(emails []inputEmail) bool {
	seen := map[string]bool{}
	for _, e := range emails {
		if e.Type == nil {
			continue
		}
		k := jsLower(jsTrim(*e.Type))
		if seen[k] {
			return false
		}
		seen[k] = true
	}
	return true
}

func readEmailSet(value any, userName string) []canonicalEmail {
	emails := readEmailValues(value)
	primaries := 0
	tuples := map[string]bool{}
	for _, e := range emails {
		if e.Primary != nil && *e.Primary {
			primaries++
		}
		tuples[inputEmailTupleKey(e)] = true
	}
	if primaries > 1 {
		invalidPatchValue("emails cannot contain multiple primary values")
	}
	if len(tuples) != len(emails) {
		invalidPatchValue("emails cannot contain duplicate type and value pairs")
	}
	if !hasUniqueDefinedInputTypes(emails) {
		invalidPatchValue("emails cannot contain duplicate defined types")
	}
	return normalizeEmails(userName, emails)
}

func inputsToAny(emails []inputEmail) []any {
	out := make([]any, len(emails))
	for i, e := range emails {
		o := jsonx.O("value", e.Value)
		if e.Type != nil {
			o.Set("type", *e.Type)
		}
		if e.Primary != nil {
			o.Set("primary", *e.Primary)
		}
		out[i] = o
	}
	return out
}

func canonicalToInput(emails []canonicalEmail) []inputEmail {
	out := make([]inputEmail, len(emails))
	for i, e := range emails {
		p := e.Primary
		out[i] = inputEmail{Value: e.Value, Primary: &p, Type: e.Type}
	}
	return out
}

func setFormattedName(s *userPatchState, formatted string) {
	derived := s.DisplayName == s.FormattedName
	s.FormattedName = formatted
	if derived {
		s.DisplayName = formatted
	}
}

func composeName(s *userPatchState) string {
	parts := []string{}
	if s.GivenName != nil && *s.GivenName != "" {
		parts = append(parts, *s.GivenName)
	}
	if s.FamilyName != nil && *s.FamilyName != "" {
		parts = append(parts, *s.FamilyName)
	}
	return strings.Join(parts, " ")
}

func setEmails(s *userPatchState, emails []inputEmail) {
	s.Emails = readEmailSet(inputsToAny(emails), s.UserName)
	for _, e := range s.Emails {
		if e.Primary {
			s.PrimaryEmail = e.Value
			return
		}
	}
	if len(s.Emails) > 0 {
		s.PrimaryEmail = s.Emails[0].Value
		return
	}
	invalidPatchValue("emails must contain at least one value")
}

func addEmails(s *userPatchState, value any) {
	var additions []canonicalEmail
	index := map[string]int{}
	for _, e := range readEmailValues(value) {
		c := canonicalEmail{Value: jsLower(jsTrim(e.Value)), Primary: e.Primary != nil && *e.Primary}
		if e.Type != nil && jsTrim(*e.Type) != "" {
			t := jsLower(jsTrim(*e.Type))
			c.Type = &t
		}
		k := emailTupleKey(c.Type, c.Value)
		if i, ok := index[k]; ok {
			if c.Primary && !additions[i].Primary {
				additions[i].Primary = true
			}
			continue
		}
		index[k] = len(additions)
		additions = append(additions, c)
	}
	primaries := 0
	for _, a := range additions {
		if a.Primary {
			primaries++
		}
	}
	if primaries > 1 {
		invalidPatchValue("emails cannot contain multiple primary values")
	}
	existing := map[string]bool{}
	for _, e := range s.Emails {
		existing[emailTupleKey(e.Type, e.Value)] = true
	}
	var newEmails []canonicalEmail
	newPrimary := false
	for _, a := range additions {
		if !existing[emailTupleKey(a.Type, a.Value)] {
			newEmails = append(newEmails, a)
			if a.Primary {
				newPrimary = true
			}
		}
	}
	if len(newEmails) == 0 {
		return
	}
	current := append([]canonicalEmail{}, s.Emails...)
	if newPrimary {
		for i := range current {
			current[i].Primary = false
		}
	}
	setEmails(s, canonicalToInput(append(current, newEmails...)))
}

func replaceAllEmailValues(s *userPatchState, value any) {
	r := readEmail(value)
	next := make([]canonicalEmail, len(s.Emails))
	for i, e := range s.Emails {
		e.Value = r
		next[i] = e
	}
	setEmails(s, canonicalToInput(next))
}

func replaceSelectedEmail(s *userPatchState, selector string, value any) {
	r := readEmail(value)
	has := false
	for _, e := range s.Emails {
		if e.Type != nil && *e.Type == selector {
			has = true
		}
	}
	if !has {
		sel := selector
		setEmails(s, canonicalToInput(append(append([]canonicalEmail{}, s.Emails...), canonicalEmail{Value: r, Type: &sel})))
		return
	}
	next := make([]canonicalEmail, len(s.Emails))
	for i, e := range s.Emails {
		if e.Type != nil && *e.Type == selector {
			e.Value = r
		}
		next[i] = e
	}
	setEmails(s, canonicalToInput(next))
}

func replacePrimaryEmail(s *userPatchState, value any) {
	r := readEmail(value)
	has := false
	for _, e := range s.Emails {
		if e.Primary {
			has = true
		}
	}
	if !has {
		throwPatch("BAD_REQUEST", "No primary email matches the PATCH path", errNoTarget)
	}
	next := make([]canonicalEmail, len(s.Emails))
	for i, e := range s.Emails {
		if e.Primary {
			e.Value = r
		}
		next[i] = e
	}
	setEmails(s, canonicalToInput(next))
}

type resolvedPatchPath struct {
	attribute       patchAttribute
	attributeName   string
	enterprise      bool
	enterpriseRoot  bool
	selectorType    *string
	selectorPrimary *bool
	subAttribute    *patchAttribute
	subAttrName     string
}

func findPatchAttribute(attrs []patchAttribute, name string) *patchAttribute {
	for i := range attrs {
		if jsLower(attrs[i].name) == jsLower(name) {
			return &attrs[i]
		}
	}
	return nil
}

func resolveMutablePatchPath(path string) resolvedPatchPath {
	canonical := resolveCanonicalAttributePath(resourceUser, jsTrim(path))
	lc := jsLower(canonical)
	enterprise := lc == "enterprise" || strings.HasPrefix(lc, "enterprise.")
	if lc == "enterprise" {
		return resolvedPatchPath{enterpriseRoot: true}
	}
	relative := canonical
	if enterprise {
		relative = canonical[len("enterprise."):]
	}
	attrs := userPatchAttributes
	if enterprise {
		attrs = enterprisePatchAttributes
	}
	valueMatch := scimValuePath.FindStringSubmatch(relative)
	var primaryMatch []string
	if valueMatch == nil {
		primaryMatch = scimPrimaryValuePath.FindStringSubmatch(relative)
	}
	filterMatch := valueMatch
	if filterMatch == nil {
		filterMatch = primaryMatch
	}
	segments := strings.Split(relative, ".")
	var attributePath, subPath string
	if filterMatch != nil {
		attributePath, subPath = filterMatch[1], filterMatch[3]
	} else {
		attributePath = segments[0]
		if len(segments) > 1 {
			subPath = segments[1]
		}
	}
	emptySegment := false
	for _, s := range segments {
		if s == "" {
			emptySegment = true
		}
	}
	if attributePath == "" || (filterMatch == nil && (len(segments) > 2 || emptySegment)) {
		unsupportedPath(path)
	}
	attribute := findPatchAttribute(attrs, attributePath)
	if attribute == nil {
		unsupportedPath(path)
	}
	if attribute.mutability == "readOnly" {
		rejectReadOnlyAttribute(path)
	}
	var sub *patchAttribute
	if subPath != "" {
		sub = findPatchAttribute(attribute.subAttributes, subPath)
		if sub == nil {
			unsupportedPath(path)
		}
	}
	if sub != nil && sub.mutability == "readOnly" {
		rejectReadOnlyAttribute(path)
	}
	if filterMatch != nil && !attribute.multiValued {
		throwPatch("BAD_REQUEST", "User PATCH path "+path+" is not a multi-valued attribute", errInvalidPath)
	}
	r := resolvedPatchPath{attribute: *attribute, attributeName: attribute.name, enterprise: enterprise}
	if valueMatch != nil && valueMatch[2] != "" {
		t := jsLower(jsTrim(valueMatch[2]))
		r.selectorType = &t
	}
	if primaryMatch != nil {
		b := jsLower(primaryMatch[2]) == "true"
		r.selectorPrimary = &b
	}
	if sub != nil {
		r.subAttribute = sub
		r.subAttrName = sub.name
	}
	return r
}

// clonePatchValue deep-copies objects and arrays.
func clonePatchValue(v any) any {
	switch t := v.(type) {
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = clonePatchValue(x)
		}
		return out
	case *jsonx.Object:
		o := jsonx.NewObject()
		for _, k := range t.Keys() {
			x, _ := t.Get(k)
			o.Set(k, clonePatchValue(x))
		}
		return o
	}
	return v
}

func getPatchContainer(doc *jsonx.Object, enterprise, create bool) *jsonx.Object {
	if !enterprise {
		return doc
	}
	if cur, ok := getObj(doc, SchemaEnterpriseUser); ok {
		return cur
	}
	if !create {
		return nil
	}
	ext := jsonx.NewObject()
	doc.Set(SchemaEnterpriseUser, ext)
	return ext
}

func setEnterpriseSchemaDeclaration(doc *jsonx.Object, declared bool) {
	var schemas []any
	for _, s := range getArr(doc, "schemas") {
		if str, ok := s.(string); ok && str != SchemaEnterpriseUser {
			schemas = append(schemas, str)
		}
	}
	if schemas == nil {
		schemas = []any{}
	}
	if declared {
		schemas = append(schemas, SchemaEnterpriseUser)
	}
	doc.Set("schemas", schemas)
}

func removeEmptyEnterpriseExtension(doc *jsonx.Object) {
	ext, ok := getObj(doc, SchemaEnterpriseUser)
	if !ok || ext.Len() > 0 {
		return
	}
	doc.Delete(SchemaEnterpriseUser)
	setEnterpriseSchemaDeclaration(doc, false)
}

func spread(objs ...*jsonx.Object) *jsonx.Object {
	out := jsonx.NewObject()
	for _, o := range objs {
		if o == nil {
			continue
		}
		for _, k := range o.Keys() {
			x, _ := o.Get(k)
			out.Set(k, x)
		}
	}
	return out
}

func mergePatchObject(current, value any, attribute string) *jsonx.Object {
	vo, ok := value.(*jsonx.Object)
	if !ok {
		invalidPatchValue(attribute + " must be an object")
	}
	co, _ := current.(*jsonx.Object)
	return spread(co, clonePatchValue(vo).(*jsonx.Object))
}

func parseEnterprisePatchObject(value any, attribute string) *jsonx.Object {
	vo, ok := value.(*jsonx.Object)
	if !ok {
		invalidPatchValue(attribute + " must be an object")
	}
	for _, k := range vo.Keys() {
		if findPatchAttribute(enterprisePatchAttributes, k) == nil {
			throwPatch("BAD_REQUEST", "User PATCH path "+SchemaEnterpriseUser+":"+k+" is not supported", errInvalidPath)
		}
	}
	out, issues := zParse(enterpriseUserInputSchema, vo)
	if len(issues) > 0 {
		invalidPatchValue(attribute + "." + joinPath(issues[0].Path) + ": " + issues[0].Message)
	}
	return clonePatchValue(out).(*jsonx.Object)
}

func mergeEnterprisePatchObject(current, value any, attribute string) *jsonx.Object {
	cur, _ := current.(*jsonx.Object)
	if cur == nil {
		cur = jsonx.NewObject()
	}
	patch := parseEnterprisePatchObject(value, attribute)
	out := spread(cur, patch)
	if pm, ok := getObj(patch, "manager"); ok {
		cm, _ := getObj(cur, "manager")
		out.Set("manager", spread(cm, pm))
	}
	return out
}

func normalizeManagerPatchValue(value any) *jsonx.Object {
	parsed := parseEnterprisePatchObject(jsonx.O("manager", value), SchemaEnterpriseUser+":manager")
	m, ok := getObj(parsed, "manager")
	if !ok {
		invalidPatchValue("manager must contain value or $ref")
	}
	return m
}

func normalizeMultiValueAdditions(v any) []any {
	arr, ok := v.([]any)
	if !ok {
		arr = []any{v}
	}
	out := make([]any, len(arr))
	for i, x := range arr {
		out[i] = clonePatchValue(x)
	}
	return out
}

func valueSetsPrimary(v any) bool {
	if arr, ok := v.([]any); ok {
		for _, x := range arr {
			if valueSetsPrimary(x) {
				return true
			}
		}
		return false
	}
	o, ok := v.(*jsonx.Object)
	return ok && objGet(o, "primary") == true
}

func enforceSinglePatchedPrimary(values []any, preferred int) []any {
	if preferred < 0 {
		return values
	}
	out := make([]any, len(values))
	for i, it := range values {
		if o, ok := it.(*jsonx.Object); ok && objGet(o, "primary") == true && i != preferred {
			c := o.Clone()
			c.Set("primary", false)
			out[i] = c
			continue
		}
		out[i] = it
	}
	return out
}

func matchesType(v any, selector string) bool {
	o, ok := v.(*jsonx.Object)
	if !ok {
		return false
	}
	t, ok := objGet(o, "type").(string)
	return ok && jsLower(jsTrim(t)) == selector
}

func matchesPrimary(v any, selector bool) bool {
	o, ok := v.(*jsonx.Object)
	return ok && objGet(o, "primary") == selector
}

func firstPrimaryIndex(values []any) int {
	for i, it := range values {
		if o, ok := it.(*jsonx.Object); ok && objGet(o, "primary") == true {
			return i
		}
	}
	return -1
}

func applyMultiValuePatch(container *jsonx.Object, r resolvedPatchPath, op string, value any, path string) {
	var current []any
	if arr, ok := objGet(container, r.attributeName).([]any); ok {
		for _, x := range arr {
			current = append(current, clonePatchValue(x))
		}
	}
	if r.selectorType == nil && r.selectorPrimary == nil && r.subAttrName == "" {
		if op == "remove" {
			container.Delete(r.attributeName)
			return
		}
		additions := normalizeMultiValueAdditions(value)
		var next []any
		if op == "add" {
			next = append(append([]any{}, current...), additions...)
		} else {
			next = additions
		}
		pref := -1
		if fp := firstPrimaryIndex(additions); fp >= 0 {
			if op == "add" {
				pref = len(current) + fp
			} else {
				pref = fp
			}
		}
		container.Set(r.attributeName, enforceSinglePatchedPrimary(next, pref))
		return
	}
	matches := make([]bool, len(current))
	hasTarget := false
	for i, it := range current {
		switch {
		case r.selectorPrimary != nil:
			matches[i] = matchesPrimary(it, *r.selectorPrimary)
		case r.selectorType != nil:
			matches[i] = matchesType(it, *r.selectorType)
		default:
			matches[i] = true
		}
		if matches[i] {
			hasTarget = true
		}
	}
	if !hasTarget {
		if op == "remove" {
			return
		}
		if r.subAttrName == "" {
			additions := normalizeMultiValueAdditions(value)
			for i, it := range additions {
				if o, ok := it.(*jsonx.Object); ok {
					c := o.Clone()
					if r.selectorType != nil {
						c.Set("type", *r.selectorType)
					}
					if r.selectorPrimary != nil {
						c.Set("primary", *r.selectorPrimary)
					}
					additions[i] = c
				}
			}
			next := append(append([]any{}, current...), additions...)
			pref := -1
			if fp := firstPrimaryIndex(additions); fp >= 0 {
				pref = len(current) + fp
			}
			container.Set(r.attributeName, enforceSinglePatchedPrimary(next, pref))
			return
		}
		item := jsonx.NewObject()
		if r.selectorType != nil {
			item.Set("type", *r.selectorType)
		}
		if r.selectorPrimary != nil {
			item.Set("primary", *r.selectorPrimary)
		}
		item.Set(r.subAttrName, clonePatchValue(value))
		next := append(append([]any{}, current...), item)
		pref := -1
		if jsLower(r.subAttrName) == "primary" && value == true {
			pref = len(next) - 1
		}
		container.Set(r.attributeName, enforceSinglePatchedPrimary(next, pref))
		return
	}
	if r.subAttrName == "" {
		if op == "remove" {
			var remaining []any
			for i, it := range current {
				if !matches[i] {
					remaining = append(remaining, it)
				}
			}
			if len(remaining) == 0 {
				container.Delete(r.attributeName)
			} else {
				container.Set(r.attributeName, remaining)
			}
			return
		}
		replacements := normalizeMultiValueAdditions(value)
		rep, ok := (*jsonx.Object)(nil), false
		if len(replacements) == 1 {
			rep, ok = replacements[0].(*jsonx.Object)
		}
		if !ok {
			invalidPatchValue("User PATCH path " + path + " requires one complex value")
		}
		next := make([]any, len(current))
		for i, it := range current {
			if !matches[i] {
				next[i] = it
				continue
			}
			io, ok := it.(*jsonx.Object)
			if !ok {
				invalidPatchValue(r.attributeName + " must contain objects")
			}
			next[i] = spread(io, rep)
		}
		first := -1
		for i, m := range matches {
			if m {
				first = i
				break
			}
		}
		pref := -1
		if objGet(rep, "primary") == true && first >= 0 {
			pref = first
		}
		container.Set(r.attributeName, enforceSinglePatchedPrimary(next, pref))
		return
	}
	next := make([]any, len(current))
	for i, it := range current {
		if !matches[i] {
			next[i] = it
			continue
		}
		io, ok := it.(*jsonx.Object)
		if !ok {
			invalidPatchValue(r.attributeName + " must contain objects")
		}
		if op == "remove" {
			c := io.Clone()
			c.Delete(r.subAttrName)
			next[i] = c
			continue
		}
		c := io.Clone()
		c.Set(r.subAttrName, clonePatchValue(value))
		next[i] = c
	}
	selected := -1
	for i, m := range matches {
		if m {
			selected = i
			break
		}
	}
	pref := -1
	if jsLower(r.subAttrName) == "primary" && value == true && selected >= 0 {
		pref = selected
	} else if valueSetsPrimary(value) {
		pref = selected
	}
	container.Set(r.attributeName, enforceSinglePatchedPrimary(next, pref))
}

func applyGenericUserAttributePatch(doc *jsonx.Object, op, path string, value any) {
	r := resolveMutablePatchPath(path)
	if r.enterpriseRoot {
		if op == "remove" {
			doc.Delete(SchemaEnterpriseUser)
			setEnterpriseSchemaDeclaration(doc, false)
			return
		}
		doc.Set(SchemaEnterpriseUser, mergeEnterprisePatchObject(objGet(doc, SchemaEnterpriseUser), value, SchemaEnterpriseUser))
		setEnterpriseSchemaDeclaration(doc, true)
		return
	}
	if !r.enterprise && (r.attributeName == "emails" || r.attributeName == "name") {
		unsupportedPath(path)
	}
	container := getPatchContainer(doc, r.enterprise, op != "remove")
	if container == nil {
		return
	}
	if r.enterprise && op != "remove" {
		setEnterpriseSchemaDeclaration(doc, true)
	}
	if r.attribute.multiValued {
		applyMultiValuePatch(container, r, op, value, path)
		removeEmptyEnterpriseExtension(doc)
		return
	}
	if r.subAttrName != "" {
		cur, ok := getObj(container, r.attributeName)
		if !ok {
			if op == "remove" {
				return
			}
			container.Set(r.attributeName, jsonx.O(r.subAttrName, clonePatchValue(value)))
			return
		}
		if op == "remove" {
			cur.Delete(r.subAttrName)
			if cur.Len() == 0 {
				container.Delete(r.attributeName)
			}
		} else {
			cur.Set(r.subAttrName, clonePatchValue(value))
		}
		removeEmptyEnterpriseExtension(doc)
		return
	}
	if op == "remove" {
		container.Delete(r.attributeName)
		removeEmptyEnterpriseExtension(doc)
		return
	}
	if r.enterprise && r.attributeName == "manager" && r.attribute.typ == "complex" {
		if value == "" {
			container.Delete(r.attributeName)
			removeEmptyEnterpriseExtension(doc)
			return
		}
		cm, _ := getObj(container, r.attributeName)
		container.Set(r.attributeName, spread(cm, normalizeManagerPatchValue(value)))
		return
	}
	if r.attribute.typ == "complex" && isRecord(value) {
		container.Set(r.attributeName, mergePatchObject(objGet(container, r.attributeName), value, r.attributeName))
		return
	}
	container.Set(r.attributeName, clonePatchValue(value))
}

func createUserPatchDocument(u *scimUserRow, attributes *jsonx.Object) *jsonx.Object {
	doc := jsonx.NewObject()
	for _, k := range attributes.Keys() {
		if k == "enterprise" {
			continue
		}
		x, _ := attributes.Get(k)
		doc.Set(k, clonePatchValue(x))
	}
	doc.Set("userName", u.UserName)
	// `user.externalId === null ? {} : { externalId }`: undefined is still assigned.
	if u.ExternalID != nil {
		doc.Set("externalId", *u.ExternalID)
	}
	doc.Set("displayName", u.DisplayName)
	doc.Set("active", u.Active)
	if ent, ok := attributes.Get("enterprise"); ok && !isUndef(ent) {
		doc.Set(SchemaEnterpriseUser, clonePatchValue(ent))
	}
	return doc
}

func finalizeUserPatch(s *userPatchState, doc *jsonx.Object) *userPatchState {
	doc.Set("userName", s.UserName)
	if s.ExternalID != nil {
		doc.Set("externalId", *s.ExternalID)
	} else {
		doc.Set("externalId", undef)
	}
	doc.Set("displayName", s.DisplayName)
	doc.Set("active", s.Active)
	doc.Set("name", buildNameObject(s.FormattedName, s.GivenName, s.FamilyName, s.MiddleName, s.HonorificPrefix, s.HonorificSuffix))
	doc.Set("emails", emailsToAny(s.Emails))
	parsed, issues := zParse(apiUserSchema, doc)
	if len(issues) > 0 {
		p := joinPath(issues[0].Path)
		if p == "" {
			p = "User"
		}
		invalidPatchValue(p + ": " + issues[0].Message)
	}
	po := parsed.(*jsonx.Object)
	profile := createCanonicalProfile(po)
	ns := &userPatchState{
		UserName: profile.UserName, PrimaryEmail: profile.PrimaryEmail, Emails: profile.Emails,
		DisplayName: profile.DisplayName, FormattedName: profile.FormattedName,
		GivenName: profile.GivenName, FamilyName: profile.FamilyName, MiddleName: profile.MiddleName,
		HonorificPrefix: profile.HonPrefix, HonorificSuffix: profile.HonSuffix,
		ExternalID: optStr(po, "externalId"), Active: objGet(po, "active") != false,
		Attributes: profile.Attributes,
	}
	return ns
}

// applyUserPatch is applySCIMUserPatch.
func applyUserPatch(u *scimUserRow, operations []patchOperation) (result *userPatchState, err error) {
	defer func() {
		if r := recover(); r != nil {
			pe, ok := r.(patchError)
			if !ok {
				panic(r)
			}
			result, err = nil, pe.err
		}
	}()
	attributes, err := readUserAttributes(u)
	if err != nil {
		return nil, err
	}
	doc := createUserPatchDocument(u, attributes)
	name, _ := getObj(attributes, "name")
	s := &userPatchState{
		UserName: u.UserName, PrimaryEmail: u.PrimaryEmail, Emails: readCanonicalEmails(objGet(attributes, "emails")),
		DisplayName: u.DisplayName, FormattedName: getStr(name, "formatted"),
		GivenName: optStr(name, "givenName"), FamilyName: optStr(name, "familyName"), MiddleName: optStr(name, "middleName"),
		HonorificPrefix: optStr(name, "honorificPrefix"), HonorificSuffix: optStr(name, "honorificSuffix"),
		ExternalID: u.ExternalID, Active: u.Active, Attributes: attributes,
	}
	applyAttribute := func(op, path string, value any) {
		relative := stripCoreAttributePrefix(resourceUser, jsTrim(path))
		normalized := jsLower(resolveCanonicalAttributePath(resourceUser, jsTrim(path)))
		if normalized == "id" || normalized == "schemas" || normalized == "meta" || strings.HasPrefix(normalized, "meta.") {
			rejectReadOnlyAttribute(path)
		}
		namePart := func(target **string, attr string) {
			if op == "remove" {
				*target = nil
				return
			}
			v := readNonEmptyString(value, attr)
			*target = &v
		}
		switch normalized {
		case "username":
			if op == "remove" {
				rejectReadOnlyAttribute("userName")
			}
			s.UserName = readNonEmptyString(value, "userName")
		case "externalid":
			if op == "remove" {
				s.ExternalID = nil
			} else {
				v := readNonEmptyString(value, "externalId")
				s.ExternalID = &v
			}
		case "active":
			if op == "remove" {
				s.Active = true
				return
			}
			b, ok := unwrapSinglePatchValue(value).(bool)
			if !ok {
				invalidPatchValue("active must be a boolean")
			}
			s.Active = b
		case "displayname":
			if op == "remove" {
				s.DisplayName = s.FormattedName
			} else {
				s.DisplayName = readNonEmptyString(value, "displayName")
			}
		case "name":
			if op == "remove" {
				s.GivenName, s.FamilyName, s.MiddleName, s.HonorificPrefix, s.HonorificSuffix = nil, nil, nil, nil, nil
				f := s.DisplayName
				if f == "" {
					f = s.PrimaryEmail
				}
				setFormattedName(s, f)
				return
			}
			n := readName(value)
			if n.given != nil {
				s.GivenName = n.given
			}
			if n.family != nil {
				s.FamilyName = n.family
			}
			if n.middle != nil {
				s.MiddleName = n.middle
			}
			if n.prefix != nil {
				s.HonorificPrefix = n.prefix
			}
			if n.suffix != nil {
				s.HonorificSuffix = n.suffix
			}
			if n.formatted != nil {
				setFormattedName(s, *n.formatted)
			}
		case "name.formatted":
			if op == "remove" {
				f := composeName(s)
				if f == "" {
					f = s.DisplayName
				}
				if f == "" {
					f = s.PrimaryEmail
				}
				setFormattedName(s, f)
			} else {
				setFormattedName(s, readNonEmptyString(value, "name.formatted"))
			}
		case "name.givenname":
			namePart(&s.GivenName, "name.givenName")
		case "name.familyname":
			namePart(&s.FamilyName, "name.familyName")
		case "name.middlename":
			namePart(&s.MiddleName, "name.middleName")
		case "name.honorificprefix":
			namePart(&s.HonorificPrefix, "name.honorificPrefix")
		case "name.honorificsuffix":
			namePart(&s.HonorificSuffix, "name.honorificSuffix")
		case "emails":
			if op == "remove" {
				invalidPatchValue("emails cannot be removed")
			}
			if op == "add" {
				addEmails(s, value)
				return
			}
			setEmails(s, canonicalToInput(readEmailSet(value, s.UserName)))
		case "emails.value":
			if op == "remove" {
				invalidPatchValue("emails.value cannot be removed")
			}
			replaceAllEmailValues(s, value)
		default:
			if m := emailTypeValuePath.FindStringSubmatch(relative); m != nil && m[1] != "" {
				selector := jsLower(jsTrim(m[1]))
				if op == "remove" {
					var remaining []canonicalEmail
					for _, e := range s.Emails {
						if e.Type == nil || *e.Type != selector {
							remaining = append(remaining, e)
						}
					}
					if len(remaining) == len(s.Emails) {
						return
					}
					setEmails(s, canonicalToInput(remaining))
					return
				}
				replaceSelectedEmail(s, selector, value)
				return
			}
			if emailPrimaryValuePath.MatchString(relative) {
				if op == "remove" {
					invalidPatchValue("emails.value cannot be removed")
				}
				replacePrimaryEmail(s, value)
				return
			}
			applyGenericUserAttributePatch(doc, op, path, value)
		}
	}
	for _, operation := range operations {
		path := ""
		if operation.Path != nil {
			path = jsTrim(*operation.Path)
		}
		if path != "" {
			applyAttribute(operation.Op, path, operation.Value)
			continue
		}
		if operation.Op == "remove" {
			throwPatch("BAD_REQUEST", "A remove User PATCH operation requires a path", errNoTarget)
		}
		vo, ok := operation.Value.(*jsonx.Object)
		if !ok {
			invalidPatchValue("A pathless User PATCH value must be an object")
		}
		for _, k := range vo.Keys() {
			x, _ := vo.Get(k)
			applyAttribute(operation.Op, k, x)
		}
	}
	return finalizeUserPatch(s, doc), nil
}

type nameParts struct{ formatted, given, family, middle, prefix, suffix *string }

func readName(value any) nameParts {
	vo, ok := value.(*jsonx.Object)
	if !ok {
		invalidPatchValue("name must be an object")
	}
	var n nameParts
	for _, k := range vo.Keys() {
		x, _ := vo.Get(k)
		set := func(target **string, attr string) {
			v := readNonEmptyString(x, attr)
			*target = &v
		}
		switch jsLower(k) {
		case "formatted":
			set(&n.formatted, "name.formatted")
		case "givenname":
			set(&n.given, "name.givenName")
		case "familyname":
			set(&n.family, "name.familyName")
		case "middlename":
			set(&n.middle, "name.middleName")
		case "honorificprefix":
			set(&n.prefix, "name.honorificPrefix")
		case "honorificsuffix":
			set(&n.suffix, "name.honorificSuffix")
		default:
			throwPatch("BAD_REQUEST", "User attribute name."+k+" is not supported", errInvalidPath)
		}
	}
	return n
}
