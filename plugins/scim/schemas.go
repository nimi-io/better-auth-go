package scim

import (
	_ "embed"
	"strings"

	"github.com/nimi-io/better-auth-go/jsonx"
)

// Schema URNs and limits (user-schemas.ts, group-schemas.ts).
const (
	SchemaUser           = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaEnterpriseUser = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	SchemaGroup          = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaPatchOp        = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaListResponse   = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaError          = "urn:ietf:params:scim:api:messages:2.0:Error"
	// MediaType is the SCIM response media type.
	MediaType = "application/scim+json"

	schemaMicrosoftEntraLegacyGroup = "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group"

	// MaxSerializedUserAttributesLength bounds the stored User attribute document.
	MaxSerializedUserAttributesLength = 65_535
	maxMultiValueCount                = 20
	maxStructuredValueCount           = 10
	// MaxGroupMembers is the maximum number of direct Group members.
	MaxGroupMembers = 1_000
	// MaxPageSize is the maximum SCIM list page size.
	MaxPageSize = 100
)

// userSchemaIDs are the supported User schema descriptors in registry order.
var userSchemaIDs = []string{SchemaUser, SchemaEnterpriseUser}

//go:embed discovery.json
var discoveryJSON []byte

type discoveryDoc struct {
	schemas               []*jsonx.Object
	resourceTypes         []*jsonx.Object
	serviceProviderConfig *jsonx.Object
}

var discovery = func() discoveryDoc {
	v, err := jsonx.Parse(discoveryJSON)
	if err != nil {
		panic(err)
	}
	o := v.(*jsonx.Object)
	var d discoveryDoc
	for _, x := range getArr(o, "schemas") {
		d.schemas = append(d.schemas, x.(*jsonx.Object))
	}
	for _, x := range getArr(o, "resourceTypes") {
		d.resourceTypes = append(d.resourceTypes, x.(*jsonx.Object))
	}
	d.serviceProviderConfig, _ = getObj(o, "serviceProviderConfig")
	return d
}()

func discoverySchema(id string) *jsonx.Object {
	for _, s := range discovery.schemas {
		if getStr(s, "id") == id {
			return s
		}
	}
	return nil
}

// patchAttribute is a SCIM schema attribute descriptor used by PATCH path resolution.
type patchAttribute struct {
	name          string
	typ           string
	multiValued   bool
	mutability    string
	subAttributes []patchAttribute
}

func toPatchAttributes(list []any) []patchAttribute {
	out := make([]patchAttribute, 0, len(list))
	for _, x := range list {
		o := x.(*jsonx.Object)
		a := patchAttribute{name: getStr(o, "name"), typ: getStr(o, "type"), mutability: getStr(o, "mutability")}
		a.multiValued, _ = getBool(o, "multiValued")
		if subs := getArr(o, "subAttributes"); subs != nil {
			a.subAttributes = toPatchAttributes(subs)
		}
		out = append(out, a)
	}
	return out
}

var (
	userPatchAttributes       = toPatchAttributes(getArr(discoverySchema(SchemaUser), "attributes"))
	enterprisePatchAttributes = toPatchAttributes(getArr(discoverySchema(SchemaEnterpriseUser), "attributes"))
)

// ---- shared zod schemas ----

var (
	scimStringSchema     = zStr().trim().min(1).max(256)
	scimLongStringSchema = zStr().trim().min(1).max(1_024)
	scimReferenceSchema  = zStr().trim().min(1).max(2_048)
	scimEmailValueSchema = zStr().email().max(254)
)

func lowerTransform(v any) any {
	if s, ok := v.(string); ok {
		return jsLower(s)
	}
	return v
}

func scimSingleValueScalar(s zSchema) zSchema {
	return zPreprocess(func(v any) any {
		if arr, ok := v.([]any); ok && len(arr) == 1 {
			return arr[0]
		}
		return v
	}, s)
}

func atMostOnePrimary(v any) bool {
	n := 0
	for _, x := range anyList(v) {
		if o, ok := x.(*jsonx.Object); ok && truthy(objGet(o, "primary")) {
			n++
		}
	}
	return n <= 1
}

// hasUniqueSCIMDefinedTypes reports whether defined types are unique case-insensitively.
func hasUniqueSCIMDefinedTypes(v any) bool {
	seen := map[string]bool{}
	for _, x := range anyList(v) {
		o, ok := x.(*jsonx.Object)
		if !ok {
			continue
		}
		t, present := o.Get("type")
		if !present || isUndef(t) {
			continue
		}
		s, _ := t.(string)
		k := jsLower(jsTrim(s))
		if seen[k] {
			return false
		}
		seen[k] = true
	}
	return true
}

// emailTupleKey is createSCIMEmailTupleKey.
func emailTupleKey(typ *string, value string) string {
	var t any
	if typ != nil {
		t = jsLower(jsTrim(*typ))
	}
	return mustStringify([]any{t, jsLower(jsTrim(value))})
}

func emailTupleKeyOf(o *jsonx.Object) string {
	var t *string
	if s, ok := o.Get("type"); ok && !isUndef(s) {
		str, _ := s.(string)
		t = &str
	}
	return emailTupleKey(t, getStr(o, "value"))
}

func uniqueEmailTuples(v any) bool {
	seen := map[string]bool{}
	list := anyList(v)
	for _, x := range list {
		o, ok := x.(*jsonx.Object)
		if !ok {
			return true
		}
		seen[emailTupleKeyOf(o)] = true
	}
	return len(seen) == len(list)
}

var (
	scimNameSchema = zObj(
		zf("formatted", zOpt(scimLongStringSchema)),
		zf("givenName", zOpt(scimStringSchema)),
		zf("familyName", zOpt(scimStringSchema)),
		zf("middleName", zOpt(scimStringSchema)),
		zf("honorificPrefix", zOpt(scimStringSchema)),
		zf("honorificSuffix", zOpt(scimStringSchema)),
	)
	scimCanonicalNameSchema = scimNameSchema.extend(zf("formatted", scimLongStringSchema))
	scimTypeSchema          = zOpt(zTransform(scimStringSchema, lowerTransform))
	scimEmailSchema         = zObj(
		zf("value", scimEmailValueSchema),
		zf("primary", zOpt(zBoolean{})),
		zf("type", scimTypeSchema),
	)
	scimCanonicalEmailSchema = scimEmailSchema.extend(zf("primary", zBoolean{}))
	scimPhoneNumberSchema    = zObj(
		zf("value", scimLongStringSchema),
		zf("type", scimTypeSchema),
		zf("primary", zOpt(zBoolean{})),
	)
	scimAddressSchema = zObj(
		zf("formatted", zOpt(scimLongStringSchema)),
		zf("streetAddress", zOpt(scimLongStringSchema)),
		zf("locality", zOpt(scimStringSchema)),
		zf("region", zOpt(scimStringSchema)),
		zf("postalCode", zOpt(scimStringSchema)),
		zf("country", zOpt(scimStringSchema)),
		zf("type", scimTypeSchema),
		zf("primary", zOpt(zBoolean{})),
	).refine(simpleRefine(func(v any) bool {
		o := v.(*jsonx.Object)
		for _, k := range o.Keys() {
			x, _ := o.Get(k)
			if k != "primary" && k != "type" && !isUndef(x) {
				return true
			}
		}
		return false
	}, "addresses must contain at least one address value"))
	scimRoleSchema = zObj(
		zf("value", scimLongStringSchema),
		zf("display", zOpt(scimLongStringSchema)),
		zf("type", scimTypeSchema),
		zf("primary", zOpt(zBoolean{})),
	)
	scimEntitlementSchema = scimRoleSchema

	scimCanonicalManagerSchema = zTransform(zObj(
		zf("value", zOpt(scimStringSchema)),
		zf("$ref", zOpt(scimReferenceSchema)),
	).refine(simpleRefine(func(v any) bool {
		o := v.(*jsonx.Object)
		return o.Has("value") || o.Has("$ref")
	}, "manager must contain value or $ref")), func(v any) any {
		o := v.(*jsonx.Object)
		out := jsonx.NewObject()
		if x, ok := o.Get("value"); ok {
			out.Set("value", x)
			if r, ok := o.Get("$ref"); ok {
				out.Set("$ref", r)
			}
			return out
		}
		if r, ok := o.Get("$ref"); ok {
			out.Set("$ref", r)
		}
		return out
	})

	scimManagerInputObjectSchema = zObj(
		zf("value", zOpt(scimStringSchema)),
		zf("$ref", zOpt(scimReferenceSchema)),
		zf("displayName", zOpt(scimLongStringSchema)),
	)
	scimManagerInputSchema = zTransform(zUnionT{options: []zSchema{
		scimStringSchema,
		scimManagerInputObjectSchema,
		zArr(scimManagerInputObjectSchema).length(1, ""),
	}}, func(v any) any {
		if s, ok := v.(string); ok {
			return jsonx.O("value", s)
		}
		var cand *jsonx.Object
		if arr, ok := v.([]any); ok {
			if len(arr) > 0 {
				cand, _ = arr[0].(*jsonx.Object)
			}
		} else {
			cand, _ = v.(*jsonx.Object)
		}
		if cand == nil {
			return undef
		}
		if x, ok := cand.Get("value"); ok {
			out := jsonx.O("value", x)
			if r, ok := cand.Get("$ref"); ok {
				out.Set("$ref", r)
			}
			return out
		}
		if r, ok := cand.Get("$ref"); ok {
			return jsonx.O("$ref", r)
		}
		return undef
	})
)

func enterpriseAttributeFields() []zField {
	return []zField{
		zf("employeeNumber", zOpt(scimSingleValueScalar(scimStringSchema))),
		zf("costCenter", zOpt(scimSingleValueScalar(scimStringSchema))),
		zf("organization", zOpt(scimSingleValueScalar(scimLongStringSchema))),
		zf("division", zOpt(scimSingleValueScalar(scimLongStringSchema))),
		zf("department", zOpt(scimSingleValueScalar(scimLongStringSchema))),
	}
}

var (
	enterpriseUserInputSchema = zTransform(zObj(append(enterpriseAttributeFields(),
		zf("manager", zOpt(scimManagerInputSchema)))...), func(v any) any {
		o := v.(*jsonx.Object)
		out := jsonx.NewObject()
		for _, k := range o.Keys() {
			if k == "manager" {
				continue
			}
			x, _ := o.Get(k)
			out.Set(k, x)
		}
		if m, ok := o.Get("manager"); ok && !isUndef(m) {
			out.Set("manager", m)
		}
		return out
	})
	enterpriseUserCanonicalSchema = zObj(append(enterpriseAttributeFields(),
		zf("manager", zOpt(scimCanonicalManagerSchema)))...)
)

var scimUserSchemasSchema = zTransform(zArr(zStr()).min(1).max(len(userSchemaIDs)).refine(func(v any) []zIssue {
	list := anyList(v)
	var issues []zIssue
	strs := make([]string, len(list))
	for i, x := range list {
		strs[i], _ = x.(string)
	}
	for _, s := range strs {
		if !containsString(userSchemaIDs, s) {
			issues = append(issues, refineIssue("Unsupported SCIM User schema "+s))
		}
		first, last := -1, -1
		for i, x := range strs {
			if x == s {
				if first < 0 {
					first = i
				}
				last = i
			}
		}
		if first != last {
			issues = append(issues, refineIssue("SCIM User schema "+s+" must not be duplicated"))
		}
	}
	if !containsString(strs, SchemaUser) {
		issues = append(issues, refineIssue("schemas must contain "+SchemaUser))
	}
	return issues
}), func(v any) any {
	list := anyList(v)
	strs := make([]string, len(list))
	for i, x := range list {
		strs[i], _ = x.(string)
	}
	out := []any{}
	for _, id := range userSchemaIDs {
		if containsString(strs, id) {
			out = append(out, id)
		}
	}
	return out
})

func validateEnterpriseDeclaration(key string) zRefineFn {
	return func(v any) []zIssue {
		o := v.(*jsonx.Object)
		ent, ok := o.Get(key)
		if !ok || isUndef(ent) {
			return nil
		}
		if containsAny(anyList(objGet(o, "schemas")), SchemaEnterpriseUser) {
			return nil
		}
		return []zIssue{refineIssue("The Enterprise User extension requires "+SchemaEnterpriseUser+" in schemas", "schemas")}
	}
}

func multiValuedArray(item zSchema, max int, name string) zSchema {
	return zOpt(zArr(item).max(max).
		refine(simpleRefine(atMostOnePrimary, name+" cannot contain multiple primary values")).
		refine(simpleRefine(hasUniqueSCIMDefinedTypes, name+" cannot contain duplicate defined types")))
}

// apiUserSchema is APIUserSchema (the SCIM User input schema).
var apiUserSchema = zObj(
	zf("schemas", scimUserSchemasSchema),
	zf("userName", zStr().trim().min(1).max(512)),
	zf("externalId", zOpt(scimLongStringSchema)),
	zf("displayName", zOpt(scimLongStringSchema)),
	zf("name", zOpt(scimNameSchema)),
	zf("emails", zOpt(zArr(scimEmailSchema).max(maxMultiValueCount).
		refine(simpleRefine(atMostOnePrimary, "emails cannot contain multiple primary values")).
		refine(simpleRefine(uniqueEmailTuples, "emails cannot contain duplicate type and value pairs")).
		refine(simpleRefine(hasUniqueSCIMDefinedTypes, "emails cannot contain duplicate defined types")))),
	zf("title", zOpt(scimSingleValueScalar(scimLongStringSchema))),
	zf("userType", zOpt(scimSingleValueScalar(scimStringSchema))),
	zf("preferredLanguage", zOpt(scimSingleValueScalar(scimStringSchema))),
	zf("locale", zOpt(scimSingleValueScalar(scimStringSchema))),
	zf("timezone", zOpt(scimSingleValueScalar(scimStringSchema))),
	zf("phoneNumbers", multiValuedArray(scimPhoneNumberSchema, maxStructuredValueCount, "phoneNumbers")),
	zf("addresses", multiValuedArray(scimAddressSchema, maxStructuredValueCount, "addresses")),
	zf("roles", multiValuedArray(scimRoleSchema, maxStructuredValueCount, "roles")),
	zf("entitlements", multiValuedArray(scimEntitlementSchema, maxStructuredValueCount, "entitlements")),
	zf("active", zOpt(zBoolean{})),
	zf(SchemaEnterpriseUser, zOpt(enterpriseUserInputSchema)),
).refine(func(v any) []zIssue {
	o := v.(*jsonx.Object)
	var issues []zIssue
	emails := anyList(objGet(o, "emails"))
	if len(emails) == 0 {
		if _, errs := zParse(scimEmailValueSchema, objGet(o, "userName")); len(errs) > 0 {
			issues = append(issues, refineIssue("emails must contain an email when userName is not an email address", "emails"))
		}
	}
	issues = append(issues, validateEnterpriseDeclaration(SchemaEnterpriseUser)(o)...)
	if s, err := jsonx.Stringify(o); err == nil && jsonx.EncodeUTF16Length(s) > MaxSerializedUserAttributesLength {
		issues = append(issues, refineIssue("SCIM User attributes exceed the supported serialized size"))
	}
	return issues
})

func storedMultiValued(item zSchema) zSchema {
	return zOpt(zArr(item).max(maxStructuredValueCount).
		refine(simpleRefine(atMostOnePrimary, "")).
		refine(simpleRefine(hasUniqueSCIMDefinedTypes, "")))
}

// canonicalUserAttributesSchema is SCIMCanonicalUserAttributesSchema.
var canonicalUserAttributesSchema = zObj(
	zf("schemas", scimUserSchemasSchema),
	zf("name", scimCanonicalNameSchema),
	zf("emails", zArr(scimCanonicalEmailSchema).min(1).max(maxMultiValueCount).
		refine(simpleRefine(func(v any) bool {
			n := 0
			for _, x := range anyList(v) {
				if o, ok := x.(*jsonx.Object); ok && truthy(objGet(o, "primary")) {
					n++
				}
			}
			return n == 1
		}, "stored emails must contain exactly one primary value")).
		refine(simpleRefine(uniqueEmailTuples, "stored emails must contain unique type and value pairs")).
		refine(simpleRefine(hasUniqueSCIMDefinedTypes, "stored emails must contain unique defined types"))),
	zf("title", zOpt(scimLongStringSchema)),
	zf("userType", zOpt(scimStringSchema)),
	zf("preferredLanguage", zOpt(scimStringSchema)),
	zf("locale", zOpt(scimStringSchema)),
	zf("timezone", zOpt(scimStringSchema)),
	zf("phoneNumbers", storedMultiValued(scimPhoneNumberSchema)),
	zf("addresses", storedMultiValued(scimAddressSchema)),
	zf("roles", storedMultiValued(scimRoleSchema)),
	zf("entitlements", storedMultiValued(scimEntitlementSchema)),
	zf("enterprise", zOpt(enterpriseUserCanonicalSchema)),
).refine(validateEnterpriseDeclaration("enterprise"))

// ---- group ----

var groupMemberSchema = zObj(
	zf("value", zStr().min(1)),
	zf("type", zOpt(zStr().refine(func(s string) bool { return jsLower(s) == "user" }, ""))),
)

// apiGroupSchema is APIGroupSchema.
var apiGroupSchema = zObj(
	zf("schemas", zArr(zLiteralT{value: SchemaGroup}).length(1, "schemas must contain only the core SCIM Group schema")),
	zf("externalId", zOpt(zStr().min(1))),
	zf("displayName", zStr().trim().min(1)),
	zf("members", zOpt(zArr(groupMemberSchema).max(MaxGroupMembers))),
)

// patchBodySchema is the PatchOp request schema (patchSCIMUserBodySchema /
// patchSCIMGroupBodySchema).
var patchBodySchema = zObj(
	zf("schemas", zArr(zLiteralT{value: SchemaPatchOp}).length(1, "schemas must contain only the PatchOp schema")),
	zf("Operations", zArr(zObj(
		zf("op", zPipe(zDefaultT{inner: zStr().lower(), def: "replace"}, zEnumT{values: []string{"replace", "add", "remove"}})),
		zf("path", zOpt(zStr())),
		zf("value", zOpt(zUnknownT{})),
	))),
)

// normalizeMicrosoftEntraGroupSchema handles the legacy Entra Group schema marker.
func normalizeMicrosoftEntraGroupSchema(body any, enabled bool) (any, string, bool) {
	o, ok := body.(*jsonx.Object)
	if !ok {
		return body, "", true
	}
	if o.Has(schemaMicrosoftEntraLegacyGroup) {
		return nil, "The Microsoft Entra Group compatibility schema cannot contain attributes", false
	}
	schemas, ok := objGet(o, "schemas").([]any)
	if !ok {
		return body, "", true
	}
	markers := 0
	for _, s := range schemas {
		if s == schemaMicrosoftEntraLegacyGroup {
			markers++
		}
	}
	if markers == 0 || !enabled {
		return body, "", true
	}
	if markers != 1 {
		return nil, "The Microsoft Entra Group compatibility schema must not be duplicated", false
	}
	filtered := []any{}
	for _, s := range schemas {
		if s != schemaMicrosoftEntraLegacyGroup {
			filtered = append(filtered, s)
		}
	}
	out := o.Clone()
	out.Set("schemas", filtered)
	return out, "", true
}

// ---- small helpers ----

func objGet(o *jsonx.Object, key string) any {
	if o == nil {
		return undef
	}
	v, ok := o.Get(key)
	if !ok {
		return undef
	}
	return v
}

func getStr(o *jsonx.Object, key string) string {
	s, _ := objGet(o, key).(string)
	return s
}

func getOptStr(o *jsonx.Object, key string) (string, bool) {
	s, ok := objGet(o, key).(string)
	return s, ok
}

func getBool(o *jsonx.Object, key string) (bool, bool) {
	b, ok := objGet(o, key).(bool)
	return b, ok
}

func getArr(o *jsonx.Object, key string) []any {
	a, _ := objGet(o, key).([]any)
	return a
}

func getObj(o *jsonx.Object, key string) (*jsonx.Object, bool) {
	x, ok := objGet(o, key).(*jsonx.Object)
	return x, ok
}

func anyList(v any) []any {
	l, _ := v.([]any)
	return l
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func containsAny(list []any, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// truthy is JavaScript truthiness for JSON-like values.
func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0 && t == t
	}
	return !isUndef(v)
}

func isRecord(v any) bool {
	_, ok := v.(*jsonx.Object)
	return ok
}

func trimLower(s string) string { return strings.ToLower(jsTrim(s)) }
