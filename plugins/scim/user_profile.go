package scim

import (
	"github.com/nimi-io/better-auth-go/jsonx"
)

// canonicalEmail is SCIMCanonicalEmail.
type canonicalEmail struct {
	Value   string
	Type    *string
	Primary bool
}

// toObject renders the email the way normalizeSCIMEmails builds it: value, type?, primary.
func (e canonicalEmail) toObject() *jsonx.Object {
	o := jsonx.O("value", e.Value)
	if e.Type != nil {
		o.Set("type", *e.Type)
	}
	o.Set("primary", e.Primary)
	return o
}

// inputEmail is SCIMEmail.
type inputEmail struct {
	Value   string
	Primary *bool
	Type    *string
}

func emailsToAny(emails []canonicalEmail) []any {
	out := make([]any, len(emails))
	for i, e := range emails {
		out[i] = e.toObject()
	}
	return out
}

func serializeEmails(emails []canonicalEmail) string { return mustStringify(emailsToAny(emails)) }

// readInputEmails reads parsed email objects.
func readInputEmails(v any) []inputEmail {
	var out []inputEmail
	for _, x := range anyList(v) {
		o, ok := x.(*jsonx.Object)
		if !ok {
			continue
		}
		e := inputEmail{Value: getStr(o, "value")}
		if b, ok := getBool(o, "primary"); ok {
			e.Primary = &b
		}
		if s, ok := getOptStr(o, "type"); ok {
			e.Type = &s
		}
		out = append(out, e)
	}
	return out
}

// readCanonicalEmails reads canonical email objects (value, primary, type).
func readCanonicalEmails(v any) []canonicalEmail {
	var out []canonicalEmail
	for _, x := range anyList(v) {
		o, ok := x.(*jsonx.Object)
		if !ok {
			continue
		}
		e := canonicalEmail{Value: getStr(o, "value")}
		e.Primary, _ = getBool(o, "primary")
		if s, ok := getOptStr(o, "type"); ok {
			e.Type = &s
		}
		out = append(out, e)
	}
	return out
}

// normalizeEmails is normalizeSCIMEmails.
func normalizeEmails(userName string, emails []inputEmail) []canonicalEmail {
	normalized := make([]canonicalEmail, 0, len(emails))
	for _, e := range emails {
		c := canonicalEmail{Value: jsLower(jsTrim(e.Value)), Primary: e.Primary != nil && *e.Primary}
		if e.Type != nil && jsTrim(*e.Type) != "" {
			t := jsLower(jsTrim(*e.Type))
			c.Type = &t
		}
		normalized = append(normalized, c)
	}
	if len(normalized) == 0 {
		return []canonicalEmail{{Value: jsLower(userName), Primary: true}}
	}
	explicit, work := -1, -1
	for i, e := range normalized {
		if explicit < 0 && e.Primary {
			explicit = i
		}
		if work < 0 && e.Type != nil && *e.Type == "work" {
			work = i
		}
	}
	primary := 0
	if explicit >= 0 {
		primary = explicit
	} else if work >= 0 {
		primary = work
	}
	for i := range normalized {
		normalized[i].Primary = i == primary
	}
	return normalized
}

// userProfile is CanonicalSCIMUserProfile.
type userProfile struct {
	UserName      string
	DisplayName   string
	FormattedName string
	Name          *jsonx.Object
	GivenName     *string
	FamilyName    *string
	MiddleName    *string
	HonPrefix     *string
	HonSuffix     *string
	Emails        []canonicalEmail
	PrimaryEmail  string
	Attributes    *jsonx.Object
}

func normalizeOptionalString(o *jsonx.Object, key string) *string {
	s, ok := getOptStr(o, key)
	if !ok {
		return nil
	}
	s = jsTrim(s)
	if s == "" {
		return nil
	}
	return &s
}

// createCanonicalProfile is createCanonicalSCIMUserProfile over a parsed APIUser.
func createCanonicalProfile(input *jsonx.Object) userProfile {
	userName := jsTrim(getStr(input, "userName"))
	emails := normalizeEmails(userName, readInputEmails(objGet(input, "emails")))
	primaryEmail := userName
	found := false
	for _, e := range emails {
		if e.Primary {
			primaryEmail, found = e.Value, true
			break
		}
	}
	if !found && len(emails) > 0 {
		primaryEmail = emails[0].Value
	}
	name, _ := getObj(input, "name")
	givenName := normalizeOptionalString(name, "givenName")
	familyName := normalizeOptionalString(name, "familyName")
	middleName := normalizeOptionalString(name, "middleName")
	prefix := normalizeOptionalString(name, "honorificPrefix")
	suffix := normalizeOptionalString(name, "honorificSuffix")
	composed := ""
	if givenName != nil {
		composed = *givenName
	}
	if familyName != nil {
		if composed != "" {
			composed += " "
		}
		composed += *familyName
	}
	formatted := ""
	if f := normalizeOptionalString(name, "formatted"); f != nil {
		formatted = *f
	} else if d := normalizeOptionalString(input, "displayName"); d != nil {
		formatted = *d
	} else if composed != "" {
		formatted = composed
	} else {
		formatted = primaryEmail
	}
	displayName := formatted
	if d := normalizeOptionalString(input, "displayName"); d != nil {
		displayName = *d
	}
	nameObj := buildNameObject(formatted, givenName, familyName, middleName, prefix, suffix)
	attrs := jsonx.O("schemas", objGet(input, "schemas"), "name", nameObj, "emails", emailsToAny(emails))
	for _, k := range []string{"title", "userType", "preferredLanguage", "locale", "timezone"} {
		if truthy(objGet(input, k)) {
			attrs.Set(k, objGet(input, k))
		}
	}
	for _, k := range []string{"phoneNumbers", "addresses", "roles", "entitlements"} {
		if v := objGet(input, k); !isUndef(v) && v != nil {
			attrs.Set(k, v)
		}
	}
	if v := objGet(input, SchemaEnterpriseUser); !isUndef(v) && v != nil {
		attrs.Set("enterprise", v)
	}
	return userProfile{
		UserName: userName, DisplayName: displayName, FormattedName: formatted, Name: nameObj,
		GivenName: givenName, FamilyName: familyName, MiddleName: middleName, HonPrefix: prefix, HonSuffix: suffix,
		Emails: emails, PrimaryEmail: primaryEmail, Attributes: attrs,
	}
}

func buildNameObject(formatted string, given, family, middle, prefix, suffix *string) *jsonx.Object {
	o := jsonx.O("formatted", formatted)
	set := func(k string, v *string) {
		if v != nil && *v != "" {
			o.Set(k, *v)
		}
	}
	set("givenName", given)
	set("familyName", family)
	set("middleName", middle)
	set("honorificPrefix", prefix)
	set("honorificSuffix", suffix)
	return o
}

// ---- stored attributes (user-attributes.ts) ----

func invalidStoredUserAttributes() error {
	return scimErr("INTERNAL_SERVER_ERROR", "Stored SCIM User attribute state is invalid")
}

// serializeUserAttributes is serializeSCIMUserAttributes.
func serializeUserAttributes(attributes *jsonx.Object) (string, error) {
	parsed, issues := zParse(canonicalUserAttributesSchema, attributes)
	if len(issues) > 0 {
		return "", invalidStoredUserAttributes()
	}
	s := mustStringify(parsed)
	if jsonx.EncodeUTF16Length(s) > MaxSerializedUserAttributesLength {
		return "", invalidStoredUserAttributes()
	}
	return s, nil
}

// readUserAttributes is readSCIMUserAttributes.
func readUserAttributes(u *scimUserRow) (*jsonx.Object, error) {
	if u.SerializedAttributes == nil || *u.SerializedAttributes == "" {
		emails, err := parseJSON([]byte(u.SerializedEmails))
		if err != nil {
			return nil, invalidStoredUserAttributes()
		}
		name := jsonx.O("formatted", u.FormattedName)
		if u.GivenName != nil && *u.GivenName != "" {
			name.Set("givenName", *u.GivenName)
		}
		if u.FamilyName != nil && *u.FamilyName != "" {
			name.Set("familyName", *u.FamilyName)
		}
		parsed, issues := zParse(canonicalUserAttributesSchema, jsonx.O("schemas", []any{SchemaUser}, "name", name, "emails", emails))
		if len(issues) > 0 {
			return nil, invalidStoredUserAttributes()
		}
		return parsed.(*jsonx.Object), nil
	}
	if jsonx.EncodeUTF16Length(*u.SerializedAttributes) > MaxSerializedUserAttributesLength {
		return nil, invalidStoredUserAttributes()
	}
	raw, err := parseJSON([]byte(*u.SerializedAttributes))
	if err != nil {
		return nil, invalidStoredUserAttributes()
	}
	parsed, issues := zParse(canonicalUserAttributesSchema, raw)
	if len(issues) > 0 {
		return nil, invalidStoredUserAttributes()
	}
	return parsed.(*jsonx.Object), nil
}
