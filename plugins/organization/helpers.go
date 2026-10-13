package organization

import (
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

func errFrom(status string, code betterauth.ErrorCode) *betterauth.APIError {
	return betterauth.ErrFrom(status, code)
}

func errMsg(status, msg string) *betterauth.APIError { return betterauth.ErrMessage(status, msg) }

func errStatus(status string) *betterauth.APIError { return betterauth.ErrStatus(status) }

func sessionField(s *betterauth.SessionWithUser, field string) string {
	if s == nil || s.Session == nil {
		return ""
	}
	v, _ := s.Session.Additional[field].(string)
	return v
}

func activeOrgID(s *betterauth.SessionWithUser) string {
	return sessionField(s, "activeOrganizationId")
}

func activeTeamID(s *betterauth.SessionWithUser) string { return sessionField(s, "activeTeamId") }

func splitRoles(role string) []string { return strings.Split(role, ",") }

func trimmedRoles(role string) []string {
	parts := strings.Split(role, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// parseRoles joins an array of roles with "," (parseRoles upstream).
func parseRoles(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		parts := make([]string, len(t))
		for i, x := range t {
			parts[i] = jsString(x)
		}
		return strings.Join(parts, ",")
	case []string:
		return strings.Join(t, ",")
	}
	return ""
}

// jsString is JavaScript String(v).
func jsString(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		return jsonx.FormatNumber(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case []any:
		parts := make([]string, len(t))
		for i, x := range t {
			if x == nil || validate.IsUndefined(x) {
				continue
			}
			parts[i] = jsString(x)
		}
		return strings.Join(parts, ",")
	case map[string]any, *jsonx.Object:
		return "[object Object]"
	}
	if validate.IsUndefined(v) {
		return "undefined"
	}
	return ""
}

// coerceString is z.coerce.string().
func coerceString() validate.Schema {
	return validate.Custom(func(v any, path []any) (any, []validate.Issue) {
		return jsString(v), nil
	})
}

// parseIntJS is parseInt(s) (NaN when no leading integer).
func parseIntJS(s string) float64 {
	s = strings.TrimLeft(s, " \t\n\r\v\f")
	i := 0
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		i++
	}
	j := i
	for j < len(s) && s[j] >= '0' && s[j] <= '9' {
		j++
	}
	if j == i {
		return math.NaN()
	}
	f, err := strconv.ParseFloat(s[:j], 64)
	if err != nil {
		return math.NaN()
	}
	return f
}

// jsNumber is Number(v) for strings and numbers.
func jsNumber(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return math.NaN()
		}
		return f
	case bool:
		if t {
			return 1
		}
		return 0
	}
	return math.NaN()
}

func truthyNum(f float64) bool { return f != 0 && !math.IsNaN(f) }

// additionalFieldsSchema ports toZodSchema({fields, isClientSide: true}).
func additionalFieldsSchema(fields []db.Field) []validate.Field {
	var out []validate.Field
	for _, f := range fields {
		if !f.IsInput() {
			continue
		}
		var s validate.Schema
		switch f.Type {
		case db.TypeJSON:
			s = validate.Any()
		case db.TypeStringArray:
			s = validate.Array(validate.String())
		case db.TypeNumberArray:
			s = validate.Array(validate.Number())
		case db.TypeString:
			s = validate.String()
		case db.TypeNumber:
			s = validate.Number()
		case db.TypeBoolean:
			s = validate.Boolean()
		case db.TypeDate:
			s = dateSchema()
		default:
			s = validate.Any()
		}
		if f.IsOptional() {
			s = validate.Nullish(s)
		}
		out = append(out, validate.F(f.Name, s))
	}
	return out
}

// dateSchema is z.date(): JSON input can never be a Date.
func dateSchema() validate.Schema {
	return validate.Custom(func(v any, path []any) (any, []validate.Issue) {
		return nil, []validate.Issue{validate.NewIssue(path, "invalid_type", "Invalid input: expected date, received "+jsTypeName(v))}
	})
}

func jsTypeName(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case float64, int, int64:
		return "number"
	case bool:
		return "boolean"
	case []any:
		return "array"
	}
	if validate.IsUndefined(v) {
		return "undefined"
	}
	return "object"
}

// partialFields makes every field optional (zod .partial()).
func partialFields(fields []validate.Field) []validate.Field {
	out := make([]validate.Field, len(fields))
	for i, f := range fields {
		out[i] = validate.F(f.Name, validate.Optional(f.Schema))
	}
	return out
}

// mergeFields is { ...a.shape, ...b.shape }: later fields replace earlier ones in place.
func mergeFields(a []validate.Field, b ...validate.Field) []validate.Field {
	out := append([]validate.Field(nil), a...)
	for _, f := range b {
		replaced := false
		for i := range out {
			if out[i].Name == f.Name {
				out[i] = f
				replaced = true
			}
		}
		if !replaced {
			out = append(out, f)
		}
	}
	return out
}

// xor is z.xor([...]): exactly one option must match.
func xor(options ...validate.Schema) validate.Schema {
	return validate.Custom(func(v any, path []any) (any, []validate.Issue) {
		var match any
		n := 0
		for _, o := range options {
			out, issues := validate.Validate(o, v)
			if len(issues) == 0 {
				n++
				match = out
			}
		}
		switch n {
		case 1:
			return match, nil
		case 0:
			return nil, []validate.Issue{validate.NewIssue(path, "invalid_union", "Invalid input")}
		}
		return nil, []validate.Issue{validate.NewIssue(path, "invalid_union", "Invalid input: more than one option matched")}
	})
}

// ---- ordered output ----

// objFor renders a record in the key order the TypeScript adapter produces (schema field
// order, then id). Keys not in the schema are appended in sorted order. hidden fields are
// omitted.
func objFor(ctx *Ctx, model string, rec Record, hidden map[string]bool) *jsonx.Object {
	if rec == nil {
		return nil
	}
	o := jsonx.NewObject()
	seen := map[string]bool{"id": true}
	if t := ctx.Auth.Tables.Table(model); t != nil {
		for _, f := range t.Fields {
			seen[f.Name] = true
			if hidden[f.Name] {
				continue
			}
			if v, ok := rec[f.Name]; ok {
				o.Set(f.Name, v)
			}
		}
	}
	if v, ok := rec["id"]; ok {
		o.Set("id", v)
	}
	var rest []string
	for k := range rec {
		if !seen[k] && !hidden[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		o.Set(k, rec[k])
	}
	return o
}

// hiddenAdditional lists additional fields with returned: false (filterOutputFields).
func hiddenAdditional(fields []db.Field) map[string]bool {
	out := map[string]bool{}
	for _, f := range fields {
		if !f.IsReturned() {
			out[f.Name] = true
		}
	}
	return out
}

func (p *plugin) orgObj(ctx *Ctx, rec Record) *jsonx.Object {
	return objFor(ctx, "organization", rec, hiddenAdditional(p.o.schema().Organization.AdditionalFields))
}

func (p *plugin) memberObj(ctx *Ctx, rec Record, filter bool) *jsonx.Object {
	var hidden map[string]bool
	if filter {
		hidden = hiddenAdditional(p.o.schema().Member.AdditionalFields)
	}
	return objFor(ctx, "member", rec, hidden)
}

func (p *plugin) memberWithUserObj(ctx *Ctx, m *memberWithUser, filter bool) *jsonx.Object {
	o := p.memberObj(ctx, m.Member, filter)
	o.Set("user", m.User)
	return o
}

func (p *plugin) invitationObj(ctx *Ctx, rec Record, filter bool) *jsonx.Object {
	var hidden map[string]bool
	if filter {
		hidden = hiddenAdditional(p.o.schema().Invitation.AdditionalFields)
	}
	return objFor(ctx, "invitation", rec, hidden)
}

func (p *plugin) teamObj(ctx *Ctx, rec Record) *jsonx.Object {
	hidden := hiddenAdditional(p.o.schema().Team.AdditionalFields)
	hidden["memberCount"] = true
	return objFor(ctx, "team", rec, hidden)
}

func (p *plugin) teamMemberObj(ctx *Ctx, rec Record) *jsonx.Object {
	return objFor(ctx, "teamMember", rec, map[string]bool{"membershipKey": true})
}

func list(items []*jsonx.Object) []any {
	out := make([]any, len(items))
	for i, x := range items {
		out[i] = x
	}
	return out
}

func copyRecord(r Record) Record {
	out := Record{}
	for k, v := range r {
		out[k] = v
	}
	return out
}
