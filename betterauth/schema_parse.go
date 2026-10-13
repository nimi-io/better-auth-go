package betterauth

import (
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
)

func coreNames(model string) []string {
	switch model {
	case "user":
		return coreUserFields
	case "session":
		return coreSessionFields
	case "account":
		return coreAccountFields
	case "verification":
		return coreVerificationFields
	}
	return nil
}

// inputFields returns the additional + plugin fields of a core model (getFields(...,"input")).
func (a *AuthContext) inputFields(model string) []db.Field {
	t := a.Tables.Table(model)
	if t == nil {
		return nil
	}
	core := map[string]bool{}
	for _, c := range coreNames(model) {
		core[c] = true
	}
	var out []db.Field
	for _, f := range t.Fields {
		if !core[f.Name] {
			out = append(out, f)
		}
	}
	return out
}

func (a *AuthContext) outputHidden(model string) map[string]bool {
	hidden := map[string]bool{}
	if t := a.Tables.Table(model); t != nil {
		for _, f := range t.Fields {
			if !f.IsReturned() {
				hidden[f.Name] = true
			}
		}
	}
	return hidden
}

// UserOutput renders a user for API responses (parseUserOutput), hiding returned=false fields.
func (a *AuthContext) UserOutput(u *User) *jsonx.Object {
	if u == nil {
		return nil
	}
	return toObject(u, a.Tables.Table("user"), coreUserFields, u.Additional, a.outputHidden("user"))
}

// SessionOutput renders a session for API responses (parseSessionOutput).
func (a *AuthContext) SessionOutput(s *Session) *jsonx.Object {
	if s == nil {
		return nil
	}
	return toObject(s, a.Tables.Table("session"), coreSessionFields, s.Additional, a.outputHidden("session"))
}

// AccountOutput renders an account without secrets (parseAccountOutput).
func (a *AuthContext) AccountOutput(acct *Account) *jsonx.Object {
	hidden := a.outputHidden("account")
	for k := range accountSecretFields {
		hidden[k] = true
	}
	return toObject(acct, a.Tables.Table("account"), coreAccountFields, acct.Additional, hidden)
}

// parseInputData mirrors db/schema.ts parseInputData.
func parseInputData(data map[string]any, fields []db.Field, action string) (map[string]any, error) {
	out := map[string]any{}
	for _, f := range fields {
		v, present := data[f.Name]
		if present {
			if !f.IsInput() {
				if f.HasDefault() && action != "update" {
					out[f.Name] = f.DefaultValue
					if f.DefaultFunc != nil {
						out[f.Name] = f.DefaultFunc()
					}
					continue
				}
				if truthy(v) {
					return nil, ErrFrom("BAD_REQUEST", ErrorCode{Code: ErrFieldNotAllowed.Code, Message: f.Name + " is not allowed to be set"})
				}
				continue
			}
			if f.Validator != nil {
				nv, err := f.Validator(v)
				if err != nil {
					msg := err.Error()
					if msg == "" {
						msg = "Validation Error"
					}
					return nil, ErrFrom("BAD_REQUEST", ErrorCode{Code: ErrValidationError.Code, Message: msg})
				}
				out[f.Name] = nv
				continue
			}
			if f.TransformInput != nil {
				nv, err := f.TransformInput(v)
				if err != nil {
					return nil, err
				}
				out[f.Name] = nv
				continue
			}
			out[f.Name] = v
			continue
		}
		if f.HasDefault() && action == "create" {
			out[f.Name] = f.Default()
			continue
		}
		if f.IsRequired() && action == "create" {
			return nil, ErrFrom("BAD_REQUEST", ErrorCode{Code: ErrMissingField.Code, Message: f.Name + " is required"})
		}
	}
	return out, nil
}

func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0
	case int:
		return t != 0
	case int64:
		return t != 0
	}
	return true
}

// ParseUserInput validates user-supplied additional user fields (parseUserInput).
func (a *AuthContext) ParseUserInput(data map[string]any, action string) (map[string]any, error) {
	if data == nil {
		data = map[string]any{}
	}
	return parseInputData(data, a.inputFields("user"), action)
}

// ParseSessionInput validates user-supplied additional session fields.
func (a *AuthContext) ParseSessionInput(data map[string]any, action string) (map[string]any, error) {
	if data == nil {
		data = map[string]any{}
	}
	return parseInputData(data, a.inputFields("session"), action)
}

// ParseAccountInput validates user-supplied additional account fields.
func (a *AuthContext) ParseAccountInput(data map[string]any) (map[string]any, error) {
	if data == nil {
		data = map[string]any{}
	}
	return parseInputData(data, a.inputFields("account"), "create")
}

// ParseAdditionalUserInputFromProfile filters a provider profile to allowed input fields.
func (a *AuthContext) ParseAdditionalUserInputFromProfile(profile map[string]any, action string) (map[string]any, error) {
	fields := a.inputFields("user")
	allowed := map[string]any{}
	byName := map[string]db.Field{}
	for _, f := range fields {
		byName[f.Name] = f
	}
	for k, v := range profile {
		if f, ok := byName[k]; ok && !f.IsInput() {
			continue
		}
		allowed[k] = v
	}
	return parseInputData(allowed, fields, action)
}

func (a *AuthContext) sessionDefaultFields() map[string]any {
	out := map[string]any{}
	for _, f := range a.inputFields("session") {
		if f.HasDefault() {
			out[f.Name] = f.Default()
		}
	}
	return out
}

// buildSyntheticUserOutput mirrors db/schema.ts buildSyntheticUserOutput.
func (a *AuthContext) buildSyntheticUserOutput(data map[string]any) *jsonx.Object {
	t := a.Tables.Table("user")
	out := jsonx.NewObject()
	for _, f := range t.Fields {
		if !f.IsReturned() {
			continue
		}
		if v, ok := data[f.Name]; ok {
			out.Set(f.Name, v)
		} else if f.HasDefault() {
			out.Set(f.Name, f.Default())
		} else if !f.IsRequired() {
			out.Set(f.Name, nil)
		}
	}
	if id, ok := data["id"]; ok {
		out.Set("id", id)
	}
	return out
}
