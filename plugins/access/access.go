// Package access is the role-based access control used by the admin and organization
// plugins (packages/better-auth/src/plugins/access).
package access

import (
	"errors"
	"slices"

	"github.com/nimi-io/better-auth-go/jsonx"
)

// ErrInvalidRequest is returned for a malformed authorize request (BetterAuthError
// "Invalid access control request" upstream).
var ErrInvalidRequest = errors.New("Invalid access control request")

// Statements maps resources to their actions.
type Statements map[string][]string

// Connector combines checks: "AND" (default) or "OR".
type Connector string

// Connectors.
const (
	AND Connector = "AND"
	OR  Connector = "OR"
)

// AuthorizeResponse is the result of Role.Authorize.
type AuthorizeResponse struct {
	Success bool
	Error   string
}

// Role is a set of allowed actions per resource.
type Role struct {
	Statements Statements
}

// NewRole creates a role from its statements (role upstream).
func NewRole(statements Statements) Role { return Role{Statements: statements} }

// Authorize checks a request. The request maps resources (in request order, which decides
// the reported error) to either a list of actions (all required) or an object
// {"actions": [...], "connector": "OR" | "AND"}. connector combines resources ("" = AND).
func (r Role) Authorize(request *jsonx.Object, connector Connector) (AuthorizeResponse, error) {
	if connector != OR {
		connector = AND
	}
	authorizedAny := false
	if request != nil {
		for _, resource := range request.Keys() {
			raw, _ := request.Get(resource)
			allowed, ok := r.Statements[resource]
			if !ok || allowed == nil {
				if connector == AND {
					return AuthorizeResponse{Error: "You are not allowed to access resource: " + resource}, nil
				}
				continue
			}
			req, err := normalize(raw)
			if err != nil {
				return AuthorizeResponse{}, err
			}
			authorized := req.authorized(allowed)
			if authorized {
				authorizedAny = true
				if connector == OR {
					return AuthorizeResponse{Success: true}, nil
				}
			} else if connector == AND {
				return AuthorizeResponse{Error: `unauthorized to access resource "` + resource + `"`}, nil
			}
		}
	}
	if authorizedAny {
		return AuthorizeResponse{Success: true}, nil
	}
	return AuthorizeResponse{Error: "Not authorized"}, nil
}

type actionRequest struct {
	actions   []any
	connector Connector
}

func (a actionRequest) authorized(allowed []string) bool {
	if len(a.actions) == 0 {
		return false
	}
	has := func(v any) bool {
		s, ok := v.(string)
		return ok && slices.Contains(allowed, s)
	}
	if a.connector == OR {
		return slices.ContainsFunc(a.actions, has)
	}
	for _, v := range a.actions {
		if !has(v) {
			return false
		}
	}
	return true
}

func toList(v any) ([]any, bool) {
	switch t := v.(type) {
	case []any:
		return t, true
	case []string:
		out := make([]any, len(t))
		for i, s := range t {
			out[i] = s
		}
		return out, true
	}
	return nil, false
}

func normalize(v any) (actionRequest, error) {
	if list, ok := toList(v); ok {
		return actionRequest{actions: list, connector: AND}, nil
	}
	var actions, conn any
	switch t := v.(type) {
	case *jsonx.Object:
		if t == nil {
			return actionRequest{}, ErrInvalidRequest
		}
		actions, _ = t.Get("actions")
		conn, _ = t.Get("connector")
	case map[string]any:
		if t == nil {
			return actionRequest{}, ErrInvalidRequest
		}
		actions, conn = t["actions"], t["connector"]
	default:
		return actionRequest{}, ErrInvalidRequest
	}
	c := AND
	if s, _ := conn.(string); s == string(OR) {
		c = OR
	}
	list, _ := toList(actions)
	return actionRequest{actions: list, connector: c}, nil
}

// AccessControl holds the statements an application defines (createAccessControl).
type AccessControl struct {
	Statements Statements
}

// New creates an access control for the given statements (createAccessControl).
func New(statements Statements) *AccessControl { return &AccessControl{Statements: statements} }

// NewRole creates a role. Resources and actions are expected to be a subset of the access
// control's statements (enforced by the type system upstream; not checked here).
func (ac *AccessControl) NewRole(statements Statements) Role { return NewRole(statements) }
