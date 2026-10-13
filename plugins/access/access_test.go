package access

import (
	"testing"

	"github.com/nimi-io/better-auth-go/jsonx"
)

// Port of plugins/access/access.test.ts.

var (
	statements = Statements{
		"project": {"create", "update", "delete", "delete-many"},
		"ui":      {"view", "edit", "comment", "hide"},
	}
	ac    = New(statements)
	role1 = ac.NewRole(Statements{
		"project": {"create", "update", "delete"},
		"ui":      {"view", "edit", "comment"},
	})
	looseRole = New(Statements{"project": {"create", "update", "delete"}}).NewRole(Statements{"project": {"create", "update", "delete"}})
)

func authorize(t *testing.T, r Role, req *jsonx.Object, c ...Connector) AuthorizeResponse {
	t.Helper()
	conn := AND
	if len(c) > 0 {
		conn = c[0]
	}
	res, err := r.Authorize(req, conn)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func list(s ...any) []any { return s }

func TestAccess(t *testing.T) {
	t.Run("should allow passing defined statements directly into newRole", func(t *testing.T) {
		if !authorize(t, ac.NewRole(statements), jsonx.O("project", list("create"))).Success {
			t.Fatal("expected success")
		}
	})
	t.Run("should preserve exact role statement types", func(t *testing.T) {
		r := ac.NewRole(Statements{"project": {"create", "update"}, "ui": {"view"}})
		if authorize(t, r, jsonx.O("project", list("delete-many"))).Success {
			t.Fatal("expected failure")
		}
	})
	t.Run("should accept dynamic role records", func(t *testing.T) {
		r := ac.NewRole(Statements{"project": {"create"}, "ui": {"view"}})
		if !authorize(t, r, jsonx.O("project", []string{"create"})).Success {
			t.Fatal("expected success")
		}
	})
	t.Run("should validate permissions", func(t *testing.T) {
		if !authorize(t, role1, jsonx.O("project", list("create"))).Success || authorize(t, role1, jsonx.O("project", list("delete-many"))).Success {
			t.Fatal("unexpected result")
		}
	})
	t.Run("should validate multiple resource permissions", func(t *testing.T) {
		if !authorize(t, role1, jsonx.O("project", list("create"), "ui", list("view"))).Success ||
			authorize(t, role1, jsonx.O("project", list("delete-many"), "ui", list("view"))).Success {
			t.Fatal("unexpected result")
		}
	})
	t.Run("should validate multiple resource multiple permissions", func(t *testing.T) {
		if !authorize(t, role1, jsonx.O("project", list("create", "delete"), "ui", list("view", "edit"))).Success ||
			authorize(t, role1, jsonx.O("project", list("create", "delete-many"), "ui", list("view", "edit"))).Success {
			t.Fatal("unexpected result")
		}
	})
	t.Run("should validate using or connector", func(t *testing.T) {
		if !authorize(t, role1, jsonx.O("project", list("create", "delete-many"), "ui", list("view", "edit")), OR).Success {
			t.Fatal("expected success")
		}
	})
	t.Run("should validate using or connector for a specific resource", func(t *testing.T) {
		orProject := jsonx.O("connector", "OR", "actions", list("create", "delete-many"))
		if !authorize(t, role1, jsonx.O("project", orProject, "ui", list("view", "edit"))).Success {
			t.Fatal("expected success")
		}
		if authorize(t, role1, jsonx.O("project", orProject, "ui", list("view", "edit", "hide"))).Success {
			t.Fatal("expected failure")
		}
	})
	t.Run("should fail when a resource is requested with an empty action list (array form)", func(t *testing.T) {
		if authorize(t, role1, jsonx.O("project", list())).Success || authorize(t, role1, jsonx.O("project", list()), OR).Success {
			t.Fatal("expected failure")
		}
	})
	t.Run("should fail when a resource is requested with an empty action list (object form)", func(t *testing.T) {
		if authorize(t, role1, jsonx.O("project", jsonx.O("actions", list(), "connector", "AND"))).Success ||
			authorize(t, role1, jsonx.O("project", map[string]any{"actions": list(), "connector": "OR"})).Success {
			t.Fatal("expected failure")
		}
	})
	t.Run("should fail when every requested resource is empty under OR across multiple resources", func(t *testing.T) {
		if authorize(t, role1, jsonx.O("project", list(), "ui", list()), OR).Success {
			t.Fatal("expected failure")
		}
	})
	t.Run("should continue evaluating remaining resources under OR when an earlier resource is unknown to the role", func(t *testing.T) {
		if !authorize(t, looseRole, jsonx.O("audit", list("read"), "project", list("create")), OR).Success {
			t.Fatal("expected success")
		}
	})
	t.Run("should still fail under OR when no resource matches, including unknown ones", func(t *testing.T) {
		if authorize(t, looseRole, jsonx.O("audit", list("read"), "project", list("delete-many")), OR).Success {
			t.Fatal("expected failure")
		}
	})
	t.Run("should fail under AND when a resource is unknown to the role", func(t *testing.T) {
		res := authorize(t, looseRole, jsonx.O("audit", list("read"), "project", list("create")))
		if res.Success || res.Error != "You are not allowed to access resource: audit" {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("should preserve unauthorized error formats for unknown and denied resources", func(t *testing.T) {
		if got := authorize(t, looseRole, jsonx.O("audit", list("read"))); got != (AuthorizeResponse{Error: "You are not allowed to access resource: audit"}) {
			t.Fatalf("%+v", got)
		}
		if got := authorize(t, looseRole, jsonx.O("project", list("delete-many"))); got != (AuthorizeResponse{Error: `unauthorized to access resource "project"`}) {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("should preserve AND behavior for unknown action connectors", func(t *testing.T) {
		if authorize(t, role1, jsonx.O("project", jsonx.O("actions", list("create", "delete-many"), "connector", "XOR"))).Success {
			t.Fatal("expected failure")
		}
	})
	t.Run("should return an unauthorized response for non-string action values", func(t *testing.T) {
		if got := authorize(t, role1, jsonx.O("project", list("create", 1.0))); got != (AuthorizeResponse{Error: `unauthorized to access resource "project"`}) {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("rejects a malformed request value", func(t *testing.T) {
		if _, err := role1.Authorize(jsonx.O("project", "create"), AND); err != ErrInvalidRequest {
			t.Fatalf("got %v", err)
		}
	})
}
