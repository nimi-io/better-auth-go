package scim

// Port of upstream collection-query.test.ts.

import (
	"math"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const cqEnterpriseUserSchema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"

func cqParse(rt resourceType, q map[string]any) (collectionQuery, *queryError) {
	return parseCollectionQuery(rt, queryInputFrom(q))
}

func cqExpectFilters(t *testing.T, rt resourceType, filter string, want ...equalityFilter) {
	t.Helper()
	q, qerr := cqParse(rt, map[string]any{"filter": filter})
	if qerr != nil {
		t.Fatalf("unexpected error %+v", *qerr)
	}
	if !reflect.DeepEqual(q.filters, want) {
		t.Fatalf("filters = %+v, want %+v", q.filters, want)
	}
}

func cqExpectError(t *testing.T, qerr *queryError, code, parameter, scimType string) {
	t.Helper()
	if qerr == nil {
		t.Fatalf("expected error %s", code)
	}
	if qerr.code != code || qerr.parameter != parameter || (scimType != "" && qerr.scimType != scimType) {
		t.Fatalf("error = %+v, want code=%s parameter=%s scimType=%s", *qerr, code, parameter, scimType)
	}
}

func cqSet(m map[string]bool) []string {
	var out []string
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func cqExpectProjection(t *testing.T, p attributeProjection, mode string, attrs ...string) {
	t.Helper()
	if p.mode != mode {
		t.Fatalf("mode = %q, want %q", p.mode, mode)
	}
	sort.Strings(attrs)
	if got := cqSet(p.attributes); !reflect.DeepEqual(got, attrs) {
		t.Fatalf("attributes = %v, want %v", got, attrs)
	}
}

func TestCollectionQuery_ParseSCIMCollectionQuery(t *testing.T) {
	t.Run("defaults classic pagination to the first page capped at 100 resources", func(t *testing.T) {
		q, qerr := cqParse("User", map[string]any{})
		if qerr != nil {
			t.Fatal(qerr.detail)
		}
		if len(q.filters) != 0 {
			t.Fatalf("filters = %+v", q.filters)
		}
		if q.pagination != (classicPagination{startIndex: 1, offset: 0, count: 100}) {
			t.Fatalf("pagination = %+v", q.pagination)
		}
		if q.projection.mode != "default" || len(q.projection.attributes) != 0 {
			t.Fatalf("projection = %+v", q.projection)
		}
	})

	t.Run("keeps the filter attribute type specific to the resource", func(t *testing.T) {
		t.Skip("TS-only: expectTypeOf type-level assertions")
	})
}

func TestCollectionQuery_Pagination(t *testing.T) {
	t.Run("normalizes one-based indexes and bounds count to the server maximum", func(t *testing.T) {
		cases := []struct {
			startIndex, count any
			want              classicPagination
		}{
			{"0", "500", classicPagination{startIndex: 1, offset: 0, count: 100}},
			{"42", "25", classicPagination{startIndex: 42, offset: 41, count: 25}},
			{float64(-4), float64(-10), classicPagination{startIndex: 1, offset: 0, count: 0}},
		}
		for _, c := range cases {
			q, qerr := cqParse("User", map[string]any{"startIndex": c.startIndex, "count": c.count})
			if qerr != nil {
				t.Fatalf("%v/%v: %s", c.startIndex, c.count, qerr.detail)
			}
			if q.pagination != c.want {
				t.Fatalf("%v/%v: pagination = %+v, want %+v", c.startIndex, c.count, q.pagination, c.want)
			}
		}
	})

	for _, c := range []struct {
		parameter string
		value     any
		code      string
	}{
		{"startIndex", "1.5", "invalid-start-index"},
		{"startIndex", "next", "invalid-start-index"},
		{"count", math.Inf(1), "invalid-count"},
		{"count", "2e2", "invalid-count"},
	} {
		t.Run("returns a typed failure for invalid "+c.parameter+" values", func(t *testing.T) {
			_, qerr := cqParse("User", map[string]any{c.parameter: c.value})
			cqExpectError(t, qerr, c.code, c.parameter, "invalidValue")
		})
	}
}

func TestCollectionQuery_Filters(t *testing.T) {
	for _, c := range [][2]string{{"ID", "id"}, {"UsErNaMe", "userName"}, {"EXTERNALID", "externalId"}, {"Emails.Value", "emails.value"}} {
		t.Run("canonicalizes the User "+c[0]+" attribute", func(t *testing.T) {
			cqExpectFilters(t, "User", c[0]+` EQ "value"`, equalityFilter{attribute: c[1], value: "value"})
		})
	}
	for _, c := range [][2]string{{"ID", "id"}, {"DisplayName", "displayName"}, {"EXTERNALID", "externalId"}} {
		t.Run("canonicalizes the Group "+c[0]+" attribute", func(t *testing.T) {
			cqExpectFilters(t, "Group", c[0]+` eq "value"`, equalityFilter{attribute: c[1], value: "value"})
		})
	}

	t.Run("decodes quoted and escaped JSON string values", func(t *testing.T) {
		cqExpectFilters(t, "User", `UsErNaMe eq "Ada \"Lovelace\" \\ admin"`,
			equalityFilter{attribute: "userName", value: `Ada "Lovelace" \ admin`})
	})

	for _, c := range [][2]string{
		{`displayName eq "MyPlatform BA SCIM - Admins"`, "MyPlatform BA SCIM - Admins"},
		{`displayName eq "Research and Development"`, "Research and Development"},
		{`displayName eq "Platform - \"Admins\""`, `Platform - "Admins"`},
	} {
		t.Run("finds the top-level equality operator in "+c[0], func(t *testing.T) {
			cqExpectFilters(t, "Group", c[0], equalityFilter{attribute: "displayName", value: c[1]})
		})
	}

	t.Run("preserves top-level conjunctions when a quoted value contains and", func(t *testing.T) {
		cqExpectFilters(t, "Group", `displayName eq "Research and Development" and externalId eq "research-and-development"`,
			equalityFilter{attribute: "displayName", value: "Research and Development"},
			equalityFilter{attribute: "externalId", value: "research-and-development"})
	})

	for _, c := range [][3]string{
		{"Group", `userName eq "ada"`, "unsupported-filter-attribute"},
		{"User", `user Name eq "ada"`, "unsupported-filter-operator"},
		{"User", `userName ne "ada"`, "unsupported-filter-operator"},
		{"Group", `displayName ne "MyPlatform BA SCIM - Admins"`, "unsupported-filter-operator"},
		{"User", "userName pr", "invalid-filter-syntax"},
		{"User", "userName eq ada", "invalid-filter-value"},
		{"User", `userName eq "ada" trailing`, "invalid-filter-value"},
		{"User", "userName eq 7", "invalid-filter-value"},
		{"Group", `displayName eq "one" ne "two"`, "invalid-filter-value"},
	} {
		t.Run("returns "+c[0]+" filter failures without throwing/"+c[1], func(t *testing.T) {
			_, qerr := cqParse(resourceType(c[0]), map[string]any{"filter": c[1]})
			cqExpectError(t, qerr, c[2], "filter", "invalidFilter")
		})
	}

	for _, c := range [][2]string{
		{"Group", `displayName eq "unterminated`},
		{"Group", `displayName] eq "Admins"`},
		{"User", `emails[type eq "work".value eq "ada@example.com"`},
	} {
		t.Run("returns invalid filter syntax for malformed "+c[0]+" quote or bracket state", func(t *testing.T) {
			_, qerr := cqParse(resourceType(c[0]), map[string]any{"filter": c[1]})
			cqExpectError(t, qerr, "invalid-filter-syntax", "filter", "invalidFilter")
		})
	}

	t.Run("allows SCIM whitespace around the supported work-email value path", func(t *testing.T) {
		cqExpectFilters(t, "User", `emails[ type eq "work" ].value eq "ada@example.com"`,
			equalityFilter{attribute: "emails.work.value", value: "ada@example.com"})
	})
}

func TestCollectionQuery_ParseSCIMAttributeProjection(t *testing.T) {
	t.Run("normalizes and de-duplicates included attribute paths", func(t *testing.T) {
		p, qerr := parseAttributeProjection("User", []any{"userName, Name.GivenName", "USERNAME"}, undef)
		if qerr != nil {
			t.Fatal(qerr.detail)
		}
		cqExpectProjection(t, p, "include", "username", "name.givenname")
	})

	t.Run("normalizes excluded attribute paths", func(t *testing.T) {
		p, qerr := parseAttributeProjection("Group", undef, "Members, Meta.Version")
		if qerr != nil {
			t.Fatal(qerr.detail)
		}
		cqExpectProjection(t, p, "exclude", "members", "meta.version")
	})

	t.Run("resolves qualified Enterprise User paths by their longest schema URI", func(t *testing.T) {
		p, qerr := parseAttributeProjection("User", []any{
			cqEnterpriseUserSchema,
			strings.ToUpper(cqEnterpriseUserSchema) + ":department",
			cqEnterpriseUserSchema + ":manager.value",
		}, undef)
		if qerr != nil {
			t.Fatal(qerr.detail)
		}
		lower := strings.ToLower(cqEnterpriseUserSchema)
		cqExpectProjection(t, p, "include", lower, lower+".department", lower+".manager.value")
	})

	t.Run("rejects simultaneous attributes and excludedAttributes", func(t *testing.T) {
		_, qerr := parseAttributeProjection("User", "userName", "emails")
		cqExpectError(t, qerr, "conflicting-attribute-projection", "attributes", "invalidValue")
	})

	t.Run("rejects malformed attribute lists", func(t *testing.T) {
		_, qerr := parseAttributeProjection("User", "userName,,emails", undef)
		cqExpectError(t, qerr, "invalid-attribute-list", "attributes", "")
	})
}
