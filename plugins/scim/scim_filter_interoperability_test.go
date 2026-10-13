package scim

// Port of upstream scim-filter-interoperability.test.ts ("SCIM provider filter interoperability").

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
)

type fiFixture struct {
	e                                 *testEnv
	ada, grace                        map[string]any
	platformGroup, partnerPlatformGrp map[string]any
	quotedGroup                       map[string]any
	quotedGroupName                   string
}

func fiNewFixture(t *testing.T) *fiFixture {
	t.Helper()
	e := newEnv(t, Options{Connections: []ConnectionOptions{
		staticConnection("workforce", "test-scim-token"),
		staticConnection("partner-workforce", "partner-scim-token"),
	}})
	headers := bearer("test-scim-token")
	partner := bearer("partner-scim-token")
	f := &fiFixture{e: e, quotedGroupName: `Research and Development - "Admins"`}
	f.ada = e.mustCall("createSCIMUser", betterauth.CallInput{Headers: headers, Body: map[string]any{
		"schemas":    []any{SchemaUser},
		"userName":   "ada.login@example.com",
		"externalId": "entra-ada",
		"emails": []any{
			map[string]any{"value": "ada.home@example.com", "type": "home", "primary": true},
			map[string]any{"value": "ada.work@example.com", "type": "other"},
			map[string]any{"value": "ada.alias@example.com", "type": "work"},
		},
	}})
	f.grace = e.mustCall("createSCIMUser", betterauth.CallInput{Headers: headers, Body: map[string]any{
		"schemas":    []any{SchemaUser},
		"userName":   "grace.login@example.com",
		"externalId": "entra-grace",
		"emails":     []any{map[string]any{"value": "grace.work@example.com", "type": "work", "primary": true}},
	}})
	f.platformGroup = e.mustCall("createSCIMGroup", betterauth.CallInput{Headers: headers, Body: map[string]any{
		"schemas": []any{SchemaGroup}, "displayName": "MyPlatform BA SCIM - Admins",
	}})
	f.partnerPlatformGrp = e.mustCall("createSCIMGroup", betterauth.CallInput{Headers: partner, Body: map[string]any{
		"schemas": []any{SchemaGroup}, "displayName": "MyPlatform BA SCIM - Admins",
	}})
	f.quotedGroup = e.mustCall("createSCIMGroup", betterauth.CallInput{Headers: headers, Body: map[string]any{
		"schemas": []any{SchemaGroup}, "externalId": "research-and-development-admins", "displayName": f.quotedGroupName,
	}})
	return f
}

type fiResult struct {
	Status int
	Body   map[string]any
}

func (f *fiFixture) list(path, filter, token string) fiResult {
	f.e.t.Helper()
	res := f.e.request("GET", path+"?"+url.Values{"filter": {filter}}.Encode(), nil, map[string]string{
		"Accept": MediaType, "Authorization": "Bearer " + token,
	})
	return fiResult{Status: res.Status, Body: res.json()}
}

func (f *fiFixture) listUsers(filter string) fiResult {
	return f.list(scimUsersURL, filter, "test-scim-token")
}

func (f *fiFixture) listGroups(filter string, token ...string) fiResult {
	tok := "test-scim-token"
	if len(token) > 0 {
		tok = token[0]
	}
	return f.list(scimGroupsURL, filter, tok)
}

func fiExpectIDs(t *testing.T, r fiResult, ids ...any) {
	t.Helper()
	if r.Status != 200 {
		t.Fatalf("status = %d body = %v", r.Status, r.Body)
	}
	resources := make([]any, len(ids))
	for i, id := range ids {
		resources[i] = map[string]any{"id": id}
	}
	rapMatchObject(t, r.Body, map[string]any{"totalResults": len(ids), "Resources": resources})
}

func fiContainsID(r fiResult, id any) bool {
	list, _ := r.Body["Resources"].([]any)
	for _, x := range list {
		if m, ok := x.(map[string]any); ok && m["id"] == id {
			return true
		}
	}
	return false
}

func TestFilterInteroperability(t *testing.T) {
	t.Run("evaluates every equality expression in a logical and filter", func(t *testing.T) {
		f := fiNewFixture(t)
		fiExpectIDs(t, f.listUsers(`userName eq "ada.login@example.com" and externalId eq "entra-ada"`), f.ada["id"])
		fiExpectIDs(t, f.listUsers(`userName eq "ada.login@example.com" and externalId eq "entra-grace"`))
	})

	t.Run("accepts a core-schema-qualified User attribute", func(t *testing.T) {
		f := fiNewFixture(t)
		fiExpectIDs(t, f.listUsers(`urn:ietf:params:scim:schemas:core:2.0:User:userName eq "grace.login@example.com"`), f.grace["id"])
	})

	t.Run(`accepts Entra emails[type eq "work"].value equality`, func(t *testing.T) {
		f := fiNewFixture(t)
		fiExpectIDs(t, f.listUsers(`emails[type eq "work"].value eq "ada.alias@example.com"`), f.ada["id"])
	})

	t.Run("filters quoted Group display names through the bearer-authenticated HTTP endpoint", func(t *testing.T) {
		f := fiNewFixture(t)
		filter := `displayName eq "MyPlatform BA SCIM - Admins"`
		quotedJSON, _ := json.Marshal(f.quotedGroupName)
		workforce := f.listGroups(filter)
		partner := f.listGroups(filter, "partner-scim-token")
		quoted := f.listGroups(`displayName eq ` + string(quotedJSON) + ` and externalId eq "research-and-development-admins"`)
		unsupported := f.listGroups(`displayName ne "MyPlatform BA SCIM - Admins"`)
		invalid := f.listGroups("displayName eq MyPlatform")

		fiExpectIDs(t, workforce, f.platformGroup["id"])
		fiExpectIDs(t, partner, f.partnerPlatformGrp["id"])
		if fiContainsID(workforce, f.partnerPlatformGrp["id"]) || fiContainsID(partner, f.platformGroup["id"]) {
			t.Fatal("groups leaked across connections")
		}
		if quoted.Status != 200 {
			t.Fatalf("quoted status = %d", quoted.Status)
		}
		rapMatchObject(t, quoted.Body, map[string]any{"totalResults": 1, "Resources": []any{
			map[string]any{"id": f.quotedGroup["id"], "displayName": f.quotedGroupName},
		}})
		for _, r := range []fiResult{unsupported, invalid} {
			if r.Status != 400 || r.Body["scimType"] != "invalidFilter" {
				t.Fatalf("got %d %v, want 400 invalidFilter", r.Status, r.Body)
			}
		}
	})
}
