package scim

// Port of upstream scim-http-contract.test.ts.

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
)

const (
	httpContractErrorSchema            = "urn:ietf:params:scim:api:messages:2.0:Error"
	httpContractUserSchema             = "urn:ietf:params:scim:schemas:core:2.0:User"
	httpContractGroupSchema            = "urn:ietf:params:scim:schemas:core:2.0:Group"
	httpContractPatchSchema            = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	httpContractListSchema             = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	httpContractEnterpriseUserSchema   = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	httpContractEntraLegacyGroupSchema = "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group"
	httpContractMicrosoftGraphGroupURN = "urn:ietf:params:scim:schemas:extension:Microsoft:Entra:2.0:Group"
	httpContractToken                  = "active-scim-token"
	httpContractUnsupportedUserSchema  = "urn:example:params:scim:schemas:extension:2.0:User"
	httpContractUnsupportedGroupSchema = "urn:example:params:scim:schemas:extension:2.0:Group"
	httpContractSchemasURL             = "/api/auth/scim/v2/Schemas"
)

// httpContractAuth is createSCIMAuth(credentials, compatibility).
func httpContractAuth(t *testing.T, creds []BearerCredential, compat *CompatibilityOptions) *testEnv {
	t.Helper()
	if creds == nil {
		creds = []BearerCredential{{Type: "bearer", ID: httpContractToken, Token: httpContractToken}}
	}
	return newEnv(t, Options{
		Connections:   []ConnectionOptions{{ID: "workforce", Credentials: creds}},
		Compatibility: compat,
	})
}

func httpContractHeaders() map[string]string {
	return map[string]string{
		"Accept":        MediaType,
		"Authorization": "Bearer " + httpContractToken,
		"Content-Type":  MediaType,
	}
}

// httpContractCreateUser is createUserRequest(body, contentType, includeSchema).
func httpContractCreateUser(e *testEnv, body map[string]any, contentType string, includeSchema bool) *response {
	e.t.Helper()
	if contentType == "" {
		contentType = MediaType
	}
	b := map[string]any{}
	for k, v := range body {
		b[k] = v
	}
	if includeSchema {
		b["schemas"] = []any{httpContractUserSchema}
	}
	h := httpContractHeaders()
	h["Content-Type"] = contentType
	return e.request("POST", scimUsersURL, b, h)
}

// httpContractExpectError is expectSCIMError.
func httpContractExpectError(t *testing.T, res *response, status int, scimType string) map[string]any {
	t.Helper()
	if res.Status != status {
		t.Fatalf("status = %d, want %d (%s)", res.Status, status, res.text())
	}
	if ct := res.Header.Get("Content-Type"); ct != MediaType {
		t.Fatalf("content-type = %q, want %q", ct, MediaType)
	}
	body := res.json()
	want := map[string]any{"schemas": []any{httpContractErrorSchema}, "status": fmt.Sprint(status)}
	if scimType != "" {
		want["scimType"] = scimType
	}
	httpContractMustMatch(t, body, want)
	if _, ok := body["code"]; ok {
		t.Fatalf("error body has a code property: %s", res.text())
	}
	return body
}

// httpContractMatch mirrors toMatchObject on decoded JSON: objects are matched as
// subsets, arrays element-wise with equal length. A func(any) bool in want is an
// asymmetric matcher (expect.any / expect.stringMatching ...). Returns "" on success.
func httpContractMatch(got, want any, path string) string {
	switch w := want.(type) {
	case func(any) bool:
		if !w(got) {
			return fmt.Sprintf("%s: matcher rejected %#v", path, got)
		}
		return ""
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return fmt.Sprintf("%s: want object, got %#v", path, got)
		}
		for k, wv := range w {
			gv, present := g[k]
			if !present {
				return fmt.Sprintf("%s.%s: missing", path, k)
			}
			if m := httpContractMatch(gv, wv, path+"."+k); m != "" {
				return m
			}
		}
		return ""
	case []string:
		arr := make([]any, len(w))
		for i, s := range w {
			arr[i] = s
		}
		return httpContractMatch(got, arr, path)
	case []any:
		g, ok := got.([]any)
		if !ok {
			return fmt.Sprintf("%s: want array, got %#v", path, got)
		}
		if len(g) != len(w) {
			return fmt.Sprintf("%s: length %d, want %d (%#v)", path, len(g), len(w), got)
		}
		for i := range w {
			if m := httpContractMatch(g[i], w[i], fmt.Sprintf("%s[%d]", path, i)); m != "" {
				return m
			}
		}
		return ""
	case int:
		if f, ok := httpContractNumber(got); !ok || f != float64(w) {
			return fmt.Sprintf("%s: got %#v, want %d", path, got, w)
		}
		return ""
	case nil:
		if got != nil {
			return fmt.Sprintf("%s: got %#v, want null", path, got)
		}
		return ""
	}
	if !reflect.DeepEqual(got, want) {
		return fmt.Sprintf("%s: got %#v, want %#v", path, got, want)
	}
	return ""
}

func httpContractNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func httpContractMustMatch(t *testing.T, got, want any) {
	t.Helper()
	if m := httpContractMatch(got, want, "$"); m != "" {
		t.Fatalf("toMatchObject failed: %s\ngot: %s", m, httpContractJSON(got))
	}
}

func httpContractJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// httpContractDecode decodes any JSON-encodable value into generic JSON values.
func httpContractDecode(t *testing.T, v any) any {
	t.Helper()
	var out any
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestHTTPContract(t *testing.T) {
	t.Run("returns the created User using the SCIM creation response contract", func(t *testing.T) {
		e := httpContractAuth(t, nil, nil)
		res := httpContractCreateUser(e, map[string]any{"userName": "ada@example.com"}, "", true)
		if res.Status != 201 {
			t.Fatalf("status = %d: %s", res.Status, res.text())
		}
		if ct := res.Header.Get("Content-Type"); ct != MediaType {
			t.Fatalf("content-type = %q", ct)
		}
		body := res.json()
		loc, _ := body["meta"].(map[string]any)["location"].(string)
		if loc == "" || res.Header.Get("Location") != loc || res.Header.Get("Content-Location") != loc {
			t.Fatalf("location = %q, content-location = %q, meta.location = %q",
				res.Header.Get("Location"), res.Header.Get("Content-Location"), loc)
		}
	})

	t.Run("returns a SCIM uniqueness error for a duplicate User", func(t *testing.T) {
		e := httpContractAuth(t, nil, nil)
		httpContractCreateUser(e, map[string]any{"userName": "ada@example.com"}, "", true)
		dup := httpContractCreateUser(e, map[string]any{"userName": "ada@example.com"}, "", true)
		httpContractExpectError(t, dup, 409, "uniqueness")
	})

	t.Run("returns invalidValue for a constrained User attribute", func(t *testing.T) {
		e := httpContractAuth(t, nil, nil)
		res := httpContractCreateUser(e, map[string]any{"userName": ""}, "", true)
		httpContractExpectError(t, res, 400, "invalidValue")
	})

	t.Run("rejects case-insensitive duplicate email types over HTTP POST", func(t *testing.T) {
		e := httpContractAuth(t, nil, nil)
		res := httpContractCreateUser(e, map[string]any{
			"userName": "duplicate-types@example.com",
			"emails": []any{
				map[string]any{"value": "first@example.com", "type": "Work", "primary": true},
				map[string]any{"value": "second@example.com", "type": "work"},
			},
		}, "", true)
		httpContractExpectError(t, res, 400, "invalidValue")
	})

	t.Run("rejects case-insensitive duplicate complex types over HTTP PUT without replacing the User", func(t *testing.T) {
		e := httpContractAuth(t, nil, nil)
		createRes := httpContractCreateUser(e, map[string]any{
			"userName":    "replace-types@example.com",
			"displayName": "Original User",
		}, "", true)
		id, _ := createRes.json()["id"].(string)
		resourceURL := scimUsersURL + "/" + url.PathEscape(id)
		headers := httpContractHeaders()
		before := e.request("GET", resourceURL, nil, headers).json()

		res := e.request("PUT", resourceURL, map[string]any{
			"schemas":     []any{httpContractUserSchema},
			"userName":    "replace-types@example.com",
			"displayName": "Rejected Replacement",
			"phoneNumbers": []any{
				map[string]any{"value": "+1-555-0100", "type": "Work"},
				map[string]any{"value": "+1-555-0101", "type": "work"},
			},
		}, headers)
		httpContractExpectError(t, res, 400, "invalidValue")
		after := e.request("GET", resourceURL, nil, headers).json()
		if !reflect.DeepEqual(after, before) {
			t.Fatalf("user changed:\nbefore %s\nafter  %s", httpContractJSON(before), httpContractJSON(after))
		}
	})

	t.Run("returns invalidSyntax for malformed JSON before endpoint dispatch", func(t *testing.T) {
		e := httpContractAuth(t, nil, nil)
		res := e.request("POST", scimUsersURL, `{"schemas":`, httpContractHeaders())
		httpContractExpectError(t, res, 400, "invalidSyntax")
	})

	t.Run("rejects a User resource without its core schema", func(t *testing.T) {
		e := httpContractAuth(t, nil, nil)
		res := httpContractCreateUser(e, map[string]any{"userName": "missing-schema@example.com"}, "", false)
		httpContractExpectError(t, res, 400, "invalidValue")
	})

	t.Run("accepts the standard Enterprise User extension schema", func(t *testing.T) {
		e := httpContractAuth(t, nil, nil)
		res := e.request("POST", scimUsersURL, map[string]any{
			"schemas":                        []any{httpContractUserSchema, httpContractEnterpriseUserSchema},
			"userName":                       "enterprise@example.com",
			httpContractEnterpriseUserSchema: map[string]any{"employeeNumber": "42"},
		}, httpContractHeaders())
		if res.Status != 201 {
			t.Fatalf("status = %d: %s", res.Status, res.text())
		}
		httpContractMustMatch(t, res.json(), map[string]any{
			"schemas":                        []any{httpContractUserSchema, httpContractEnterpriseUserSchema},
			httpContractEnterpriseUserSchema: map[string]any{"employeeNumber": "42"},
		})
	})

	t.Run("rejects unknown User schema URIs", func(t *testing.T) {
		e := httpContractAuth(t, nil, nil)
		res := e.request("POST", scimUsersURL, map[string]any{
			"schemas":                         []any{httpContractUserSchema, httpContractUnsupportedUserSchema},
			"userName":                        "unsupported@example.com",
			httpContractUnsupportedUserSchema: map[string]any{"employeeNumber": "42"},
		}, httpContractHeaders())
		httpContractExpectError(t, res, 400, "invalidValue")
	})

	t.Run("rejects Enterprise User data without its schema URI", func(t *testing.T) {
		e := httpContractAuth(t, nil, nil)
		res := e.request("POST", scimUsersURL, map[string]any{
			"schemas":                        []any{httpContractUserSchema},
			"userName":                       "undeclared-enterprise@example.com",
			httpContractEnterpriseUserSchema: map[string]any{"employeeNumber": "42"},
		}, httpContractHeaders())
		httpContractExpectError(t, res, 400, "invalidValue")
	})

	t.Run("rejects duplicate User schema URNs", func(t *testing.T) {
		e := httpContractAuth(t, nil, nil)
		res := e.request("POST", scimUsersURL, map[string]any{
			"schemas":  []any{httpContractUserSchema, httpContractUserSchema},
			"userName": "duplicate-schema@example.com",
		}, httpContractHeaders())
		httpContractExpectError(t, res, 400, "invalidValue")
	})

	t.Run("rejects an unsupported Group extension schema", func(t *testing.T) {
		e := httpContractAuth(t, nil, nil)
		res := e.request("POST", scimGroupsURL, map[string]any{
			"schemas":                          []any{httpContractGroupSchema, httpContractUnsupportedGroupSchema},
			"displayName":                      "Engineering",
			httpContractUnsupportedGroupSchema: map[string]any{"code": "engineering"},
		}, httpContractHeaders())
		httpContractExpectError(t, res, 400, "invalidValue")
	})

	t.Run("accepts the exact classic Entra Group marker only on enabled POST ingress", func(t *testing.T) {
		e := httpContractAuth(t, nil, &CompatibilityOptions{
			MicrosoftEntra: &MicrosoftEntraCompatibilityOptions{AcceptLegacyGroupSchema: true},
		})
		headers := httpContractHeaders()
		createRes := e.request("POST", scimGroupsURL, map[string]any{
			"schemas":     []any{httpContractGroupSchema, httpContractEntraLegacyGroupSchema},
			"externalId":  "73f7f508-4e50-4b7f-ba50-0cdbf0638d95",
			"displayName": "Marketing",
			"members":     []any{},
			"meta":        map[string]any{"resourceType": "Group"},
		}, headers)
		if createRes.Status != 201 {
			t.Fatalf("status = %d: %s", createRes.Status, createRes.text())
		}
		created := createRes.json()
		if !reflect.DeepEqual(created["schemas"], []any{httpContractGroupSchema}) {
			t.Fatalf("schemas = %v", created["schemas"])
		}
		locRe := regexp.MustCompile(`/scim/v2/Groups/[^/]+$`)
		httpContractMustMatch(t, created["meta"], map[string]any{
			"resourceType": "Group",
			"location": func(v any) bool {
				s, ok := v.(string)
				return ok && locRe.MatchString(s)
			},
		})
		if _, ok := created[httpContractEntraLegacyGroupSchema]; ok {
			t.Fatal("created group has the legacy schema property")
		}
		if strings.Contains(createRes.text(), httpContractEntraLegacyGroupSchema) {
			t.Fatalf("created group mentions the legacy schema: %s", createRes.text())
		}
		id, ok := created["id"].(string)
		if !ok {
			t.Fatal("Expected the classic Entra Group to have an id")
		}
		groupURL := scimGroupsURL + "/" + url.PathEscape(id)

		getRes := e.request("GET", groupURL, nil, headers)
		if getRes.Status != 200 || strings.Contains(getRes.text(), httpContractEntraLegacyGroupSchema) {
			t.Fatalf("get: %d %s", getRes.Status, getRes.text())
		}
		schemasRes := e.request("GET", httpContractSchemasURL, nil, headers)
		if schemasRes.Status != 200 || strings.Contains(schemasRes.text(), httpContractEntraLegacyGroupSchema) {
			t.Fatalf("schemas: %d", schemasRes.Status)
		}

		replaceRes := e.request("PUT", groupURL, map[string]any{
			"schemas":     []any{httpContractGroupSchema, httpContractEntraLegacyGroupSchema},
			"displayName": "Marketing",
		}, headers)
		httpContractExpectError(t, replaceRes, 400, "invalidValue")

		patchRes := e.request("PATCH", groupURL, map[string]any{
			"schemas": []any{httpContractPatchSchema, httpContractEntraLegacyGroupSchema},
			"Operations": []any{map[string]any{
				"op": "Replace", "path": "displayName", "value": "Marketing leaders",
			}},
		}, headers)
		httpContractExpectError(t, patchRes, 400, "invalidValue")

		attributedReplaceRes := e.request("PUT", groupURL, map[string]any{
			"schemas":                          []any{httpContractGroupSchema},
			"displayName":                      "Marketing",
			httpContractEntraLegacyGroupSchema: map[string]any{},
		}, headers)
		httpContractExpectError(t, attributedReplaceRes, 400, "invalidValue")

		attributedPatchRes := e.request("PATCH", groupURL, map[string]any{
			"schemas": []any{httpContractPatchSchema},
			"Operations": []any{map[string]any{
				"op": "Replace", "path": "displayName", "value": "Marketing leaders",
			}},
			httpContractEntraLegacyGroupSchema: map[string]any{},
		}, headers)
		httpContractExpectError(t, attributedPatchRes, 400, "invalidValue")
	})

	t.Run("rejects disabled, attributed, duplicate, unknown, and Graph Group schema markers", func(t *testing.T) {
		disabled := httpContractAuth(t, nil, nil)
		enabled := httpContractAuth(t, nil, &CompatibilityOptions{
			MicrosoftEntra: &MicrosoftEntraCompatibilityOptions{AcceptLegacyGroupSchema: true},
		})
		create := func(e *testEnv, body map[string]any) *response {
			return e.request("POST", scimGroupsURL, body, httpContractHeaders())
		}
		httpContractExpectError(t, create(disabled, map[string]any{
			"schemas":     []any{httpContractGroupSchema, httpContractEntraLegacyGroupSchema},
			"displayName": "Disabled compatibility",
		}), 400, "invalidValue")
		httpContractExpectError(t, create(enabled, map[string]any{
			"schemas":                          []any{httpContractGroupSchema, httpContractEntraLegacyGroupSchema},
			"displayName":                      "Attributed marker",
			httpContractEntraLegacyGroupSchema: map[string]any{"department": "Marketing"},
		}), 400, "invalidValue")
		httpContractExpectError(t, create(enabled, map[string]any{
			"schemas": []any{httpContractGroupSchema, httpContractEntraLegacyGroupSchema,
				httpContractEntraLegacyGroupSchema},
			"displayName": "Duplicate marker",
		}), 400, "invalidValue")
		httpContractExpectError(t, create(enabled, map[string]any{
			"schemas":     []any{httpContractGroupSchema, httpContractUnsupportedGroupSchema},
			"displayName": "Unknown extension",
		}), 400, "invalidValue")
		httpContractExpectError(t, create(enabled, map[string]any{
			"schemas":     []any{httpContractGroupSchema, httpContractMicrosoftGraphGroupURN},
			"displayName": "Graph extension",
		}), 400, "invalidValue")
	})

	t.Run("rejects the User-only Enterprise schema on a Group resource", func(t *testing.T) {
		e := httpContractAuth(t, nil, nil)
		res := e.request("POST", scimGroupsURL, map[string]any{
			"schemas":                        []any{httpContractGroupSchema, httpContractEnterpriseUserSchema},
			"displayName":                    "Engineering",
			httpContractEnterpriseUserSchema: map[string]any{"department": "Engineering"},
		}, httpContractHeaders())
		httpContractExpectError(t, res, 400, "invalidValue")
	})

	t.Run("returns noTarget for a pathless Group remove", func(t *testing.T) {
		e := httpContractAuth(t, nil, nil)
		group := e.mustCall("createSCIMGroup", betterauth.CallInput{
			Body: map[string]any{
				"schemas":     []any{httpContractGroupSchema},
				"displayName": "Engineering",
			},
			Headers: bearer(httpContractToken),
		})
		id, _ := group["id"].(string)
		res := e.request("PATCH", scimGroupsURL+"/"+url.PathEscape(id), map[string]any{
			"schemas":    []any{httpContractPatchSchema},
			"Operations": []any{map[string]any{"op": "remove"}},
		}, map[string]string{
			"Authorization": "Bearer " + httpContractToken,
			"Content-Type":  MediaType,
		})
		httpContractExpectError(t, res, 400, "noTarget")
	})

	t.Run("returns a SCIM error for an unsupported request media type", func(t *testing.T) {
		e := httpContractAuth(t, nil, nil)
		res := httpContractCreateUser(e, map[string]any{"userName": "ada@example.com"}, "text/plain", true)
		httpContractExpectError(t, res, 415, "")
	})

	for _, tc := range []struct{ kind, authorization string }{
		{"missing", ""},
		{"expired", "Bearer expired-scim-token"},
	} {
		t.Run("returns a challenged SCIM error for "+tc.kind+" authentication", func(t *testing.T) {
			past := time.Now().Add(-60 * time.Second)
			e := httpContractAuth(t, []BearerCredential{
				{Type: "bearer", ID: httpContractToken, Token: httpContractToken},
				{Type: "bearer", ID: "expired-scim-token", Token: "expired-scim-token", ExpiresAt: &past},
			}, nil)
			headers := map[string]string{"Accept": MediaType}
			if tc.authorization != "" {
				headers["Authorization"] = tc.authorization
			}
			res := e.request("GET", scimUsersURL, nil, headers)
			httpContractExpectError(t, res, 401, "")
			if got := res.Header.Get("WWW-Authenticate"); got != `Bearer realm="SCIM"` {
				t.Fatalf("www-authenticate = %q", got)
			}
		})
	}
}
