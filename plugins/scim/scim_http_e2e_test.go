package scim

// Port of upstream scim-http-e2e.test.ts, including runSCIMLifecycle from
// packages/test-utils/src/scim-lifecycle.ts.

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
)

// httpE2EResponse is a fetch() Response.
type httpE2EResponse struct {
	status int
	header http.Header
	body   []byte
}

func (r *httpE2EResponse) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.body, &m); err != nil {
		t.Fatalf("decode %q: %v", string(r.body), err)
	}
	return m
}

// httpE2ELifecycleOptions is SCIMLifecycleOptions.
type httpE2ELifecycleOptions struct {
	baseURL           string
	token             string
	testID            string
	projectionFailure *struct{ enable, disable func() }
	onCheckpoint      func(checkpoint string)
}

// httpE2ELifecycleResult is SCIMLifecycleResult.
type httpE2ELifecycleResult struct {
	userID, groupID, reprovisionedUserID, userLocation, groupLocation string
}

func httpE2EFetch(t *testing.T, client *http.Client, method, u string, headers map[string]string, body any) *httpE2EResponse {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return &httpE2EResponse{status: res.StatusCode, header: res.Header, body: b}
}

func httpE2EExpectResponse(t *testing.T, res *httpE2EResponse, status int) {
	t.Helper()
	if res.status != status {
		t.Fatalf("status = %d, want %d: %s", res.status, status, string(res.body))
	}
	if status == 204 {
		return
	}
	if ct := strings.SplitN(res.header.Get("Content-Type"), ";", 2)[0]; ct != MediaType {
		t.Fatalf("content-type = %q", ct)
	}
}

func httpE2EExpectError(t *testing.T, res *httpE2EResponse, status int) map[string]any {
	t.Helper()
	httpE2EExpectResponse(t, res, status)
	body := res.json(t)
	httpContractMustMatch(t, body, map[string]any{
		"schemas": []any{httpContractErrorSchema},
		"status":  httpE2EItoa(status),
	})
	return body
}

func httpE2EItoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func httpE2EExpectNoContent(t *testing.T, res *httpE2EResponse) {
	t.Helper()
	httpE2EExpectResponse(t, res, 204)
	if len(res.body) != 0 {
		t.Fatalf("body = %q, want empty", string(res.body))
	}
}

func httpE2EMembers(t *testing.T, res *httpE2EResponse) any {
	t.Helper()
	m := res.json(t)
	return m["members"]
}

func httpE2EExpectMembers(t *testing.T, got any, want []any) {
	t.Helper()
	if want == nil {
		want = []any{}
	}
	httpContractMustMatch(t, got, want)
}

// httpE2ERunLifecycle is runSCIMLifecycle.
func httpE2ERunLifecycle(t *testing.T, client *http.Client, o httpE2ELifecycleOptions) httpE2ELifecycleResult {
	t.Helper()
	origin := strings.TrimSuffix(o.baseURL, "/")
	scimBaseURL := origin + "/api/auth/scim/v2"
	request := func(path, method string, body any) *httpE2EResponse {
		t.Helper()
		h := map[string]string{"Accept": MediaType, "Authorization": "Bearer " + o.token}
		if body != nil {
			h["Content-Type"] = MediaType
		}
		if method == "" {
			method = "GET"
		}
		return httpE2EFetch(t, client, method, scimBaseURL+path, h, body)
	}
	checkpoint := func(v string) {
		if o.onCheckpoint != nil {
			o.onCheckpoint(v)
		}
	}
	userFilterPath := func(userName string) string {
		q := url.Values{"filter": {`userName eq "` + userName + `"`}}
		return "/Users?" + q.Encode()
	}
	userName := o.testID + ".user@example.com"
	email := o.testID + ".primary@example.com"
	userExternalID := o.testID + "-directory-user"
	groupExternalID := o.testID + "-finance-admins"
	userCreateBody := map[string]any{
		"schemas":    []any{httpContractUserSchema},
		"externalId": userExternalID,
		"userName":   userName,
		"name": map[string]any{
			"formatted": "Ada Lovelace", "givenName": "Ada", "familyName": "Lovelace",
		},
		"displayName": "Ada Lovelace",
		"active":      true,
		"emails":      []any{map[string]any{"value": email, "type": "work", "primary": true}},
	}

	unauthorized := httpE2EFetch(t, client, "GET", scimBaseURL+"/Users", map[string]string{"Accept": MediaType}, nil)
	httpE2EExpectError(t, unauthorized, 401)
	if got := unauthorized.header.Get("WWW-Authenticate"); got != `Bearer realm="SCIM"` {
		t.Fatalf("www-authenticate = %q", got)
	}

	discoveryRes := httpE2EFetch(t, client, "GET", scimBaseURL+"/ServiceProviderConfig", map[string]string{"Accept": MediaType}, nil)
	httpE2EExpectResponse(t, discoveryRes, 200)
	httpContractMustMatch(t, discoveryRes.json(t), map[string]any{
		"patch":  map[string]any{"supported": true},
		"filter": map[string]any{"supported": true},
		"meta": map[string]any{
			"resourceType": "ServiceProviderConfig",
			"location":     scimBaseURL + "/ServiceProviderConfig",
		},
	})

	initialList := request(userFilterPath(userName), "", nil)
	httpE2EExpectResponse(t, initialList, 200)
	httpContractMustMatch(t, initialList.json(t), map[string]any{
		"schemas": []any{httpContractListSchema}, "totalResults": 0, "Resources": []any{},
	})

	createUserRes := request("/Users", "POST", userCreateBody)
	httpE2EExpectResponse(t, createUserRes, 201)
	createdUser := createUserRes.json(t)
	createdUserID, _ := createdUser["id"].(string)
	userPath := "/Users/" + url.PathEscape(createdUserID)
	userLocation := scimBaseURL + userPath
	httpContractMustMatch(t, createdUser, map[string]any{
		"schemas":     []any{httpContractUserSchema},
		"externalId":  userExternalID,
		"userName":    userName,
		"displayName": "Ada Lovelace",
		"active":      true,
		"meta":        map[string]any{"resourceType": "User", "location": userLocation},
	})
	if createUserRes.header.Get("Location") != userLocation || createUserRes.header.Get("Content-Location") != userLocation {
		t.Fatalf("location headers = %q / %q, want %q", createUserRes.header.Get("Location"),
			createUserRes.header.Get("Content-Location"), userLocation)
	}

	populatedList := request(userFilterPath(userName), "", nil)
	httpE2EExpectResponse(t, populatedList, 200)
	httpContractMustMatch(t, populatedList.json(t), map[string]any{
		"totalResults": 1, "itemsPerPage": 1, "Resources": []any{map[string]any{"id": createdUserID}},
	})

	replaceUserRes := request(userPath, "PUT", map[string]any{
		"schemas":    []any{httpContractUserSchema},
		"externalId": userExternalID,
		"userName":   userName,
		"name": map[string]any{
			"formatted": "Ada Byron", "givenName": "Ada", "familyName": "Byron",
		},
		"displayName": "Ada Byron",
		"active":      true,
		"emails":      []any{map[string]any{"value": email, "type": "work", "primary": true}},
	})
	httpE2EExpectResponse(t, replaceUserRes, 200)
	replacedWant := map[string]any{
		"id": createdUserID, "externalId": userExternalID, "displayName": "Ada Byron", "active": true,
	}
	httpContractMustMatch(t, replaceUserRes.json(t), replacedWant)
	replacedUserRes := request(userPath, "", nil)
	httpE2EExpectResponse(t, replacedUserRes, 200)
	replacedUser := replacedUserRes.json(t)
	httpContractMustMatch(t, replacedUser, replacedWant)

	unchangedPatch := request(userPath, "PATCH", map[string]any{
		"schemas":    []any{httpContractPatchSchema},
		"Operations": []any{map[string]any{"op": "Replace", "path": "displayName", "value": "Ada Byron"}},
	})
	httpE2EExpectResponse(t, unchangedPatch, 200)
	httpContractMustMatch(t, unchangedPatch.json(t), map[string]any{"id": createdUserID, "displayName": "Ada Byron"})
	unchangedUser := request(userPath, "", nil)
	httpE2EExpectResponse(t, unchangedUser, 200)
	if got := unchangedUser.json(t); httpContractJSON(got) != httpContractJSON(replacedUser) {
		t.Fatalf("unchanged user differs:\n%s\n%s", httpContractJSON(got), httpContractJSON(replacedUser))
	}

	createGroupRes := request("/Groups", "POST", map[string]any{
		"schemas":     []any{httpContractGroupSchema},
		"externalId":  groupExternalID,
		"displayName": "Finance administrators",
	})
	httpE2EExpectResponse(t, createGroupRes, 201)
	createdGroup := createGroupRes.json(t)
	createdGroupID, _ := createdGroup["id"].(string)
	groupPath := "/Groups/" + url.PathEscape(createdGroupID)
	groupLocation := scimBaseURL + groupPath
	httpContractMustMatch(t, createdGroup, map[string]any{
		"schemas":     []any{httpContractGroupSchema},
		"externalId":  groupExternalID,
		"displayName": "Finance administrators",
		"members":     []any{},
		"meta":        map[string]any{"resourceType": "Group", "location": groupLocation},
	})
	if createGroupRes.header.Get("Location") != groupLocation || createGroupRes.header.Get("Content-Location") != groupLocation {
		t.Fatalf("group location headers = %q / %q", createGroupRes.header.Get("Location"), createGroupRes.header.Get("Content-Location"))
	}
	checkpoint("group-created")

	addMember := func() *httpE2EResponse {
		return request(groupPath, "PATCH", map[string]any{
			"schemas": []any{httpContractPatchSchema},
			"Operations": []any{map[string]any{
				"op": "Add", "path": "members", "value": []any{map[string]any{"value": createdUserID}},
			}},
		})
	}
	memberValue := func(id string) map[string]any { return map[string]any{"value": id} }

	if o.projectionFailure != nil {
		o.projectionFailure.enable()
		failedAdd := addMember()
		o.projectionFailure.disable()
		body := httpE2EExpectError(t, failedAdd, 500)
		want := map[string]any{
			"schemas": []any{httpContractErrorSchema},
			"status":  "500",
			"detail":  "SCIM projection reconciliation failed",
		}
		if httpContractJSON(body) != httpContractJSON(want) {
			t.Fatalf("failed add body = %s", httpContractJSON(body))
		}
		after := request(groupPath, "", nil)
		httpE2EExpectResponse(t, after, 200)
		httpE2EExpectMembers(t, httpE2EMembers(t, after), nil)
		checkpoint("failed-add-rolled-back")
	}

	addMemberRes := addMember()
	httpE2EExpectResponse(t, addMemberRes, 200)
	httpE2EExpectMembers(t, httpE2EMembers(t, addMemberRes), []any{memberValue(createdUserID)})

	groupWithMember := request(groupPath, "", nil)
	httpE2EExpectResponse(t, groupWithMember, 200)
	httpE2EExpectMembers(t, httpE2EMembers(t, groupWithMember), []any{map[string]any{
		"value": createdUserID, "type": "User", "$ref": userLocation,
	}})
	checkpoint("member-added")

	oktaRemoval := request(groupPath, "PATCH", map[string]any{
		"schemas": []any{httpContractPatchSchema},
		"Operations": []any{map[string]any{
			"op": "Remove", "path": `members[value eq "` + createdUserID + `"]`,
		}},
	})
	httpE2EExpectResponse(t, oktaRemoval, 200)
	httpE2EExpectMembers(t, httpE2EMembers(t, oktaRemoval), nil)
	afterOkta := request(groupPath, "", nil)
	httpE2EExpectResponse(t, afterOkta, 200)
	httpE2EExpectMembers(t, httpE2EMembers(t, afterOkta), nil)
	checkpoint("okta-member-removed")

	secondAdd := addMember()
	httpE2EExpectResponse(t, secondAdd, 200)
	httpE2EExpectMembers(t, httpE2EMembers(t, secondAdd), []any{memberValue(createdUserID)})
	entraRemoval := request(groupPath, "PATCH", map[string]any{
		"schemas": []any{httpContractPatchSchema},
		"Operations": []any{map[string]any{
			"op": "Remove", "path": "members", "value": []any{map[string]any{"value": createdUserID}},
		}},
	})
	httpE2EExpectResponse(t, entraRemoval, 200)
	httpE2EExpectMembers(t, httpE2EMembers(t, entraRemoval), nil)
	afterEntra := request(groupPath, "", nil)
	httpE2EExpectResponse(t, afterEntra, 200)
	httpE2EExpectMembers(t, httpE2EMembers(t, afterEntra), nil)
	checkpoint("entra-member-removed")

	restore := addMember()
	httpE2EExpectResponse(t, restore, 200)
	restored := request(groupPath, "", nil)
	httpE2EExpectResponse(t, restored, 200)
	httpE2EExpectMembers(t, httpE2EMembers(t, restored), []any{map[string]any{"value": createdUserID, "$ref": userLocation}})
	checkpoint("member-restored")

	deactivate := request(userPath, "PATCH", map[string]any{
		"schemas":    []any{httpContractPatchSchema},
		"Operations": []any{map[string]any{"op": "Replace", "path": "active", "value": false}},
	})
	httpE2EExpectResponse(t, deactivate, 200)
	httpContractMustMatch(t, deactivate.json(t), map[string]any{"id": createdUserID, "active": false})
	inactive := request(userPath, "", nil)
	httpE2EExpectResponse(t, inactive, 200)
	httpContractMustMatch(t, inactive.json(t), map[string]any{"id": createdUserID, "active": false})
	groupWithInactive := request(groupPath, "", nil)
	httpE2EExpectResponse(t, groupWithInactive, 200)
	httpE2EExpectMembers(t, httpE2EMembers(t, groupWithInactive), []any{memberValue(createdUserID)})
	checkpoint("user-deactivated")

	reactivate := request(userPath, "PATCH", map[string]any{
		"schemas":    []any{httpContractPatchSchema},
		"Operations": []any{map[string]any{"op": "Replace", "path": "active", "value": true}},
	})
	httpE2EExpectResponse(t, reactivate, 200)
	httpContractMustMatch(t, reactivate.json(t), map[string]any{"id": createdUserID, "active": true})
	active := request(userPath, "", nil)
	httpE2EExpectResponse(t, active, 200)
	httpContractMustMatch(t, active.json(t), map[string]any{"id": createdUserID, "active": true})
	checkpoint("user-reactivated")

	httpE2EExpectNoContent(t, request(userPath, "DELETE", nil))
	httpE2EExpectError(t, request(userPath, "", nil), 404)
	afterUserDelete := request(groupPath, "", nil)
	httpE2EExpectResponse(t, afterUserDelete, 200)
	httpE2EExpectMembers(t, httpE2EMembers(t, afterUserDelete), nil)
	checkpoint("populated-user-deleted")
	emptyAfterDelete := request(userFilterPath(userName), "", nil)
	httpE2EExpectResponse(t, emptyAfterDelete, 200)
	httpContractMustMatch(t, emptyAfterDelete.json(t), map[string]any{"totalResults": 0, "Resources": []any{}})

	reprovisionRes := request("/Users", "POST", userCreateBody)
	httpE2EExpectResponse(t, reprovisionRes, 201)
	reprovisioned := reprovisionRes.json(t)
	httpContractMustMatch(t, reprovisioned, map[string]any{
		"externalId": userExternalID, "userName": userName, "active": true,
	})
	reprovisionedID, _ := reprovisioned["id"].(string)
	if reprovisionedID == createdUserID {
		t.Fatal("reprovisioned user reused the deleted id")
	}
	reprovisionedPath := "/Users/" + url.PathEscape(reprovisionedID)
	reprovisionedLocation := scimBaseURL + reprovisionedPath
	httpContractMustMatch(t, reprovisioned["meta"], map[string]any{"location": reprovisionedLocation})
	if reprovisionRes.header.Get("Location") != reprovisionedLocation {
		t.Fatalf("location = %q", reprovisionRes.header.Get("Location"))
	}
	checkpoint("user-reprovisioned")

	addReprovisioned := request(groupPath, "PATCH", map[string]any{
		"schemas": []any{httpContractPatchSchema},
		"Operations": []any{map[string]any{
			"op": "Add", "path": "members", "value": []any{map[string]any{"value": reprovisionedID}},
		}},
	})
	httpE2EExpectResponse(t, addReprovisioned, 200)
	groupWithReprovisioned := request(groupPath, "", nil)
	httpE2EExpectResponse(t, groupWithReprovisioned, 200)
	httpE2EExpectMembers(t, httpE2EMembers(t, groupWithReprovisioned), []any{map[string]any{
		"value": reprovisionedID, "$ref": reprovisionedLocation,
	}})
	checkpoint("reprovisioned-member-added")

	httpE2EExpectNoContent(t, request(groupPath, "DELETE", nil))
	httpE2EExpectError(t, request(groupPath, "", nil), 404)
	userAfterGroupDelete := request(reprovisionedPath, "", nil)
	httpE2EExpectResponse(t, userAfterGroupDelete, 200)
	httpContractMustMatch(t, userAfterGroupDelete.json(t), map[string]any{"id": reprovisionedID, "active": true})
	checkpoint("populated-group-deleted")

	httpE2EExpectNoContent(t, request(reprovisionedPath, "DELETE", nil))
	httpE2EExpectError(t, request(reprovisionedPath, "", nil), 404)
	emptyFinal := request(userFilterPath(userName), "", nil)
	httpE2EExpectResponse(t, emptyFinal, 200)
	httpContractMustMatch(t, emptyFinal.json(t), map[string]any{"totalResults": 0, "Resources": []any{}})
	checkpoint("lifecycle-complete")

	return httpE2ELifecycleResult{
		userID: createdUserID, groupID: createdGroupID, reprovisionedUserID: reprovisionedID,
		userLocation: userLocation, groupLocation: groupLocation,
	}
}

func TestHTTPE2E(t *testing.T) {
	t.Run("normalizes SCIM DELETE requests from runtimes with empty body streams", func(t *testing.T) {
		pl := New(Options{Connections: []ConnectionOptions{staticConnection("streaming-runtime", "streaming-token")}})
		req := httptest.NewRequest("DELETE", "https://example.com/scim/v2/Users/user-1", bytes.NewReader([]byte{}))
		req.Header.Set("Authorization", "Bearer streaming-token")
		nr, res, err := pl.OnRequest(req, nil)
		if err != nil || res != nil || nr == nil {
			t.Fatalf("Expected SCIM DELETE normalization to return a request (req=%v res=%v err=%v)", nr, res, err)
		}
		if nr.Body != nil && nr.Body != http.NoBody {
			t.Fatalf("body = %#v, want null", nr.Body)
		}
		if nr.ContentLength != 0 {
			t.Fatalf("content length = %d", nr.ContentLength)
		}
		if got := nr.Header.Get("Authorization"); got != "Bearer streaming-token" {
			t.Fatalf("authorization = %q", got)
		}
	})

	// @see https://github.com/better-auth/better-auth/issues/8549
	t.Run("provisions users and groups through a real HTTP listener", func(t *testing.T) {
		const role = "billing-manager"
		var (
			mu                   sync.Mutex
			projectedStates      []ProjectedUserState
			rejectRoleProjection atomic.Bool
		)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		baseURL := "http://" + ln.Addr().String()
		e := newEnv(t, Options{
			Connections: []ConnectionOptions{{
				ID:                   "sqlite-workforce",
				ProvisioningDomainID: "workspace-sqlite",
				Credentials:          []BearerCredential{{Type: "bearer", ID: "sqlite-scim-token", Token: "sqlite-scim-token"}},
			}},
			Projection: &Projection{
				Roles: &RoleProjection{
					Map: func(in RoleMappingInput, _ DatabaseContext) ([]string, error) {
						if in.Source.ExternalID == "sqlite-finance-admins" {
							return []string{role}, nil
						}
						return []string{}, nil
					},
					Exists: func(in RoleExistenceInput, _ DatabaseContext) (bool, error) {
						return in.Role == role, nil
					},
				},
				ReconcileUser: func(state ProjectedUserState, dc DatabaseContext) error {
					var value any
					if len(state.Grants) > 0 {
						value = state.Grants[0].Role
					}
					if _, err := dc.Database.Update(dc.Context, "user", []adapter.Where{{Field: "id", Value: state.UserID}},
						adapter.Record{"scimTestRole": value}); err != nil {
						return err
					}
					if rejectRoleProjection.Load() {
						for _, g := range state.Grants {
							if g.Role == role {
								return errHTTPE2EInjected
							}
						}
					}
					cp := state
					cp.Sources = append([]IdentitySource{}, state.Sources...)
					cp.Grants = append([]ProjectedRoleGrant{}, state.Grants...)
					mu.Lock()
					projectedStates = append(projectedStates, cp)
					mu.Unlock()
					return nil
				},
			},
		}, envOptions{
			sqlite:  true,
			baseURL: baseURL,
			mutate: func(cfg *betterauth.Config) {
				cfg.User = &betterauth.UserConfig{ModelConfig: betterauth.ModelConfig{
					AdditionalFields: []db.Field{{Name: "scimTestRole", Type: db.TypeString, Required: db.False}},
				}}
			},
		})
		srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: e.auth.Handler()}}
		srv.Start()
		t.Cleanup(srv.Close)

		var groupRevisionBefore, subjectRevisionBefore any
		checkpointsWithRole := map[string]bool{
			"member-added": true, "member-restored": true, "user-reactivated": true, "reprovisioned-member-added": true,
		}
		checkpointsWithMembership := map[string]bool{
			"member-added": true, "member-restored": true, "user-deactivated": true, "user-reactivated": true,
			"reprovisioned-member-added": true,
		}
		roleOf := func(r adapter.Record) any {
			if v, ok := r["scimTestRole"]; ok && v != nil {
				return v
			}
			return nil
		}

		result := httpE2ERunLifecycle(t, srv.Client(), httpE2ELifecycleOptions{
			baseURL: baseURL,
			token:   "sqlite-scim-token",
			testID:  "sqlite",
			projectionFailure: &struct{ enable, disable func() }{
				enable:  func() { rejectRoleProjection.Store(true) },
				disable: func() { rejectRoleProjection.Store(false) },
			},
			onCheckpoint: func(cp string) {
				users := e.rows("user")
				groups := e.rows("scimGroup")
				subjects := e.rows("scimSubject")
				memberships := e.rows("scimGroupMember")
				grants := e.rows("scimProjectionGrant")
				if cp == "group-created" {
					if len(groups) != 1 || len(subjects) != 1 {
						t.Fatalf("%s: groups=%d subjects=%d", cp, len(groups), len(subjects))
					}
					if _, ok := httpContractNumber(groups[0]["revision"]); !ok {
						t.Fatalf("group revision = %#v", groups[0]["revision"])
					}
					if _, ok := httpContractNumber(subjects[0]["revision"]); !ok {
						t.Fatalf("subject revision = %#v", subjects[0]["revision"])
					}
					groupRevisionBefore = groups[0]["revision"]
					subjectRevisionBefore = subjects[0]["revision"]
				}
				if cp == "failed-add-rolled-back" {
					if len(groups) != 1 || len(subjects) != 1 {
						t.Fatalf("%s: groups=%d subjects=%d", cp, len(groups), len(subjects))
					}
					g, _ := httpContractNumber(groups[0]["revision"])
					gb, _ := httpContractNumber(groupRevisionBefore)
					s, _ := httpContractNumber(subjects[0]["revision"])
					sb, _ := httpContractNumber(subjectRevisionBefore)
					if g != gb || s != sb {
						t.Fatalf("%s: revisions changed group %v->%v subject %v->%v", cp, gb, g, sb, s)
					}
				}
				if len(users) != 1 {
					t.Fatalf("%s: users = %d", cp, len(users))
				}
				var wantRole any
				wantGrants, wantMemberships := 0, 0
				if checkpointsWithRole[cp] {
					wantRole = role
					wantGrants = 1
				}
				if checkpointsWithMembership[cp] {
					wantMemberships = 1
				}
				if got := roleOf(users[0]); got != wantRole {
					t.Fatalf("%s: scimTestRole = %#v, want %#v", cp, got, wantRole)
				}
				if len(grants) != wantGrants {
					t.Fatalf("%s: grants = %d, want %d", cp, len(grants), wantGrants)
				}
				if len(memberships) != wantMemberships {
					t.Fatalf("%s: memberships = %d, want %d", cp, len(memberships), wantMemberships)
				}
			},
		})

		mu.Lock()
		states := append([]ProjectedUserState{}, projectedStates...)
		mu.Unlock()
		find := func(from int, pred func(ProjectedUserState) bool) int {
			for i := from; i < len(states); i++ {
				if pred(states[i]) {
					return i
				}
			}
			return -1
		}
		grantedAt := find(0, func(s ProjectedUserState) bool {
			for _, g := range s.Grants {
				if g.Role == "billing-manager" && g.Source.ID == result.groupID {
					return true
				}
			}
			return false
		})
		revokedAt := find(grantedAt+1, func(s ProjectedUserState) bool { return len(s.Grants) == 0 })
		deactivatedAt := find(revokedAt+1, func(s ProjectedUserState) bool { return !s.Active })
		reactivatedAt := find(deactivatedAt+1, func(s ProjectedUserState) bool {
			if !s.Active {
				return false
			}
			for _, g := range s.Grants {
				if g.Role == role {
					return true
				}
			}
			return false
		})
		if grantedAt < 0 || revokedAt <= grantedAt || deactivatedAt <= revokedAt || reactivatedAt <= deactivatedAt {
			t.Fatalf("projection order: granted=%d revoked=%d deactivated=%d reactivated=%d",
				grantedAt, revokedAt, deactivatedAt, reactivatedAt)
		}
		if len(states[deactivatedAt].Grants) != 0 {
			t.Fatalf("deactivated grants = %+v", states[deactivatedAt].Grants)
		}

		users := e.rows("user")
		for _, m := range []string{"account", "scimUser", "scimGroup", "scimGroupMember", "scimProjectionGrant"} {
			if rows := e.rows(m); len(rows) != 0 {
				t.Fatalf("%s rows = %v", m, rows)
			}
		}
		if len(users) != 1 || roleOf(users[0]) != nil {
			t.Fatalf("users = %v", users)
		}
		userID := users[0]["id"]
		subjects := e.rows("scimSubject")
		if len(subjects) != 1 || subjects[0]["userId"] != userID {
			t.Fatalf("subjects = %v", subjects)
		}
		tombstones := e.rows("scimIdentityTombstone")
		if len(tombstones) != 1 || tombstones[0]["userId"] != userID {
			t.Fatalf("tombstones = %v", tombstones)
		}
		for _, s := range states {
			if s.UserID != userID {
				t.Fatalf("projected state for unexpected user %q (want %v)", s.UserID, userID)
			}
		}
	})
}

var errHTTPE2EInjected = httpE2EError("Injected SCIM role projection failure")

type httpE2EError string

func (e httpE2EError) Error() string { return string(e) }
