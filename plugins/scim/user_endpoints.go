package scim

import (
	"bytes"
	"context"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// getResourceURL resolves path against baseURL (new URL(path, baseURL + "/")).
func getResourceURL(path, baseURL string) string {
	base := baseURL
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	rel := strings.TrimLeft(path, "/")
	if b, err := url.Parse(base); err == nil && b.Scheme != "" {
		return b.Scheme + "://" + b.Host + b.EscapedPath() + rel
	}
	return base + rel
}

// encodeURIComponent is JavaScript's encodeURIComponent.
func encodeURIComponent(s string) string {
	const safe = "-_.!~*'()"
	var b strings.Builder
	for _, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.IndexByte(safe, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteString("%" + strings.ToUpper(string("0123456789abcdef"[c>>4])+string("0123456789abcdef"[c&15])))
	}
	return b.String()
}

func queryProjection(rt resourceType, q map[string]any) (attributeProjection, error) {
	in := queryInputFrom(q)
	p, qerr := parseAttributeProjection(rt, in.attributes, in.excludedAttributes)
	if qerr != nil {
		return attributeProjection{}, scimErr("BAD_REQUEST", qerr.detail, qerr.scimType)
	}
	return p, nil
}

func createUserCollectionWhere(connectionID string, filters []equalityFilter) []adapter.Where {
	where := []adapter.Where{w("connectionId", connectionID)}
	for _, f := range filters {
		switch f.attribute {
		case "id":
			where = append(where, w("id", f.value))
		case "userName":
			where = append(where, w("userNameKey", createUserNameKey(connectionID, jsLower(f.value))))
		case "externalId":
			k := ""
			if p := createExternalIDKey(connectionID, f.value); p != nil {
				k = *p
			}
			where = append(where, w("externalIdKey", k))
		case "emails.value":
			where = append(where, wop("emailValueIndex", adapter.Contains, "|"+createEmailValueToken(f.value)+"|"))
		case "emails.work.value":
			where = append(where, wop("workEmailValueIndex", adapter.Contains, "|"+createEmailValueToken(f.value)+"|"))
		}
	}
	return where
}

func createUserResource(baseURL string, u *scimUserRow) (*jsonx.Object, error) {
	attrs, err := readUserAttributes(u)
	if err != nil {
		return nil, err
	}
	res := jsonx.NewObject()
	for _, k := range attrs.Keys() {
		if k == "enterprise" {
			continue
		}
		v, _ := attrs.Get(k)
		res.Set(k, v)
	}
	res.Set("id", u.ID)
	if u.ExternalID != nil && *u.ExternalID != "" {
		res.Set("externalId", *u.ExternalID)
	}
	res.Set("userName", u.UserName)
	res.Set("displayName", u.DisplayName)
	res.Set("active", u.Active)
	if ent, ok := attrs.Get("enterprise"); ok && !isUndef(ent) {
		res.Set(SchemaEnterpriseUser, ent)
	}
	res.Set("meta", jsonx.O("resourceType", "User", "created", u.CreatedAt, "lastModified", u.UpdatedAt,
		"location", getResourceURL("/scim/v2/Users/"+encodeURIComponent(u.ID), baseURL)))
	return res, nil
}

func resourceLocation(res *jsonx.Object) string {
	meta, _ := getObj(res, "meta")
	return getStr(meta, "location")
}

func findSCIMUser(ctx context.Context, db adapter.Adapter, conn Connection, id string) (*scimUserRow, error) {
	r, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelUser, Where: []adapter.Where{w("id", id), w("connectionId", conn.ID)}})
	if err != nil {
		return nil, err
	}
	u := toSCIMUser(r)
	if u != nil && u.ProvisioningDomainID != conn.ProvisioningDomainID {
		return nil, scimErr("CONFLICT", "The connection provisioningDomainId changed after resources were created")
	}
	return u, nil
}

func userNotFound() error { return scimErr("NOT_FOUND", "SCIM User not found") }

func requireSubject(ctx context.Context, db adapter.Adapter, userID string) (*subjectRow, error) {
	r, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelSubject, Where: []adapter.Where{w("userId", userID)}})
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, scimErr("INTERNAL_SERVER_ERROR", "The SCIM User subject is missing")
	}
	return toSubject(r), nil
}

func assertConnectionUserAvailable(ctx context.Context, db adapter.Adapter, connectionID, userID string) error {
	r, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelUser, Where: []adapter.Where{
		w("connectionId", connectionID), w("connectionUserKey", createConnectionUserKey(connectionID, userID))}})
	if err != nil {
		return err
	}
	if r != nil {
		return scimErr("CONFLICT", "This connection already provisions the resolved Better Auth User", errUniqueness)
	}
	return nil
}

func assertUserConnectionDomainStable(ctx context.Context, db adapter.Adapter, conn Connection) error {
	r, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelUser, Where: []adapter.Where{
		w("connectionId", conn.ID), wop("provisioningDomainId", adapter.Ne, conn.ProvisioningDomainID)}})
	if err != nil {
		return err
	}
	if r != nil {
		return scimErr("CONFLICT", "The connection provisioningDomainId changed after resources were created")
	}
	return nil
}

func assertUserKeysAvailable(ctx context.Context, db adapter.Adapter, connectionID, userNameKey string, externalIDKey *string, exclude string) error {
	r, err := db.FindOne(ctx, adapter.FindOneInput{Model: modelUser, Where: []adapter.Where{
		w("connectionId", connectionID), w("userNameKey", userNameKey)}})
	if err != nil {
		return err
	}
	if r != nil && recStr(r, "id") != exclude {
		return scimErr("CONFLICT", "SCIM User userName already exists", errUniqueness)
	}
	if externalIDKey == nil {
		return nil
	}
	r, err = db.FindOne(ctx, adapter.FindOneInput{Model: modelUser, Where: []adapter.Where{
		w("connectionId", connectionID), w("externalIdKey", *externalIDKey)}})
	if err != nil {
		return err
	}
	if r != nil && recStr(r, "id") != exclude {
		return scimErr("CONFLICT", "SCIM User externalId already exists", errUniqueness)
	}
	return nil
}

func assertBetterAuthEmailAvailable(ctx context.Context, db adapter.Adapter, email, exclude string) error {
	r, err := db.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{w("email", email)}})
	if err != nil {
		return err
	}
	if r != nil && recStr(r, "id") != exclude {
		return scimErr("CONFLICT", "A Better Auth User already uses this email", errUniqueness)
	}
	return nil
}

func updateManagedBetterAuthUser(ctx context.Context, auth *betterauth.AuthContext, userID, email, name string, updatedAt time.Time) error {
	db := auth.Adapter
	r, err := db.FindOne(ctx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{w("id", userID)}})
	if err != nil {
		return err
	}
	if r == nil {
		return scimErr("CONFLICT", "The linked Better Auth User no longer exists")
	}
	id := recStr(r, "id")
	if err := assertBetterAuthEmailAvailable(ctx, db, email, id); err != nil {
		return err
	}
	update := adapter.Record{"email": email, "name": name}
	if recStr(r, "email") != email {
		update["emailVerified"] = false
	}
	update["updatedAt"] = updatedAt
	u, err := auth.InternalAdapter.UpdateUser(ctx, id, update)
	if err != nil {
		return err
	}
	if u == nil {
		return scimErr("CONFLICT", "The linked Better Auth User no longer exists")
	}
	return nil
}

// runCreateWithUniquenessCheck is runSCIMCreateWithUniquenessCheck.
func runCreateWithUniquenessCheck(create func() error, assertAvailable func() error) error {
	err := create()
	if err == nil {
		return nil
	}
	if _, ok := betterauth.AsAPIError(err); ok {
		return err
	}
	if aerr := assertAvailable(); aerr != nil && isUniquenessError(aerr) {
		return aerr
	}
	return err
}

func optValue(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func profileUpdate(profile userProfile, userNameKey string, externalID, externalIDKey *string, active bool, serialized string, updatedAt time.Time) adapter.Record {
	work := "work"
	return adapter.Record{
		"userName": profile.UserName, "userNameKey": userNameKey, "primaryEmail": profile.PrimaryEmail,
		"workEmailValueIndex": createEmailValueIndex(profile.Emails, &work),
		"emailValueIndex":     createEmailValueIndex(profile.Emails, nil),
		"displayName":         profile.DisplayName, "formattedName": profile.FormattedName,
		"givenName": optValue(profile.GivenName), "familyName": optValue(profile.FamilyName),
		"serializedEmails": serializeEmails(profile.Emails), "serializedAttributes": serialized,
		"externalId": optValue(externalID), "externalIdKey": optValue(externalIDKey),
		"active": active, "updatedAt": updatedAt,
	}
}

func bodyObject(ctx *betterauth.EndpointContext, schema zSchema) *jsonx.Object {
	body, _ := ctx.Body.(*jsonx.Object)
	if ob := orderedRequestBody(ctx, schema); ob != nil {
		return ob
	}
	return body
}

// orderedRequestBody re-parses the raw HTTP body so object key order matches the request.
func orderedRequestBody(ctx *betterauth.EndpointContext, schema zSchema) *jsonx.Object {
	if ctx.Request == nil || ctx.Request.Body == nil {
		return nil
	}
	raw, err := io.ReadAll(ctx.Request.Body)
	ctx.Request.Body = io.NopCloser(bytes.NewReader(raw))
	if err != nil || len(raw) == 0 {
		return nil
	}
	v, err := parseJSON(raw)
	if err != nil {
		return nil
	}
	out, issues := zParse(schema, v)
	if len(issues) > 0 {
		return nil
	}
	o, _ := out.(*jsonx.Object)
	return o
}

func (p *plugin) userEndpoints() []*betterauth.Endpoint {
	return []*betterauth.Endpoint{
		p.scimEndpoint("createSCIMUser", "/scim/v2/Users", "POST", apiUserSchema, true, p.createUser),
		p.scimEndpoint("deleteSCIMUser", "/scim/v2/Users/:userId", "DELETE", nil, false, p.deleteUser),
		p.scimEndpoint("getSCIMUser", "/scim/v2/Users/:userId", "GET", nil, true, p.getUser),
		p.scimEndpoint("listSCIMUsers", "/scim/v2/Users", "GET", nil, true, p.listUsers),
		p.scimEndpoint("patchSCIMUser", "/scim/v2/Users/:userId", "PATCH", patchBodySchema, true, p.patchUser),
		p.scimEndpoint("replaceSCIMUser", "/scim/v2/Users/:userId", "PUT", apiUserSchema, true, p.replaceUser),
	}
}

func canonicalUserInput(profile userProfile, externalID string, active bool) CanonicalUser {
	res := profile.Attributes.Clone()
	if externalID != "" {
		res.Set("externalId", externalID)
	}
	res.Set("userName", profile.UserName)
	res.Set("primaryEmail", profile.PrimaryEmail)
	res.Set("displayName", profile.DisplayName)
	res.Set("active", active)
	return CanonicalUser{ExternalID: externalID, UserName: profile.UserName, PrimaryEmail: profile.PrimaryEmail,
		DisplayName: profile.DisplayName, Active: active, Resource: res}
}

func (p *plugin) createUser(ctx *betterauth.EndpointContext) (any, error) {
	db := ctx.Auth.Adapter
	base := ctx.Context()
	conn := ConnectionFrom(ctx)
	projection, err := queryProjection(resourceUser, ctx.Query)
	if err != nil {
		return nil, err
	}
	body := bodyObject(ctx, apiUserSchema)
	profile := createCanonicalProfile(body)
	active := objGet(body, "active") != false
	externalID := getStr(body, "externalId")
	userNameKey := createUserNameKey(conn.ID, jsLower(profile.UserName))
	externalIDKey := createExternalIDKey(conn.ID, externalID)
	if err := assertUserConnectionDomainStable(base, db, conn); err != nil {
		return nil, err
	}
	if err := assertUserKeysAvailable(base, db, conn.ID, userNameKey, externalIDKey, ""); err != nil {
		return nil, err
	}
	resolved, err := p.identity.resolveUser(base, db, IdentityResolutionInput{ConnectionID: conn.ID,
		ProvisioningDomainID: conn.ProvisioningDomainID, Resource: canonicalUserInput(profile, externalID, active)})
	if err != nil {
		return nil, err
	}
	resolution := resolved.resolution
	var created *scimUserRow
	subjectCreationUserID := ""
	if resolution.Action == "link" {
		subjectCreationUserID = resolution.UserID
	}
	err = runCreateWithUniquenessCheck(func() error {
		return runIdentityMutationTransaction(base, ctx.Auth, subjectCreationUserID, func(tx context.Context) error {
			if err := assertUserKeysAvailable(tx, db, conn.ID, userNameKey, externalIDKey, ""); err != nil {
				return err
			}
			var userID string
			if resolution.Action == "create" {
				if err := assertBetterAuthEmailAvailable(tx, db, profile.PrimaryEmail, ""); err != nil {
					return err
				}
				u, err := ctx.Auth.InternalAdapter.CreateUser(tx, adapter.Record{"email": profile.PrimaryEmail, "name": profile.DisplayName},
					betterauth.UserInfoSource{Method: "scim"})
				if err != nil {
					return err
				}
				if u == nil {
					return betterauth.ErrFrom("UNPROCESSABLE_ENTITY", betterauth.ErrFailedToCreateUser)
				}
				userID = u.ID
			} else {
				r, err := db.FindOne(tx, adapter.FindOneInput{Model: "user", Where: []adapter.Where{w("id", resolution.UserID)}})
				if err != nil {
					return err
				}
				if r == nil {
					return scimErr("CONFLICT", "The resolved Better Auth User does not exist")
				}
				userID = recStr(r, "id")
			}
			if err := assertConnectionUserAvailable(tx, db, conn.ID, userID); err != nil {
				return err
			}
			now := time.Now()
			subject, err := p.identity.acquireSubject(tx, db, userID, now)
			if err != nil {
				return err
			}
			serialized, err := serializeUserAttributes(profile.Attributes)
			if err != nil {
				return err
			}
			data := profileUpdate(profile, userNameKey, nil, externalIDKey, active, serialized, now)
			data["connectionId"] = conn.ID
			data["provisioningDomainId"] = conn.ProvisioningDomainID
			data["userId"] = userID
			data["connectionUserKey"] = createConnectionUserKey(conn.ID, userID)
			if externalID != "" {
				data["externalId"] = externalID
			} else {
				delete(data, "externalId")
			}
			if externalIDKey == nil {
				delete(data, "externalIdKey")
			}
			if profile.GivenName == nil {
				delete(data, "givenName")
			}
			if profile.FamilyName == nil {
				delete(data, "familyName")
			}
			data["orderKey"] = createOrderKey(now)
			data["createdAt"] = now
			cr, err := db.Create(tx, adapter.CreateInput{Model: modelUser, Data: data})
			if err != nil {
				return err
			}
			createdUser := toSCIMUser(cr)
			if resolution.Action == "create" || resolution.Profile == "manage" {
				subject, err = p.identity.claimProfileSource(tx, db, subject, createdUser.ID, now)
				if err != nil {
					return err
				}
				if resolution.Action == "link" {
					if err := updateManagedBetterAuthUser(tx, ctx.Auth, userID, profile.PrimaryEmail, profile.DisplayName, now); err != nil {
						return err
					}
				}
			}
			if err := p.identity.consumeTombstone(tx, db, resolved.tombstoneID); err != nil {
				return err
			}
			if err := p.projection.reconcileUser(tx, db, conn.ProvisioningDomainID, createdUser.ID, ""); err != nil {
				return err
			}
			if _, err := p.identity.reconcileUser(tx, ctx.Auth, db, subject); err != nil {
				return err
			}
			if _, err := fenceActiveConnection(tx, db, conn.ID); err != nil {
				return err
			}
			created = createdUser
			return nil
		})
	}, func() error {
		if err := assertUserKeysAvailable(base, db, conn.ID, userNameKey, externalIDKey, ""); err != nil {
			return err
		}
		if resolution.Action == "create" {
			return assertBetterAuthEmailAvailable(base, db, profile.PrimaryEmail, "")
		}
		return assertConnectionUserAvailable(base, db, conn.ID, resolution.UserID)
	})
	if err != nil {
		return nil, err
	}
	complete, err := createUserResource(ctx.BaseURL(), created)
	if err != nil {
		return nil, err
	}
	resource := projectResourceAttributes(complete, projection)
	ctx.SetStatus(201)
	ctx.SetHeader("Location", resourceLocation(complete))
	ctx.SetHeader("Content-Location", resourceLocation(complete))
	return resource, nil
}

func (p *plugin) getUser(ctx *betterauth.EndpointContext) (any, error) {
	u, err := findSCIMUser(ctx.Context(), ctx.Auth.Adapter, ConnectionFrom(ctx), ctx.Params["userId"])
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, userNotFound()
	}
	projection, err := queryProjection(resourceUser, ctx.Query)
	if err != nil {
		return nil, err
	}
	res, err := createUserResource(ctx.BaseURL(), u)
	if err != nil {
		return nil, err
	}
	return projectResourceAttributes(res, projection), nil
}

func (p *plugin) listUsers(ctx *betterauth.EndpointContext) (any, error) {
	db := ctx.Auth.Adapter
	conn := ConnectionFrom(ctx)
	if err := assertUserConnectionDomainStable(ctx.Context(), db, conn); err != nil {
		return nil, err
	}
	q, qerr := parseCollectionQuery(resourceUser, queryInputFrom(ctx.Query))
	if qerr != nil {
		return nil, scimErr("BAD_REQUEST", qerr.detail, qerr.scimType)
	}
	where := createUserCollectionWhere(conn.ID, q.filters)
	total, err := db.Count(ctx.Context(), modelUser, where)
	if err != nil {
		return nil, err
	}
	resources := []any{}
	if q.pagination.count > 0 {
		rows, err := db.FindMany(ctx.Context(), adapter.FindManyInput{Model: modelUser, Where: where, Limit: q.pagination.count,
			Offset: q.pagination.offset, SortBy: &adapter.SortBy{Field: "orderKey", Direction: "asc"}})
		if err != nil {
			return nil, err
		}
		for _, u := range toSCIMUsers(rows) {
			res, err := createUserResource(ctx.BaseURL(), u)
			if err != nil {
				return nil, err
			}
			resources = append(resources, projectResourceAttributes(res, q.projection))
		}
	}
	return jsonx.O("schemas", []any{SchemaListResponse}, "totalResults", total, "startIndex", q.pagination.startIndex,
		"itemsPerPage", len(resources), "Resources", resources), nil
}

func (p *plugin) replaceUser(ctx *betterauth.EndpointContext) (any, error) {
	db := ctx.Auth.Adapter
	base := ctx.Context()
	conn := ConnectionFrom(ctx)
	projection, err := queryProjection(resourceUser, ctx.Query)
	if err != nil {
		return nil, err
	}
	u, err := findSCIMUser(base, db, conn, ctx.Params["userId"])
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, userNotFound()
	}
	body := bodyObject(ctx, apiUserSchema)
	profile := createCanonicalProfile(body)
	externalID := getStr(body, "externalId")
	userNameKey := createUserNameKey(conn.ID, jsLower(profile.UserName))
	externalIDKey := createExternalIDKey(conn.ID, externalID)
	if err := assertUserKeysAvailable(base, db, conn.ID, userNameKey, externalIDKey, u.ID); err != nil {
		return nil, err
	}
	active := objGet(body, "active") != false
	var updated *scimUserRow
	err = runIdentityMutationTransaction(base, ctx.Auth, "", func(tx context.Context) error {
		current, err := findSCIMUser(tx, db, conn, u.ID)
		if err != nil {
			return err
		}
		if current == nil {
			return userNotFound()
		}
		now := time.Now()
		subject, err := p.identity.acquireSubject(tx, db, current.UserID, now)
		if err != nil {
			return err
		}
		if err := assertUserKeysAvailable(tx, db, conn.ID, userNameKey, externalIDKey, current.ID); err != nil {
			return err
		}
		if subject.profileSource() == current.ID {
			if err := updateManagedBetterAuthUser(tx, ctx.Auth, current.UserID, profile.PrimaryEmail, profile.DisplayName, now); err != nil {
				return err
			}
		}
		serialized, err := serializeUserAttributes(profile.Attributes)
		if err != nil {
			return err
		}
		var ext *string
		if externalID != "" {
			ext = &externalID
		}
		r, err := db.Update(tx, modelUser, []adapter.Where{w("id", current.ID), w("connectionId", conn.ID)},
			profileUpdate(profile, userNameKey, ext, externalIDKey, active, serialized, now))
		if err != nil {
			return err
		}
		if r == nil {
			return userNotFound()
		}
		updated = toSCIMUser(r)
		if err := p.projection.reconcileUser(tx, db, conn.ProvisioningDomainID, updated.ID, ""); err != nil {
			return err
		}
		if _, err := p.identity.reconcileUser(tx, ctx.Auth, db, subject); err != nil {
			return err
		}
		_, err = fenceActiveConnection(tx, db, conn.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	complete, err := createUserResource(ctx.BaseURL(), updated)
	if err != nil {
		return nil, err
	}
	ctx.SetHeader("Location", resourceLocation(complete))
	return projectResourceAttributes(complete, projection), nil
}

func (p *plugin) patchUser(ctx *betterauth.EndpointContext) (any, error) {
	db := ctx.Auth.Adapter
	base := ctx.Context()
	projection, err := queryProjection(resourceUser, ctx.Query)
	if err != nil {
		return nil, err
	}
	conn := ConnectionFrom(ctx)
	u, err := findSCIMUser(base, db, conn, ctx.Params["userId"])
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, userNotFound()
	}
	ops := readPatchOperations(bodyObject(ctx, patchBodySchema))
	var result *scimUserRow
	err = runIdentityMutationTransaction(base, ctx.Auth, "", func(tx context.Context) error {
		before, err := findSCIMUser(tx, db, conn, u.ID)
		if err != nil {
			return err
		}
		if before == nil {
			return userNotFound()
		}
		subjectBefore, err := requireSubject(tx, db, before.UserID)
		if err != nil {
			return err
		}
		now := time.Now()
		subject, err := advanceSubjectRevision(tx, db, subjectBefore, now)
		if err != nil {
			return err
		}
		current, err := findSCIMUser(tx, db, conn, before.ID)
		if err != nil {
			return err
		}
		if current == nil {
			return userNotFound()
		}
		if current.UserID != before.UserID {
			return scimErr("CONFLICT", "The SCIM User identity changed concurrently")
		}
		patch, err := applyUserPatch(current, ops)
		if err != nil {
			return err
		}
		changed, err := userPatchChangesState(current, patch)
		if err != nil {
			return err
		}
		if !changed {
			if _, err := fenceActiveConnection(tx, db, conn.ID); err != nil {
				return err
			}
			result = current
			return nil
		}
		ext := ""
		if patch.ExternalID != nil {
			ext = *patch.ExternalID
		}
		userNameKey := createUserNameKey(conn.ID, jsLower(patch.UserName))
		externalIDKey := createExternalIDKey(conn.ID, ext)
		if err := assertUserKeysAvailable(tx, db, conn.ID, userNameKey, externalIDKey, current.ID); err != nil {
			return err
		}
		if subject.profileSource() == current.ID {
			if err := updateManagedBetterAuthUser(tx, ctx.Auth, current.UserID, patch.PrimaryEmail, patch.DisplayName, now); err != nil {
				return err
			}
		}
		serialized, err := serializeUserAttributes(patch.Attributes)
		if err != nil {
			return err
		}
		profile := userProfile{UserName: patch.UserName, PrimaryEmail: patch.PrimaryEmail, Emails: patch.Emails,
			DisplayName: patch.DisplayName, FormattedName: patch.FormattedName, GivenName: patch.GivenName, FamilyName: patch.FamilyName}
		var extPtr *string
		if ext != "" {
			extPtr = &ext
		}
		r, err := db.Update(tx, modelUser, []adapter.Where{w("id", current.ID), w("connectionId", conn.ID)},
			profileUpdate(profile, userNameKey, extPtr, externalIDKey, patch.Active, serialized, now))
		if err != nil {
			return err
		}
		if r == nil {
			return userNotFound()
		}
		result = toSCIMUser(r)
		if err := p.projection.reconcileUser(tx, db, conn.ProvisioningDomainID, result.ID, ""); err != nil {
			return err
		}
		if _, err := p.identity.reconcileUser(tx, ctx.Auth, db, subject); err != nil {
			return err
		}
		_, err = fenceActiveConnection(tx, db, conn.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	complete, err := createUserResource(ctx.BaseURL(), result)
	if err != nil {
		return nil, err
	}
	ctx.SetHeader("Location", resourceLocation(complete))
	return projectResourceAttributes(complete, projection), nil
}

func (p *plugin) deleteUser(ctx *betterauth.EndpointContext) (any, error) {
	db := ctx.Auth.Adapter
	base := ctx.Context()
	conn := ConnectionFrom(ctx)
	u, err := findSCIMUser(base, db, conn, ctx.Params["userId"])
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, userNotFound()
	}
	err = runGroupMutationTransaction(base, ctx.Auth, func(tx context.Context) error {
		before, err := findSCIMUser(tx, db, conn, u.ID)
		if err != nil {
			return err
		}
		if before == nil {
			return userNotFound()
		}
		subjectBefore, err := requireSubject(tx, db, before.UserID)
		if err != nil {
			return err
		}
		memberWhere := func(id string) []adapter.Where {
			return []adapter.Where{w("connectionId", conn.ID), w("scimUserId", id)}
		}
		mrows, err := db.FindMany(tx, adapter.FindManyInput{Model: modelGroupMember, Where: memberWhere(before.ID)})
		if err != nil {
			return err
		}
		var groupIDs []string
		for _, m := range toMembers(mrows) {
			groupIDs = append(groupIDs, m.GroupID)
		}
		locked, err := acquireGroupMutationLocks(tx, db, conn, groupIDs)
		if err != nil {
			return err
		}
		now := time.Now()
		subject, err := advanceSubjectRevision(tx, db, subjectBefore, now)
		if err != nil {
			return err
		}
		current, err := findSCIMUser(tx, db, conn, before.ID)
		if err != nil {
			return err
		}
		if current == nil {
			return userNotFound()
		}
		if current.UserID != before.UserID {
			return scimErr("CONFLICT", "The SCIM User identity changed concurrently")
		}
		lrows, err := db.FindMany(tx, adapter.FindManyInput{Model: modelGroupMember, Where: memberWhere(current.ID)})
		if err != nil {
			return err
		}
		lockedIDs := map[string]bool{}
		for _, m := range toMembers(lrows) {
			lockedIDs[m.GroupID] = true
		}
		allLocked := len(lockedIDs) == len(locked)
		for _, g := range locked {
			if !lockedIDs[g.ID] {
				allLocked = false
			}
		}
		if !allLocked {
			return concurrentGroupMutation()
		}
		if err := p.identity.preserveDeletedSource(tx, db, current, subject, now); err != nil {
			return err
		}
		if _, err := db.DeleteMany(tx, modelGroupMember, memberWhere(current.ID)); err != nil {
			return err
		}
		if err := markGroupsModified(tx, db, conn.ID, locked, now); err != nil {
			return err
		}
		if _, err := db.DeleteMany(tx, modelProjectionGrant, []adapter.Where{w("scimUserId", current.ID)}); err != nil {
			return err
		}
		if err := db.Delete(tx, modelUser, []adapter.Where{w("id", current.ID), w("connectionId", conn.ID)}); err != nil {
			return err
		}
		subject, err = clearProfileSource(tx, db, subject, current.ID, now)
		if err != nil {
			return err
		}
		if err := p.projection.reconcileUser(tx, db, current.ProvisioningDomainID, current.ID, current.UserID); err != nil {
			return err
		}
		if _, err := p.identity.reconcileUser(tx, ctx.Auth, db, subject); err != nil {
			return err
		}
		_, err = fenceActiveConnection(tx, db, conn.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	ctx.SetStatus(204)
	return betterauth.NoContent, nil
}
