package organization

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// orgAdapter ports getOrgAdapter (adapter.ts). It uses the raw database adapter (no
// database hooks), joined to the active transaction through the endpoint context.
type orgAdapter struct {
	ctx *Ctx
	o   *Options
}

func newAdapter(ctx *Ctx, o *Options) *orgAdapter { return &orgAdapter{ctx: ctx, o: o} }

func (a *orgAdapter) c() context.Context  { return a.ctx.Context() }
func (a *orgAdapter) db() adapter.Adapter { return a.ctx.Auth.Adapter }

func eq(field string, value any) adapter.Where { return adapter.Where{Field: field, Value: value} }

const joinLimit = 100

func (a *orgAdapter) findOne(model string, where ...adapter.Where) (Record, error) {
	return a.db().FindOne(a.c(), adapter.FindOneInput{Model: model, Where: where})
}

func (a *orgAdapter) findMany(model string, limit int, where ...adapter.Where) ([]Record, error) {
	return a.db().FindMany(a.c(), adapter.FindManyInput{Model: model, Where: where, Limit: limit})
}

// userSummary is {id, name, email, image}.
func userSummary(u Record) *jsonx.Object {
	img, ok := u["image"]
	if !ok {
		img = nil
	}
	return jsonx.O("id", u["id"], "name", u["name"], "email", u["email"], "image", img)
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// memberWithUser is a member record plus its user summary (stored under "user").
type memberWithUser struct {
	Member Record
	User   *jsonx.Object
}

func (m *memberWithUser) role() string { return str(m.Member["role"]) }
func (m *memberWithUser) id() string   { return str(m.Member["id"]) }

func (a *orgAdapter) findOrganizationBySlug(slug string) (Record, error) {
	return a.findOne("organization", eq("slug", slug))
}

func (a *orgAdapter) findOrganizationByID(id string) (Record, error) {
	return a.findOne("organization", eq("id", id))
}

func parseMetadata(v any) any {
	s, ok := v.(string)
	if !ok || s == "" {
		return jsonx.Undefined
	}
	parsed, err := jsonx.Parse([]byte(s))
	if err != nil {
		return s
	}
	return parsed
}

func (a *orgAdapter) createOrganization(data Record) (Record, error) {
	in := Record{}
	for k, v := range data {
		in[k] = v
	}
	if md, ok := data["metadata"]; ok && md != nil && !isUndefined(md) {
		s, err := jsonx.Stringify(md)
		if err != nil {
			return nil, err
		}
		in["metadata"] = s
	} else {
		delete(in, "metadata")
	}
	org, err := a.db().Create(a.c(), adapter.CreateInput{Model: "organization", Data: in, ForceAllowID: true})
	if err != nil {
		return nil, err
	}
	org["metadata"] = parseMetadata(org["metadata"])
	return org, nil
}

func (a *orgAdapter) findUserByEmail(email string) (Record, error) {
	return a.findOne("user", eq("email", strings.ToLower(email)))
}

func (a *orgAdapter) findMemberByEmail(email, orgID string) (*memberWithUser, error) {
	u, err := a.findUserByEmail(email)
	if err != nil || u == nil {
		return nil, err
	}
	m, err := a.findOne("member", eq("organizationId", orgID), eq("userId", u["id"]))
	if err != nil || m == nil {
		return nil, err
	}
	return &memberWithUser{Member: m, User: userSummary(u)}, nil
}

type listMembersInput struct {
	OrganizationID string
	Limit, Offset  int
	SortBy         string
	SortOrder      string
	Filter         *adapter.Where
}

func (a *orgAdapter) listMembers(in listMembersInput) ([]*memberWithUser, int64, error) {
	where := []adapter.Where{eq("organizationId", in.OrganizationID)}
	if in.Filter != nil && in.Filter.Field != "" {
		where = append(where, *in.Filter)
	}
	limit := in.Limit
	if limit == 0 {
		limit = a.o.listLimit()
	}
	var sort *adapter.SortBy
	if in.SortBy != "" {
		dir := in.SortOrder
		if dir == "" {
			dir = "asc"
		}
		sort = &adapter.SortBy{Field: in.SortBy, Direction: dir}
	}
	members, err := a.db().FindMany(a.c(), adapter.FindManyInput{Model: "member", Where: where, Limit: limit, Offset: in.Offset, SortBy: sort})
	if err != nil {
		return nil, 0, err
	}
	total, err := a.db().Count(a.c(), "member", where)
	if err != nil {
		return nil, 0, err
	}
	users, err := a.usersByID(members)
	if err != nil {
		return nil, 0, err
	}
	out := make([]*memberWithUser, 0, len(members))
	for _, m := range members {
		u, ok := users[str(m["userId"])]
		if !ok {
			return nil, 0, errors.New("Unexpected error: User not found for member")
		}
		out = append(out, &memberWithUser{Member: m, User: userSummary(u)})
	}
	return out, total, nil
}

func (a *orgAdapter) usersByID(members []Record) (map[string]Record, error) {
	out := map[string]Record{}
	if len(members) == 0 {
		return out, nil
	}
	ids := make([]any, 0, len(members))
	for _, m := range members {
		ids = append(ids, m["userId"])
	}
	users, err := a.db().FindMany(a.c(), adapter.FindManyInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: ids, Operator: adapter.In}}, Limit: len(members)})
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		out[str(u["id"])] = u
	}
	return out, nil
}

func (a *orgAdapter) findMemberByOrgID(userID, orgID string) (*memberWithUser, error) {
	m, err := a.findOne("member", eq("userId", userID), eq("organizationId", orgID))
	if err != nil || m == nil {
		return nil, err
	}
	u, err := a.findOne("user", eq("id", m["userId"]))
	if err != nil || u == nil {
		return nil, err
	}
	return &memberWithUser{Member: m, User: userSummary(u)}, nil
}

func (a *orgAdapter) findMemberByID(id string) (*memberWithUser, error) {
	m, err := a.findOne("member", eq("id", id))
	if err != nil || m == nil {
		return nil, err
	}
	u, err := a.findOne("user", eq("id", m["userId"]))
	if err != nil {
		return nil, err
	}
	if u == nil {
		return &memberWithUser{Member: m, User: jsonx.O("id", jsonx.Undefined)}, nil
	}
	return &memberWithUser{Member: m, User: userSummary(u)}, nil
}

func (a *orgAdapter) createMember(data Record) (Record, error) {
	in := Record{}
	for k, v := range data {
		in[k] = v
	}
	in["createdAt"] = time.Now()
	return a.db().Create(a.c(), adapter.CreateInput{Model: "member", Data: in})
}

func (a *orgAdapter) updateMember(id, role string) (Record, error) {
	return a.db().Update(a.c(), "member", []adapter.Where{eq("id", id)}, Record{"role": role})
}

func (a *orgAdapter) deleteMember(memberID, orgID, userID string) error {
	return a.ctx.Transaction(func() error {
		if userID == "" {
			m, err := a.findOne("member", eq("id", memberID))
			if err != nil {
				return err
			}
			if m == nil {
				return errors.New("Member not found")
			}
			userID = str(m["userId"])
		}
		if err := a.db().Delete(a.c(), "member", []adapter.Where{eq("id", memberID)}); err != nil {
			return err
		}
		if a.o.teamsEnabled() {
			teams, err := a.findMany("team", 0, eq("organizationId", orgID))
			if err != nil {
				return err
			}
			for _, t := range teams {
				n, err := a.db().DeleteMany(a.c(), "teamMember", []adapter.Where{eq("userId", userID), eq("teamId", t["id"])})
				if err != nil {
					return err
				}
				if err := a.releaseTeamSeats(str(t["id"]), n); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func isUndefined(v any) bool { return v == jsonx.Undefined || validate.IsUndefined(v) }

func (a *orgAdapter) updateOrganization(id string, data Record) (Record, error) {
	upd := Record{}
	for k, v := range data {
		upd[k] = v
	}
	if md, ok := upd["metadata"]; ok {
		switch md.(type) {
		case string:
		default:
			s, err := jsonx.Stringify(md)
			if err != nil {
				return nil, err
			}
			upd["metadata"] = s
		}
	}
	org, err := a.db().Update(a.c(), "organization", []adapter.Where{eq("id", id)}, upd)
	if err != nil || org == nil {
		return nil, err
	}
	org["metadata"] = parseMetadata(org["metadata"])
	return org, nil
}

func (a *orgAdapter) deleteOrganization(id string) error {
	return a.ctx.Transaction(func() error {
		if _, err := a.db().DeleteMany(a.c(), "member", []adapter.Where{eq("organizationId", id)}); err != nil {
			return err
		}
		if _, err := a.db().DeleteMany(a.c(), "invitation", []adapter.Where{eq("organizationId", id)}); err != nil {
			return err
		}
		return a.db().Delete(a.c(), "organization", []adapter.Where{eq("id", id)})
	})
}

func (a *orgAdapter) setActiveOrganization(token string, orgID any) (*betterauth.Session, error) {
	return a.ctx.Auth.InternalAdapter.UpdateSession(a.c(), token, Record{"activeOrganizationId": orgID})
}

func (a *orgAdapter) setActiveTeam(token string, teamID any) (*betterauth.Session, error) {
	return a.ctx.Auth.InternalAdapter.UpdateSession(a.c(), token, Record{"activeTeamId": teamID})
}

func (a *orgAdapter) checkMembership(userID, orgID string) (Record, error) {
	return a.findOne("member", eq("userId", userID), eq("organizationId", orgID))
}

type fullOrganization struct {
	Org         Record
	Invitations []Record
	Members     []*memberWithUser
	Teams       []Record
	HasTeams    bool
}

func (a *orgAdapter) findFullOrganization(idOrSlug string, isSlug, includeTeams bool, membersLimit int) (*fullOrganization, error) {
	field := "id"
	if isSlug {
		field = "slug"
	}
	org, err := a.findOne("organization", eq(field, idOrSlug))
	if err != nil || org == nil {
		return nil, err
	}
	invitations, err := a.findMany("invitation", joinLimit, eq("organizationId", org["id"]))
	if err != nil {
		return nil, err
	}
	limit := joinLimit
	if membersLimit > 0 {
		limit = membersLimit
	}
	members, err := a.findMany("member", limit, eq("organizationId", org["id"]))
	if err != nil {
		return nil, err
	}
	out := &fullOrganization{Org: org, Invitations: invitations, HasTeams: includeTeams}
	if includeTeams {
		out.Teams, err = a.findMany("team", joinLimit, eq("organizationId", org["id"]))
		if err != nil {
			return nil, err
		}
	}
	if len(members) > 0 {
		ids := make([]any, 0, len(members))
		for _, m := range members {
			ids = append(ids, m["userId"])
		}
		users, err := a.db().FindMany(a.c(), adapter.FindManyInput{Model: "user", Where: []adapter.Where{{Field: "id", Value: ids, Operator: adapter.In}}, Limit: a.o.listLimit()})
		if err != nil {
			return nil, err
		}
		byID := map[string]Record{}
		for _, u := range users {
			byID[str(u["id"])] = u
		}
		for _, m := range members {
			u, ok := byID[str(m["userId"])]
			if !ok {
				return nil, errors.New("Unexpected error: User not found for member")
			}
			out.Members = append(out.Members, &memberWithUser{Member: m, User: userSummary(u)})
		}
	}
	return out, nil
}

func (a *orgAdapter) listOrganizations(userID string) ([]Record, error) {
	members, err := a.findMany("member", 0, eq("userId", userID))
	if err != nil {
		return nil, err
	}
	out := []Record{}
	for _, m := range members {
		org, err := a.findOne("organization", eq("id", m["organizationId"]))
		if err != nil {
			return nil, err
		}
		if org != nil {
			out = append(out, org)
		}
	}
	return out, nil
}

func stripTeam(t Record) Record {
	if t == nil {
		return nil
	}
	out := Record{}
	for k, v := range t {
		if k != "memberCount" {
			out[k] = v
		}
	}
	return out
}

func stripTeamMember(m Record) Record {
	if m == nil {
		return nil
	}
	out := Record{}
	for k, v := range m {
		if k != "membershipKey" {
			out[k] = v
		}
	}
	return out
}

func (a *orgAdapter) createTeam(data Record) (Record, error) {
	in := Record{}
	for k, v := range data {
		in[k] = v
	}
	in["memberCount"] = 0
	t, err := a.db().Create(a.c(), adapter.CreateInput{Model: "team", Data: in, ForceAllowID: true})
	if err != nil {
		return nil, err
	}
	return stripTeam(t), nil
}

// findTeamByID returns the team (without memberCount) and, when includeMembers is set,
// its members.
func (a *orgAdapter) findTeamByID(teamID, orgID string, includeMembers bool) (Record, []Record, error) {
	where := []adapter.Where{eq("id", teamID)}
	if orgID != "" {
		where = append(where, eq("organizationId", orgID))
	}
	t, err := a.findOne("team", where...)
	if err != nil || t == nil {
		return nil, nil, err
	}
	var members []Record
	if includeMembers {
		ms, err := a.findMany("teamMember", joinLimit, eq("teamId", t["id"]))
		if err != nil {
			return nil, nil, err
		}
		for _, m := range ms {
			members = append(members, stripTeamMember(m))
		}
	}
	return stripTeam(t), members, nil
}

func (a *orgAdapter) updateTeam(teamID string, data Record) (Record, error) {
	upd := Record{}
	for k, v := range data {
		if k == "id" || isUndefined(v) {
			continue
		}
		upd[k] = v
	}
	t, err := a.db().Update(a.c(), "team", []adapter.Where{eq("id", teamID)}, upd)
	if err != nil || t == nil {
		return nil, err
	}
	return stripTeam(t), nil
}

func (a *orgAdapter) deleteTeam(teamID string) error {
	if _, err := a.db().DeleteMany(a.c(), "teamMember", []adapter.Where{eq("teamId", teamID)}); err != nil {
		return err
	}
	return a.db().Delete(a.c(), "team", []adapter.Where{eq("id", teamID)})
}

func (a *orgAdapter) listTeams(orgID string) ([]Record, error) {
	teams, err := a.findMany("team", 0, eq("organizationId", orgID))
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(teams))
	for _, t := range teams {
		out = append(out, stripTeam(t))
	}
	return out, nil
}

func (a *orgAdapter) listTeamMembers(teamID string) ([]Record, error) {
	ms, err := a.findMany("teamMember", 0, eq("teamId", teamID))
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(ms))
	for _, m := range ms {
		out = append(out, stripTeamMember(m))
	}
	return out, nil
}

func (a *orgAdapter) countMembers(orgID string) (int64, error) {
	return a.db().Count(a.c(), "member", []adapter.Where{eq("organizationId", orgID)})
}

func (a *orgAdapter) listTeamsByUser(userID string) ([]Record, error) {
	ms, err := a.findMany("teamMember", 0, eq("userId", userID))
	if err != nil {
		return nil, err
	}
	out := []Record{}
	for _, m := range ms {
		t, err := a.findOne("team", eq("id", m["teamId"]))
		if err != nil {
			return nil, err
		}
		if t != nil {
			out = append(out, stripTeam(t))
		}
	}
	return out, nil
}

func (a *orgAdapter) findTeamMember(teamID, userID string) (Record, error) {
	m, err := a.findOne("teamMember", eq("teamId", teamID), eq("userId", userID))
	if err != nil || m == nil {
		return nil, err
	}
	return stripTeamMember(m), nil
}

func membershipKey(teamID, userID string) string {
	b, _ := jsonx.Marshal([]any{teamID, userID})
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (a *orgAdapter) findTeamMemberByKeyOrPair(teamID, userID, key string) (Record, error) {
	m, err := a.findOne("teamMember", eq("membershipKey", key))
	if err != nil || m != nil {
		return m, err
	}
	return a.findOne("teamMember", eq("teamId", teamID), eq("userId", userID))
}

func (a *orgAdapter) syncTeamMemberCount(teamID string) error {
	n, err := a.db().Count(a.c(), "teamMember", []adapter.Where{eq("teamId", teamID)})
	if err != nil {
		return err
	}
	_, err = a.db().IncrementOne(a.c(), adapter.IncrementInput{Model: "team",
		Where:     []adapter.Where{eq("id", teamID), {Field: "memberCount", Operator: adapter.Lt, Value: n}},
		Increment: map[string]float64{}, Set: Record{"memberCount": n}})
	return err
}

func (a *orgAdapter) reserveTeamSeat(teamID string, max int) (bool, error) {
	t, err := a.db().IncrementOne(a.c(), adapter.IncrementInput{Model: "team",
		Where:     []adapter.Where{eq("id", teamID), {Field: "memberCount", Operator: adapter.Lt, Value: max}},
		Increment: map[string]float64{"memberCount": 1}})
	return t != nil, err
}

func (a *orgAdapter) incrementTeamMemberCount(teamID string) error {
	_, err := a.db().IncrementOne(a.c(), adapter.IncrementInput{Model: "team",
		Where: []adapter.Where{eq("id", teamID)}, Increment: map[string]float64{"memberCount": 1}})
	return err
}

func (a *orgAdapter) releaseTeamSeats(teamID string, count int64) error {
	if count <= 0 {
		return nil
	}
	_, err := a.db().IncrementOne(a.c(), adapter.IncrementInput{Model: "team",
		Where:     []adapter.Where{eq("id", teamID), {Field: "memberCount", Operator: adapter.Gte, Value: count}},
		Increment: map[string]float64{"memberCount": -float64(count)}})
	return err
}

// createTeamMemberWithKey returns the member and whether it was created (false when a
// concurrent insert won).
func (a *orgAdapter) createTeamMemberWithKey(teamID, userID, key string) (Record, bool, error) {
	m, err := a.db().Create(a.c(), adapter.CreateInput{Model: "teamMember", Data: Record{
		"teamId": teamID, "userId": userID, "membershipKey": key, "createdAt": time.Now(),
	}})
	if err == nil {
		return m, true, nil
	}
	existing, ferr := a.findTeamMemberByKeyOrPair(teamID, userID, key)
	if ferr == nil && existing != nil {
		return existing, false, nil
	}
	return nil, false, err
}

func (a *orgAdapter) findOrCreateTeamMember(teamID, userID string) (Record, error) {
	var out Record
	err := a.ctx.Transaction(func() error {
		key := membershipKey(teamID, userID)
		existing, err := a.findTeamMemberByKeyOrPair(teamID, userID, key)
		if err != nil {
			return err
		}
		if existing != nil {
			out = stripTeamMember(existing)
			return nil
		}
		if err := a.syncTeamMemberCount(teamID); err != nil {
			return err
		}
		m, created, err := a.createTeamMemberWithKey(teamID, userID, key)
		if err != nil {
			return err
		}
		if created {
			if err := a.incrementTeamMemberCount(teamID); err != nil {
				return err
			}
		}
		out = stripTeamMember(m)
		return nil
	})
	return out, err
}

// addTeamMemberWithLimit returns (member, false) when added or (nil, true) when the team
// member limit was reached.
func (a *orgAdapter) addTeamMemberWithLimit(teamID, userID string, max int) (Record, bool, error) {
	var out Record
	limitReached := false
	err := a.ctx.Transaction(func() error {
		key := membershipKey(teamID, userID)
		existing, err := a.findTeamMemberByKeyOrPair(teamID, userID, key)
		if err != nil {
			return err
		}
		if existing != nil {
			out = stripTeamMember(existing)
			return nil
		}
		if err := a.syncTeamMemberCount(teamID); err != nil {
			return err
		}
		ok, err := a.reserveTeamSeat(teamID, max)
		if err != nil {
			return err
		}
		if !ok {
			limitReached = true
			return nil
		}
		m, created, err := a.createTeamMemberWithKey(teamID, userID, key)
		if err != nil {
			_ = a.releaseTeamSeats(teamID, 1)
			return err
		}
		if !created {
			if err := a.releaseTeamSeats(teamID, 1); err != nil {
				return err
			}
		}
		out = stripTeamMember(m)
		return nil
	})
	return out, limitReached, err
}

func (a *orgAdapter) removeTeamMember(teamID, userID string) error {
	n, err := a.db().DeleteMany(a.c(), "teamMember", []adapter.Where{eq("teamId", teamID), eq("userId", userID)})
	if err != nil {
		return err
	}
	return a.releaseTeamSeats(teamID, n)
}

// listUserInvitations returns the invitations sent to email with organizationName.
func (a *orgAdapter) listUserInvitations(email string) ([]Record, error) {
	invs, err := a.findMany("invitation", 0, eq("email", strings.ToLower(email)))
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(invs))
	for _, inv := range invs {
		org, err := a.findOne("organization", eq("id", inv["organizationId"]))
		if err != nil {
			return nil, err
		}
		inv["organizationName"] = jsonx.Undefined
		if org != nil {
			inv["organizationName"] = org["name"]
		}
		out = append(out, inv)
	}
	return out, nil
}

func (a *orgAdapter) createInvitation(inv Record, teamIDs []string, user *betterauth.User) (Record, error) {
	data := Record{
		"status":    "pending",
		"expiresAt": time.Now().Add(a.o.invitationExpiresIn()),
		"createdAt": time.Now(),
		"inviterId": user.ID,
	}
	for k, v := range inv {
		data[k] = v
	}
	delete(data, "teamIds")
	if len(teamIDs) > 0 {
		data["teamId"] = strings.Join(teamIDs, ",")
	} else {
		data["teamId"] = nil
	}
	if !a.o.teamsEnabled() {
		delete(data, "teamId")
	}
	return a.db().Create(a.c(), adapter.CreateInput{Model: "invitation", Data: data, ForceAllowID: true})
}

func (a *orgAdapter) findInvitationByID(id string) (Record, error) {
	return a.findOne("invitation", eq("id", id))
}

func notExpired(invs []Record) []Record {
	out := []Record{}
	for _, inv := range invs {
		if t, ok := adapter.ToTime(inv["expiresAt"]); ok && t.After(time.Now()) {
			out = append(out, inv)
		}
	}
	return out
}

func (a *orgAdapter) findPendingInvitation(email, orgID string) ([]Record, error) {
	invs, err := a.findMany("invitation", 0, eq("email", strings.ToLower(email)), eq("organizationId", orgID), eq("status", "pending"))
	if err != nil {
		return nil, err
	}
	return notExpired(invs), nil
}

func (a *orgAdapter) findPendingInvitations(orgID string) ([]Record, error) {
	invs, err := a.findMany("invitation", 0, eq("organizationId", orgID), eq("status", "pending"))
	if err != nil {
		return nil, err
	}
	return notExpired(invs), nil
}

func (a *orgAdapter) listInvitations(orgID string) ([]Record, error) {
	return a.findMany("invitation", 0, eq("organizationId", orgID))
}

func (a *orgAdapter) updateInvitation(id, status, fromStatus string) (Record, error) {
	where := []adapter.Where{eq("id", id)}
	if fromStatus != "" {
		where = append(where, eq("status", fromStatus))
	}
	return a.db().IncrementOne(a.c(), adapter.IncrementInput{Model: "invitation", Where: where,
		Increment: map[string]float64{}, Set: Record{"status": status}})
}
