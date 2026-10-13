package organization

import (
	"time"

	"github.com/nimi-io/better-auth-go/db"
)

func col(m db.ModelOptions, name string) string { return m.Fields[name] }

func ref(model string) *db.Reference { return &db.Reference{Model: model, Field: "id"} }

func now() any { return time.Now() }

// pluginSchema builds the plugin tables in upstream order: organization, organizationRole
// (dynamic access control), team and teamMember (teams), member, invitation, then the
// session extension.
func pluginSchema(o *Options) []db.PluginTable {
	s := o.schema()
	teams := o.teamsEnabled()
	var tables []db.PluginTable

	org := s.Organization
	tables = append(tables, db.PluginTable{
		Key: "organization", ModelName: org.ModelName,
		Fields: append([]db.Field{
			{Name: "name", Type: db.TypeString, Required: db.True, Sortable: true, FieldName: col(org, "name")},
			{Name: "slug", Type: db.TypeString, Required: db.True, Unique: true, Sortable: true, FieldName: col(org, "slug"), Index: true},
			{Name: "logo", Type: db.TypeString, Required: db.False, FieldName: col(org, "logo")},
			{Name: "createdAt", Type: db.TypeDate, Required: db.True, FieldName: col(org, "createdAt")},
			{Name: "metadata", Type: db.TypeString, Required: db.False, FieldName: col(org, "metadata")},
		}, org.AdditionalFields...),
	})

	if o.dacEnabled() {
		r := s.OrganizationRole
		// updateOrgRole marks the additional fields optional by mutating the options before
		// the schema is built upstream, so they are nullable columns.
		roleExtra := append([]db.Field(nil), r.AdditionalFields...)
		for i := range roleExtra {
			roleExtra[i].Required = db.False
		}
		tables = append(tables, db.PluginTable{
			Key: "organizationRole", ModelName: r.ModelName,
			Fields: append([]db.Field{
				{Name: "organizationId", Type: db.TypeString, Required: db.True, References: ref("organization"), FieldName: col(r, "organizationId"), Index: true},
				{Name: "role", Type: db.TypeString, Required: db.True, FieldName: col(r, "role"), Index: true},
				{Name: "permission", Type: db.TypeString, Required: db.True, FieldName: col(r, "permission")},
				{Name: "createdAt", Type: db.TypeDate, Required: db.True, DefaultFunc: now, FieldName: col(r, "createdAt")},
				{Name: "updatedAt", Type: db.TypeDate, Required: db.False, FieldName: col(r, "updatedAt"), OnUpdate: now},
			}, roleExtra...),
		})
	}

	if teams {
		t := s.Team
		tables = append(tables, db.PluginTable{
			Key: "team", ModelName: t.ModelName,
			Fields: append([]db.Field{
				{Name: "name", Type: db.TypeString, Required: db.True, FieldName: col(t, "name")},
				{Name: "memberCount", Type: db.TypeNumber, Required: db.True, DefaultValue: 0, Input: db.False, Returned: db.False, FieldName: col(t, "memberCount")},
				{Name: "organizationId", Type: db.TypeString, Required: db.True, References: ref("organization"), FieldName: col(t, "organizationId"), Index: true},
				{Name: "createdAt", Type: db.TypeDate, Required: db.True, FieldName: col(t, "createdAt")},
				{Name: "updatedAt", Type: db.TypeDate, Required: db.False, FieldName: col(t, "updatedAt"), OnUpdate: now},
			}, t.AdditionalFields...),
		})
		tm := s.TeamMember
		tables = append(tables, db.PluginTable{
			Key: "teamMember", ModelName: tm.ModelName,
			Fields: []db.Field{
				{Name: "teamId", Type: db.TypeString, Required: db.True, References: ref("team"), FieldName: col(tm, "teamId"), Index: true},
				{Name: "userId", Type: db.TypeString, Required: db.True, References: ref("user"), FieldName: col(tm, "userId"), Index: true},
				{Name: "membershipKey", Type: db.TypeString, Required: db.False, Unique: true, Input: db.False, Returned: db.False, FieldName: col(tm, "membershipKey")},
				{Name: "createdAt", Type: db.TypeDate, Required: db.False, FieldName: col(tm, "createdAt")},
			},
		})
	}

	m := s.Member
	tables = append(tables, db.PluginTable{
		Key: "member", ModelName: m.ModelName,
		Fields: append([]db.Field{
			{Name: "organizationId", Type: db.TypeString, Required: db.True, References: ref("organization"), FieldName: col(m, "organizationId"), Index: true},
			{Name: "userId", Type: db.TypeString, Required: db.True, FieldName: col(m, "userId"), References: ref("user"), Index: true},
			{Name: "role", Type: db.TypeString, Required: db.True, Sortable: true, DefaultValue: "member", FieldName: col(m, "role")},
			{Name: "createdAt", Type: db.TypeDate, Required: db.True, FieldName: col(m, "createdAt")},
		}, m.AdditionalFields...),
	})

	inv := s.Invitation
	invFields := []db.Field{
		{Name: "organizationId", Type: db.TypeString, Required: db.True, References: ref("organization"), FieldName: col(inv, "organizationId"), Index: true},
		{Name: "email", Type: db.TypeString, Required: db.True, Sortable: true, FieldName: col(inv, "email"), Index: true},
		{Name: "role", Type: db.TypeString, Required: db.False, Sortable: true, FieldName: col(inv, "role")},
	}
	if teams {
		invFields = append(invFields, db.Field{Name: "teamId", Type: db.TypeString, Required: db.False, Sortable: true, FieldName: col(inv, "teamId")})
	}
	invFields = append(invFields,
		db.Field{Name: "status", Type: db.TypeString, Required: db.True, Sortable: true, DefaultValue: "pending", FieldName: col(inv, "status")},
		db.Field{Name: "expiresAt", Type: db.TypeDate, Required: db.True, FieldName: col(inv, "expiresAt")},
		db.Field{Name: "createdAt", Type: db.TypeDate, Required: db.True, FieldName: col(inv, "createdAt"), DefaultFunc: now},
		db.Field{Name: "inviterId", Type: db.TypeString, References: ref("user"), FieldName: col(inv, "inviterId"), Required: db.True},
	)
	tables = append(tables, db.PluginTable{
		Key: "invitation", ModelName: inv.ModelName,
		Fields: append(invFields, inv.AdditionalFields...),
	})

	sess := s.Session
	sessFields := []db.Field{
		{Name: "activeOrganizationId", Type: db.TypeString, Required: db.False, Input: db.False, FieldName: col(sess, "activeOrganizationId")},
	}
	if teams {
		sessFields = append(sessFields, db.Field{Name: "activeTeamId", Type: db.TypeString, Required: db.False, Input: db.False, FieldName: col(sess, "activeTeamId")})
	}
	tables = append(tables, db.PluginTable{Key: "session", Fields: sessFields})
	return tables
}
