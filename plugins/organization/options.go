package organization

import (
	"net/http"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/plugins/access"
)

// Record is a database row with logical field names (organization, member, invitation,
// team, teamMember or organizationRole).
type Record = map[string]any

// Ctx is the endpoint context passed to option callbacks and hooks.
type Ctx = betterauth.EndpointContext

// Options configures the organization plugin (OrganizationOptions upstream). Union-typed
// upstream options (boolean | function, number | function) are split into a value field and
// a ...Func field; the function wins when both are set.
type Options struct {
	// AllowUserToCreateOrganization defaults to true.
	AllowUserToCreateOrganization     *bool
	AllowUserToCreateOrganizationFunc func(ctx *Ctx, user *betterauth.User) (bool, error)
	// OrganizationLimit is the maximum number of organizations a user may belong to when
	// creating one (nil = unlimited). OrganizationLimitFunc returns whether the limit is
	// reached.
	OrganizationLimit     *int
	OrganizationLimitFunc func(ctx *Ctx, user *betterauth.User) (bool, error)
	// CreatorRole is the role given to the creator (default "owner").
	CreatorRole string
	// MembershipLimit is the maximum number of members per organization (0 = 100).
	MembershipLimit     int
	MembershipLimitFunc func(ctx *Ctx, user *betterauth.User, organization Record) (int, error)
	// AC is the access control instance (required for dynamic access control).
	AC *access.AccessControl
	// Roles replaces the default roles (admin, owner, member) when set.
	Roles map[string]access.Role
	// DynamicAccessControl enables per-organization roles stored in the database.
	DynamicAccessControl *DynamicAccessControlOptions
	Teams                *TeamsOptions
	// InvitationExpiresIn defaults to 48 hours.
	InvitationExpiresIn time.Duration
	// InvitationLimit is the maximum number of pending invitations (nil = 100).
	InvitationLimit     *int
	InvitationLimitFunc func(ctx *Ctx, data InvitationLimitData) (int, error)
	// CancelPendingInvitationsOnReInvite cancels a pending invitation when re-inviting.
	CancelPendingInvitationsOnReInvite bool
	// RequireEmailVerificationOnInvitation requires a verified email to accept, reject,
	// view or list invitations by id. When nil it is required only when invitation ids are
	// not opaque (a custom id generator, serial or database generated ids).
	RequireEmailVerificationOnInvitation *bool
	// SendInvitationEmail sends the invitation email.
	SendInvitationEmail func(ctx *Ctx, data InvitationEmailData, r *http.Request) error
	Schema              *SchemaOptions
	// DisableOrganizationDeletion disables /organization/delete.
	DisableOrganizationDeletion bool
	OrganizationHooks           *OrganizationHooks
}

// DynamicAccessControlOptions configures dynamic access control.
type DynamicAccessControlOptions struct {
	Enabled bool
	// MaximumRolesPerOrganization limits the custom roles per organization (nil = unlimited).
	MaximumRolesPerOrganization     *int
	MaximumRolesPerOrganizationFunc func(ctx *Ctx, organizationID string) (int, error)
}

// TeamsOptions configures teams.
type TeamsOptions struct {
	Enabled     bool
	DefaultTeam *DefaultTeamOptions
	// MaximumTeams limits the teams per organization (nil or 0 = unlimited).
	MaximumTeams     *int
	MaximumTeamsFunc func(ctx *Ctx, data MaximumTeamsData) (int, error)
	// MaximumMembersPerTeam limits team members (nil = unlimited).
	MaximumMembersPerTeam     *int
	MaximumMembersPerTeamFunc func(ctx *Ctx, data MaximumMembersPerTeamData) (int, error)
	AllowRemovingAllTeams     bool
}

// DefaultTeamOptions configures the team created with each organization.
type DefaultTeamOptions struct {
	// Enabled defaults to true.
	Enabled *bool
	// CustomCreateDefaultTeam creates the default team instead of the plugin. The returned
	// record must contain "id".
	CustomCreateDefaultTeam func(ctx *Ctx, organization Record) (Record, error)
}

// MaximumTeamsData is passed to TeamsOptions.MaximumTeamsFunc.
type MaximumTeamsData struct {
	OrganizationID string
	// Session is nil for server calls without a session.
	Session *betterauth.SessionWithUser
}

// MaximumMembersPerTeamData is passed to TeamsOptions.MaximumMembersPerTeamFunc.
type MaximumMembersPerTeamData struct {
	TeamID         string
	Session        *betterauth.SessionWithUser
	OrganizationID string
}

// InvitationLimitData is passed to Options.InvitationLimitFunc.
type InvitationLimitData struct {
	User         *betterauth.User
	Organization Record
	Member       Record
}

// InvitationEmailData is passed to Options.SendInvitationEmail.
type InvitationEmailData struct {
	ID           string
	Role         string
	Email        string
	Organization Record
	Invitation   Record
	// Inviter is the inviting member; Inviter["user"] is the inviting *betterauth.User.
	Inviter Record
}

// SchemaOptions customises table and column names and adds fields.
type SchemaOptions struct {
	// Session.Fields renames activeOrganizationId / activeTeamId.
	Session          db.ModelOptions
	Organization     db.ModelOptions
	Member           db.ModelOptions
	Invitation       db.ModelOptions
	Team             db.ModelOptions
	TeamMember       db.ModelOptions
	OrganizationRole db.ModelOptions
}

// HookData carries the arguments of an organization hook. Only the fields relevant to the
// hook are set (see each hook's documentation upstream).
type HookData struct {
	Organization Record
	Member       Record
	Invitation   Record
	Team         Record
	TeamMember   Record
	// Updates is the requested team update (beforeUpdateTeam).
	Updates Record
	// User is the acting or affected user (nil for server-side team calls).
	User *betterauth.User
	// Inviter is set for invitation creation hooks.
	Inviter *betterauth.User
	// CancelledBy is set for invitation cancellation hooks.
	CancelledBy *betterauth.User
	// NewRole is set for beforeUpdateMemberRole; PreviousRole for afterUpdateMemberRole.
	NewRole      string
	PreviousRole string
}

// BeforeHook may return data to merge into the record being written (the `{ data }`
// result upstream). A nil map leaves the input unchanged; an error aborts the request.
type BeforeHook func(ctx *Ctx, data HookData) (map[string]any, error)

// Hook is a hook without a result. An error aborts the request.
type Hook func(ctx *Ctx, data HookData) error

// OrganizationHooks are lifecycle hooks (organizationHooks upstream).
type OrganizationHooks struct {
	BeforeCreateOrganization BeforeHook
	AfterCreateOrganization  Hook
	BeforeUpdateOrganization BeforeHook
	AfterUpdateOrganization  Hook
	BeforeDeleteOrganization Hook
	AfterDeleteOrganization  Hook
	BeforeAddMember          BeforeHook
	AfterAddMember           Hook
	BeforeRemoveMember       Hook
	AfterRemoveMember        Hook
	BeforeUpdateMemberRole   BeforeHook
	AfterUpdateMemberRole    Hook
	BeforeCreateInvitation   BeforeHook
	AfterCreateInvitation    Hook
	BeforeAcceptInvitation   Hook
	AfterAcceptInvitation    Hook
	BeforeRejectInvitation   Hook
	AfterRejectInvitation    Hook
	BeforeCancelInvitation   Hook
	AfterCancelInvitation    Hook
	BeforeCreateTeam         BeforeHook
	AfterCreateTeam          Hook
	BeforeUpdateTeam         BeforeHook
	AfterUpdateTeam          Hook
	BeforeDeleteTeam         Hook
	AfterDeleteTeam          Hook
	BeforeAddTeamMember      BeforeHook
	AfterAddTeamMember       Hook
	BeforeRemoveTeamMember   Hook
	AfterRemoveTeamMember    Hook
}

func (o *Options) teamsEnabled() bool { return o.Teams != nil && o.Teams.Enabled }

func (o *Options) dacEnabled() bool {
	return o.DynamicAccessControl != nil && o.DynamicAccessControl.Enabled
}

func (o *Options) creatorRole() string {
	if o.CreatorRole != "" {
		return o.CreatorRole
	}
	return "owner"
}

func (o *Options) hooks() *OrganizationHooks {
	if o.OrganizationHooks == nil {
		return &OrganizationHooks{}
	}
	return o.OrganizationHooks
}

func (o *Options) schema() *SchemaOptions {
	if o.Schema == nil {
		return &SchemaOptions{}
	}
	return o.Schema
}

func (o *Options) membershipLimit(ctx *Ctx, user *betterauth.User, org Record) (int, error) {
	if o.MembershipLimitFunc != nil {
		return o.MembershipLimitFunc(ctx, user, org)
	}
	if o.MembershipLimit != 0 {
		return o.MembershipLimit, nil
	}
	return 100, nil
}

// listLimit mirrors `(typeof membershipLimit === "number" ? membershipLimit : 100) || 100`.
func (o *Options) listLimit() int {
	if o.MembershipLimitFunc == nil && o.MembershipLimit > 0 {
		return o.MembershipLimit
	}
	return 100
}

func (o *Options) invitationExpiresIn() time.Duration {
	if o.InvitationExpiresIn > 0 {
		return o.InvitationExpiresIn
	}
	return 48 * time.Hour
}

func (o *Options) hasMaxMembersPerTeam() bool {
	return o.Teams != nil && (o.Teams.MaximumMembersPerTeam != nil || o.Teams.MaximumMembersPerTeamFunc != nil)
}

func (o *Options) maxMembersPerTeam(ctx *Ctx, d MaximumMembersPerTeamData) (int, error) {
	if o.Teams.MaximumMembersPerTeamFunc != nil {
		return o.Teams.MaximumMembersPerTeamFunc(ctx, d)
	}
	return *o.Teams.MaximumMembersPerTeam, nil
}

// roleNames returns the static role names (defaults plus custom roles).
func (o *Options) staticRoleNames() map[string]bool {
	out := map[string]bool{}
	for _, r := range defaultRoleNames {
		out[r] = true
	}
	for r := range o.Roles {
		out[r] = true
	}
	return out
}
