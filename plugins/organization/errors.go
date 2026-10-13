package organization

import "github.com/nimi-io/better-auth-go/betterauth"

func ec(code, message string) betterauth.ErrorCode {
	return betterauth.ErrorCode{Code: code, Message: message}
}

// Error codes (ORGANIZATION_ERROR_CODES upstream).
var (
	ErrYouAreNotAllowedToCreateANewOrganization                      = ec("YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION", "You are not allowed to create a new organization")
	ErrYouHaveReachedTheMaximumNumberOfOrganizations                 = ec("YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS", "You have reached the maximum number of organizations")
	ErrOrganizationAlreadyExists                                     = ec("ORGANIZATION_ALREADY_EXISTS", "Organization already exists")
	ErrOrganizationSlugAlreadyTaken                                  = ec("ORGANIZATION_SLUG_ALREADY_TAKEN", "Organization slug already taken")
	ErrOrganizationNotFound                                          = ec("ORGANIZATION_NOT_FOUND", "Organization not found")
	ErrUserIsNotAMemberOfTheOrganization                             = ec("USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION", "User is not a member of the organization")
	ErrYouAreNotAllowedToUpdateThisOrganization                      = ec("YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION", "You are not allowed to update this organization")
	ErrYouAreNotAllowedToDeleteThisOrganization                      = ec("YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION", "You are not allowed to delete this organization")
	ErrNoActiveOrganization                                          = ec("NO_ACTIVE_ORGANIZATION", "No active organization")
	ErrUserIsAlreadyAMemberOfThisOrganization                        = ec("USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION", "User is already a member of this organization")
	ErrMemberNotFound                                                = ec("MEMBER_NOT_FOUND", "Member not found")
	ErrRoleNotFound                                                  = ec("ROLE_NOT_FOUND", "Role not found")
	ErrYouAreNotAllowedToCreateANewTeam                              = ec("YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM", "You are not allowed to create a new team")
	ErrTeamAlreadyExists                                             = ec("TEAM_ALREADY_EXISTS", "Team already exists")
	ErrTeamNotFound                                                  = ec("TEAM_NOT_FOUND", "Team not found")
	ErrYouCannotLeaveTheOrganizationAsTheOnlyOwner                   = ec("YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER", "You cannot leave the organization as the only owner")
	ErrYouCannotLeaveTheOrganizationWithoutAnOwner                   = ec("YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER", "You cannot leave the organization without an owner")
	ErrYouAreNotAllowedToDeleteThisMember                            = ec("YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER", "You are not allowed to delete this member")
	ErrYouAreNotAllowedToInviteUsersToThisOrganization               = ec("YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION", "You are not allowed to invite users to this organization")
	ErrUserIsAlreadyInvitedToThisOrganization                        = ec("USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION", "User is already invited to this organization")
	ErrInvitationNotFound                                            = ec("INVITATION_NOT_FOUND", "Invitation not found")
	ErrYouAreNotTheRecipientOfTheInvitation                          = ec("YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION", "You are not the recipient of the invitation")
	ErrEmailVerificationRequiredBeforeAcceptingOrRejectingInvitation = ec("EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION", "Email verification required before accepting or rejecting invitation")
	ErrEmailVerificationRequiredForInvitation                        = ec("EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION", "Email verification required to view or list invitations for the session email")
	ErrYouAreNotAllowedToCancelThisInvitation                        = ec("YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION", "You are not allowed to cancel this invitation")
	ErrInviterIsNoLongerAMemberOfTheOrganization                     = ec("INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION", "Inviter is no longer a member of the organization")
	ErrYouAreNotAllowedToInviteUserWithThisRole                      = ec("YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE", "You are not allowed to invite a user with this role")
	ErrFailedToRetrieveInvitation                                    = ec("FAILED_TO_RETRIEVE_INVITATION", "Failed to retrieve invitation")
	ErrYouHaveReachedTheMaximumNumberOfTeams                         = ec("YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS", "You have reached the maximum number of teams")
	ErrUnableToRemoveLastTeam                                        = ec("UNABLE_TO_REMOVE_LAST_TEAM", "Unable to remove last team")
	ErrYouAreNotAllowedToUpdateThisMember                            = ec("YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER", "You are not allowed to update this member")
	ErrOrganizationMembershipLimitReached                            = ec("ORGANIZATION_MEMBERSHIP_LIMIT_REACHED", "Organization membership limit reached")
	ErrYouAreNotAllowedToCreateTeamsInThisOrganization               = ec("YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION", "You are not allowed to create teams in this organization")
	ErrYouAreNotAllowedToDeleteTeamsInThisOrganization               = ec("YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION", "You are not allowed to delete teams in this organization")
	ErrYouAreNotAllowedToUpdateThisTeam                              = ec("YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM", "You are not allowed to update this team")
	ErrYouAreNotAllowedToDeleteThisTeam                              = ec("YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM", "You are not allowed to delete this team")
	ErrInvitationLimitReached                                        = ec("INVITATION_LIMIT_REACHED", "Invitation limit reached")
	ErrTeamMemberLimitReached                                        = ec("TEAM_MEMBER_LIMIT_REACHED", "Team member limit reached")
	ErrUserIsNotAMemberOfTheTeam                                     = ec("USER_IS_NOT_A_MEMBER_OF_THE_TEAM", "User is not a member of the team")
	ErrYouCanNotAccessTheMembersOfThisTeam                           = ec("YOU_CAN_NOT_ACCESS_THE_MEMBERS_OF_THIS_TEAM", "You are not allowed to list the members of this team")
	ErrYouDoNotHaveAnActiveTeam                                      = ec("YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM", "You do not have an active team")
	ErrYouAreNotAllowedToCreateANewTeamMember                        = ec("YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER", "You are not allowed to create a new member")
	ErrYouAreNotAllowedToRemoveATeamMember                           = ec("YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER", "You are not allowed to remove a team member")
	ErrYouAreNotAllowedToAccessThisOrganization                      = ec("YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION", "You are not allowed to access this organization as an owner")
	ErrYouAreNotAMemberOfThisOrganization                            = ec("YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION", "You are not a member of this organization")
	ErrMissingAcInstance                                             = ec("MISSING_AC_INSTANCE", "Dynamic Access Control requires a pre-defined ac instance on the server auth plugin. Read server logs for more information")
	ErrYouMustBeInAnOrganizationToCreateARole                        = ec("YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE", "You must be in an organization to create a role")
	ErrYouAreNotAllowedToCreateARole                                 = ec("YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE", "You are not allowed to create a role")
	ErrYouAreNotAllowedToUpdateARole                                 = ec("YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE", "You are not allowed to update a role")
	ErrYouAreNotAllowedToDeleteARole                                 = ec("YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE", "You are not allowed to delete a role")
	ErrYouAreNotAllowedToReadARole                                   = ec("YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE", "You are not allowed to read a role")
	ErrYouAreNotAllowedToListARole                                   = ec("YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE", "You are not allowed to list a role")
	ErrYouAreNotAllowedToGetARole                                    = ec("YOU_ARE_NOT_ALLOWED_TO_GET_A_ROLE", "You are not allowed to get a role")
	ErrTooManyRoles                                                  = ec("TOO_MANY_ROLES", "This organization has too many roles")
	ErrInvalidResource                                               = ec("INVALID_RESOURCE", "The provided permission includes an invalid resource")
	ErrRoleNameIsAlreadyTaken                                        = ec("ROLE_NAME_IS_ALREADY_TAKEN", "That role name is already taken")
	ErrCannotDeleteAPreDefinedRole                                   = ec("CANNOT_DELETE_A_PRE_DEFINED_ROLE", "Cannot delete a pre-defined role")
	ErrRoleIsAssignedToMembers                                       = ec("ROLE_IS_ASSIGNED_TO_MEMBERS", "Cannot delete a role that is assigned to members. Please reassign the members to a different role first")
	ErrInvalidTeamId                                                 = ec("INVALID_TEAM_ID", "Team id contains a reserved character")
)

// ErrorCodes lists every organization error code in declaration order.
var ErrorCodes = []betterauth.ErrorCode{
	ErrYouAreNotAllowedToCreateANewOrganization,
	ErrYouHaveReachedTheMaximumNumberOfOrganizations,
	ErrOrganizationAlreadyExists,
	ErrOrganizationSlugAlreadyTaken,
	ErrOrganizationNotFound,
	ErrUserIsNotAMemberOfTheOrganization,
	ErrYouAreNotAllowedToUpdateThisOrganization,
	ErrYouAreNotAllowedToDeleteThisOrganization,
	ErrNoActiveOrganization,
	ErrUserIsAlreadyAMemberOfThisOrganization,
	ErrMemberNotFound,
	ErrRoleNotFound,
	ErrYouAreNotAllowedToCreateANewTeam,
	ErrTeamAlreadyExists,
	ErrTeamNotFound,
	ErrYouCannotLeaveTheOrganizationAsTheOnlyOwner,
	ErrYouCannotLeaveTheOrganizationWithoutAnOwner,
	ErrYouAreNotAllowedToDeleteThisMember,
	ErrYouAreNotAllowedToInviteUsersToThisOrganization,
	ErrUserIsAlreadyInvitedToThisOrganization,
	ErrInvitationNotFound,
	ErrYouAreNotTheRecipientOfTheInvitation,
	ErrEmailVerificationRequiredBeforeAcceptingOrRejectingInvitation,
	ErrEmailVerificationRequiredForInvitation,
	ErrYouAreNotAllowedToCancelThisInvitation,
	ErrInviterIsNoLongerAMemberOfTheOrganization,
	ErrYouAreNotAllowedToInviteUserWithThisRole,
	ErrFailedToRetrieveInvitation,
	ErrYouHaveReachedTheMaximumNumberOfTeams,
	ErrUnableToRemoveLastTeam,
	ErrYouAreNotAllowedToUpdateThisMember,
	ErrOrganizationMembershipLimitReached,
	ErrYouAreNotAllowedToCreateTeamsInThisOrganization,
	ErrYouAreNotAllowedToDeleteTeamsInThisOrganization,
	ErrYouAreNotAllowedToUpdateThisTeam,
	ErrYouAreNotAllowedToDeleteThisTeam,
	ErrInvitationLimitReached,
	ErrTeamMemberLimitReached,
	ErrUserIsNotAMemberOfTheTeam,
	ErrYouCanNotAccessTheMembersOfThisTeam,
	ErrYouDoNotHaveAnActiveTeam,
	ErrYouAreNotAllowedToCreateANewTeamMember,
	ErrYouAreNotAllowedToRemoveATeamMember,
	ErrYouAreNotAllowedToAccessThisOrganization,
	ErrYouAreNotAMemberOfThisOrganization,
	ErrMissingAcInstance,
	ErrYouMustBeInAnOrganizationToCreateARole,
	ErrYouAreNotAllowedToCreateARole,
	ErrYouAreNotAllowedToUpdateARole,
	ErrYouAreNotAllowedToDeleteARole,
	ErrYouAreNotAllowedToReadARole,
	ErrYouAreNotAllowedToListARole,
	ErrYouAreNotAllowedToGetARole,
	ErrTooManyRoles,
	ErrInvalidResource,
	ErrRoleNameIsAlreadyTaken,
	ErrCannotDeleteAPreDefinedRole,
	ErrRoleIsAssignedToMembers,
	ErrInvalidTeamId,
}
