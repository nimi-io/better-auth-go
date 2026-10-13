package admin

import "github.com/nimi-io/better-auth-go/betterauth"

func ec(code, message string) betterauth.ErrorCode {
	return betterauth.ErrorCode{Code: code, Message: message}
}

// Error codes (ADMIN_ERROR_CODES).
var (
	ErrFailedToCreateUser                   = ec("FAILED_TO_CREATE_USER", "Failed to create user")
	ErrUserAlreadyExists                    = ec("USER_ALREADY_EXISTS", "User already exists.")
	ErrUserAlreadyExistsUseAnotherEmail     = ec("USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL", "User already exists. Use another email.")
	ErrYouCannotBanYourself                 = ec("YOU_CANNOT_BAN_YOURSELF", "You cannot ban yourself")
	ErrNotAllowedToChangeUsersRole          = ec("YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE", "You are not allowed to change users role")
	ErrNotAllowedToCreateUsers              = ec("YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS", "You are not allowed to create users")
	ErrNotAllowedToListUsers                = ec("YOU_ARE_NOT_ALLOWED_TO_LIST_USERS", "You are not allowed to list users")
	ErrNotAllowedToListUsersSessions        = ec("YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS", "You are not allowed to list users sessions")
	ErrNotAllowedToBanUsers                 = ec("YOU_ARE_NOT_ALLOWED_TO_BAN_USERS", "You are not allowed to ban users")
	ErrNotAllowedToImpersonateUsers         = ec("YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS", "You are not allowed to impersonate users")
	ErrNotAllowedToRevokeUsersSessions      = ec("YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS", "You are not allowed to revoke users sessions")
	ErrNotAllowedToDeleteUsers              = ec("YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS", "You are not allowed to delete users")
	ErrNotAllowedToSetUsersPassword         = ec("YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD", "You are not allowed to set users password")
	ErrBannedUser                           = ec("BANNED_USER", "You have been banned from this application")
	ErrNotAllowedToGetUser                  = ec("YOU_ARE_NOT_ALLOWED_TO_GET_USER", "You are not allowed to get user")
	ErrNoDataToUpdate                       = ec("NO_DATA_TO_UPDATE", "No data to update")
	ErrNotAllowedToUpdateUsers              = ec("YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS", "You are not allowed to update users")
	ErrYouCannotRemoveYourself              = ec("YOU_CANNOT_REMOVE_YOURSELF", "You cannot remove yourself")
	ErrNotAllowedToSetNonExistentValue      = ec("YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE", "You are not allowed to set a non-existent role value")
	ErrYouCannotImpersonateAdmins           = ec("YOU_CANNOT_IMPERSONATE_ADMINS", "You cannot impersonate admins")
	ErrInvalidRoleType                      = ec("INVALID_ROLE_TYPE", "Invalid role type")
	ErrNotAllowedToSetUsersEmail            = ec("YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL", "You are not allowed to update users email")
	ErrPasswordCannotBeUpdatedViaUpdateUser = ec("PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER", "Password cannot be updated through update-user. Use the set-user-password endpoint instead")
)

// ErrorCodes lists every admin error code in declaration order ($ERROR_CODES).
var ErrorCodes = []betterauth.ErrorCode{
	ErrFailedToCreateUser, ErrUserAlreadyExists, ErrUserAlreadyExistsUseAnotherEmail,
	ErrYouCannotBanYourself, ErrNotAllowedToChangeUsersRole, ErrNotAllowedToCreateUsers,
	ErrNotAllowedToListUsers, ErrNotAllowedToListUsersSessions, ErrNotAllowedToBanUsers,
	ErrNotAllowedToImpersonateUsers, ErrNotAllowedToRevokeUsersSessions, ErrNotAllowedToDeleteUsers,
	ErrNotAllowedToSetUsersPassword, ErrBannedUser, ErrNotAllowedToGetUser, ErrNoDataToUpdate,
	ErrNotAllowedToUpdateUsers, ErrYouCannotRemoveYourself, ErrNotAllowedToSetNonExistentValue,
	ErrYouCannotImpersonateAdmins, ErrInvalidRoleType, ErrNotAllowedToSetUsersEmail,
	ErrPasswordCannotBeUpdatedViaUpdateUser,
}
