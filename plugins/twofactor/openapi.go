package twofactor

import "github.com/nimi-io/better-auth-go/jsonx"

// OpenAPI metadata, transcribed from the upstream endpoint definitions.

func o(kv ...any) *jsonx.Object { return jsonx.O(kv...) }

func jsonResponse(description string, schema *jsonx.Object) *jsonx.Object {
	return o("200", o("description", description, "content", o("application/json", o("schema", schema))))
}

func statusBoolSchema() *jsonx.Object {
	return o("type", "object", "properties", o("status", o("type", "boolean")))
}

func openapi(kv ...any) map[string]any { return map[string]any{"openapi": o(kv...)} }

func userProperties(withTwoFactor bool) *jsonx.Object {
	p := o(
		"id", o("type", "string", "description", "Unique identifier of the user"),
		"email", o("type", "string", "format", "email", "nullable", true, "description", "User's email address"),
		"emailVerified", o("type", "boolean", "nullable", true, "description", "Whether the email is verified"),
		"name", o("type", "string", "nullable", true, "description", "User's name"),
		"image", o("type", "string", "format", "uri", "nullable", true, "description", "User's profile image URL"),
	)
	if withTwoFactor {
		p.Set("twoFactorEnabled", o("type", "boolean", "description", "Whether two-factor authentication is enabled for the user"))
	}
	p.Set("createdAt", o("type", "string", "format", "date-time", "description", "Timestamp when the user was created"))
	p.Set("updatedAt", o("type", "string", "format", "date-time", "description", "Timestamp when the user was last updated"))
	return p
}

func enableMetadata() map[string]any {
	return openapi(
		"summary", "Enable two factor authentication",
		"description", "Enable two factor authentication. Pass method 'totp' (default) to set up an authenticator app (returns TOTP URI and backup codes), or 'otp' to enable email/SMS-based codes immediately.",
		"responses", jsonResponse("Successful response", o(
			"type", "object",
			"properties", o(
				"method", o("type", "string", "enum", []any{"otp", "totp"}, "description", "The 2FA method that was enabled."),
				"totpURI", o("type", "string", "description", "TOTP URI for authenticator app setup. Only present when method is 'totp'."),
				"backupCodes", o("type", "array", "items", o("type", "string"), "description", "Recovery backup codes. Only present when method is 'totp'."),
			),
			"required", []any{"method"},
		)),
	)
}

func disableMetadata() map[string]any {
	return openapi(
		"summary", "Disable two factor authentication",
		"description", "Use this endpoint to disable two factor authentication.",
		"responses", jsonResponse("Successful response", statusBoolSchema()),
	)
}

func generateTOTPMetadata() map[string]any {
	return openapi(
		"summary", "Generate TOTP code",
		"description", "Use this endpoint to generate a TOTP code",
		"responses", jsonResponse("Successful response", o("type", "object", "properties", o("code", o("type", "string")))),
	)
}

func getTOTPURIMetadata() map[string]any {
	return openapi(
		"summary", "Get TOTP URI",
		"description", "Use this endpoint to get the TOTP URI",
		"responses", jsonResponse("Successful response", o("type", "object", "properties", o("totpURI", o("type", "string")))),
	)
}

func verifyTOTPMetadata() map[string]any {
	return openapi(
		"summary", "Verify two factor TOTP",
		"description", "Verify two factor TOTP",
		"responses", jsonResponse("Successful response", statusBoolSchema()),
	)
}

func sendOTPMetadata() map[string]any {
	return openapi(
		"summary", "Send two factor OTP",
		"description", "Send two factor OTP to the user",
		"responses", jsonResponse("Successful response", statusBoolSchema()),
	)
}

func verifyOTPMetadata() map[string]any {
	return openapi(
		"summary", "Verify two factor OTP",
		"description", "Verify two factor OTP",
		"responses", jsonResponse("Two-factor OTP verified successfully", o(
			"type", "object",
			"properties", o(
				"token", o("type", "string", "description", "Session token for the authenticated session"),
				"user", o(
					"type", "object",
					"properties", userProperties(false),
					"required", []any{"id", "createdAt", "updatedAt"},
					"description", "The authenticated user object",
				),
			),
			"required", []any{"token", "user"},
		)),
	)
}

func verifyBackupCodeMetadata() map[string]any {
	return openapi(
		"description", "Verify a backup code for two-factor authentication",
		"responses", jsonResponse("Backup code verified successfully", o(
			"type", "object",
			"properties", o(
				"user", o(
					"type", "object",
					"properties", userProperties(true),
					"required", []any{"id", "twoFactorEnabled", "createdAt", "updatedAt"},
					"description", "The authenticated user object with two-factor details",
				),
				"session", o(
					"type", "object",
					"properties", o(
						"token", o("type", "string", "description", "Session token"),
						"userId", o("type", "string", "description", "ID of the user associated with the session"),
						"createdAt", o("type", "string", "format", "date-time", "description", "Timestamp when the session was created"),
						"expiresAt", o("type", "string", "format", "date-time", "description", "Timestamp when the session expires"),
					),
					"required", []any{"token", "userId", "createdAt", "expiresAt"},
					"description", "The current session object, included unless disableSession is true",
				),
			),
			"required", []any{"user", "session"},
		)),
	)
}

func generateBackupCodesMetadata() map[string]any {
	return openapi(
		"description", "Generate new backup codes for two-factor authentication",
		"responses", jsonResponse("Backup codes generated successfully", o(
			"type", "object",
			"properties", o(
				"status", o("type", "boolean", "description", "Indicates if the backup codes were generated successfully", "enum", []any{true}),
				"backupCodes", o("type", "array", "items", o("type", "string"), "description", "Array of generated backup codes in plain text"),
			),
			"required", []any{"status", "backupCodes"},
		)),
	)
}
