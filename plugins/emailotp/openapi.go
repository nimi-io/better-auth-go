package emailotp

import "github.com/nimi-io/better-auth-go/jsonx"

// OpenAPI metadata of the endpoints (metadata.openapi upstream).

func jsonResponse(description string, schema *jsonx.Object) *jsonx.Object {
	return jsonx.O("description", description, "content", jsonx.O("application/json", jsonx.O("schema", schema)))
}

func openapi(operationID, description string, status any, resp *jsonx.Object) map[string]any {
	o := jsonx.O()
	if operationID != "" {
		o.Set("operationId", operationID)
	}
	key := "200"
	if s, ok := status.(string); ok {
		key = s
	}
	o.Set("description", description)
	o.Set("responses", jsonx.O(key, resp))
	return map[string]any{"openapi": o}
}

func successBoolSchema(description string) *jsonx.Object {
	prop := jsonx.O("type", "boolean")
	if description != "" {
		prop.Set("description", description)
	}
	return jsonx.O("type", "object", "properties", jsonx.O("success", prop))
}

var (
	metaSendVerificationOTP = openapi("sendEmailVerificationOTP", "Send a verification OTP to an email", nil,
		jsonResponse("Success", successBoolSchema("")))
	metaCreateVerificationOTP = openapi("createEmailVerificationOTP", "Create a verification OTP for an email", nil,
		jsonResponse("Success", jsonx.O("type", "string")))
	metaGetVerificationOTP = openapi("getEmailVerificationOTP", "Get a verification OTP for an email", "200",
		jsonResponse("OTP retrieved successfully or not found/expired", jsonx.O(
			"type", "object",
			"properties", jsonx.O("otp", jsonx.O("type", "string", "nullable", true, "description", "The stored OTP, or null if not found or expired")),
			"required", []any{"otp"},
		)))
	metaCheckVerificationOTP = openapi("verifyEmailWithOTP", "Verify an email with an OTP", nil,
		jsonResponse("Success", successBoolSchema("")))
	metaVerifyEmailOTP = openapi("", "Verify email with OTP", nil,
		jsonResponse("Success", jsonx.O(
			"type", "object",
			"properties", jsonx.O(
				"status", jsonx.O("type", "boolean", "description", "Indicates if the verification was successful", "enum", []any{true}),
				"token", jsonx.O("type", "string", "nullable", true, "description", "Session token if autoSignInAfterVerification is enabled, otherwise null"),
				"user", jsonx.O("$ref", "#/components/schemas/User"),
			),
			"required", []any{"status", "token", "user"},
		)))
	metaSignInEmailOTP = openapi("signInWithEmailOTP", "Sign in with email and OTP", nil,
		jsonResponse("Success", jsonx.O(
			"type", "object",
			"properties", jsonx.O(
				"token", jsonx.O("type", "string", "description", "Session token for the authenticated session"),
				"user", jsonx.O("$ref", "#/components/schemas/User"),
			),
			"required", []any{"token", "user"},
		)))
	metaRequestPasswordReset = openapi("requestPasswordResetWithEmailOTP", "Request password reset with email and OTP", nil,
		jsonResponse("Success", successBoolSchema("Indicates if the OTP was sent successfully")))
	metaForgetPassword = openapi("forgetPasswordWithEmailOTP", "Deprecated: Use /email-otp/request-password-reset instead.", nil,
		jsonResponse("Success", successBoolSchema("Indicates if the OTP was sent successfully")))
	metaResetPassword = openapi("resetPasswordWithEmailOTP", "Reset password with email and OTP", nil,
		jsonResponse("Success", successBoolSchema("")))
	metaRequestEmailChange = openapi("requestEmailChangeWithEmailOTP", "Request email change with verification OTP sent to the new email", nil,
		jsonResponse("Success", successBoolSchema("")))
	metaChangeEmail = openapi("changeEmailWithEmailOTP", "Verify new email with OTP and change the email if verification is successful", nil,
		jsonResponse("Success", successBoolSchema("")))
)
