package oauthprovider

import (
	"strings"
	"testing"
)

// Port of oauth-endpoint.test.ts.

func mxIssues(s zSchema, v map[string]any) []zIssue {
	_, issues := zParse(s, v)
	return issues
}

func mxExpectMapped(t *testing.T, gotCode, gotDesc, code, desc string) {
	t.Helper()
	if gotCode != code || (desc != "" && gotDesc != desc) {
		t.Fatalf("got {%s, %s}, want {%s, %s}", gotCode, gotDesc, code, desc)
	}
}

func TestMx_MapIssuesToOAuthError(t *testing.T) {
	t.Run("returns defaultError when issue list is empty", func(t *testing.T) {
		code, desc := mapIssuesToOAuthError(nil, nil, "")
		mxExpectMapped(t, code, desc, "invalid_request", "Invalid request.")
	})
	t.Run("honors custom defaultError when no mapping matches", func(t *testing.T) {
		issues := mxIssues(zObject("strip", nil, zf("foo", zString())), map[string]any{})
		code, desc := mapIssuesToOAuthError(issues, nil, "invalid_client_metadata")
		mxExpectMapped(t, code, desc, "invalid_client_metadata", "foo is required")
	})
	t.Run("applies string field mapping to both missing and invalid cases", func(t *testing.T) {
		s := zObject("strip", nil, zf("redirect_uris", zArray(zString(), 1)))
		mapping := map[string]fieldErrorCodes{"redirect_uris": {All: "invalid_redirect_uri"}}
		code, _ := mapIssuesToOAuthError(mxIssues(s, map[string]any{}), mapping, "")
		if code != "invalid_redirect_uri" {
			t.Fatalf("missing: %s", code)
		}
		code, _ = mapIssuesToOAuthError(mxIssues(s, map[string]any{"redirect_uris": "nope"}), mapping, "")
		if code != "invalid_redirect_uri" {
			t.Fatalf("invalid: %s", code)
		}
	})
	t.Run("distinguishes missing from invalid when mapping uses object form", func(t *testing.T) {
		s := zObject("strip", nil, zf("grant_type", zStringEnum("authorization_code", "client_credentials", "refresh_token")))
		mapping := map[string]fieldErrorCodes{"grant_type": {Missing: "invalid_request", Invalid: "unsupported_grant_type"}}
		code, desc := mapIssuesToOAuthError(mxIssues(s, map[string]any{}), mapping, "")
		mxExpectMapped(t, code, desc, "invalid_request", "grant_type is required")
		code, _ = mapIssuesToOAuthError(mxIssues(s, map[string]any{"grant_type": "password"}), mapping, "")
		if code != "unsupported_grant_type" {
			t.Fatalf("invalid: %s", code)
		}
	})
	t.Run("falls back to the other object mapping half when only one is defined", func(t *testing.T) {
		s := zObject("strip", nil, zf("token_type_hint", zOptional(zEnum("access_token", "refresh_token"))))
		code, _ := mapIssuesToOAuthError(mxIssues(s, map[string]any{"token_type_hint": "id_token"}),
			map[string]fieldErrorCodes{"token_type_hint": {Invalid: "unsupported_token_type"}}, "")
		if code != "unsupported_token_type" {
			t.Fatalf("got %s", code)
		}
	})
	t.Run("describes duplicated scalar fields as appearing more than once", func(t *testing.T) {
		s := zObject("strip", nil, zf("resource", zString()))
		code, desc := mapIssuesToOAuthError(mxIssues(s, map[string]any{"resource": []any{"one", "two"}}), nil, "")
		mxExpectMapped(t, code, desc, "invalid_request", "resource must not appear more than once")
	})
	t.Run("routes duplicated fields to defaultError even when mapping.invalid is set", func(t *testing.T) {
		s := zObject("strip", nil, zf("response_type", zOptional(zStringEnum("code"))))
		code, desc := mapIssuesToOAuthError(mxIssues(s, map[string]any{"response_type": []any{"code", "token"}}),
			map[string]fieldErrorCodes{"response_type": {Invalid: "unsupported_response_type"}}, "")
		mxExpectMapped(t, code, desc, "invalid_request", "response_type must not appear more than once")
	})
	t.Run("routes unsupported enum values through mapping.invalid", func(t *testing.T) {
		s := zObject("strip", nil, zf("response_type", zOptional(zStringEnum("code"))))
		code, desc := mapIssuesToOAuthError(mxIssues(s, map[string]any{"response_type": "token"}),
			map[string]fieldErrorCodes{"response_type": {Invalid: "unsupported_response_type"}}, "")
		if code != "unsupported_response_type" || !strings.Contains(desc, "response_type") {
			t.Fatalf("got {%s, %s}", code, desc)
		}
	})
}

func TestMx_ZodV4IssueShapeContract(t *testing.T) {
	t.Run("reports missing required string as invalid_type + 'received undefined'", func(t *testing.T) {
		issues := mxIssues(zObject("strip", nil, zf("grant_type", zString())), map[string]any{})
		if len(issues) == 0 {
			t.Fatal("expected an issue")
		}
		is := issues[0]
		if is.Code != "invalid_type" || !strings.HasSuffix(is.Message, "received undefined") || !isMissingValueIssue(is) {
			t.Fatalf("issue: %+v", is)
		}
	})
	t.Run("reports duplicated string field as invalid_type + 'received array'", func(t *testing.T) {
		issues := mxIssues(zObject("strip", nil, zf("resource", zString())), map[string]any{"resource": []any{"a", "b"}})
		if len(issues) == 0 {
			t.Fatal("expected an issue")
		}
		is := issues[0]
		if is.Code != "invalid_type" || !strings.HasSuffix(is.Message, "received array") || isMissingValueIssue(is) {
			t.Fatalf("issue: %+v", is)
		}
	})
	t.Run("reports unsupported enum value as invalid_value", func(t *testing.T) {
		issues := mxIssues(zObject("strip", nil, zf("grant_type", zStringEnum("authorization_code"))), map[string]any{"grant_type": "password"})
		if len(issues) == 0 {
			t.Fatal("expected an issue")
		}
		if is := issues[0]; is.Code != "invalid_value" || isMissingValueIssue(is) {
			t.Fatalf("issue: %+v", is)
		}
	})
}
