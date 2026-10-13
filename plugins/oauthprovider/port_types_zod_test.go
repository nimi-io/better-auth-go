package oauthprovider

import (
	"strings"
	"testing"
)

// Port of types/zod.test.ts.

func mxSafeURL(v string) []zIssue {
	_, issues := zParse(safeURL(), v)
	return issues
}

func mxResourceURI(v string) bool {
	_, issues := zParse(resourceURI(), v)
	return len(issues) == 0
}

func TestMx_SafeUrlSchema(t *testing.T) {
	accept := func(t *testing.T, v string) {
		t.Helper()
		if is := mxSafeURL(v); len(is) > 0 {
			t.Fatalf("%s rejected: %v", v, is)
		}
	}
	reject := func(t *testing.T, v, msg string) {
		t.Helper()
		is := mxSafeURL(v)
		if len(is) == 0 {
			t.Fatalf("%s accepted", v)
		}
		if msg != "" && !strings.Contains(is[0].Message, msg) {
			t.Fatalf("%s: message %q does not contain %q", v, is[0].Message, msg)
		}
	}
	t.Run("HTTPS enforcement", func(t *testing.T) {
		t.Run("should accept HTTPS URLs", func(t *testing.T) { accept(t, "https://example.com/callback") })
		t.Run("should accept HTTP localhost", func(t *testing.T) { accept(t, "http://localhost:3000/api/auth/callback") })
		t.Run("should accept HTTP 127.0.0.1", func(t *testing.T) { accept(t, "http://127.0.0.1:8080/callback") })
		t.Run("should accept HTTP [::1] (IPv6 localhost)", func(t *testing.T) { accept(t, "http://[::1]:3000/callback") })
		t.Run("should reject HTTP for non-localhost domains", func(t *testing.T) { reject(t, "http://example.com/callback", "HTTPS") })
		t.Run("should reject HTTP for IP addresses other than 127.0.0.1", func(t *testing.T) { reject(t, "http://192.168.1.1/callback", "") })
		t.Run("should reject HTTP localhost.evil.com (subdomain attack)", func(t *testing.T) { reject(t, "http://localhost.evil.com/callback", "") })
		t.Run("should reject HTTP 127.0.0.1.evil.com (subdomain attack)", func(t *testing.T) { reject(t, "http://127.0.0.1.evil.com/callback", "") })
	})
	t.Run("dangerous schemes", func(t *testing.T) {
		t.Run("should reject javascript: scheme", func(t *testing.T) { reject(t, "javascript:alert(1)", "javascript:") })
		t.Run("should reject data: scheme", func(t *testing.T) { reject(t, "data:text/html,<script>", "data:") })
		t.Run("should reject vbscript: scheme", func(t *testing.T) { reject(t, "vbscript:msgbox", "vbscript:") })
	})
	t.Run("custom schemes (mobile apps)", func(t *testing.T) {
		t.Run("should accept custom schemes for mobile apps", func(t *testing.T) { accept(t, "myapp://oauth/callback") })
	})
	t.Run("URL parsing", func(t *testing.T) {
		t.Run("should reject URLs with fragments", func(t *testing.T) { reject(t, "https://api.example.com#frag", "") })
		t.Run("should reject URLs with a bare trailing fragment marker", func(t *testing.T) { reject(t, "https://api.example.com/cb#", "") })
		t.Run("should reject invalid URLs", func(t *testing.T) { reject(t, "not-a-valid-url", "") })
		t.Run("should reject empty strings", func(t *testing.T) { reject(t, "", "") })
	})
}

func TestMx_ResourceUriSchema(t *testing.T) {
	t.Run("accepts an HTTPS absolute URI", func(t *testing.T) {
		if !mxResourceURI("https://api.example.com") {
			t.Fatal("rejected")
		}
	})
	t.Run("accepts a non-loopback HTTP absolute URI (not HTTPS-restricted)", func(t *testing.T) {
		if !mxResourceURI("http://internal.svc/api") {
			t.Fatal("rejected")
		}
	})
	t.Run("accepts a urn resource identifier", func(t *testing.T) {
		if !mxResourceURI("urn:example:api") {
			t.Fatal("rejected")
		}
	})
	t.Run("rejects a fragment, including a bare trailing marker", func(t *testing.T) {
		if mxResourceURI("https://api.example.com#x") || mxResourceURI("https://api.example.com#") {
			t.Fatal("accepted")
		}
	})
	t.Run("rejects a relative (non-absolute) URI", func(t *testing.T) {
		if mxResourceURI("/api") {
			t.Fatal("accepted")
		}
	})
	t.Run("rejects dangerous schemes", func(t *testing.T) {
		if mxResourceURI("javascript:alert(1)") {
			t.Fatal("accepted")
		}
	})
}
