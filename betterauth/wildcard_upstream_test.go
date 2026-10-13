package betterauth

import "testing"

// Expected values produced by better-auth@1.7.7's wildcardMatch(pattern)(sample).
func TestWildcardMatchMatchesUpstream(t *testing.T) {
	for _, c := range []struct {
		pattern, sample string
		want            bool
	}{
		{"/sign-in/*", "/sign-in/email", true},
		{"/sign-in/*", "/sign-in/email/x", false},
		{"/sign-in/**", "/sign-in/email/x", true},
		{"https://*.example.com", "https://a.example.com", true},
		{"https://*.example.com", "https://a.b.example.com", true},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "evil.com/a.example.com", false},
		{"/api/*/x", "/api/a/x", true},
		{"a?c", "abc", true},
		{"a?c", "a/c", false},
		{"**/x", "a/b/x", true},
		{"/x/", "/x", false},
		{"http://localhost:*", "http://localhost:3000", true},
		{"/two-factor/*", "/two-factor/enable", true},
		{"*", "a/b", false},
		{"exp://**", "exp://192.168.1.1:8081/--/home", true},
	} {
		if got := wildcardMatch(c.pattern, c.sample); got != c.want {
			t.Errorf("wildcardMatch(%q)(%q) = %v, want %v", c.pattern, c.sample, got, c.want)
		}
	}
}
