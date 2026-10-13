package multisession_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/multisession"
)

// applySetCookies is cookieSetter (setCookieToHeader).
func applySetCookies(h http.Header, res *response) {
	for _, sc := range res.Header.Values("Set-Cookie") {
		n, v, _ := betterauth.ParseSetCookie(sc)
		betterauth.SetRequestCookie(h, n, v)
	}
}

type setCookie struct {
	value  string
	maxAge string
	has    bool
}

// parsedSetCookies mirrors parseSetCookieHeader (last entry per name wins).
func parsedSetCookies(res *response) map[string]setCookie {
	out := map[string]setCookie{}
	for _, sc := range res.Header.Values("Set-Cookie") {
		n, v, attrs := betterauth.ParseSetCookie(sc)
		out[n] = setCookie{value: v, maxAge: attrs["max-age"], has: true}
	}
	return out
}

func tokenOf(res *response) string {
	return strings.Split(parsedSetCookies(res)["better-auth.session_token"].value, ".")[0]
}

func deviceSessions(t *testing.T, in *instance, h http.Header) []map[string]map[string]any {
	t.Helper()
	res := in.do("GET", "/multi-session/list-device-sessions", nil, h)
	if res.Status != 200 {
		t.Fatalf("list %d %s", res.Status, res.Body)
	}
	var out []map[string]map[string]any
	if err := json.Unmarshal(res.Body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func body(email, password, name string) map[string]any {
	return map[string]any{"email": email, "password": password, "name": name}
}

func TestMultiSession(t *testing.T) {
	in := newInstance(t, func(c *betterauth.Config) {
		c.Plugins = append(c.Plugins, multisession.New(multisession.Options{MaximumSessions: 2}))
	})
	headers := http.Header{}
	user2 := body("second-email@test.com", "password", "Name")

	t.Run("should set multi session when there is set-cookie header", func(t *testing.T) {
		res := in.do("POST", "/sign-in/email", map[string]any{"email": in.email, "password": in.password}, nil)
		cookies := parsedSetCookies(res)
		tok := tokenOf(res)
		multi := cookies["better-auth.session_token_multi-"+strings.ToLower(tok)]
		if tok == "" || !multi.has || !strings.Contains(multi.value, tok) {
			t.Fatalf("set-cookie %v", res.Header.Values("Set-Cookie"))
		}
		applySetCookies(headers, res)
		res = in.do("POST", "/sign-up/email", user2, nil)
		applySetCookies(headers, res)
	})
	t.Run("should get active session", func(t *testing.T) {
		s := in.do("GET", "/get-session", nil, headers).json(t)
		if s["user"].(map[string]any)["email"] != user2["email"] {
			t.Fatalf("session %v", s)
		}
	})
	var sessionToken string
	t.Run("should list all device sessions", func(t *testing.T) {
		list := deviceSessions(t, in, headers)
		for _, s := range list {
			if s["user"]["email"] == in.email {
				sessionToken, _ = s["session"]["token"].(string)
			}
		}
		if len(list) != 2 {
			t.Fatalf("sessions %d", len(list))
		}
	})
	t.Run("should set active session when only multi-session cookies are present", func(t *testing.T) {
		var parts []string
		for _, c := range strings.Split(headers.Get("Cookie"), ";") {
			c = strings.TrimSpace(c)
			if c != "" && !strings.HasPrefix(c, "better-auth.session_token=") {
				parts = append(parts, c)
			}
		}
		h := http.Header{}
		h.Set("Cookie", strings.Join(parts, "; "))
		res := in.do("POST", "/multi-session/set-active", map[string]any{"sessionToken": sessionToken}, h)
		if res.Status != 200 || res.json(t)["user"].(map[string]any)["email"] != in.email {
			t.Fatalf("%d %s", res.Status, res.Body)
		}
	})
	t.Run("should set active session", func(t *testing.T) {
		res := in.do("POST", "/multi-session/set-active", map[string]any{"sessionToken": sessionToken}, headers)
		if res.Status != 200 || res.json(t)["user"].(map[string]any)["email"] != in.email {
			t.Fatalf("%d %s", res.Status, res.Body)
		}
	})
	t.Run("should revoke a session and set the next active", func(t *testing.T) {
		res := in.do("POST", "/sign-up/email", body("my-email@email.com", "password", "Name"), nil)
		if !strings.Contains(strings.Join(res.Header.Values("Set-Cookie"), ", "), "better-auth.session_token") {
			t.Fatal("no session cookie")
		}
		token := tokenOf(res)
		rev := in.do("POST", "/multi-session/revoke", map[string]any{"sessionToken": token}, headers)
		if rev.Status == 200 && !strings.Contains(strings.Join(rev.Header.Values("Set-Cookie"), ", "), "better-auth.session_token=") {
			t.Fatal("expected the next session cookie")
		}
		if n := len(deviceSessions(t, in, headers)); n != 2 {
			t.Fatalf("sessions %d", n)
		}
	})
	t.Run("should sign-out all sessions", func(t *testing.T) {
		newHeaders := http.Header{}
		res := in.do("POST", "/sign-out", nil, headers)
		applySetCookies(newHeaders, res)
		if n := len(deviceSessions(t, in, headers)); n != 0 {
			t.Fatalf("sessions %d", n)
		}
		if n := len(deviceSessions(t, in, newHeaders)); n != 0 {
			t.Fatalf("sessions (new headers) %d", n)
		}
	})
	t.Run("should replace old multi-session cookie when same user signs in again", func(t *testing.T) {
		h := http.Header{}
		res := in.do("POST", "/sign-up/email", body("same-user@test.com", "password", "Same User"), nil)
		first := tokenOf(res)
		applySetCookies(h, res)
		count := func() []map[string]map[string]any {
			var out []map[string]map[string]any
			for _, s := range deviceSessions(t, in, h) {
				if s["user"]["email"] == "same-user@test.com" {
					out = append(out, s)
				}
			}
			return out
		}
		if n := len(count()); n != 1 {
			t.Fatalf("after first %d", n)
		}
		res = in.do("POST", "/sign-in/email", map[string]any{"email": "same-user@test.com", "password": "password"}, h)
		second := tokenOf(res)
		old := parsedSetCookies(res)["better-auth.session_token_multi-"+strings.ToLower(first)]
		if old.maxAge != "0" {
			t.Fatalf("old cookie not deleted: %v", res.Header.Values("Set-Cookie"))
		}
		applySetCookies(h, res)
		if second == first {
			t.Fatal("same token")
		}
		list := count()
		if len(list) != 1 || list[0]["session"]["token"] != second {
			t.Fatalf("after second %v", list)
		}
	})
	t.Run("should reject forged multi-session cookies on sign-out", func(t *testing.T) {
		attacker := http.Header{}
		applySetCookies(attacker, in.do("POST", "/sign-up/email", body("attacker@test.com", "password", "Attacker"), nil))
		victim := http.Header{}
		res := in.do("POST", "/sign-up/email", body("victim@test.com", "password", "Victim"), nil)
		victimToken := tokenOf(res)
		applySetCookies(victim, res)
		if in.do("GET", "/get-session", nil, attacker).json(t)["user"].(map[string]any)["email"] != "attacker@test.com" {
			t.Fatal("attacker session")
		}
		forged := http.Header{}
		forged.Set("Cookie", attacker.Get("Cookie")+"; better-auth.session_token_multi-"+strings.ToLower(victimToken)+"="+victimToken+".fake-signature")
		in.do("POST", "/sign-out", nil, forged)
		v := in.do("GET", "/get-session", nil, victim).json(t)
		if v["user"].(map[string]any)["email"] != "victim@test.com" || v["session"].(map[string]any)["token"] != victimToken {
			t.Fatalf("victim %v", v)
		}
		if a := in.do("GET", "/get-session", nil, attacker); string(a.Body) != "null" {
			t.Fatalf("attacker still signed in: %s", a.Body)
		}
	})
	t.Run("binds set-active and revoke to the signed cookie value, not the body token", func(t *testing.T) {
		caller := http.Header{}
		res := in.do("POST", "/sign-up/email", body("ms-bind-caller@test.com", "password", "Caller"), nil)
		callerToken := tokenOf(res)
		callerMulti := parsedSetCookies(res)["better-auth.session_token_multi-"+strings.ToLower(callerToken)].value
		applySetCookies(caller, res)
		other := http.Header{}
		res = in.do("POST", "/sign-up/email", body("ms-bind-other@test.com", "password", "Other"), nil)
		otherToken := tokenOf(res)
		applySetCookies(other, res)
		if callerMulti == "" || otherToken == "" {
			t.Fatal("missing cookies")
		}
		crafted := http.Header{}
		crafted.Set("Cookie", caller.Get("Cookie")+"; better-auth.session_token_multi-"+strings.ToLower(otherToken)+"="+betterauth.EncodeURIComponent(callerMulti))
		in.do("POST", "/multi-session/revoke", map[string]any{"sessionToken": otherToken}, crafted)
		o := in.do("GET", "/get-session", nil, other).json(t)
		if o["session"].(map[string]any)["token"] != otherToken {
			t.Fatalf("other %v", o)
		}
	})
}

func TestMultiSessionInvalidToken(t *testing.T) {
	in := newInstance(t, func(c *betterauth.Config) { c.Plugins = append(c.Plugins, multisession.New()) })
	h := in.signInWithTestUser()
	res := in.do("POST", "/multi-session/set-active", map[string]any{"sessionToken": "nope"}, h)
	m := res.json(t)
	if res.Status != 401 || m["code"] != "INVALID_SESSION_TOKEN" || m["message"] != "Invalid session token" {
		t.Fatalf("%d %s", res.Status, res.Body)
	}
	if res := in.do("POST", "/multi-session/set-active", map[string]any{}, h); res.Status != 400 {
		t.Fatalf("validation %d %s", res.Status, res.Body)
	}
}
