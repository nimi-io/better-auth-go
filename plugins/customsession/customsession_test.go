package customsession_test

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/customsession"
	"github.com/nimi-io/better-auth-go/plugins/multisession"
)

func applySetCookies(h http.Header, res *response) {
	for _, sc := range res.Header.Values("Set-Cookie") {
		n, v, _ := betterauth.ParseSetCookie(sc)
		betterauth.SetRequestCookie(h, n, v)
	}
}

func helloFn(_ *betterauth.EndpointContext, s *betterauth.SessionWithUser) (any, error) {
	parts := strings.Split(s.User.Name, " ")
	user := jsonx.O("firstName", parts[0])
	if len(parts) > 1 {
		user.Set("lastName", parts[1])
	}
	return jsonx.O("user", user, "newData", jsonx.O("message", "Hello, World!"), "session", s.Session), nil
}

func passthrough(_ *betterauth.EndpointContext, s *betterauth.SessionWithUser) (any, error) {
	return jsonx.O("user", s.User, "session", s.Session), nil
}

func TestCustomSession(t *testing.T) {
	in := newInstance(t, func(c *betterauth.Config) {
		c.Session = &betterauth.SessionConfig{UpdateAge: betterauth.Duration(0),
			CookieCache: &betterauth.CookieCacheConfig{Enabled: true, MaxAge: 10 * time.Second}}
		c.Plugins = append(c.Plugins, multisession.New(),
			customsession.New(helloFn, customsession.Options{ShouldMutateListDeviceSessionsEndpoint: true}))
	})

	t.Run("should return the session", func(t *testing.T) {
		h := in.signInWithTestUser()
		res, err := in.auth.API.Call(context.Background(), "getSession", betterauth.CallInput{Headers: h})
		if err != nil {
			t.Fatal(err)
		}
		var api map[string]any
		if err := res.Decode(&api); err != nil {
			t.Fatal(err)
		}
		s := in.do("GET", "/get-session", nil, h).json(t)
		want := map[string]any{"message": "Hello, World!"}
		if !equalJSON(s["newData"], want) || !equalJSON(api["newData"], want) {
			t.Fatalf("http %v api %v", s, api)
		}
		// API.GetSession still exposes the underlying session.
		if sw, _ := in.auth.API.GetSession(context.Background(), h); sw == nil || sw.User.Email != in.email {
			t.Fatalf("GetSession %+v", sw)
		}
	})
	t.Run("should return set cookie headers as separate entries", func(t *testing.T) {
		res := in.do("GET", "/get-session", nil, in.signInWithTestUser())
		sc := res.Header.Values("Set-Cookie")
		joined := strings.Join(sc, "; ")
		if len(sc) < 2 || !strings.Contains(joined, "better-auth.session_token") || !strings.Contains(joined, "better-auth.session_data") {
			t.Fatalf("set-cookie %v", sc)
		}
	})
	t.Run("should not double-encode session cookie during get-session refresh", func(t *testing.T) {
		h := in.signInWithTestUser()
		signed := regexp.MustCompile(`better-auth\.session_token=([^;]+)`).FindStringSubmatch(h.Get("Cookie"))[1]
		res := in.do("GET", "/get-session", nil, h)
		var refreshed string
		for _, sc := range res.Header.Values("Set-Cookie") {
			if n, _, _ := betterauth.ParseSetCookie(sc); n == "better-auth.session_token" {
				refreshed = strings.SplitN(strings.SplitN(sc, ";", 2)[0], "=", 2)[1]
				break
			}
		}
		if refreshed == "" || refreshed != signed || strings.Contains(refreshed, "%25") {
			t.Fatalf("refreshed %q signed %q", refreshed, signed)
		}
	})
	t.Run("should return the custom session for multi-session", func(t *testing.T) {
		h := http.Header{}
		res := in.do("POST", "/sign-up/email", map[string]any{"name": "Name", "email": "second-email@test.com", "password": "password"}, nil)
		applySetCookies(h, res)
		r, err := in.auth.API.Call(context.Background(), "listDeviceSessions", betterauth.CallInput{Headers: h})
		if err != nil {
			t.Fatal(err)
		}
		var list []map[string]any
		if err := r.Decode(&list); err != nil {
			t.Fatal(err)
		}
		if len(list) == 0 || !equalJSON(list[0]["newData"], map[string]any{"message": "Hello, World!"}) {
			t.Fatalf("list %v", list)
		}
	})
	t.Run("should accept disableRefresh as a query string without validation error", func(t *testing.T) {
		res := in.do("GET", "/get-session?disableRefresh=true", nil, in.signInWithTestUser())
		if res.Status != 200 || string(res.Body) == "null" {
			t.Fatalf("%d %s", res.Status, res.Body)
		}
	})
	t.Run("should not comma-join Set-Cookie headers", func(t *testing.T) {
		res := in.do("GET", "/get-session", nil, in.signInWithTestUser())
		for _, c := range res.Header.Values("Set-Cookie") {
			n := 0
			for _, p := range strings.Split(c, ";") {
				if strings.HasPrefix(strings.ToLower(strings.SplitN(strings.TrimSpace(p), "=", 2)[0]), "better-auth.") {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("cookie %q", c)
			}
		}
	})
}

func TestCustomSessionCookieMaxAge(t *testing.T) {
	t.Run("should preserve individual cookie Max-Age when cookieCache is enabled", func(t *testing.T) {
		const expiresIn, cacheMaxAge = 86400, 300
		in := newInstance(t, func(c *betterauth.Config) {
			c.Session = &betterauth.SessionConfig{ExpiresIn: expiresIn * time.Second, UpdateAge: betterauth.Duration(0),
				CookieCache: &betterauth.CookieCacheConfig{Enabled: true, MaxAge: cacheMaxAge * time.Second}}
			c.Plugins = append(c.Plugins, customsession.New(passthrough))
		})
		res := in.do("GET", "/get-session", nil, in.signInWithTestUser())
		var tokenC, dataC string
		for _, c := range res.Header.Values("Set-Cookie") {
			if strings.Contains(c, "better-auth.session_token") {
				tokenC = c
			}
			if strings.Contains(c, "better-auth.session_data") {
				dataC = c
			}
		}
		re := regexp.MustCompile(`(?i)Max-Age=(\d+)`)
		tm, dm := re.FindStringSubmatch(tokenC), re.FindStringSubmatch(dataC)
		if tm == nil || dm == nil {
			t.Fatalf("cookies %q %q", tokenC, dataC)
		}
		tv, _ := strconv.Atoi(tm[1])
		dv, _ := strconv.Atoi(dm[1])
		if tv <= expiresIn-10 || tv > expiresIn || dv != cacheMaxAge || tv == dv {
			t.Fatalf("token max-age %d data max-age %d", tv, dv)
		}
	})
	t.Run("should preserve partitioned cookie attributes during get-session refresh", func(t *testing.T) {
		in := newInstance(t, func(c *betterauth.Config) {
			c.Advanced = &betterauth.AdvancedConfig{DefaultCookieAttributes: &betterauth.CookieAttributes{
				Partitioned: betterauth.Bool(true), SameSite: betterauth.StrPtr("none"), Secure: betterauth.Bool(true), HTTPOnly: betterauth.Bool(true)}}
			c.Session = &betterauth.SessionConfig{UpdateAge: betterauth.Duration(0)}
			c.Plugins = append(c.Plugins, customsession.New(passthrough))
		})
		res := in.do("GET", "/get-session", nil, in.signInWithTestUser())
		n := 0
		for _, c := range res.Header.Values("Set-Cookie") {
			name, _, attrs := betterauth.ParseSetCookie(c)
			if !strings.HasPrefix(name, "better-auth.") {
				continue
			}
			n++
			if _, ok := attrs["partitioned"]; !ok {
				t.Fatalf("cookie %q not partitioned", c)
			}
		}
		if n == 0 {
			t.Fatalf("no refreshed cookies: %v", res.Header.Values("Set-Cookie"))
		}
	})
	t.Run("should not create memory leaks with multiple plugin instances", func(t *testing.T) {
		t.Skip("TypeScript-only: V8 heap measurement with --expose-gc")
	})
	t.Run("should infer the session type", func(t *testing.T) {
		t.Skip("TypeScript-only: type inference")
	})
	t.Run("should not add user/session to client getSession type when custom session omits them", func(t *testing.T) {
		t.Skip("TypeScript-only: client type inference")
	})
	t.Run("should infer both customSessionClient and inferAdditionalFields when combined", func(t *testing.T) {
		t.Skip("TypeScript-only: client type inference")
	})
}

func TestCustomSessionSignedOut(t *testing.T) {
	calls := 0
	in := newInstance(t, func(c *betterauth.Config) {
		c.Plugins = append(c.Plugins, customsession.New(func(ctx *betterauth.EndpointContext, s *betterauth.SessionWithUser) (any, error) {
			calls++
			return passthrough(ctx, s)
		}))
	})
	if res := in.do("GET", "/get-session", nil, nil); string(res.Body) != "null" {
		t.Fatalf("signed out %s", res.Body)
	}
	// session middlewares resolve the core session without calling the function
	h := in.signInWithTestUser()
	if res := in.do("GET", "/list-sessions", nil, h); res.Status != 200 {
		t.Fatalf("list-sessions %d %s", res.Status, res.Body)
	}
	if calls != 0 {
		t.Fatalf("custom function called %d times by session middleware", calls)
	}
}

func equalJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
