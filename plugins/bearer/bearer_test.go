package bearer_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/bearer"
)

func auth(v string) http.Header {
	h := http.Header{}
	h.Set("Authorization", v)
	return h
}

func TestBearer(t *testing.T) {
	in := newInstance(t, nil, instanceOpts{disableTestUser: true})
	var token string

	t.Run("should get session", func(t *testing.T) {
		res := in.do("POST", "/sign-up/email", map[string]any{"email": in.email, "password": in.password, "name": in.name}, nil)
		token = res.Header.Get("set-auth-token")
		if token == "" {
			t.Fatalf("no set-auth-token: %v", res.Header)
		}
		if !strings.Contains(res.Header.Get("Access-Control-Expose-Headers"), "set-auth-token") {
			t.Fatalf("expose headers %q", res.Header.Get("Access-Control-Expose-Headers"))
		}
		s := in.do("GET", "/get-session", nil, auth("Bearer "+token)).json(t)
		if s["session"] == nil {
			t.Fatal("no session")
		}
	})
	t.Run("should list session", func(t *testing.T) {
		res := in.do("GET", "/list-sessions", nil, auth("Bearer "+token))
		if res.Status != 200 || strings.Count(string(res.Body), `"token"`) != 1 {
			t.Fatalf("%d %s", res.Status, res.Body)
		}
	})
	t.Run("should work on server actions", func(t *testing.T) {
		h := http.Header{}
		h.Set("authorization", "Bearer "+token)
		s, err := in.auth.API.GetSession(context.Background(), h)
		if err != nil || s == nil || s.Session == nil {
			t.Fatalf("session %v %v", s, err)
		}
	})
	t.Run("should work with ", func(t *testing.T) {
		s := in.do("GET", "/get-session", nil, auth("Bearer "+strings.Split(token, ".")[0])).json(t)
		if s["session"] == nil {
			t.Fatal("no session")
		}
	})
	t.Run("should work if valid cookie is provided even if authorization header isn't valid", func(t *testing.T) {
		h := auth("Bearer invalid.token")
		h.Set("Cookie", "better-auth.session_token="+token)
		s := in.do("GET", "/get-session", nil, h).json(t)
		if s["session"] == nil {
			t.Fatal("no session")
		}
	})
	for _, c := range [][2]string{{"lowercase 'bearer'", "bearer"}, {"uppercase 'BEARER'", "BEARER"}, {"mixed case 'BeArEr'", "BeArEr"}, {"extra whitespace", "Bearer "}} {
		t.Run("should work with "+c[0]+" prefix (RFC 7235)", func(t *testing.T) {
			s, err := in.auth.API.GetSession(context.Background(), auth(c[1]+" "+token))
			if err != nil || s == nil {
				t.Fatalf("session %v %v", s, err)
			}
		})
	}
	for _, c := range []struct {
		name string
		fn   func(string) string
	}{
		{"Raw (already URL-encoded from header)", func(s string) string { return s }},
		{"URL-decoded", func(s string) string { d, _ := url.PathUnescape(s); return d }},
		{"URL-encoded", betterauth.EncodeURIComponent},
	} {
		t.Run("should work with "+c.name+" token", func(t *testing.T) {
			s, err := in.auth.API.GetSession(context.Background(), auth("Bearer "+c.fn(token)))
			if err != nil || s == nil {
				t.Fatalf("session %v %v", s, err)
			}
		})
	}
}

func TestBearerRequireSignature(t *testing.T) {
	in := newInstance(t, func(c *betterauth.Config) {
		c.Plugins = append(c.Plugins, bearer.New(bearer.Options{RequireSignature: true}))
	}, instanceOpts{disableTestUser: true})
	res := in.do("POST", "/sign-up/email", map[string]any{"email": in.email, "password": in.password, "name": in.name}, nil)
	token := res.Header.Get("set-auth-token")
	unsigned := strings.Split(token, ".")[0]
	// The default bearer plugin from the test instance accepts unsigned tokens; a separate
	// instance with only requireSignature verifies they are rejected.
	t.Setenv("NODE_ENV", "test")
	a, err := betterauth.New(betterauth.Config{BaseURL: in.baseURL, Secret: testSecret, Database: in.auth.Options().Database,
		Logger: betterauth.NopLogger{}, EmailAndPassword: &betterauth.EmailAndPasswordConfig{Enabled: true},
		Plugins: []*betterauth.Plugin{bearer.New(bearer.Options{RequireSignature: true})}})
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := a.API.GetSession(context.Background(), auth("Bearer "+unsigned)); s != nil {
		t.Fatal("unsigned token accepted with requireSignature")
	}
	if s, _ := a.API.GetSession(context.Background(), auth("Bearer "+token)); s == nil {
		t.Fatal("signed token rejected")
	}
}

func TestBearerDoesNotMutateCallerHeaders(t *testing.T) {
	in := newInstance(t, nil, instanceOpts{disableTestUser: true})
	res := in.do("POST", "/sign-up/email", map[string]any{"email": in.email, "password": in.password, "name": in.name}, nil)
	h := auth("Bearer " + res.Header.Get("set-auth-token"))
	if s, _ := in.auth.API.GetSession(context.Background(), h); s == nil {
		t.Fatal("no session")
	}
	if h.Get("Cookie") != "" {
		t.Fatalf("caller headers mutated: %v", h)
	}
}
