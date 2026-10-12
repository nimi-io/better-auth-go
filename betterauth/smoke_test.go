package betterauth

import "testing"

func TestSmokeSignUpSessionSignOut(t *testing.T) {
	env := newTestEnv(t, nil)
	c := env.client()
	res := c.signUp("test@example.com", "password1234", "Test User")
	body := res.JSON(t)
	if body["token"] == nil {
		t.Fatalf("expected token: %s", res.Body)
	}
	user := body["user"].(map[string]any)
	if user["email"] != "test@example.com" || user["emailVerified"] != false {
		t.Fatalf("unexpected user %v", user)
	}
	if _, ok := res.cookie("better-auth.session_token"); !ok {
		t.Fatalf("no session cookie: %v", res.Header)
	}
	s := c.session()
	if s == nil || s["user"].(map[string]any)["email"] != "test@example.com" {
		t.Fatalf("session: %v", s)
	}
	out := c.post("/sign-out", map[string]any{})
	if out.Status != 200 || string(out.Body) != `{"success":true}` {
		t.Fatalf("sign-out: %d %s", out.Status, out.Body)
	}
	if s := c.session(); s != nil {
		t.Fatalf("expected no session after sign out: %v", s)
	}
}
