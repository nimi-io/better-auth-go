// Command goserver runs the Go Better Auth server used by the e2e suite. The PROFILE
// environment variable selects a configuration that mirrors e2e/servers/ts-server.mjs.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
)

type email struct {
	Type  string `json:"type"`
	To    string `json:"to"`
	URL   string `json:"url"`
	Token string `json:"token"`
}

type mailbox struct {
	mu     sync.Mutex
	emails []email
}

func (m *mailbox) add(e email) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.emails = append(m.emails, e)
}

func (m *mailbox) last(to, typ string) *email {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.emails) - 1; i >= 0; i-- {
		e := m.emails[i]
		if (to == "" || strings.EqualFold(e.To, to)) && (typ == "" || e.Type == typ) {
			return &e
		}
	}
	return nil
}

func config(profile, baseURL string, mb *mailbox) betterauth.Config {
	capture := func(typ string) func(ctx context.Context, d betterauth.EmailData, r *http.Request) error {
		return func(_ context.Context, d betterauth.EmailData, _ *http.Request) error {
			mb.add(email{Type: typ, To: d.User.Email, URL: d.URL, Token: d.Token})
			return nil
		}
	}
	cfg := betterauth.Config{
		BaseURL:  baseURL,
		Secret:   "e2e-secret-that-is-long-enough-for-better-auth-tests",
		Database: memory.New(),
		Logger:   betterauth.NewLogger("error", nil),
		EmailAndPassword: &betterauth.EmailAndPasswordConfig{
			Enabled:           true,
			SendResetPassword: capture("reset-password"),
		},
		EmailVerification: &betterauth.EmailVerificationConfig{
			SendVerificationEmail: capture("verify-email"),
			SendOnSignUp:          betterauth.Bool(true),
		},
		User: &betterauth.UserConfig{
			ChangeEmail: &betterauth.ChangeEmailConfig{
				Enabled: true,
				SendChangeEmailConfirmation: func(_ context.Context, d betterauth.ChangeEmailData, _ *http.Request) error {
					mb.add(email{Type: "change-email-confirmation", To: d.User.Email, URL: d.URL, Token: d.Token})
					return nil
				},
			},
			DeleteUser: &betterauth.DeleteUserConfig{Enabled: true},
		},
		TrustedOrigins: []string{"http://trusted.example.com"},
		RateLimit:      &betterauth.RateLimitConfig{Enabled: betterauth.Bool(false)},
		Advanced:       &betterauth.AdvancedConfig{DisableOriginCheck: betterauth.Bool(false)},
	}
	switch profile {
	case "compact", "jwt", "jwe":
		cfg.Session = &betterauth.SessionConfig{CookieCache: &betterauth.CookieCacheConfig{Enabled: true, Strategy: profile, MaxAge: 5 * time.Minute}}
	case "secondary":
		cfg.SecondaryStorage = betterauth.NewMemoryStorage()
	case "ratelimit":
		cfg.RateLimit = &betterauth.RateLimitConfig{Enabled: betterauth.Bool(true), Window: 10 * time.Second, Max: 100}
	case "stateless":
		cfg.Database = nil
	case "delete-verify":
		cfg.User.DeleteUser.SendDeleteAccountVerification = capture("delete-account")
	}
	return cfg
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "4100"
	}
	profile := os.Getenv("PROFILE")
	baseURL := "http://127.0.0.1:" + port
	mb := &mailbox{}
	auth, err := betterauth.New(config(profile, baseURL, mb))
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/__test/email", func(w http.ResponseWriter, r *http.Request) {
		e := mb.last(r.URL.Query().Get("to"), r.URL.Query().Get("type"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(e)
	})
	mux.HandleFunc("/__test/hash", func(w http.ResponseWriter, r *http.Request) {
		h, _ := bacrypto.HashPassword(r.URL.Query().Get("password"))
		_ = json.NewEncoder(w).Encode(map[string]string{"hash": h})
	})
	mux.HandleFunc("/__test/verify", func(w http.ResponseWriter, r *http.Request) {
		ok, err := bacrypto.VerifyPassword(r.URL.Query().Get("hash"), r.URL.Query().Get("password"))
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": ok, "error": errString(err)})
	})
	mux.HandleFunc("/__test/session", func(w http.ResponseWriter, r *http.Request) {
		s, err := auth.API.GetSession(r.Context(), r.Header)
		w.Header().Set("Content-Type", "application/json")
		if err != nil || s == nil {
			_, _ = w.Write([]byte("null"))
			return
		}
		_ = json.NewEncoder(w).Encode(s)
	})
	mux.HandleFunc("/__test/health", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	log.Printf("go better-auth e2e server on %s (profile=%q)", baseURL, profile)
	// Route /api/auth without ServeMux so non-canonical paths (e.g. "//ok") reach the
	// Better Auth router unmodified, as they do on the Node server.
	root := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/auth") {
			auth.Handler().ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
	log.Fatal(http.ListenAndServe("127.0.0.1:"+port, root))
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
