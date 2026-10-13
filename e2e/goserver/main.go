// Command goserver runs the Go Better Auth server used by the e2e suite. The PROFILE
// environment variable selects a configuration that mirrors e2e/servers/ts-server.mjs.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nimi-io/better-auth-go/adapter/mongodb"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
	_ "modernc.org/sqlite"

	"github.com/nimi-io/better-auth-go/adapter/memory"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/providers/apple"
	"github.com/nimi-io/better-auth-go/providers/atlassian"
	"github.com/nimi-io/better-auth-go/providers/cloudflare"
	"github.com/nimi-io/better-auth-go/providers/cognito"
	"github.com/nimi-io/better-auth-go/providers/discord"
	"github.com/nimi-io/better-auth-go/providers/dropbox"
	"github.com/nimi-io/better-auth-go/providers/facebook"
	"github.com/nimi-io/better-auth-go/providers/figma"
	"github.com/nimi-io/better-auth-go/providers/github"
	"github.com/nimi-io/better-auth-go/providers/gitlab"
	"github.com/nimi-io/better-auth-go/providers/google"
	"github.com/nimi-io/better-auth-go/providers/huggingface"
	"github.com/nimi-io/better-auth-go/providers/kakao"
	"github.com/nimi-io/better-auth-go/providers/kick"
	"github.com/nimi-io/better-auth-go/providers/line"
	"github.com/nimi-io/better-auth-go/providers/linear"
	"github.com/nimi-io/better-auth-go/providers/linkedin"
	"github.com/nimi-io/better-auth-go/providers/microsoft"
	"github.com/nimi-io/better-auth-go/providers/naver"
	"github.com/nimi-io/better-auth-go/providers/notion"
	"github.com/nimi-io/better-auth-go/providers/paybin"
	"github.com/nimi-io/better-auth-go/providers/paypal"
	"github.com/nimi-io/better-auth-go/providers/polar"
	"github.com/nimi-io/better-auth-go/providers/railway"
	"github.com/nimi-io/better-auth-go/providers/reddit"
	"github.com/nimi-io/better-auth-go/providers/roblox"
	"github.com/nimi-io/better-auth-go/providers/salesforce"
	"github.com/nimi-io/better-auth-go/providers/slack"
	"github.com/nimi-io/better-auth-go/providers/spotify"
	"github.com/nimi-io/better-auth-go/providers/tiktok"
	"github.com/nimi-io/better-auth-go/providers/twitch"
	"github.com/nimi-io/better-auth-go/providers/twitter"
	"github.com/nimi-io/better-auth-go/providers/vercel"
	"github.com/nimi-io/better-auth-go/providers/vk"
	"github.com/nimi-io/better-auth-go/providers/wechat"
	"github.com/nimi-io/better-auth-go/providers/zoom"
)

// idpTransport rewrites https://host/path to <target>/host/path (the mock IdP).
type idpTransport struct{ target string }

func (t idpTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme == "https" {
		u, err := url.Parse(t.target + "/" + r.URL.Host + r.URL.Path)
		if err != nil {
			return nil, err
		}
		u.RawQuery = r.URL.RawQuery
		r = r.Clone(r.Context())
		r.URL = u
		r.Host = u.Host
	}
	return http.DefaultTransport.RoundTrip(r)
}

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
	case "shared":
		// Shares DB_URL with the TypeScript server (database compatibility tests).
		cfg.Database = sharedDatabase(os.Getenv("DB_URL"))
	case "oauth":
		if idp := os.Getenv("IDP_URL"); idp != "" {
			oauth2.HTTPClient.Transport = idpTransport{target: idp}
		}
		cfg.SocialProviders = []oauth2.Provider{
			github.New(github.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "gh-client", ClientSecret: "gh-secret"}}),
			google.New(google.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "google-client", ClientSecret: "google-secret"}}),
			// The remaining providers are only exercised for authorization-URL parity.
			apple.New(apple.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "apple-client", ClientSecret: "apple-secret"}}),
			atlassian.New(atlassian.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "atlassian-client", ClientSecret: "atlassian-secret"}}),
			cloudflare.New(cloudflare.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "cloudflare-client", ClientSecret: "cloudflare-secret"}}),
			cognito.New(cognito.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "cognito-client", ClientSecret: "cognito-secret"}, Domain: "auth.example.com", Region: "us-east-1", UserPoolID: "us-east-1_pool"}),
			discord.New(discord.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "discord-client", ClientSecret: "discord-secret"}}),
			dropbox.New(dropbox.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "dropbox-client", ClientSecret: "dropbox-secret"}}),
			facebook.New(facebook.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "facebook-client", ClientSecret: "facebook-secret"}}),
			figma.New(figma.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "figma-client", ClientSecret: "figma-secret"}}),
			gitlab.New(gitlab.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "gitlab-client", ClientSecret: "gitlab-secret"}}),
			huggingface.New(huggingface.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "huggingface-client", ClientSecret: "huggingface-secret"}}),
			kakao.New(kakao.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "kakao-client", ClientSecret: "kakao-secret"}}),
			kick.New(kick.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "kick-client", ClientSecret: "kick-secret"}}),
			line.New(line.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "line-client", ClientSecret: "line-secret"}}),
			linear.New(linear.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "linear-client", ClientSecret: "linear-secret"}}),
			linkedin.New(linkedin.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "linkedin-client", ClientSecret: "linkedin-secret"}}),
			microsoft.New(microsoft.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "microsoft-client", ClientSecret: "microsoft-secret"}, TenantID: "e2e-tenant"}),
			naver.New(naver.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "naver-client", ClientSecret: "naver-secret"}}),
			notion.New(notion.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "notion-client", ClientSecret: "notion-secret"}}),
			paybin.New(paybin.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "paybin-client", ClientSecret: "paybin-secret"}}),
			paypal.New(paypal.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "paypal-client", ClientSecret: "paypal-secret"}}),
			polar.New(polar.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "polar-client", ClientSecret: "polar-secret"}}),
			railway.New(railway.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "railway-client", ClientSecret: "railway-secret"}}),
			reddit.New(reddit.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "reddit-client", ClientSecret: "reddit-secret"}}),
			roblox.New(roblox.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "roblox-client", ClientSecret: "roblox-secret"}}),
			salesforce.New(salesforce.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "salesforce-client", ClientSecret: "salesforce-secret"}}),
			slack.New(slack.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "slack-client", ClientSecret: "slack-secret"}}),
			spotify.New(spotify.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "spotify-client", ClientSecret: "spotify-secret"}}),
			tiktok.New(tiktok.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "tiktok-client", ClientSecret: "tiktok-secret", ClientKey: "tiktok-key"}}),
			twitch.New(twitch.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "twitch-client", ClientSecret: "twitch-secret"}}),
			twitter.New(twitter.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "twitter-client", ClientSecret: "twitter-secret"}}),
			vercel.New(vercel.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "vercel-client", ClientSecret: "vercel-secret"}}),
			vk.New(vk.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "vk-client", ClientSecret: "vk-secret"}}),
			wechat.New(wechat.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "wechat-client", ClientSecret: "wechat-secret"}}),
			zoom.New(zoom.Options{ProviderOptions: oauth2.ProviderOptions{ClientID: "zoom-client", ClientSecret: "zoom-secret"}}),
		}
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
	if os.Getenv("MIGRATE") == "1" {
		if err := auth.RunMigrations(context.Background()); err != nil {
			log.Fatalf("migrate: %v", err)
		}
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

// sharedDatabase opens DB_URL: "sqlite:<path>", "postgres://..." or "mysql://user:pass@host:port/db".
func sharedDatabase(dbURL string) adapter.Factory {
	var (
		conn *sql.DB
		err  error
	)
	switch {
	case strings.HasPrefix(dbURL, "sqlite:"):
		conn, err = sql.Open("sqlite", "file:"+strings.TrimPrefix(dbURL, "sqlite:")+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	case strings.HasPrefix(dbURL, "postgres://"), strings.HasPrefix(dbURL, "postgresql://"):
		conn, err = sql.Open("pgx", dbURL)
	case strings.HasPrefix(dbURL, "mysql://"):
		u, perr := url.Parse(dbURL)
		if perr != nil {
			log.Fatal(perr)
		}
		pw, _ := u.User.Password()
		conn, err = sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)%s?parseTime=true", u.User.Username(), pw, u.Host, u.Path))
	case strings.HasPrefix(dbURL, "mongodb://"):
		u, perr := url.Parse(dbURL)
		if perr != nil {
			log.Fatal(perr)
		}
		client, cerr := mongo.Connect(options.Client().ApplyURI(dbURL))
		if cerr != nil {
			log.Fatal(cerr)
		}
		return mongodb.New(client.Database(strings.TrimPrefix(u.Path, "/")), mongodb.Config{Client: client})
	default:
		log.Fatalf("unsupported DB_URL %q", dbURL)
	}
	if err != nil {
		log.Fatal(err)
	}
	return sqladapter.New(conn, sqladapter.Config{})
}
