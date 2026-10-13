package scim

// Port of scim-sso-http-e2e.test.ts (SCIM-provisioned SSO authentication over HTTP). The
// oauth2-mock-server identity provider is replaced by an in-process httptest OpenID
// provider (discovery, JWKS, authorize, token and userinfo endpoints), the same approach
// as the plugins/sso test helpers.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/adapter/sqladapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/sso"
)

const (
	ssoE2EUserSchema           = "urn:ietf:params:scim:schemas:core:2.0:User"
	ssoE2EPatchSchema          = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	ssoE2EMediaType            = "application/scim+json"
	ssoE2EWorkforceConnection  = "workforce"
	ssoE2EWorkforceToken       = "workforce-scim-token"
	ssoE2EContractorConnection = "contractors"
	ssoE2EContractorToken      = "contractors-scim-token"
	ssoE2EExternalID           = "directory-user-1"
)

// ---- in-process OpenID provider ----

type ssoE2EOIDCProvider struct {
	server *httptest.Server
	URL    string
	key    *rsa.PrivateKey
	keyID  string
	mu     sync.Mutex
	nonces map[string]string
}

func ssoE2ENewOIDCProvider(t *testing.T) *ssoE2EOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m := &ssoE2EOIDCProvider{key: key, keyID: "mock-key", nonces: map[string]string{}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m.server = httptest.NewUnstartedServer(http.HandlerFunc(m.serve))
	m.server.Listener = ln
	m.server.Start()
	t.Cleanup(m.server.Close)
	m.URL = "http://localhost:" + fmt.Sprint(ln.Addr().(*net.TCPAddr).Port)
	return m
}

func ssoE2EWriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (m *ssoE2EOIDCProvider) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		ssoE2EWriteJSON(w, 200, map[string]any{
			"issuer":                                m.URL,
			"authorization_endpoint":                m.URL + "/authorize",
			"token_endpoint":                        m.URL + "/token",
			"userinfo_endpoint":                     m.URL + "/userinfo",
			"jwks_uri":                              m.URL + "/jwks",
			"end_session_endpoint":                  m.URL + "/endsession",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic", "client_secret_post"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"subject_types_supported":               []string{"public"},
			"scopes_supported":                      []string{"openid", "email", "profile"},
			"code_challenge_methods_supported":      []string{"plain", "S256"},
		})
	case "/jwks":
		j, _ := jose.JWKFromPublicKey(&m.key.PublicKey)
		j.Kid, j.Alg, j.Use = m.keyID, "RS256", "sig"
		ssoE2EWriteJSON(w, 200, jose.JWKS{Keys: []jose.JWK{j}})
	case "/authorize":
		q := r.URL.Query()
		code := bacrypto.RandomString(16)
		m.mu.Lock()
		m.nonces[code] = q.Get("nonce")
		m.mu.Unlock()
		target, _ := url.Parse(q.Get("redirect_uri"))
		tq := target.Query()
		tq.Set("code", code)
		if s := q.Get("state"); s != "" {
			tq.Set("state", s)
		}
		target.RawQuery = tq.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
	case "/token":
		_ = r.ParseForm()
		m.mu.Lock()
		nonce := m.nonces[r.PostForm.Get("code")]
		m.mu.Unlock()
		clientID := r.PostForm.Get("client_id")
		if u, _, ok := r.BasicAuth(); ok {
			clientID, _ = url.QueryUnescape(u)
		}
		now := float64(time.Now().Unix())
		p := jsonx.NewObject()
		p.Set("iss", m.URL)
		p.Set("aud", clientID)
		p.Set("iat", now)
		p.Set("exp", now+3600)
		p.Set("nbf", now-10)
		if nonce != "" {
			p.Set("nonce", nonce)
		}
		// beforeTokenSigning
		p.Set("sub", ssoE2EExternalID)
		p.Set("email", "employee@identity-provider.example")
		p.Set("name", "Identity Provider Employee")
		p.Set("email_verified", true)
		tok, err := jose.SignJWT(jsonx.O("alg", "RS256", "kid", m.keyID, "typ", "JWT"), p, m.key)
		if err != nil {
			ssoE2EWriteJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		ssoE2EWriteJSON(w, 200, map[string]any{
			"access_token":  "mock-access-token-" + bacrypto.RandomString(8),
			"token_type":    "Bearer",
			"expires_in":    3600,
			"scope":         "openid email profile",
			"refresh_token": "mock-refresh-token",
			"id_token":      tok,
		})
	case "/userinfo":
		// beforeUserinfo
		ssoE2EWriteJSON(w, 200, map[string]any{
			"sub":            ssoE2EExternalID,
			"email":          "employee@identity-provider.example",
			"name":           "Identity Provider Employee",
			"email_verified": true,
		})
	default:
		http.NotFound(w, r)
	}
}

// ---- HTTP helpers ----

var ssoE2EClient = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// ssoE2EJar is a name → value cookie jar (the CookieJar map of the upstream test).
type ssoE2EJar map[string]string

func (j ssoE2EJar) store(res *http.Response) {
	for _, sc := range res.Header.Values("Set-Cookie") {
		cookie := strings.SplitN(sc, ";", 2)[0]
		i := strings.Index(cookie, "=")
		if i < 1 {
			continue
		}
		name, value := cookie[:i], cookie[i+1:]
		if value != "" {
			j[name] = value
		} else {
			delete(j, name)
		}
	}
}

func (j ssoE2EJar) header() string {
	parts := make([]string, 0, len(j))
	for k, v := range j {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, "; ")
}

type ssoE2EResponse struct {
	status int
	header http.Header
	body   []byte
}

func ssoE2EDo(t *testing.T, method, rawURL string, headers map[string]string, body any) *ssoE2EResponse {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Error(err)
			return &ssoE2EResponse{}
		}
		rd = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, rawURL, rd)
	if err != nil {
		t.Error(err)
		return &ssoE2EResponse{}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := ssoE2EClient.Do(req)
	if err != nil {
		t.Error(err)
		return &ssoE2EResponse{}
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return &ssoE2EResponse{status: res.StatusCode, header: res.Header, body: b}
}

func ssoE2ESCIMHeaders(token string) map[string]string {
	return map[string]string{"Accept": ssoE2EMediaType, "Authorization": "Bearer " + token, "Content-Type": ssoE2EMediaType}
}

// ssoE2EListen opens a listener before the auth instance is built (so baseURL matches);
// ssoE2EServe then serves the instance on it.
func ssoE2EListen(t *testing.T) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln, "http://" + ln.Addr().String()
}

func ssoE2EServe(t *testing.T, ln net.Listener, e *testEnv) {
	t.Helper()
	srv := httptest.NewUnstartedServer(e.auth.Handler())
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
}

// ssoE2EPausingDB wraps the transaction adapter so incrementOne on scimSubject can pause.
type ssoE2EPausingDB struct {
	db    adapter.Adapter
	pause func()
}

func (d ssoE2EPausingDB) FindOne(ctx context.Context, in adapter.FindOneInput) (adapter.Record, error) {
	return d.db.FindOne(ctx, in)
}

func (d ssoE2EPausingDB) IncrementOne(ctx context.Context, in adapter.IncrementInput) (adapter.Record, error) {
	if in.Model == "scimSubject" {
		d.pause()
	}
	return d.db.IncrementOne(ctx, in)
}

type ssoE2EPause struct {
	reached chan struct{}
	release chan struct{}
}

func TestSSOE2EProvisionedAuthentication(t *testing.T) {
	t.Run("authenticates only the active User owned by the paired SCIM connection", func(t *testing.T) {
		t.Setenv("NODE_ENV", "test")
		idp := ssoE2ENewOIDCProvider(t)

		var pauseMu sync.Mutex
		var resolverPause *ssoE2EPause
		takePause := func() {
			pauseMu.Lock()
			p := resolverPause
			resolverPause = nil
			pauseMu.Unlock()
			if p != nil {
				close(p.reached)
				<-p.release
			}
		}

		dbPath := filepath.Join(t.TempDir(), "auth.sqlite")
		dsn := "file:" + dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
		openDB := func() *sql.DB {
			conn, err := sql.Open("sqlite", dsn)
			if err != nil {
				t.Fatal(err)
			}
			// node:sqlite DatabaseSync is a single connection.
			conn.SetMaxOpenConns(1)
			t.Cleanup(func() { conn.Close() })
			return conn
		}
		mainConn, lifecycleConn := openDB(), openDB()

		scimOptions := func() Options {
			return Options{Connections: []ConnectionOptions{
				{ID: ssoE2EWorkforceConnection, Credentials: []BearerCredential{{Type: "bearer", ID: "workforce-token", Token: ssoE2EWorkforceToken}}},
				{ID: ssoE2EContractorConnection, Credentials: []BearerCredential{{Type: "bearer", ID: "contractors-token", Token: ssoE2EContractorToken}}},
			}}
		}

		ssoPlugin := sso.New(sso.Options{
			DisableImplicitSignUp: true,
			DefaultSSO: []sso.DefaultSSOProvider{{
				Domain:     "example.com",
				ProviderID: "workforce",
				OIDCConfig: &sso.OIDCConfig{
					Issuer:            idp.URL,
					ClientID:          "workforce-client",
					ClientSecret:      "workforce-secret",
					PKCE:              false,
					DiscoveryEndpoint: idp.URL + "/.well-known/openid-configuration",
				},
			}},
			ResolveUser: func(ctx context.Context, in sso.UserResolutionInput, rc sso.UserResolutionContext) (sso.UserResolution, error) {
				if in.ProviderID != "workforce" {
					return sso.UserResolution{Action: "continue"}, nil
				}
				link, err := AcquireActiveUserLink(ctx, UserExternalIDReference{
					ConnectionID: ssoE2EWorkforceConnection,
					ExternalID:   in.AccountKey.AccountID,
				}, ssoE2EPausingDB{db: rc.Adapter, pause: takePause})
				if err != nil {
					return sso.UserResolution{}, err
				}
				if link != nil {
					return sso.UserResolution{Action: "link", UserID: link.UserID, Profile: "preserve"}, nil
				}
				msg := "This directory user is not active"
				return sso.UserResolution{Action: "reject", Code: "SCIM_USER_NOT_ACTIVE", Message: &msg}, nil
			},
		})

		mainLn, mainBase := ssoE2EListen(t)
		instance := newEnv(t, scimOptions(), envOptions{
			sqlite:       true,
			baseURL:      mainBase,
			extraPlugins: []*betterauth.Plugin{ssoPlugin},
			mutate: func(cfg *betterauth.Config) {
				cfg.Database = sqladapter.New(mainConn, sqladapter.Config{Transaction: betterauth.Bool(true)})
				cfg.TrustedOrigins = []string{idp.URL}
			},
		})
		ssoE2EServe(t, mainLn, instance)
		lifecycleLn, lifecycleBase := ssoE2EListen(t)
		lifecycle := newEnv(t, scimOptions(), envOptions{
			sqlite:  true,
			baseURL: lifecycleBase,
			mutate: func(cfg *betterauth.Config) {
				cfg.Database = sqladapter.New(lifecycleConn, sqladapter.Config{Transaction: betterauth.Bool(true)})
			},
		})
		ssoE2EServe(t, lifecycleLn, lifecycle)

		count := func(model string) int64 {
			t.Helper()
			n, err := lifecycle.db().Count(context.Background(), model, nil)
			if err != nil {
				t.Fatalf("count %s: %v", model, err)
			}
			return n
		}
		instanceCount := func(model string) int64 {
			t.Helper()
			n, err := instance.db().Count(context.Background(), model, nil)
			if err != nil {
				t.Fatalf("count %s: %v", model, err)
			}
			return n
		}

		provisionSCIMUser := func(token, userName string) map[string]any {
			t.Helper()
			res := ssoE2EDo(t, "POST", lifecycleBase+"/api/auth/scim/v2/Users", ssoE2ESCIMHeaders(token), map[string]any{
				"schemas":    []string{ssoE2EUserSchema},
				"externalId": ssoE2EExternalID,
				"userName":   userName,
				"name":       map[string]any{"formatted": "Provisioned Employee"},
				"active":     true,
			})
			if res.status != 201 {
				t.Fatalf("provision: %d %s", res.status, res.body)
			}
			var m map[string]any
			_ = json.Unmarshal(res.body, &m)
			return m
		}
		// setSCIMUserActive returns an error instead of failing so the paused resolver is always released.
		setSCIMUserActive := func(userID string, active bool) error {
			res := ssoE2EDo(t, "PATCH", lifecycleBase+"/api/auth/scim/v2/Users/"+url.PathEscape(userID), ssoE2ESCIMHeaders(ssoE2EWorkforceToken), map[string]any{
				"schemas":    []string{ssoE2EPatchSchema},
				"Operations": []map[string]any{{"op": "replace", "path": "active", "value": active}},
			})
			if res.status != 200 {
				return fmt.Errorf("set active %v: %d %s", active, res.status, res.body)
			}
			return nil
		}
		mustSetActive := func(userID string, active bool) {
			t.Helper()
			if err := setSCIMUserActive(userID, active); err != nil {
				t.Fatal(err)
			}
		}
		deleteSCIMUser := func(userID string) {
			t.Helper()
			res := ssoE2EDo(t, "DELETE", lifecycleBase+"/api/auth/scim/v2/Users/"+url.PathEscape(userID), ssoE2ESCIMHeaders(ssoE2EWorkforceToken), nil)
			if res.status != 204 {
				t.Fatalf("delete: %d %s", res.status, res.body)
			}
		}

		type flow struct {
			callbackURL string
			cookies     ssoE2EJar
		}
		type signIn struct {
			status   int
			location string
			cookies  ssoE2EJar
		}
		// initiateSSO / completeSSO use t.Error (safe from goroutines) and return ok.
		initiateSSO := func() (flow, bool) {
			cookies := ssoE2EJar{}
			req, _ := http.NewRequest("POST", mainBase+"/api/auth/sign-in/sso", strings.NewReader(
				`{"providerId":"workforce","callbackURL":"`+mainBase+`/employee"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", mainBase)
			res, err := ssoE2EClient.Do(req)
			if err != nil {
				t.Error(err)
				return flow{}, false
			}
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			cookies.store(res)
			if res.StatusCode != 200 {
				t.Errorf("sign-in/sso: %d %s", res.StatusCode, body)
				return flow{}, false
			}
			var signInBody struct {
				URL string `json:"url"`
			}
			_ = json.Unmarshal(body, &signInBody)
			auth, err := ssoE2EClient.Get(signInBody.URL)
			if err != nil {
				t.Error(err)
				return flow{}, false
			}
			auth.Body.Close()
			loc := auth.Header.Get("Location")
			if loc == "" {
				t.Error("OIDC provider did not return a callback URL")
				return flow{}, false
			}
			return flow{callbackURL: loc, cookies: cookies}, true
		}
		completeSSO := func(f flow) signIn {
			req, _ := http.NewRequest("GET", f.callbackURL, nil)
			req.Header.Set("Cookie", f.cookies.header())
			res, err := ssoE2EClient.Do(req)
			if err != nil {
				t.Error(err)
				return signIn{cookies: f.cookies}
			}
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode != 302 {
				t.Errorf("callback status %d %s", res.StatusCode, body)
			}
			f.cookies.store(res)
			return signIn{status: res.StatusCode, location: res.Header.Get("Location"), cookies: f.cookies}
		}
		signInWithSSO := func() signIn {
			t.Helper()
			f, ok := initiateSSO()
			if !ok {
				t.FailNow()
			}
			return completeSSO(f)
		}
		type sessionUser struct {
			ID    string `json:"id"`
			Email string `json:"email"`
			Name  string `json:"name"`
		}
		type sessionResponse struct {
			User sessionUser `json:"user"`
		}
		getSession := func(cookies ssoE2EJar) *sessionResponse {
			t.Helper()
			res := ssoE2EDo(t, "GET", mainBase+"/api/auth/get-session", map[string]string{"Cookie": cookies.header()}, nil)
			if res.status != 200 {
				t.Fatalf("get-session: %d %s", res.status, res.body)
			}
			var s *sessionResponse
			if err := json.Unmarshal(res.body, &s); err != nil {
				t.Fatalf("get-session body %s: %v", res.body, err)
			}
			return s
		}
		errorParam := func(location string) string {
			t.Helper()
			base, _ := url.Parse(mainBase)
			u, err := base.Parse(location)
			if err != nil {
				t.Fatalf("location %q: %v", location, err)
			}
			return u.Query().Get("error")
		}
		type records struct{ users, accounts, sessions int64 }
		recordCounts := func() records {
			return records{count("user"), count("account"), count("session")}
		}
		expectRejectedSignIn := func() {
			t.Helper()
			before := recordCounts()
			s := signInWithSSO()
			if s.location == "" {
				t.Fatal("SSO rejection did not redirect")
			}
			if got := errorParam(s.location); got != "SCIM_USER_NOT_ACTIVE" {
				t.Fatalf("rejection error = %q (location %s)", got, s.location)
			}
			if sess := getSession(s.cookies); sess != nil {
				t.Fatalf("session after rejection: %+v", sess)
			}
			if after := recordCounts(); after != before {
				t.Fatalf("records changed on rejection: %+v -> %+v", before, after)
			}
		}
		type fence struct {
			subject, connection any
		}
		getFenceRevisions := func() fence {
			t.Helper()
			ctx := context.Background()
			subject, err := lifecycle.db().FindOne(ctx, adapter.FindOneInput{Model: "scimSubject"})
			if err != nil {
				t.Fatal(err)
			}
			conn, err := lifecycle.db().FindOne(ctx, adapter.FindOneInput{Model: "scimConnectionBinding",
				Where: []adapter.Where{{Field: "connectionId", Value: ssoE2EWorkforceConnection}}})
			if err != nil {
				t.Fatal(err)
			}
			var f fence
			if subject != nil {
				f.subject = fmt.Sprint(subject["revision"])
			}
			if conn != nil {
				f.connection = fmt.Sprint(conn["decommissionRevision"])
			}
			return f
		}

		provisioned := provisionSCIMUser(ssoE2EWorkforceToken, "provisioned.employee@example.com")
		provisionedSCIMID, _ := provisioned["id"].(string)
		if n := count("user"); n != 1 {
			t.Fatalf("users = %d", n)
		}
		if n := count("account"); n != 0 {
			t.Fatalf("accounts = %d", n)
		}

		// A deactivation committed while the resolver holds the link conflicts with it.
		pause := &ssoE2EPause{reached: make(chan struct{}), release: make(chan struct{})}
		pauseMu.Lock()
		resolverPause = pause
		pauseMu.Unlock()
		conflictedFlow, ok := initiateSSO()
		if !ok {
			t.FailNow()
		}
		conflictedDone := make(chan signIn, 1)
		go func() { conflictedDone <- completeSSO(conflictedFlow) }()
		select {
		case <-pause.reached:
		case <-time.After(30 * time.Second):
			t.Fatal("resolver never reached the subject fence")
		}
		type committedState struct {
			revisions          fence
			accounts, sessions int64
		}
		var stateAfterDeactivation *committedState
		lifecycleErr := setSCIMUserActive(provisionedSCIMID, false)
		if lifecycleErr == nil {
			stateAfterDeactivation = &committedState{getFenceRevisions(), count("account"), count("session")}
		}
		close(pause.release)
		conflicted := <-conflictedDone
		if lifecycleErr != nil {
			t.Fatal(lifecycleErr)
		}
		if got := errorParam(conflicted.location); got != "SSO_USER_RESOLUTION_FAILED" {
			t.Fatalf("conflicted error = %q (location %s)", got, conflicted.location)
		}
		if sess := getSession(conflicted.cookies); sess != nil {
			t.Fatalf("session after conflicted sign-in: %+v", sess)
		}
		if stateAfterDeactivation.accounts != 0 || stateAfterDeactivation.sessions != 0 {
			t.Fatalf("state after deactivation: %+v", stateAfterDeactivation)
		}
		if now := (committedState{getFenceRevisions(), count("account"), count("session")}); now != *stateAfterDeactivation {
			t.Fatalf("state changed after conflicted sign-in: %+v -> %+v", *stateAfterDeactivation, now)
		}
		expectRejectedSignIn()
		mustSetActive(provisionedSCIMID, true)

		// Concurrent sign-ins of the active user share one account.
		flows := make([]flow, 2)
		var wg sync.WaitGroup
		okFlows := make([]bool, 2)
		for i := range flows {
			wg.Add(1)
			go func(i int) { defer wg.Done(); flows[i], okFlows[i] = initiateSSO() }(i)
		}
		wg.Wait()
		if !okFlows[0] || !okFlows[1] {
			t.FailNow()
		}
		signIns := make([]signIn, 2)
		for i := range flows {
			wg.Add(1)
			go func(i int) { defer wg.Done(); signIns[i] = completeSSO(flows[i]) }(i)
		}
		wg.Wait()
		for i, s := range signIns {
			if s.location != mainBase+"/employee" {
				t.Fatalf("concurrent sign-in %d location = %q", i, s.location)
			}
		}
		sessions := []*sessionResponse{getSession(signIns[0].cookies), getSession(signIns[1].cookies)}
		first := sessions[0]
		if first == nil {
			t.Fatal("SSO sign-in did not create a session")
		}
		if first.User.Email != "provisioned.employee@example.com" || first.User.Name != "Provisioned Employee" {
			t.Fatalf("session user = %+v", first.User)
		}
		provisionedUserID := first.User.ID
		for i, s := range sessions {
			if s == nil || s.User.ID != provisionedUserID {
				t.Fatalf("session %d = %+v", i, s)
			}
		}
		if n := instanceCount("session"); n != 2 {
			t.Fatalf("sessions = %d", n)
		}
		if n := instanceCount("user"); n != 1 {
			t.Fatalf("users = %d", n)
		}
		if n := instanceCount("account"); n != 1 {
			t.Fatalf("accounts = %d", n)
		}
		expectAccount := func() {
			t.Helper()
			acc, err := instance.db().FindOne(context.Background(), adapter.FindOneInput{Model: "account"})
			if err != nil {
				t.Fatal(err)
			}
			if acc == nil || acc["accountId"] != ssoE2EExternalID || acc["providerId"] != "workforce" || acc["userId"] != provisionedUserID {
				t.Fatalf("account = %v", acc)
			}
		}
		expectAccount()

		// Deactivation revokes sessions and blocks sign-in; reactivation restores it.
		mustSetActive(provisionedSCIMID, false)
		if n := instanceCount("session"); n != 0 {
			t.Fatalf("sessions after deactivation = %d", n)
		}
		expectRejectedSignIn()
		mustSetActive(provisionedSCIMID, true)
		if s := getSession(signInWithSSO().cookies); s == nil || s.User.ID != provisionedUserID {
			t.Fatalf("session after reactivation = %+v", s)
		}

		// Deletion blocks sign-in; a same-externalId User of another connection does not unlock it.
		deleteSCIMUser(provisionedSCIMID)
		if n := instanceCount("session"); n != 0 {
			t.Fatalf("sessions after deletion = %d", n)
		}
		expectRejectedSignIn()
		provisionSCIMUser(ssoE2EContractorToken, "contractor.employee@example.com")
		expectRejectedSignIn()

		// Reprovisioning on the paired connection restores the same user.
		restored := provisionSCIMUser(ssoE2EWorkforceToken, "restored.employee@example.com")
		if restored["id"] == provisionedSCIMID {
			t.Fatalf("restored SCIM id equals the deleted one: %v", restored["id"])
		}
		restoredSession := getSession(signInWithSSO().cookies)
		if restoredSession == nil || restoredSession.User.ID != provisionedUserID || restoredSession.User.Email != "restored.employee@example.com" {
			t.Fatalf("restored session = %+v", restoredSession)
		}
		if n := instanceCount("user"); n != 2 {
			t.Fatalf("users = %d", n)
		}
		if n := instanceCount("account"); n != 1 {
			t.Fatalf("accounts = %d", n)
		}
		expectAccount()
	})
}
