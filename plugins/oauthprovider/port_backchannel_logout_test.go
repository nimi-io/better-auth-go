package oauthprovider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of packages/oauth-provider/src/backchannel-logout.test.ts. The mock RP is a fake
// host served through the swapped BackchannelHTTPClient (env.serveHost).

type loReceivedLogout struct {
	contentType string
	logoutToken string
	raw         string
}

type loMockRP struct {
	mu        sync.Mutex
	received  []loReceivedLogout
	status    int
	host      string
	publicURL string
}

var loRPCounter int

func loStartMockRP(env *testEnv, status int) *loMockRP {
	loRPCounter++
	host := fmt.Sprintf("rp-%d.example.com", 40000+loRPCounter)
	rp := &loMockRP{status: status, host: host, publicURL: "https://" + host}
	env.serveHost(host, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		params, _ := url.ParseQuery(string(raw))
		rp.mu.Lock()
		rp.received = append(rp.received, loReceivedLogout{contentType: r.Header.Get("Content-Type"),
			logoutToken: params.Get("logout_token"), raw: string(raw)})
		rp.mu.Unlock()
		code := rp.status
		if code == 0 {
			code = 200
		}
		w.WriteHeader(code)
	}))
	return rp
}

func (rp *loMockRP) count() int {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	return len(rp.received)
}

func (rp *loMockRP) waitForDispatches(t *testing.T, min int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for rp.count() < min {
		if time.Now().After(deadline) {
			t.Fatalf("Timed out waiting for %d logout dispatches; received %d", min, rp.count())
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// loMemoryStorage is a map-backed secondary storage.
type loMemoryStorage struct {
	mu sync.Mutex
	m  map[string]string
}

func (s *loMemoryStorage) Get(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[key]
	return v, ok, nil
}

func (s *loMemoryStorage) Set(_ context.Context, key, value string, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = value
	return nil
}

func (s *loMemoryStorage) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
	return nil
}

func (s *loMemoryStorage) GetAndDelete(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[key]
	delete(s.m, key)
	return v, ok, nil
}

func (s *loMemoryStorage) Increment(_ context.Context, key string, _ time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	fmt.Sscan(s.m[key], &n)
	n++
	s.m[key] = fmt.Sprint(n)
	return n, nil
}

type loBackchannelSuite struct {
	t       *testing.T
	env     *testEnv
	ad      *loAdapter
	rp      *loMockRP
	headers http.Header
	scopes  []string
	veto    *bool
	vetoMu  *sync.Mutex
}

var errLoRollback = errors.New("rollback session revocation")

func loTransactionalRevocationPlugin(ad **loAdapter) *betterauth.Plugin {
	return &betterauth.Plugin{
		ID: "transactional-session-revocation-test",
		Endpoints: []*betterauth.Endpoint{{
			Key: "testTransactionalSessionRevocation", Path: "/test/transactional-session-revocation", Methods: []string{"POST"},
			Handler: func(ctx *betterauth.EndpointContext) (any, error) {
				body := ctx.BodyMap()
				rollback, _ := body["rollback"].(bool)
				sessionToken, _ := body["sessionToken"].(string)
				clientID, _ := body["clientId"].(string)
				txTokenID, _ := body["transactionAccessTokenId"].(string)
				track, _ := body["trackActiveAdapterWrites"].(bool)
				revoke := func() (bool, error) {
					err := ctx.Transaction(func() error {
						if clientID != "" && txTokenID != "" {
							active, err := ctx.Auth.InternalAdapter.FindSession(ctx.Context(), sessionToken)
							if err != nil {
								return err
							}
							if active == nil {
								return errors.New("Session not found")
							}
							if _, err := ctx.Auth.Adapter.Create(ctx.Context(), adapter.CreateInput{Model: modelAccessToken, ForceAllowID: true,
								Data: adapter.Record{"id": txTokenID, "token": txTokenID, "clientId": clientID,
									"sessionId": active.Session.ID, "userId": active.User.ID, "scopes": []any{"openid"},
									"expiresAt": time.Now().Add(time.Minute), "createdAt": time.Now(), "revoked": nil}}); err != nil {
								return err
							}
						}
						if err := ctx.Auth.InternalAdapter.DeleteSession(ctx.Context(), sessionToken); err != nil {
							return err
						}
						if rollback {
							return errLoRollback
						}
						return nil
					})
					if err != nil {
						if errors.Is(err, errLoRollback) {
							return false, nil
						}
						return false, err
					}
					return true, nil
				}
				w := *ad
				if track {
					w.mu.Lock()
					w.trackUpdateMany, w.updateManyModels = true, []string{}
					w.mu.Unlock()
				}
				committed, err := revoke()
				out := map[string]any{"committed": committed}
				if track {
					w.mu.Lock()
					w.trackUpdateMany = false
					out["updatedModelsThroughActiveAdapter"] = append([]string{}, w.updateManyModels...)
					w.mu.Unlock()
				}
				if err != nil {
					return nil, err
				}
				return out, nil
			}}},
	}
}

func loNewBackchannelSuite(t *testing.T) *loBackchannelSuite {
	scopes := []string{"openid", "email", "profile", "offline_access"}
	veto := false
	vetoMu := &sync.Mutex{}
	var ad *loAdapter
	env, w := loNewEnv(t, Options{LoginPage: "/login", ConsentPage: "/consent", AllowDynamicClientRegistration: true,
		PairwiseSecret: "test-backchannel-pairwise-secret-32-chars", Scopes: scopes}, envOptions{
		plugins: []*betterauth.Plugin{loTransactionalRevocationPlugin(&ad)},
		mutate: func(c *betterauth.Config) {
			c.DatabaseHooks = &betterauth.DatabaseHooks{Session: betterauth.DBModelHooks{Delete: betterauth.DBOperationHooks{
				Before: func(context.Context, adapter.Record) (*betterauth.DBHookResult, error) {
					vetoMu.Lock()
					defer vetoMu.Unlock()
					if !veto {
						return nil, nil
					}
					veto = false
					return &betterauth.DBHookResult{Abort: true}, nil
				},
			}}}
		},
	})
	ad = w
	s := &loBackchannelSuite{t: t, env: env, ad: w, scopes: scopes, veto: &veto, vetoMu: vetoMu}
	s.rp = loStartMockRP(env, 200)
	s.headers = env.signInWithTestUser()
	return s
}

func (s *loBackchannelSuite) setVeto(v bool) {
	s.vetoMu.Lock()
	*s.veto = v
	s.vetoMu.Unlock()
}

type loClientOverrides struct {
	noBackchannelURI   bool
	backchannelURI     string
	subjectTypePairwis bool
}

func (s *loBackchannelSuite) redirectURI() string { return "http://127.0.0.1:5555/callback" }

func (s *loBackchannelSuite) registerClient(o loClientOverrides) map[string]any {
	s.t.Helper()
	body := map[string]any{
		"redirect_uris":              []any{s.redirectURI()},
		"application_type":           "native",
		"token_endpoint_auth_method": "client_secret_post",
		"skip_consent":               true,
		"enable_end_session":         true,
		"backchannel_logout_uri":     s.rp.publicURL + "/logout/backchannel",
	}
	if o.noBackchannelURI {
		delete(body, "backchannel_logout_uri")
	}
	if o.backchannelURI != "" {
		body["backchannel_logout_uri"] = o.backchannelURI
	}
	if o.subjectTypePairwis {
		body["subject_type"] = "pairwise"
	}
	resp := s.env.adminCreateClient(s.headers, body)
	if resp["client_id"] == nil || resp["client_secret"] == nil {
		s.t.Fatalf("client registration failed: %v", resp)
	}
	return resp
}

func (s *loBackchannelSuite) issueTokens(client map[string]any, scopes []string) map[string]any {
	s.t.Helper()
	if scopes == nil {
		scopes = s.scopes
	}
	return loIssueTokens(s.env, s.headers, client, s.redirectURI(), scopes)
}

func (s *loBackchannelSuite) signOut() *response {
	s.t.Helper()
	return s.env.do("POST", "/sign-out", nil, s.headers)
}

type loRevokeInput struct {
	clientID                 string
	rollback                 bool
	sessionToken             string
	trackActiveAdapterWrites bool
	transactionAccessTokenID string
}

func (s *loBackchannelSuite) revokeSessionOverHTTP(in loRevokeInput) map[string]any {
	s.t.Helper()
	body := map[string]any{"rollback": in.rollback, "sessionToken": in.sessionToken}
	if in.clientID != "" {
		body["clientId"] = in.clientID
	}
	if in.trackActiveAdapterWrites {
		body["trackActiveAdapterWrites"] = true
	}
	if in.transactionAccessTokenID != "" {
		body["transactionAccessTokenId"] = in.transactionAccessTokenID
	}
	res := s.env.do("POST", "/test/transactional-session-revocation", body, nil)
	if res.status != 200 {
		s.t.Fatalf("Transactional session revocation failed: %d %s", res.status, res.body)
	}
	return res.json()
}

func (s *loBackchannelSuite) readClientTokenRevocation(clientID string) ([]adapter.Record, []adapter.Record) {
	return s.env.findMany(modelAccessToken, eq("clientId", clientID)), s.env.findMany(modelRefreshToken, eq("clientId", clientID))
}

func loIsRevoked(r adapter.Record) bool {
	_, ok := r["revoked"].(time.Time)
	return ok
}

func loExpectUnrevoked(t *testing.T, rows []adapter.Record) {
	t.Helper()
	for _, r := range rows {
		if r["revoked"] != nil {
			t.Fatalf("expected unrevoked token, got %v", r["revoked"])
		}
	}
}

func loExpectRevoked(t *testing.T, rows []adapter.Record) {
	t.Helper()
	for _, r := range rows {
		if !loIsRevoked(r) {
			t.Fatalf("expected revoked Date, got %#v", r["revoked"])
		}
	}
}

func loNum(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	}
	return 0, false
}

func TestLo_OAuthBackChannelLogout(t *testing.T) {
	t.Run("dispatches a conformant logout token when the session is signed out", func(t *testing.T) {
		s := loNewBackchannelSuite(t)
		oc := s.registerClient(loClientOverrides{})
		tokens := s.issueTokens(oc, nil)
		s.signOut()
		s.rp.waitForDispatches(t, 1)
		if s.rp.count() != 1 {
			t.Fatalf("received %d", s.rp.count())
		}
		rec := s.rp.received[0]
		if !strings.Contains(rec.contentType, "application/x-www-form-urlencoded") {
			t.Fatalf("content-type %q", rec.contentType)
		}
		if rec.logoutToken == "" {
			t.Fatal("missing logout_token")
		}
		jwks := s.env.mustCall("getJwks", betterauth.CallInput{})
		keys, err := oauthcore.LocalJWKSet(jwks)
		if err != nil {
			t.Fatal(err)
		}
		v, err := oauthcore.CompactVerify(rec.logoutToken, keys, nil)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		pv, err := jsonx.Parse(v.RawPayload)
		if err != nil {
			t.Fatal(err)
		}
		payload := pv.(*jsonx.Object)
		if objString(v.Header, "typ") != "logout+jwt" {
			t.Fatalf("typ %q", objString(v.Header, "typ"))
		}
		if objString(v.Header, "alg") == "none" {
			t.Fatal("alg none")
		}
		if objString(payload, "iss") != testAuthBase {
			t.Fatalf("iss %q", objString(payload, "iss"))
		}
		if aud, _ := payload.Get("aud"); aud != loStr(oc, "client_id") {
			t.Fatalf("aud %v", aud)
		}
		iatV, _ := payload.Get("iat")
		expV, _ := payload.Get("exp")
		iat, ok1 := loNum(iatV)
		exp, ok2 := loNum(expV)
		if !ok1 || !ok2 || exp-iat > 120 {
			t.Fatalf("iat %v exp %v", iatV, expV)
		}
		for _, k := range []string{"jti", "sub", "sid"} {
			if objString(payload, k) == "" {
				t.Fatalf("missing %s", k)
			}
		}
		if _, ok := payload.Get("nonce"); ok {
			t.Fatal("nonce should be undefined")
		}
		events, _ := payload.Get("events")
		eb, _ := jsonx.Marshal(events)
		if string(eb) != `{"http://schemas.openid.net/event/backchannel-logout":{}}` {
			t.Fatalf("events %s", eb)
		}
		idp := decodeJWTPayload(t, loStr(tokens, "id_token"))
		if objString(payload, "sid") != idp["sid"] {
			t.Fatalf("sid %q != %v", objString(payload, "sid"), idp["sid"])
		}
	})

	t.Run("dispatches logout only after a transactional session revocation commits", func(t *testing.T) {
		s := loNewBackchannelSuite(t)
		s.headers = s.env.signInWithTestUser()
		oc := s.registerClient(loClientOverrides{})
		s.issueTokens(oc, nil)
		rolledBack := s.revokeSessionOverHTTP(loRevokeInput{rollback: true, sessionToken: loSessionToken(s.env, s.headers)})
		if !reflect.DeepEqual(rolledBack, map[string]any{"committed": false}) {
			t.Fatalf("rolledBack %v", rolledBack)
		}
		time.Sleep(200 * time.Millisecond)
		if s.rp.count() != 0 {
			t.Fatalf("received %d", s.rp.count())
		}
		if !loSessionActive(s.env, s.headers) {
			t.Fatal("expected session")
		}
		access, refresh := s.readClientTokenRevocation(loStr(oc, "client_id"))
		if len(access) == 0 || len(refresh) == 0 {
			t.Fatalf("tokens: %d %d", len(access), len(refresh))
		}
		loExpectUnrevoked(t, access)
		loExpectUnrevoked(t, refresh)
		committed := s.revokeSessionOverHTTP(loRevokeInput{clientID: loStr(oc, "client_id"), rollback: false,
			sessionToken: loSessionToken(s.env, s.headers), transactionAccessTokenID: "transaction-only-access-token"})
		if !reflect.DeepEqual(committed, map[string]any{"committed": true}) {
			t.Fatalf("committed %v", committed)
		}
		s.rp.waitForDispatches(t, 1)
		if s.rp.count() != 1 {
			t.Fatalf("received %d", s.rp.count())
		}
		if loSessionActive(s.env, s.headers) {
			t.Fatal("expected session deleted")
		}
		access, refresh = s.readClientTokenRevocation(loStr(oc, "client_id"))
		loExpectRevoked(t, access)
		loExpectUnrevoked(t, refresh)
		txOnly := s.env.findOne(modelAccessToken, eq("id", "transaction-only-access-token"))
		if txOnly == nil || !loIsRevoked(txOnly) {
			t.Fatalf("transaction-only token: %v", txOnly)
		}
	})

	t.Run("applies committed token revocation through the active adapter", func(t *testing.T) {
		s := loNewBackchannelSuite(t)
		s.headers = s.env.signInWithTestUser()
		oc := s.registerClient(loClientOverrides{})
		s.issueTokens(oc, []string{"openid", "email", "profile"})
		committed := s.revokeSessionOverHTTP(loRevokeInput{rollback: false, sessionToken: loSessionToken(s.env, s.headers),
			trackActiveAdapterWrites: true})
		want := map[string]any{"committed": true, "updatedModelsThroughActiveAdapter": []any{"oauthAccessToken"}}
		if !reflect.DeepEqual(committed, want) {
			t.Fatalf("got %v", committed)
		}
	})

	t.Run("keeps the session and tokens active when a later hook vetoes deletion", func(t *testing.T) {
		s := loNewBackchannelSuite(t)
		s.headers = s.env.signInWithTestUser()
		oc := s.registerClient(loClientOverrides{})
		s.issueTokens(oc, nil)
		s.setVeto(true)
		result := s.revokeSessionOverHTTP(loRevokeInput{rollback: false, sessionToken: loSessionToken(s.env, s.headers)})
		if !reflect.DeepEqual(result, map[string]any{"committed": true}) {
			t.Fatalf("result %v", result)
		}
		time.Sleep(200 * time.Millisecond)
		if !loSessionActive(s.env, s.headers) {
			t.Fatal("expected session")
		}
		if s.rp.count() != 0 {
			t.Fatalf("received %d", s.rp.count())
		}
		access, refresh := s.readClientTokenRevocation(loStr(oc, "client_id"))
		loExpectUnrevoked(t, append(access, refresh...))
	})

	t.Run("dispatches when RP-Initiated Logout tears down the session", func(t *testing.T) {
		s := loNewBackchannelSuite(t)
		oc := s.registerClient(loClientOverrides{})
		tokens := s.issueTokens(oc, nil)
		s.env.do("GET", "/oauth2/end-session?id_token_hint="+url.QueryEscape(loStr(tokens, "id_token")), nil, nil)
		s.rp.waitForDispatches(t, 1)
		if s.rp.count() != 1 {
			t.Fatalf("received %d", s.rp.count())
		}
	})

	t.Run("marks non-offline_access access + refresh tokens revoked, preserves offline_access refresh tokens", func(t *testing.T) {
		s := loNewBackchannelSuite(t)
		oc := s.registerClient(loClientOverrides{})
		s.issueTokens(oc, nil)
		access, refresh := s.readClientTokenRevocation(loStr(oc, "client_id"))
		if len(access) == 0 || len(refresh) == 0 {
			t.Fatalf("tokens: %d %d", len(access), len(refresh))
		}
		loExpectUnrevoked(t, access)
		loExpectUnrevoked(t, refresh)
		s.signOut()
		s.rp.waitForDispatches(t, 1)
		access, refresh = s.readClientTokenRevocation(loStr(oc, "client_id"))
		loExpectRevoked(t, access)
		for _, r := range refresh {
			if contains(recStrings(r, "scopes"), "offline_access") {
				loExpectUnrevoked(t, []adapter.Record{r})
			} else {
				loExpectRevoked(t, []adapter.Record{r})
			}
		}
	})

	t.Run("revokes access tokens on session end even when no refresh token was issued", func(t *testing.T) {
		s := loNewBackchannelSuite(t)
		oc := s.registerClient(loClientOverrides{})
		s.issueTokens(oc, []string{"openid", "email", "profile"})
		access, refresh := s.readClientTokenRevocation(loStr(oc, "client_id"))
		if len(refresh) != 0 {
			t.Fatalf("refresh tokens: %d", len(refresh))
		}
		if len(access) == 0 {
			t.Fatal("no access tokens")
		}
		loExpectUnrevoked(t, access)
		s.signOut()
		s.rp.waitForDispatches(t, 1)
		access, _ = s.readClientTokenRevocation(loStr(oc, "client_id"))
		loExpectRevoked(t, access)
	})

	t.Run("does not dispatch to clients without a backchannel_logout_uri", func(t *testing.T) {
		s := loNewBackchannelSuite(t)
		oc := s.registerClient(loClientOverrides{noBackchannelURI: true})
		s.issueTokens(oc, nil)
		s.signOut()
		time.Sleep(200 * time.Millisecond)
		if s.rp.count() != 0 {
			t.Fatalf("received %d", s.rp.count())
		}
	})

	t.Run("treats RP failures as non-fatal for the user-facing sign-out", func(t *testing.T) {
		s := loNewBackchannelSuite(t)
		s.rp = loStartMockRP(s.env, 500)
		oc := s.registerClient(loClientOverrides{backchannelURI: s.rp.publicURL + "/logout/backchannel"})
		s.issueTokens(oc, nil)
		res := s.signOut()
		if res.status != 200 {
			t.Fatalf("sign out: %d %s", res.status, res.body)
		}
		s.rp.waitForDispatches(t, 1)
		if s.rp.count() != 1 {
			t.Fatalf("received %d", s.rp.count())
		}
	})

	t.Run("isolates a malformed pairwise client from revocation and healthy RP delivery", func(t *testing.T) {
		s := loNewBackchannelSuite(t)
		healthy := s.registerClient(loClientOverrides{})
		malformed := s.registerClient(loClientOverrides{subjectTypePairwis: true})
		s.issueTokens(healthy, nil)
		s.issueTokens(malformed, nil)
		s.env.update(modelClient, adapter.Record{"redirectUris": []any{}}, eq("clientId", loStr(malformed, "client_id")))
		s.signOut()
		s.rp.waitForDispatches(t, 1)
		if s.rp.count() != 1 {
			t.Fatalf("received %d", s.rp.count())
		}
		for _, id := range []string{loStr(healthy, "client_id"), loStr(malformed, "client_id")} {
			access, _ := s.readClientTokenRevocation(id)
			if len(access) == 0 {
				t.Fatalf("no access tokens for %s", id)
			}
			loExpectRevoked(t, access)
		}
	})
}

// loRevokeOnSignOut covers the jwt-disabled and secondary-storage describes.
func loRevokeOnSignOut(t *testing.T, env *testEnv, redirectURI string) {
	t.Helper()
	h := env.signInWithTestUser()
	oc := env.adminCreateClient(h, map[string]any{
		"redirect_uris":              []any{redirectURI},
		"application_type":           "native",
		"token_endpoint_auth_method": "client_secret_post",
		"skip_consent":               true,
		"enable_end_session":         true,
	})
	if oc["client_id"] == nil || oc["client_secret"] == nil {
		t.Fatalf("client registration failed: %v", oc)
	}
	tokens := loIssueTokens(env, h, oc, redirectURI, []string{"openid", "profile"})
	if tokens["access_token"] == nil {
		t.Fatalf("tokens: %v", tokens)
	}
	before := env.findMany(modelAccessToken, eq("clientId", loStr(oc, "client_id")))
	if len(before) == 0 {
		t.Fatal("no access tokens")
	}
	loExpectUnrevoked(t, before)
	env.do("POST", "/sign-out", nil, h)
	after := env.findMany(modelAccessToken, eq("clientId", loStr(oc, "client_id")))
	loExpectRevoked(t, after)
}

func TestLo_OAuthBackChannelLogoutJwtPluginDisabled(t *testing.T) {
	t.Run("revokes session-bound access tokens on sign-out even when the jwt plugin is disabled", func(t *testing.T) {
		env := newEnv(t, Options{LoginPage: "/login", ConsentPage: "/consent", DisableJwtPlugin: true}, envOptions{noJwt: true})
		loRevokeOnSignOut(t, env, "http://localhost:5556/callback")
	})
}

func TestLo_OAuthBackChannelLogoutSecondaryStoragePreserveSessionInDatabase(t *testing.T) {
	t.Run("revokes session-bound access tokens on sign-out when the row is preserved", func(t *testing.T) {
		store := &loMemoryStorage{m: map[string]string{}}
		env := newEnv(t, Options{LoginPage: "/login", ConsentPage: "/consent", DisableJwtPlugin: true}, envOptions{noJwt: true,
			mutate: func(c *betterauth.Config) {
				c.SecondaryStorage = store
				c.Session = &betterauth.SessionConfig{StoreSessionInDatabase: true, PreserveSessionInDatabase: true}
			}})
		loRevokeOnSignOut(t, env, testBaseURL+"/callback")
	})
}
