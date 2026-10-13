package oauthprovider

import (
	"context"
	"net/url"
	"testing"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/genericoauth"
	"github.com/nimi-io/better-auth-go/plugins/multisession"
	"github.com/nimi-io/better-auth-go/plugins/organization"
)

// Port of oauth.test.ts: describe("oauth - prompt").

func TestOa_OAuthPrompt(t *testing.T) {
	scopes := []string{"openid", "profile", "email", "offline_access", "read:posts"}
	enableSelectAccount := false
	enablePostLogin := false
	selectedPostLogin := false
	forcePostLoginRedirect := false
	bypassReferenceIDCheck := false
	isUserRegistered := true
	authorizeBeforeHookCount := 0
	var env *testEnv

	selectAccount := func(c UserSessionContext) (bool, error) {
		if !enableSelectAccount {
			return false, nil
		}
		res, err := env.auth.API.Call(context.Background(), "listDeviceSessions", betterauth.CallInput{Headers: c.Headers})
		if err != nil {
			return false, err
		}
		var all []any
		_ = res.Decode(&all)
		return len(all) >= 1, nil
	}
	activeOrg := func(s *betterauth.Session) string {
		if s == nil {
			return ""
		}
		v, _ := s.Get("activeOrganizationId").(string)
		return v
	}
	env = newEnv(t, Options{
		Signup: &SignupOptions{Page: "/signup", ShouldRedirect: func(UserSessionContext) (bool, string, error) {
			if isUserRegistered {
				return false, "", nil
			}
			return false, "/setup", nil
		}},
		Scopes:        scopes,
		SelectAccount: &SelectAccountOptions{Page: "/select-account", ShouldRedirect: selectAccount},
		PostLogin: &PostLoginOptions{
			Page: "/select-organization",
			ShouldRedirect: func(c UserSessionContext) (bool, error) {
				if !enablePostLogin || selectedPostLogin {
					return false, nil
				}
				if forcePostLoginRedirect {
					return true, nil
				}
				return activeOrg(c.Session) == "", nil
			},
			ConsentReferenceID: func(c UserSessionContext) (string, error) {
				if !enablePostLogin || selectedPostLogin || bypassReferenceIDCheck {
					return "", nil
				}
				id := activeOrg(c.Session)
				if id == "" {
					return "", betterauth.NewAPIError("BAD_REQUEST", jsonx.O("error", "set_organization",
						"error_description", "must set organization for these scopes"))
				}
				return id, nil
			},
		},
	}, envOptions{
		before: []*betterauth.Plugin{multisession.New(), organization.New(organization.Options{})},
		mutate: func(c *betterauth.Config) {
			c.Hooks = &betterauth.HooksConfig{Before: func(ctx *betterauth.EndpointContext) (any, error) {
				if ctx.Path == "/oauth2/authorize" {
					authorizeBeforeHookCount++
				}
				return nil, nil
			}}
		},
	})
	oaRouteOAuth2(t, env)
	oaServeDiscovery(env)

	headers := oaNewJar()
	signInRes := oaSignInEmail(t, env, "", headers, nil)
	if signInRes.status != 200 {
		t.Fatalf("sign in: %d %s", signInRes.status, signInRes.body)
	}
	headers.apply(signInRes.header)
	userMap, _ := signInRes.json()["user"].(map[string]any)
	userID := oaStr(userMap, "id")
	if userID == "" {
		t.Fatalf("user: %s", signInRes.body)
	}
	oauthClient := env.adminCreateClient(headers.header(), map[string]any{
		"grant_types":                []any{"authorization_code", "client_credentials", "refresh_token"},
		"redirect_uris":              []any{oaRedirectURI},
		"application_type":           "native",
		"token_endpoint_auth_method": "client_secret_post",
	})
	clientID, secret := oaStr(oauthClient, "client_id"), oaStr(oauthClient, "client_secret")
	if clientID == "" || secret == "" || oauthClient["user_id"] == nil {
		t.Fatalf("client: %v", oauthClient)
	}
	org := env.mustCall("createOrganization", betterauth.CallInput{Body: map[string]any{"name": "my-org", "slug": "my-org", "userId": userID}})
	orgID, orgSlug := oaStr(org, "id"), oaStr(org, "slug")
	if orgID == "" {
		t.Fatalf("org: %v", org)
	}
	encRedirect := "redirect_uri=" + url.QueryEscape(oaRedirectURI)
	newRP := func(t *testing.T, cfg genericoauth.Config) *oaRP { return oaNewRP(t, env, clientID, secret, cfg) }

	// serverClient.oauth2.continue / consent with window.location.search = search.
	post := func(t *testing.T, path string, body map[string]any, search string, jar *oaJar) (bool, string) {
		t.Helper()
		res := oaFetch(t, env, "POST", path, oaWithQuery(body, search), jar, nil)
		if res.status != 200 {
			t.Fatalf("%s: %d %s", path, res.status, res.body)
		}
		jar.apply(res.header)
		return oaRedirectResult(t, res)
	}

	t.Run("login - should always redirect to login", func(t *testing.T) {
		rp := newRP(t, genericoauth.Config{Prompt: "login"})
		authURL := rp.signInSocial(t, env, oaNewJar())
		oaContains(t, authURL, oaAuthorizeURL)
		oaContains(t, authURL, "client_id="+clientID)
		loc, _ := oaAuthorize(t, env, authURL, nil)
		oaContains(t, loc, "/login")
		oaContains(t, loc, "client_id="+clientID)
		oaContains(t, loc, encRedirect)
	})

	t.Run("create - should always redirect to signup", func(t *testing.T) {
		rp := newRP(t, genericoauth.Config{Prompt: "create"})
		authURL := rp.signInSocial(t, env, oaNewJar())
		oaContains(t, authURL, oaAuthorizeURL)
		oaContains(t, authURL, "client_id="+clientID)
		loc, _ := oaAuthorize(t, env, authURL, nil)
		oaContains(t, loc, "/signup")
		oaContains(t, loc, "client_id="+clientID)
		oaContains(t, loc, encRedirect)
	})

	t.Run("create - should redirect to setup page", func(t *testing.T) {
		isUserRegistered = false
		defer func() { isUserRegistered = true }()
		rp := newRP(t, genericoauth.Config{})
		authURL := rp.signInSocial(t, env, oaNewJar())
		oaContains(t, authURL, oaAuthorizeURL)
		oaContains(t, authURL, "client_id="+clientID)
		loc, _ := oaAuthorize(t, env, authURL, headers)
		oaContains(t, loc, "/setup")
		oaContains(t, loc, "client_id="+clientID)
		oaContains(t, loc, encRedirect)
	})

	t.Run("create - should return JSON redirect when continuing from setup", func(t *testing.T) {
		isUserRegistered = false
		defer func() { isUserRegistered = true }()
		temp := env.adminCreateClient(headers.header(), map[string]any{
			"grant_types":      []any{"authorization_code", "client_credentials", "refresh_token"},
			"redirect_uris":    []any{oaRedirectURI},
			"application_type": "native",
		})
		tempID := oaStr(temp, "client_id")
		if tempID == "" || oaStr(temp, "client_secret") == "" {
			t.Fatalf("temp client: %v", temp)
		}
		rp := oaNewRP(t, env, tempID, oaStr(temp, "client_secret"), genericoauth.Config{})
		authURL := rp.signInSocial(t, env, oaNewJar())
		loc, _ := oaAuthorize(t, env, authURL, headers)
		oaContains(t, loc, "/setup")
		isUserRegistered = true
		res := oaFetch(t, env, "POST", "/oauth2/continue", oaWithQuery(map[string]any{"created": true}, oaSearch(t, loc)), headers, nil)
		if res.location() != "" {
			t.Fatalf("unexpected Location %q", res.location())
		}
		redirect, u := oaRedirectResult(t, res)
		if !redirect {
			t.Fatalf("redirect: %s", res.body)
		}
		oaContains(t, u, "/consent")
		oaContains(t, u, "client_id="+tempID)
	})

	t.Run("consent - should sign in", func(t *testing.T) {
		rp := newRP(t, genericoauth.Config{Prompt: "consent"})
		oauthHeaders := oaNewJar()
		authURL := rp.signInSocial(t, env, oauthHeaders)
		oaContains(t, authURL, oaAuthorizeURL)
		oaContains(t, authURL, "client_id="+clientID)
		oaContains(t, authURL, "prompt=consent")
		loc, res := oaAuthorize(t, env, authURL, headers)
		headers.apply(res.header)
		oaContains(t, loc, "/consent")
		oaContains(t, loc, "client_id="+clientID)
		oaContains(t, loc, "scope=")
		oaContains(t, loc, "state=")
		redirect, u := post(t, "/oauth2/consent", map[string]any{"accept": true}, oaSearch(t, loc), headers)
		if !redirect {
			t.Fatal("expected redirect")
		}
		oaContains(t, u, oaRedirectURI)
		oaContains(t, u, "code=")
		cb := oaFetch(t, env, "GET", u, nil, oauthHeaders, nil)
		oaContains(t, cb.location(), "/success")
		oaContains(t, headers.cookie(), "better-auth.session_token=")
	})

	t.Run("consent - should sign in given previous consent (see previous test)", func(t *testing.T) {
		rp := newRP(t, genericoauth.Config{})
		rpJar := oaNewJar()
		authURL := rp.signInSocial(t, env, rpJar)
		oaContains(t, authURL, oaAuthorizeURL)
		oaContains(t, authURL, "client_id="+clientID)
		loc, res := oaAuthorize(t, env, authURL, headers)
		headers.apply(res.header)
		oaContains(t, loc, oaRedirectURI)
		oaContains(t, loc, "code=")
		oaContains(t, loc, "state=")
		cb := oaFetch(t, env, "GET", loc, nil, rpJar, nil)
		oaContains(t, cb.location(), "/success")
	})

	t.Run("consent - should require consent again when new scope is requested", func(t *testing.T) {
		rp := newRP(t, genericoauth.Config{Scopes: []string{"openid", "profile", "email", "offline_access"}})
		authURL := rp.signInSocial(t, env, oaNewJar())
		oaContains(t, authURL, oaAuthorizeURL)
		oaContains(t, authURL, "client_id="+clientID)
		loc, _ := oaAuthorize(t, env, authURL, headers)
		oaContains(t, loc, "/consent")
		oaContains(t, loc, "client_id="+clientID)
		oaContains(t, loc, "scope=")
		oaContains(t, loc, "state=")
	})

	t.Run("consent - should issue code when user consents to fewer scopes", func(t *testing.T) {
		rp := newRP(t, genericoauth.Config{Prompt: "consent", Scopes: []string{"openid", "profile", "email", "read:posts"}})
		oauthHeaders := oaNewJar()
		authURL := rp.signInSocial(t, env, oauthHeaders)
		oaContains(t, authURL, "prompt=consent")
		loc, res := oaAuthorize(t, env, authURL, headers)
		headers.apply(res.header)
		oaContains(t, loc, "/consent")
		redirect, u := post(t, "/oauth2/consent", map[string]any{"accept": true, "scope": "openid profile email"}, oaSearch(t, loc), headers)
		if !redirect {
			t.Fatal("expected redirect")
		}
		oaContains(t, u, oaRedirectURI)
		oaContains(t, u, "code=")
		oaNotContains(t, u, "/consent")
		cu, _ := url.Parse(u)
		if cu.Query().Get("code") == "" {
			t.Fatal("missing code")
		}
		cb := oaFetch(t, env, "GET", u, nil, oauthHeaders, nil)
		authToken := cb.header.Get("set-auth-token")
		if authToken == "" {
			t.Fatalf("missing session bearer token: %d %v", cb.status, cb.header)
		}
		bearerH := map[string][]string{"Authorization": {"Bearer " + authToken}}
		accRes := oaFetch(t, env, "GET", oaRPBase+"/api/auth/list-accounts", nil, nil, bearerH)
		var accounts []map[string]any
		_ = jsonUnmarshalOa(accRes.body, &accounts)
		accountID := ""
		for _, a := range accounts {
			if a["providerId"] == oaProviderID {
				accountID = oaStr(a, "id")
			}
		}
		if accountID == "" {
			t.Fatalf("missing provider account: %s", accRes.body)
		}
		tok := oaFetch(t, env, "POST", oaRPBase+"/api/auth/get-access-token", map[string]any{"accountId": accountID}, nil, bearerH)
		tm := tok.json()
		if oaStr(tm, "accessToken") == "" {
			t.Fatalf("get-access-token: %d %s", tok.status, tok.body)
		}
		sc, _ := tm["scopes"].([]any)
		if len(sc) != 3 || sc[0] != "openid" || sc[1] != "profile" || sc[2] != "email" {
			t.Fatalf("scopes: %v", tm["scopes"])
		}
	})

	t.Run("select_account - should sign in requesting account selection", func(t *testing.T) {
		enableSelectAccount = true
		defer func() { enableSelectAccount = false }()
		rp := newRP(t, genericoauth.Config{})
		authURL := rp.signInSocial(t, env, oaNewJar())
		oaContains(t, authURL, oaAuthorizeURL)
		oaContains(t, authURL, "client_id="+clientID)
		loc, res := oaAuthorize(t, env, authURL, headers)
		headers.apply(res.header)
		oaContains(t, loc, "/select-account")
		oaContains(t, loc, "client_id="+clientID)
		oaContains(t, loc, "scope=")
		oaContains(t, loc, "state=")
		redirect, u := post(t, "/oauth2/continue", map[string]any{"selected": true}, oaSearch(t, loc), headers)
		if !redirect {
			t.Fatal("expected redirect")
		}
		oaContains(t, u, oaRedirectURI)
		oaContains(t, u, "code=")
	})

	t.Run("runs configured hooks when authorize resumes from continue", func(t *testing.T) {
		enableSelectAccount = true
		defer func() { enableSelectAccount = false }()
		rp := newRP(t, genericoauth.Config{})
		authURL := rp.signInSocial(t, env, oaNewJar())
		loc, res := oaAuthorize(t, env, authURL, headers)
		headers.apply(res.header)
		oaContains(t, loc, "/select-account")
		before := authorizeBeforeHookCount
		if before <= 0 {
			t.Fatalf("hook count %d", before)
		}
		redirect, _ := post(t, "/oauth2/continue", map[string]any{"selected": true}, oaSearch(t, loc), headers)
		if !redirect {
			t.Fatal("expected redirect")
		}
		if authorizeBeforeHookCount != before+1 {
			t.Fatalf("hook count %d, want %d", authorizeBeforeHookCount, before+1)
		}
	})

	encIss := "iss=" + url.QueryEscape(testBaseURL)

	t.Run("none - should return account_selection_required when account selection is required", func(t *testing.T) {
		enableSelectAccount = true
		defer func() { enableSelectAccount = false }()
		rp := newRP(t, genericoauth.Config{Prompt: "none"})
		authURL := rp.signInSocial(t, env, oaNewJar())
		oaContains(t, authURL, "prompt=none")
		loc, _ := oaAuthorize(t, env, authURL, headers)
		oaContains(t, loc, oaRedirectURI)
		oaContains(t, loc, "error=account_selection_required")
		oaContains(t, loc, "state=")
		oaContains(t, loc, encIss)
		oaNotContains(t, loc, "/select-account")
	})

	t.Run("none - should return interaction_required when post login is required", func(t *testing.T) {
		enableSelectAccount = false
		enablePostLogin = true
		defer func() { enablePostLogin = false }()
		rp := newRP(t, genericoauth.Config{Prompt: "none"})
		authURL := rp.signInSocial(t, env, oaNewJar())
		oaContains(t, authURL, "prompt=none")
		loc, _ := oaAuthorize(t, env, authURL, headers)
		oaContains(t, loc, oaRedirectURI)
		oaContains(t, loc, "error=interaction_required")
		oaContains(t, loc, "state=")
		oaContains(t, loc, encIss)
		oaNotContains(t, loc, "/select-organization")
	})

	t.Run("login+consent - should always redirect to login and force consent (notice consent previously given)", func(t *testing.T) {
		rp := newRP(t, genericoauth.Config{Prompt: "login consent"})
		authURL := rp.signInSocial(t, env, oaNewJar())
		oaContains(t, authURL, oaAuthorizeURL)
		oaContains(t, authURL, "client_id="+clientID)
		loc, res := oaAuthorize(t, env, authURL, headers)
		headers.apply(res.header)
		oaContains(t, loc, "/login")
		oaContains(t, loc, "client_id="+clientID)
		oaContains(t, loc, encRedirect)
		search := oaSearch(t, loc)
		si := oaSignInEmail(t, env, search, headers, nil)
		headers.apply(si.header)
		redirect, u := oaRedirectResult(t, si)
		if !redirect {
			t.Fatalf("redirect: %s", si.body)
		}
		oaContains(t, u, "/consent")
		oaContains(t, u, "prompt=consent")
		oaNotContains(t, u, "prompt=login")
		redirect, u = post(t, "/oauth2/consent", map[string]any{"accept": true}, search, headers)
		if !redirect {
			t.Fatal("expected redirect")
		}
		oaContains(t, u, oaRedirectURI)
		oaContains(t, u, "code=")
		oaNotContains(t, u, "/login")
	})

	t.Run("login+consent - should not accept stale login prompt without reauthentication", func(t *testing.T) {
		staleHeaders := oaNewJar()
		si := oaSignInEmail(t, env, "", staleHeaders, nil)
		staleHeaders.apply(si.header)
		if u, _ := si.json()["user"].(map[string]any); oaStr(u, "id") == "" {
			t.Fatalf("sign in: %s", si.body)
		}
		rp := newRP(t, genericoauth.Config{Prompt: "login consent"})
		rpHeaders := oaNewJar()
		authURL := rp.signInSocial(t, env, rpHeaders)
		loc, _ := oaAuthorize(t, env, authURL, rpHeaders)
		oaContains(t, loc, "/login")
		oaContains(t, loc, "prompt=login")
		redirect, u := post(t, "/oauth2/consent", map[string]any{"accept": true}, oaSearch(t, loc), staleHeaders)
		if !redirect {
			t.Fatal("expected redirect")
		}
		oaContains(t, u, "/login")
		oaContains(t, u, "prompt=login")
		oaNotContains(t, u, "code=")
	})

	t.Run("select_account+consent - should always redirect to select_account and force consent (notice consent previously given)", func(t *testing.T) {
		enableSelectAccount = true
		defer func() { enableSelectAccount = false }()
		rp := newRP(t, genericoauth.Config{Prompt: "select_account consent"})
		authURL := rp.signInSocial(t, env, oaNewJar())
		oaContains(t, authURL, oaAuthorizeURL)
		oaContains(t, authURL, "client_id="+clientID)
		loc, res := oaAuthorize(t, env, authURL, headers)
		headers.apply(res.header)
		oaContains(t, loc, "/select-account")
		oaContains(t, loc, "client_id="+clientID)
		oaContains(t, loc, "scope=")
		oaContains(t, loc, "state=")
		redirect, u := post(t, "/oauth2/continue", map[string]any{"selected": true}, oaSearch(t, loc), headers)
		if !redirect {
			t.Fatal("expected redirect")
		}
		oaContains(t, u, "/consent")
		oaContains(t, u, "client_id="+clientID)
		oaContains(t, u, "scope=")
		oaContains(t, u, "state=")
	})

	t.Run("shall allow user to post login via continue", func(t *testing.T) {
		enablePostLogin = true
		defer func() { enablePostLogin = false; selectedPostLogin = false }()
		rp := newRP(t, genericoauth.Config{})
		authURL := rp.signInSocial(t, env, oaNewJar())
		oaContains(t, authURL, oaAuthorizeURL)
		oaContains(t, authURL, "client_id="+clientID)
		loc, res := oaAuthorize(t, env, authURL, headers)
		headers.apply(res.header)
		oaContains(t, loc, "/select-organization")
		oaContains(t, loc, "client_id="+clientID)
		oaContains(t, loc, "scope=")
		oaContains(t, loc, "state=")
		selectedPostLogin = true
		_, u := post(t, "/oauth2/continue", map[string]any{"postLogin": true}, oaSearch(t, loc), headers)
		oaContains(t, u, oaRedirectURI)
		oaContains(t, u, "code=")
	})

	t.Run("shall not let a client self-attest post login completion via continue", func(t *testing.T) {
		enablePostLogin = true
		bypassReferenceIDCheck = true
		defer func() { bypassReferenceIDCheck = false; selectedPostLogin = false; enablePostLogin = false }()
		rp := newRP(t, genericoauth.Config{})
		authURL := rp.signInSocial(t, env, oaNewJar())
		loc, res := oaAuthorize(t, env, authURL, headers)
		headers.apply(res.header)
		oaContains(t, loc, "/select-organization")
		selectedPostLogin = false
		_, u := post(t, "/oauth2/continue", map[string]any{"postLogin": true}, oaSearch(t, loc), headers)
		oaContains(t, u, "/select-organization")
		oaNotContains(t, u, "code=")
	})

	setActive := func(t *testing.T, search string, jar *oaJar) string {
		t.Helper()
		res := oaFetch(t, env, "POST", "/organization/set-active",
			oaWithQuery(map[string]any{"organizationId": orgID, "organizationSlug": orgSlug}, search), jar, nil)
		if res.status != 200 {
			t.Fatalf("set-active: %d %s", res.status, res.body)
		}
		jar.apply(res.header)
		redirect, u := oaRedirectResult(t, res)
		if !redirect || u == "" {
			t.Fatalf("set-active result: %s", res.body)
		}
		return u
	}

	t.Run("shall allow user to select an organization/team post login and consent", func(t *testing.T) {
		enablePostLogin = true
		defer func() { enablePostLogin = false }()
		rp := newRP(t, genericoauth.Config{})
		authURL := rp.signInSocial(t, env, oaNewJar())
		oaContains(t, authURL, oaAuthorizeURL)
		oaContains(t, authURL, "client_id="+clientID)
		loc, res := oaAuthorize(t, env, authURL, headers)
		headers.apply(res.header)
		oaContains(t, loc, "/select-organization")
		oaContains(t, loc, "client_id="+clientID)
		oaContains(t, loc, "scope=")
		oaContains(t, loc, "state=")
		consentURI := setActive(t, oaSearch(t, loc), headers)
		oaContains(t, consentURI, "/consent")
		oaContains(t, consentURI, "client_id="+clientID)
		oaContains(t, consentURI, "scope=")
		oaContains(t, consentURI, "state=")
		_, u := post(t, "/oauth2/consent", map[string]any{"accept": true}, oaSearch(t, consentURI), headers)
		oaContains(t, u, oaRedirectURI)
		oaContains(t, u, "code=")
	})

	t.Run("consent accept should not re-trigger postLogin redirect", func(t *testing.T) {
		enablePostLogin = true
		defer func() { enablePostLogin = false; forcePostLoginRedirect = false }()
		fresh := oaNewJar()
		si := oaSignInEmail(t, env, "", fresh, nil)
		fresh.apply(si.header)
		rp := newRP(t, genericoauth.Config{Prompt: "consent"})
		authURL := rp.signInSocial(t, env, oaNewJar())
		loc, res := oaAuthorize(t, env, authURL, fresh)
		fresh.apply(res.header)
		oaContains(t, loc, "/select-organization")
		consentURI := setActive(t, oaSearch(t, loc), fresh)
		oaContains(t, consentURI, "/consent")
		forcePostLoginRedirect = true
		_, u := post(t, "/oauth2/consent", map[string]any{"accept": true}, oaSearch(t, consentURI), fresh)
		oaContains(t, u, oaRedirectURI)
		oaContains(t, u, "code=")
		oaNotContains(t, u, "/select-organization")
	})

	t.Run("consent accept should not bypass postLogin when posted with a pre-postLogin signed query", func(t *testing.T) {
		enablePostLogin = true
		bypassReferenceIDCheck = true
		defer func() { enablePostLogin = false; bypassReferenceIDCheck = false }()
		fresh := oaNewJar()
		si := oaSignInEmail(t, env, "", fresh, nil)
		fresh.apply(si.header)
		rp := newRP(t, genericoauth.Config{Prompt: "consent"})
		authURL := rp.signInSocial(t, env, oaNewJar())
		loc, res := oaAuthorize(t, env, authURL, fresh)
		fresh.apply(res.header)
		oaContains(t, loc, "/select-organization")
		_, u := post(t, "/oauth2/consent", map[string]any{"accept": true}, oaSearch(t, loc), fresh)
		oaContains(t, u, "/select-organization")
		oaNotContains(t, u, "code=")
	})

	t.Run("consent accept should not skip postLogin when the ba_pl marker is from another session", func(t *testing.T) {
		enablePostLogin = true
		bypassReferenceIDCheck = true
		defer func() { enablePostLogin = false; bypassReferenceIDCheck = false }()
		headersA := oaNewJar()
		si := oaSignInEmail(t, env, "", headersA, nil)
		headersA.apply(si.header)
		rp := newRP(t, genericoauth.Config{Prompt: "consent"})
		authURL := rp.signInSocial(t, env, oaNewJar())
		loc, res := oaAuthorize(t, env, authURL, headersA)
		headersA.apply(res.header)
		oaContains(t, loc, "/select-organization")
		consentWithMarker := setActive(t, oaSearch(t, loc), headersA)
		oaContains(t, consentWithMarker, "/consent")
		headersB := oaNewJar()
		siB := oaSignInEmail(t, env, "", headersB, nil)
		headersB.apply(siB.header)
		_, u := post(t, "/oauth2/consent", map[string]any{"accept": true}, oaSearch(t, consentWithMarker), headersB)
		oaContains(t, u, "/select-organization")
		oaNotContains(t, u, "code=")
	})
}
