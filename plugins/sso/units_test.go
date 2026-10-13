package sso

// Ports of packages/sso/src/utils.test.ts, provider-reference.test.ts,
// provider-lock.test.ts and user-resolution.test.ts.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
)

// ---- utils.test.ts ----

func TestUnitUtils(t *testing.T) {
	t.Run("parseProviderEmailVerified", func(t *testing.T) {
		t.Run(`treats only boolean true and the string "true" as verified`, func(t *testing.T) {
			u1Eq(t, parseProviderEmailVerified(true), true)
			u1Eq(t, parseProviderEmailVerified("true"), true)
		})
		t.Run(`treats the string "false" as unverified (the coercion bug)`, func(t *testing.T) {
			u1Eq(t, parseProviderEmailVerified("false"), false)
		})
		t.Run("treats every other value as unverified", func(t *testing.T) {
			for _, v := range []any{false, "False", "TRUE", "0", "1", 0, 1, float64(0), float64(1), "", " ", nil,
				map[string]any{}, []any{}, []any{"true"}, []string{"true"}} {
				if parseProviderEmailVerified(v) {
					t.Fatalf("parseProviderEmailVerified(%#v) = true", v)
				}
			}
		})
	})

	t.Run("parseProviderDomains", func(t *testing.T) {
		t.Run("normalizes comma-separated provider domains", func(t *testing.T) {
			u1Eq(t, parseProviderDomains("https://company.com/path, subsidiary.com, COMPANY.com"), []string{"company.com", "subsidiary.com"})
		})
		t.Run("returns null when no domain can be parsed", func(t *testing.T) {
			if parseProviderDomains(", ,") != nil || parseProviderDomains("") != nil {
				t.Fatal("expected nil")
			}
		})
	})

	t.Run("validateEmailDomain", func(t *testing.T) {
		t.Run("single domain", func(t *testing.T) {
			t.Run("should validate email matches domain exactly", func(t *testing.T) {
				u1Eq(t, validateEmailDomain("user@company.com", "company.com"), true)
			})
			t.Run("should validate email matches subdomain", func(t *testing.T) {
				u1Eq(t, validateEmailDomain("user@hr.company.com", "company.com"), true)
				u1Eq(t, validateEmailDomain("user@dept.hr.company.com", "company.com"), true)
			})
			t.Run("should reject email from different domain", func(t *testing.T) {
				u1Eq(t, validateEmailDomain("user@other.com", "company.com"), false)
			})
			t.Run("should reject email where domain is a suffix but not subdomain", func(t *testing.T) {
				u1Eq(t, validateEmailDomain("user@notcompany.com", "company.com"), false)
			})
			t.Run("should be case-insensitive", func(t *testing.T) {
				u1Eq(t, validateEmailDomain("USER@COMPANY.COM", "company.com"), true)
				u1Eq(t, validateEmailDomain("user@company.com", "COMPANY.COM"), true)
			})
		})

		t.Run("multiple domains (enterprise multi-domain SSO)", func(t *testing.T) {
			t.Run("should validate email against any domain in comma-separated list", func(t *testing.T) {
				domains := "company.com,subsidiary.com,acquired-company.com"
				u1Eq(t, validateEmailDomain("user@company.com", domains), true)
				u1Eq(t, validateEmailDomain("user@subsidiary.com", domains), true)
				u1Eq(t, validateEmailDomain("user@acquired-company.com", domains), true)
			})
			t.Run("should validate subdomains for any domain in the list", func(t *testing.T) {
				domains := "company.com,subsidiary.com"
				u1Eq(t, validateEmailDomain("user@hr.company.com", domains), true)
				u1Eq(t, validateEmailDomain("user@dept.subsidiary.com", domains), true)
			})
			t.Run("should reject email not matching any domain", func(t *testing.T) {
				domains := "company.com,subsidiary.com,acquired-company.com"
				u1Eq(t, validateEmailDomain("user@other.com", domains), false)
				u1Eq(t, validateEmailDomain("user@notcompany.com", domains), false)
			})
			t.Run("should handle whitespace in domain list", func(t *testing.T) {
				domains := "company.com, subsidiary.com , acquired-company.com"
				u1Eq(t, validateEmailDomain("user@company.com", domains), true)
				u1Eq(t, validateEmailDomain("user@subsidiary.com", domains), true)
				u1Eq(t, validateEmailDomain("user@acquired-company.com", domains), true)
			})
			t.Run("should handle empty domains in list gracefully", func(t *testing.T) {
				domains := "company.com,,subsidiary.com"
				u1Eq(t, validateEmailDomain("user@company.com", domains), true)
				u1Eq(t, validateEmailDomain("user@subsidiary.com", domains), true)
			})
			t.Run("should be case-insensitive for multiple domains", func(t *testing.T) {
				domains := "Company.COM,SUBSIDIARY.com"
				u1Eq(t, validateEmailDomain("user@company.com", domains), true)
				u1Eq(t, validateEmailDomain("USER@SUBSIDIARY.COM", domains), true)
			})
			t.Run("should use the same normalized domains as ownership verification", func(t *testing.T) {
				domains := "https://attacker.com/path,victim.com"
				u1Eq(t, domainMatches("attacker.com", domains), true)
				u1Eq(t, validateEmailDomain("user@attacker.com", domains), true)
				u1Eq(t, validateEmailDomain("user@victim.com", domains), true)
			})
			t.Run("should not normalize malformed email domains", func(t *testing.T) {
				u1Eq(t, validateEmailDomain("user@https://victim.com/path", "victim.com"), false)
			})
		})

		t.Run("edge cases", func(t *testing.T) {
			t.Run("should return false for empty email", func(t *testing.T) {
				u1Eq(t, validateEmailDomain("", "company.com"), false)
			})
			t.Run("should return false for empty domain", func(t *testing.T) {
				u1Eq(t, validateEmailDomain("user@company.com", ""), false)
			})
			t.Run("should return false for email without @", func(t *testing.T) {
				u1Eq(t, validateEmailDomain("usercompany.com", "company.com"), false)
			})
			t.Run("should return false for domain list with only whitespace/commas", func(t *testing.T) {
				u1Eq(t, validateEmailDomain("user@company.com", ", ,"), false)
			})
		})
	})

	t.Run("parseProviderDomains hostname normalization", func(t *testing.T) {
		t.Run("should extract hostname from a bare domain", func(t *testing.T) {
			u1Eq(t, parseProviderDomains("github.com"), []string{"github.com"})
		})
		t.Run("should extract hostname from a full URL", func(t *testing.T) {
			u1Eq(t, parseProviderDomains("https://github.com"), []string{"github.com"})
		})
		t.Run("should extract hostname from a URL with port", func(t *testing.T) {
			u1Eq(t, parseProviderDomains("https://github.com:8081"), []string{"github.com"})
		})
		t.Run("should extract hostname from a subdomain", func(t *testing.T) {
			u1Eq(t, parseProviderDomains("auth.github.com"), []string{"auth.github.com"})
		})
		t.Run("should extract hostname from a URL with path", func(t *testing.T) {
			u1Eq(t, parseProviderDomains("https://github.com/path/to/resource"), []string{"github.com"})
		})
		t.Run("should return null for an empty string", func(t *testing.T) {
			if parseProviderDomains("") != nil {
				t.Fatal("expected nil")
			}
		})
	})
}

// ---- provider-reference.test.ts ----

func u1ConfiguredProvider(clientSecret string) *SSOProvider {
	return &SSOProvider{
		Issuer:     "https://idp.example.com",
		ProviderID: "workforce",
		UserID:     "default",
		Domain:     "example.com",
		OIDCConfig: &OIDCConfig{
			Issuer:                "https://idp.example.com",
			ClientID:              "workforce-client",
			ClientSecret:          clientSecret,
			PKCE:                  false,
			DiscoveryEndpoint:     "https://idp.example.com/.well-known/openid-configuration",
			AuthorizationEndpoint: "https://idp.example.com/authorize",
			TokenEndpoint:         "https://idp.example.com/token",
			JwksEndpoint:          "https://idp.example.com/jwks",
		},
	}
}

func u1ConfiguredSAMLProvider(privateKey string) *SSOProvider {
	return &SSOProvider{
		Issuer:     "https://service.example.com/saml",
		ProviderID: "workforce-saml",
		UserID:     "default",
		Domain:     "example.com",
		SAMLConfig: &SAMLConfig{
			Issuer:     "https://service.example.com/saml",
			EntryPoint: "https://idp.example.com/sso",
			Cert:       Cert("idp-signing-certificate"),
			PrivateKey: privateKey,
			IdpMetadata: &SAMLIdentityProviderMetadata{
				EntityID:          "https://idp.example.com/metadata",
				Cert:              Cert("idp-signing-certificate"),
				PrivateKey:        privateKey,
				PrivateKeyPass:    "private-key-password",
				EncPrivateKey:     "encryption-private-key",
				EncPrivateKeyPass: "encryption-private-key-password",
			},
			SpMetadata: &SAMLServiceProviderMetadata{
				EntityID:          "https://service.example.com/saml",
				PrivateKey:        privateKey,
				PrivateKeyPass:    "private-key-password",
				EncPrivateKey:     "encryption-private-key",
				EncPrivateKeyPass: "encryption-private-key-password",
			},
		},
	}
}

func TestUnitProviderReference(t *testing.T) {
	t.Run("SSO provider references", func(t *testing.T) {
		t.Run("binds state to non-secret authentication configuration", func(t *testing.T) {
			ref := computeProviderReference(u1ConfiguredProvider("secret"))
			u1Eq(t, isCurrentProviderReference(u1ConfiguredProvider("rotated-secret"), &ref), true)
			changed := u1ConfiguredProvider("secret")
			changed.OIDCConfig.TokenEndpoint = "https://attacker.example/token"
			u1Eq(t, isCurrentProviderReference(changed, &ref), false)
		})
		t.Run("binds persisted providers to the same database row", func(t *testing.T) {
			p := u1ConfiguredProvider("secret")
			p.ID = "provider-row-1"
			p.UserID = "default"
			ref := computeProviderReference(p)
			u1Eq(t, ref.Source.Type, "persisted")
			u1Eq(t, ref.Source.RecordID, "provider-row-1")
			u1Eq(t, ref.toServerContext()["source"], map[string]any{"type": "persisted", "recordId": "provider-row-1"})
			u1Eq(t, isCurrentProviderReference(p, &ref), true)
			other := u1ConfiguredProvider("secret")
			other.ID = "provider-row-2"
			u1Eq(t, isCurrentProviderReference(other, &ref), false)
		})
		t.Run("binds SAML state to authentication configuration without private keys", func(t *testing.T) {
			ref := computeProviderReference(u1ConfiguredSAMLProvider("private-key"))
			rotated := u1ConfiguredSAMLProvider("rotated-private-key")
			idp, sp := rotated.SAMLConfig.IdpMetadata, rotated.SAMLConfig.SpMetadata
			idp.PrivateKey = "rotated-idp-private-key"
			idp.PrivateKeyPass = "rotated-idp-private-key-password"
			idp.EncPrivateKey = "rotated-idp-encryption-private-key"
			idp.EncPrivateKeyPass = "rotated-idp-encryption-private-key-password"
			sp.PrivateKey = "rotated-sp-private-key"
			sp.PrivateKeyPass = "rotated-sp-private-key-password"
			sp.EncPrivateKey = "rotated-sp-encryption-private-key"
			sp.EncPrivateKeyPass = "rotated-sp-encryption-private-key-password"
			u1Eq(t, isCurrentProviderReference(rotated, &ref), true)

			entry := u1ConfiguredSAMLProvider("private-key")
			entry.SAMLConfig.EntryPoint = "https://attacker.example.com/sso"
			u1Eq(t, isCurrentProviderReference(entry, &ref), false)

			cert := u1ConfiguredSAMLProvider("private-key")
			cert.SAMLConfig.Cert = Cert("replacement-signing-certificate")
			u1Eq(t, isCurrentProviderReference(cert, &ref), false)
		})
		t.Run("rejects malformed state", func(t *testing.T) {
			if r := parseProviderReference(map[string]any{"providerId": "workforce"}); r != nil {
				t.Fatalf("expected nil, got %#v", r)
			}
		})
	})
}

// ---- provider-lock.test.ts ----

// u1LockAdapter is a stub adapter (vi.fn update) recording Update calls.
type u1LockAdapter struct {
	adapter.Adapter
	mu      sync.Mutex
	updates int
	result  adapter.Record
}

func (a *u1LockAdapter) Update(_ context.Context, _ string, _ []adapter.Where, _ adapter.Record) (adapter.Record, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.updates++
	return a.result, nil
}

func TestUnitProviderLock(t *testing.T) {
	t.Run("SSO provider account-link locking", func(t *testing.T) {
		t.Run("does not bypass a persisted provider owned by user default", func(t *testing.T) {
			a := &u1LockAdapter{}
			err := lockSSOProviderForAccountLink(context.Background(), a, &SSOProvider{
				ID: "provider-row-1", ProviderID: "workforce", Issuer: "https://idp.example.com", UserID: "default",
			})
			u1ExpectContains(t, err, "SSO provider changed while account linking was in progress")
			u1Eq(t, a.updates, 1)
		})
		t.Run("does not run a databaseHooks.ssoProvider.update hook during a sign-in lock", func(t *testing.T) {
			// Go's betterauth.DatabaseHooks has no ssoProvider entry and the lock writes via the
			// raw adapter, so no hook can run; assert the lock succeeds with exactly one update.
			a := &u1LockAdapter{result: adapter.Record{
				"id": "provider-row-1", "providerId": "workforce", "issuer": "https://idp.example.com", "userId": "default",
			}}
			err := lockSSOProviderForAccountLink(context.Background(), a, &SSOProvider{
				ID: "provider-row-1", ProviderID: "workforce", Issuer: "https://idp.example.com", UserID: "default",
			})
			if err != nil {
				t.Fatal(err)
			}
			u1Eq(t, a.updates, 1)
		})
	})
}

// ---- user-resolution.test.ts ----

type u1LogCall struct {
	msg  string
	args []any
}

type u1Logger struct {
	mu    sync.Mutex
	calls []u1LogCall
}

func (l *u1Logger) Error(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, u1LogCall{msg, args})
}

func u1ResolutionInput() UserResolutionInput {
	in := UserResolutionInput{
		Protocol:   "oidc",
		ProviderID: "workforce",
		AccountKey: AccountKey{Issuer: "https://idp.example.com", AccountID: "directory-user-1"},
		ProviderUser: ProviderUserProfile{
			Email: "employee@example.com", EmailVerified: true, Name: "Directory Employee",
		},
		ProviderClaims:        map[string]any{"sub": "directory-user-1"},
		VerifiedIDTokenClaims: map[string]any{"iss": "https://idp.example.com", "sub": "directory-user-1"},
	}
	in.ProviderReference.ProviderID = "workforce"
	in.ProviderReference.Source.Type = "configured"
	in.ProviderReference.AuthenticationConfigurationFingerprint = "fingerprint"
	return in
}

func u1APIErr(t *testing.T, err error) *betterauth.APIError {
	t.Helper()
	var ae *betterauth.APIError
	if !errors.As(err, &ae) {
		t.Fatalf("expected *betterauth.APIError, got %T: %v", err, err)
	}
	return ae
}

func TestUnitUserResolution(t *testing.T) {
	t.Run("SSO user resolution", func(t *testing.T) {
		t.Run("fails closed when database transaction async context is unavailable", func(t *testing.T) {
			t.Skip("TS-only: AsyncLocalStorage availability check (assertSSOUserResolutionAsyncContextSupport); Go passes transactions via context.Context")
		})
		t.Run("exposes mapped provider profile fields as unknown", func(t *testing.T) {
			t.Skip("TS-only: expectTypeOf type-level assertion")
		})
		t.Run("does not expose resolver exceptions to custom loggers", func(t *testing.T) {
			secret := "tenant-token=directory-secret"
			for _, mode := range []string{"error", "panic"} {
				logger := &u1Logger{}
				_, err := resolveSSOUser(context.Background(), func(context.Context, UserResolutionInput, UserResolutionContext) (UserResolution, error) {
					privateErr := fmt.Errorf("%s (providerClaims access_token=%s)", secret, secret)
					if mode == "panic" {
						panic(privateErr)
					}
					return UserResolution{}, privateErr
				}, u1ResolutionInput(), nil, logger)
				ae := u1APIErr(t, err)
				u1Eq(t, ae.Code(), "SSO_USER_RESOLUTION_FAILED")
				u1Eq(t, ae.Message(), "Unable to resolve the SSO user")
				found := false
				for _, c := range logger.calls {
					if c.msg == "SSO user resolution failed" {
						found = true
					}
					if len(c.args) > 0 {
						t.Fatalf("[%s] logger.error called with extra args: %#v", mode, c.args)
					}
					if strings.Contains(fmt.Sprintf("%#v", c), secret) {
						t.Fatalf("[%s] secret leaked to logger", mode)
					}
				}
				if !found {
					t.Fatalf("[%s] logger.error not called with %q: %#v", mode, "SSO user resolution failed", logger.calls)
				}
			}
		})
		t.Run("logs malformed decisions without logging their value", func(t *testing.T) {
			logger := &u1Logger{}
			_, err := resolveSSOUser(context.Background(), func(context.Context, UserResolutionInput, UserResolutionContext) (UserResolution, error) {
				return UserResolution{Action: "link", UserID: "user-1"}, nil
			}, u1ResolutionInput(), nil, logger)
			u1Eq(t, u1APIErr(t, err).Code(), "SSO_USER_RESOLUTION_FAILED")
			found := false
			for _, c := range logger.calls {
				if c.msg == "SSO user resolver returned an invalid decision" {
					found = true
				}
			}
			if !found {
				t.Fatalf("logger calls: %#v", logger.calls)
			}
		})
		t.Run("requires a database session fallback when secondary storage is configured", func(t *testing.T) {
			storage := betterauth.NewMemoryStorage()
			err := assertSSOUserResolutionSessionStorage(&betterauth.Config{SecondaryStorage: storage})
			u1ExpectContains(t, err, "SSO user resolution requires database-backed sessions")
			if err := assertSSOUserResolutionSessionStorage(&betterauth.Config{SecondaryStorage: storage,
				Session: &betterauth.SessionConfig{StoreSessionInDatabase: true}}); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			err = assertSSOUserResolutionSessionStorage(&betterauth.Config{SecondaryStorage: storage,
				Session: &betterauth.SessionConfig{StoreSessionInDatabase: true, PreserveSessionInDatabase: true}})
			u1ExpectContains(t, err, "SSO user resolution requires database-backed sessions")
		})
	})
}
