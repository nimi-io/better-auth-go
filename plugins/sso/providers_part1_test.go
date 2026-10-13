package sso

// Port of providers.test.ts lines 1-1212: "SAML redirect URL schema" and, within
// "SSO provider read endpoints", the createTestAuth setup plus "GET /sso/providers",
// "GET /sso/get-provider" and "sanitization".

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/plugins/organization"
	"github.com/nimi-io/better-auth-go/validate"
)

const p1TestCert = `MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0Gcm9markup
temporary cert for testing`

const p1RotationCert1 = `-----BEGIN CERTIFICATE-----
MIIDlzCCAn+gAwIBAgIJAO1ymQc33+bWMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNV
BAYTAkhLMRMwEQYDVQQIDApTb21lLVN0YXRlMRowGAYDVQQKDBFJZGVudGl0eSBQ
cm92aWRlcjEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxDDAKBgNVBAMMA0lEUDAeFw0x
NTA3MDUxODAyMjdaFw0xODA3MDQxODAyMjdaMGIxCzAJBgNVBAYTAkhLMRMwEQYD
VQQIDApTb21lLVN0YXRlMRowGAYDVQQKDBFJZGVudGl0eSBQcm92aWRlcjEUMBIG
A1UECwwLRGV2ZWxvcG1lbnQxDDAKBgNVBAMMA0lEUDCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAODZsWhCe+yG0PalQPTUoD7yko5MTWMCRxJ8hSm2k7mG
3Eg/Y2v0EBdCmTw7iDCevRqUmbmFnq7MROyV4eriJzh0KabAdZf7/k6koghst3ZU
tWOwzshyxkBtWDwGmBpQGTGsKxJ8M1js3aSqNRXBT4OBWM9w2Glt1+8ty30RhYv3
pSF+/HHLH7Ac+vLSIAlokaFW34RWTcJ/8rADuRWlXih4GfnIu0W/ncm5nTSaJiRA
vr3dGDRO/khiXoJdbbOj7dHPULxVGbH9IbPK76TCwLbF7ikIMsPovVbTrpyL6vsb
VUKeEl/5GKppTwp9DLAOeoSYpCYkkDkYKu9TRQjF02MCAwEAAaNQME4wHQYDVR0O
BBYEFP2ut2AQdy6D1dwdwK740IHmbh38MB8GA1UdIwQYMBaAFP2ut2AQdy6D1dwd
wK740IHmbh38MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBANMZUoPN
mHzgja2PYkbvBYMHmpvUkVoiuvQ9cJPlqGTB2CRfG68BNNs/Clz8P7cIrAdkhCUw
i1rSBhDuslGFNrSaIpv6B10FpBuKwef3G7YrPWFNEN6khY7aHNWSTHqKgs1DrGef
2B9hvkrnHWbQVSVXrBFKe1wTCqcgGcOpYoSK7L8C6iX6uIA/uZYnVQ4NgBrizJ0a
zkjdegz3hwO/gt4malEURy8D85/AAVt6PAzhpb9VJUGxSXr/EfntVUEz3L2gUFWW
k1CnZFyz0rIOEt/zPmeAY8BLyd/Tjxm4Y+gwNazKq5y9AJS+m858b/nM4QdCnUE4
yyoWAJDUHiAmvFA=
-----END CERTIFICATE-----`

const p1RotationCert2 = `-----BEGIN CERTIFICATE-----
MIIDATCCAemgAwIBAgIUTDC29D27otkSCpMVYZSZ7135bZcwDQYJKoZIhvcNAQEL
BQAwEDEOMAwGA1UEAwwFVGVzdDIwHhcNMjYwMzI3MTcyNDA4WhcNMzYwMzI0MTcy
NDA4WjAQMQ4wDAYDVQQDDAVUZXN0MjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBALXz/zRq88hhlLTJ47MoLdFqwjC9A9HiV6xOdezHhZ+vBaqCXsUcru9N
3FfG6EVtuxSTLQIfgMpxifS4tF2tqkxBcW7JDGIuN02hjeWzlVztyAzISlZJUrGS
kNnE11Br7p4O3OC1OcrpTBi/uBUPBiCFeeQCSIk+pf0h7Y4NUa27oTsZ6Qy0II7A
2m5yqtlfyvxyLKIVIlDt1yCcvvJ2MSdiCcGDfyB/BmL5ow8kaR6bal1w/NRh8pNr
OOjHmx3W+6Qv6g1M/mK7tITlstEEFJyWdzw6yEAZ7jyrHMkJKj9wTgmMxlx/H1d7
st234qgFjm6w3WxA0AwaqNcjiD3SpxkCAwEAAaNTMFEwHQYDVR0OBBYEFPegA1b2
piumrJ5DhMqgauhDrSYpMB8GA1UdIwQYMBaAFPegA1b2piumrJ5DhMqgauhDrSYp
MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAE9imWiQSn1nde7x
HPCZTuu3ydTNl6vT8yDHYUYBAC7kqUuhJ3gFd8x6toolxP2FvVuF4I7ovvRpW5zk
eJ/AGOY4YB5g6K0MUpgy42V5WDXTqLR/62VCH+jQHgIjd0I728FWVoElXHYhupnR
EKG5qVkfs8ySaBr/IV5nTSa0R9IyJX+Sb+qqITcD4CUmtNSwB1XhJq403VFCwiu+
TQNsZdoNl0fm5SR11rDA3IffIxeAvTtZwSJ/hOfBQM1RnM24t6xYX7Oe/2ZPhN7v
epyw0Ikhqk/BFtQCRei+t1HJ9GIu6qnsC7CxrUA80IcxZjeg7N6ua+uctzRWzDhn
kBGIJYs=
-----END CERTIFICATE-----`

// ---- createTestAuth equivalent ----

type p1Auth struct {
	*testEnv
	t *testing.T
}

// p1CreateTestAuth mirrors createTestAuth(includeOrgPlugin, enableDomainVerification).
func p1CreateTestAuth(t *testing.T, includeOrgPlugin bool) *p1Auth {
	t.Helper()
	ec := envConfig{noTestUser: true}
	if includeOrgPlugin {
		ec.extraPlugins = []*betterauth.Plugin{organization.New(organization.Options{})}
	}
	return &p1Auth{testEnv: newEnv(t, Options{}, ec), t: t}
}

// getAuthHeaders signs up and signs in a user, returning session headers.
func (a *p1Auth) getAuthHeaders(email, password, name string) http.Header {
	a.t.Helper()
	a.signUp(email, password, name)
	return a.signIn(email, password)
}

func (a *p1Auth) userID(email string) string {
	a.t.Helper()
	for _, u := range a.rows("user") {
		if u["email"] == email {
			id, _ := u["id"].(string)
			return id
		}
	}
	a.t.Fatalf("user %s not found", email)
	return ""
}

func (a *p1Auth) createOrganization(name string, headers http.Header) string {
	a.t.Helper()
	r := a.mustAPI("createOrganization", headers, map[string]any{"name": name, "slug": name}, nil)
	id, _ := r.m()["id"].(string)
	if id == "" {
		a.t.Fatalf("createOrganization: %s", r.Raw)
	}
	return id
}

func (a *p1Auth) addMember(userID, orgID, role string, headers http.Header) {
	a.t.Helper()
	a.mustAPI("addMember", headers, map[string]any{"userId": userID, "role": role, "organizationId": orgID}, nil)
}

func (a *p1Auth) registerSAMLProvider(headers http.Header, providerID, organizationID string) *result {
	a.t.Helper()
	body := map[string]any{
		"providerId": providerID,
		"issuer":     "https://idp.example.com",
		"domain":     "example.com",
		"samlConfig": map[string]any{
			"entryPoint":           "https://idp.example.com/sso",
			"cert":                 p1TestCert,
			"audience":             "my-audience",
			"wantAssertionsSigned": true,
			"idpMetadata":          map[string]any{"entityID": "https://idp.example.com"},
			"spMetadata":           map[string]any{},
		},
	}
	if organizationID != "" {
		body["organizationId"] = organizationID
	}
	return a.api("registerSSOProvider", headers, body, nil)
}

// insert pushes a row directly into the database (data.<model>.push).
func (a *p1Auth) insert(model string, rec map[string]any) {
	a.t.Helper()
	_, err := a.auth.Context().Adapter.Create(context.Background(), adapter.CreateInput{Model: model, Data: rec, ForceAllowID: true})
	if err != nil {
		a.t.Fatalf("insert %s: %v", model, err)
	}
}

func (a *p1Auth) createOIDCProviderData(userID, providerID, clientID, organizationID string) {
	a.t.Helper()
	cfg, _ := json.Marshal(map[string]any{
		"clientId":          clientID,
		"clientSecret":      "super-secret-value",
		"discoveryEndpoint": "https://idp.example.com/.well-known",
		"pkce":              true,
	})
	rec := map[string]any{
		"id":         "oidc-" + providerID,
		"providerId": providerID,
		"issuer":     "https://idp.example.com",
		"domain":     "example.com",
		"userId":     userID,
		"oidcConfig": string(cfg),
	}
	if organizationID != "" {
		rec["organizationId"] = organizationID
	}
	a.insert("ssoProvider", rec)
}

func p1JSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func p1Providers(t *testing.T, r *result) []map[string]any {
	t.Helper()
	if r.Err != nil {
		t.Fatalf("listSSOProviders: %d %s %s", r.Status, r.code(), r.message())
	}
	raw, ok := r.m()["providers"].([]any)
	if !ok {
		t.Fatalf("providers missing: %s", r.Raw)
	}
	out := make([]map[string]any, len(raw))
	for i, p := range raw {
		out[i], _ = p.(map[string]any)
	}
	return out
}

func p1ExpectLen(t *testing.T, providers []map[string]any, n int) {
	t.Helper()
	if len(providers) != n {
		t.Fatalf("expected %d providers, got %d: %v", n, len(providers), providers)
	}
}

func p1SAMLConfigJSON() string {
	b, _ := json.Marshal(map[string]any{
		"entryPoint":           "https://idp.example.com/sso",
		"cert":                 p1TestCert,
		"audience":             "my-audience",
		"wantAssertionsSigned": true,
		"spMetadata":           map[string]any{},
	})
	return string(b)
}

func p1Certs(t *testing.T, r *result) []map[string]any {
	t.Helper()
	sc, _ := r.m()["samlConfig"].(map[string]any)
	raw, ok := sc["certificate"].([]any)
	if !ok {
		t.Fatalf("certificate is not an array: %s", r.Raw)
	}
	out := make([]map[string]any, len(raw))
	for i, c := range raw {
		out[i], _ = c.(map[string]any)
	}
	return out
}

// ---- SAML redirect URL schema ----

func TestProviders1SAMLRedirectURLSchema(t *testing.T) {
	schema := registerBodySchema(&Options{})
	cases := []struct {
		url      string
		expected bool
	}{
		{"/dashboard", true},
		{"https://frontend.example.com/dashboard", true},
		{"//evil.example.com", false},
		{"/\\evil.example.com", false},
		{"/%2fevil.example.com", false},
		{"/%5cevil.example.com", false},
		{"dashboard", false},
	}
	for _, c := range cases {
		t.Run("validates "+c.url, func(t *testing.T) {
			_, issues := validate.Validate(schema, map[string]any{
				"providerId": "saml-provider",
				"issuer":     "https://idp.example.com",
				"domain":     "example.com",
				"samlConfig": map[string]any{
					"entryPoint":              "https://idp.example.com/sso",
					"idpInitiatedCallbackUrl": c.url,
					"idpMetadata":             map[string]any{"entityID": "https://idp.example.com"},
				},
			})
			if got := len(issues) == 0; got != c.expected {
				t.Fatalf("success = %v, want %v (issues %v)", got, c.expected, issues)
			}
		})
	}
}

// ---- SSO provider read endpoints ----

func TestProviders1ReadEndpoints(t *testing.T) {
	t.Run("GET /sso/providers", func(t *testing.T) {
		t.Run("should return 401 when not authenticated", func(t *testing.T) {
			a := p1CreateTestAuth(t, true)
			r := a.api("listSSOProviders", nil, nil, nil)
			if r.Status != 401 {
				t.Fatalf("status %d", r.Status)
			}
		})

		t.Run("should return empty list when no providers exist", func(t *testing.T) {
			a := p1CreateTestAuth(t, true)
			h := a.getAuthHeaders("test@example.com", "password123", "Test User")
			ps := p1Providers(t, a.api("listSSOProviders", h, nil, nil))
			p1ExpectLen(t, ps, 0)
		})

		t.Run("should return only providers owned by the user", func(t *testing.T) {
			a := p1CreateTestAuth(t, false)
			h := a.getAuthHeaders("owner@example.com", "password123", "Owner")
			if r := a.registerSAMLProvider(h, "my-saml-provider", ""); r.Err != nil {
				t.Fatalf("register: %d %s", r.Status, r.message())
			}
			cfg, _ := json.Marshal(map[string]any{
				"clientId": "client123456", "clientSecret": "secret",
				"discoveryEndpoint": "https://other.com/.well-known", "pkce": true,
			})
			a.insert("ssoProvider", map[string]any{
				"id": "provider-2", "providerId": "other-provider", "issuer": "https://other.com",
				"domain": "other.com", "userId": "different-user-id", "oidcConfig": string(cfg),
			})
			ps := p1Providers(t, a.api("listSSOProviders", h, nil, nil))
			p1ExpectLen(t, ps, 1)
			if ps[0]["providerId"] != "my-saml-provider" {
				t.Fatalf("providerId %v", ps[0]["providerId"])
			}
		})

		t.Run("should return providers for org admin when org plugin enabled", func(t *testing.T) {
			a := p1CreateTestAuth(t, true)
			h := a.getAuthHeaders("admin@example.com", "password123", "Admin")
			org := a.createOrganization("test-org", h)
			if r := a.registerSAMLProvider(h, "org-saml-provider", org); r.Err != nil {
				t.Fatalf("register: %d %s", r.Status, r.message())
			}
			ps := p1Providers(t, a.api("listSSOProviders", h, nil, nil))
			p1ExpectLen(t, ps, 1)
			if ps[0]["providerId"] != "org-saml-provider" {
				t.Fatalf("providerId %v", ps[0]["providerId"])
			}
		})

		t.Run("should return providers for org owner", func(t *testing.T) {
			a := p1CreateTestAuth(t, true)
			h := a.getAuthHeaders("owner@example.com", "password123", "Owner")
			org := a.createOrganization("test-org", h)
			if r := a.registerSAMLProvider(h, "org-saml-provider", org); r.Err != nil {
				t.Fatalf("register: %d %s", r.Status, r.message())
			}
			ps := p1Providers(t, a.api("listSSOProviders", h, nil, nil))
			p1ExpectLen(t, ps, 1)
			if ps[0]["providerId"] != "org-saml-provider" {
				t.Fatalf("providerId %v", ps[0]["providerId"])
			}
		})

		t.Run("should handle comma-separated roles", func(t *testing.T) {
			a := p1CreateTestAuth(t, true)
			creator := a.getAuthHeaders("creator@example.com", "password123", "Creator")
			org := a.createOrganization("test-org", creator)
			if r := a.registerSAMLProvider(creator, "org-saml-provider", org); r.Err != nil {
				t.Fatalf("register: %d %s", r.Status, r.message())
			}
			multi := a.getAuthHeaders("multi@example.com", "password123", "Multi Role User")
			a.insert("member", map[string]any{
				"id": "multi-member", "userId": a.userID("multi@example.com"), "organizationId": org,
				"role": "admin,member", "createdAt": time.Now(),
			})
			ps := p1Providers(t, a.api("listSSOProviders", multi, nil, nil))
			p1ExpectLen(t, ps, 1)
		})

		t.Run("should not return org providers to non-admin members", func(t *testing.T) {
			a := p1CreateTestAuth(t, true)
			creator := a.getAuthHeaders("creator@example.com", "password123", "Creator")
			org := a.createOrganization("test-org", creator)
			if r := a.registerSAMLProvider(creator, "org-saml-provider", org); r.Err != nil {
				t.Fatalf("register: %d %s", r.Status, r.message())
			}
			member := a.getAuthHeaders("member@example.com", "password123", "Member")
			a.addMember(a.userID("member@example.com"), org, "member", creator)
			ps := p1Providers(t, a.api("listSSOProviders", member, nil, nil))
			p1ExpectLen(t, ps, 0)
		})

		t.Run("should return provider with organizationId when org plugin is disabled if user owns it", func(t *testing.T) {
			a := p1CreateTestAuth(t, false)
			h := a.getAuthHeaders("owner@example.com", "password123", "Owner")
			a.insert("ssoProvider", map[string]any{
				"id": "provider-with-org-id", "providerId": "my-provider", "issuer": "https://idp.example.com",
				"domain": "example.com", "userId": a.userID("owner@example.com"), "organizationId": "some-org-id",
				"samlConfig": p1SAMLConfigJSON(),
			})
			ps := p1Providers(t, a.api("listSSOProviders", h, nil, nil))
			p1ExpectLen(t, ps, 1)
			if ps[0]["providerId"] != "my-provider" {
				t.Fatalf("providerId %v", ps[0]["providerId"])
			}
		})

		t.Run("should require org admin access for user-owned provider with organizationId when org plugin enabled", func(t *testing.T) {
			a := p1CreateTestAuth(t, true)
			owner := a.getAuthHeaders("owner@example.com", "password123", "Owner")
			org := a.createOrganization("test-org", owner)
			a.insert("ssoProvider", map[string]any{
				"id": "provider-owned-by-user-in-org", "providerId": "user-owned-org-provider",
				"issuer": "https://idp.example.com", "domain": "example.com",
				"userId": a.userID("owner@example.com"), "organizationId": org, "samlConfig": p1SAMLConfigJSON(),
			})
			ps := p1Providers(t, a.api("listSSOProviders", owner, nil, nil))
			p1ExpectLen(t, ps, 1)
			if ps[0]["providerId"] != "user-owned-org-provider" {
				t.Fatalf("providerId %v", ps[0]["providerId"])
			}
			nonAdmin := a.getAuthHeaders("nonadmin@example.com", "password123", "Non Admin")
			ps = p1Providers(t, a.api("listSSOProviders", nonAdmin, nil, nil))
			p1ExpectLen(t, ps, 0)
		})
	})

	t.Run("GET /sso/get-provider", func(t *testing.T) {
		t.Run("should return 401 when not authenticated", func(t *testing.T) {
			a := p1CreateTestAuth(t, true)
			r := a.api("getSSOProvider", nil, nil, map[string]any{"providerId": "test"})
			if r.Status != 401 {
				t.Fatalf("status %d", r.Status)
			}
		})

		t.Run("should return 404 when provider not found", func(t *testing.T) {
			a := p1CreateTestAuth(t, true)
			h := a.getAuthHeaders("test@example.com", "password123", "Test User")
			r := a.api("getSSOProvider", h, nil, map[string]any{"providerId": "nonexistent"})
			if r.Status != 404 {
				t.Fatalf("status %d", r.Status)
			}
		})

		t.Run("should return 403 when user does not own provider", func(t *testing.T) {
			a := p1CreateTestAuth(t, false)
			owner := a.getAuthHeaders("owner@example.com", "password123", "Owner")
			if r := a.registerSAMLProvider(owner, "other-provider", ""); r.Err != nil {
				t.Fatalf("register: %d %s", r.Status, r.message())
			}
			other := a.getAuthHeaders("other@example.com", "password123", "Other User")
			r := a.api("getSSOProvider", other, nil, map[string]any{"providerId": "other-provider"})
			if r.Status != 403 {
				t.Fatalf("status %d", r.Status)
			}
		})

		t.Run("should return sanitized SAML provider details", func(t *testing.T) {
			a := p1CreateTestAuth(t, false)
			h := a.getAuthHeaders("owner@example.com", "password123", "Owner")
			if r := a.registerSAMLProvider(h, "my-saml-provider", ""); r.Err != nil {
				t.Fatalf("register: %d %s", r.Status, r.message())
			}
			r := a.mustAPI("getSSOProvider", h, nil, map[string]any{"providerId": "my-saml-provider"})
			m := r.m()
			if m["providerId"] != "my-saml-provider" || m["type"] != "saml" || m["issuer"] != "https://idp.example.com" {
				t.Fatalf("response %s", r.Raw)
			}
			sc, ok := m["samlConfig"].(map[string]any)
			if !ok {
				t.Fatalf("samlConfig missing: %s", r.Raw)
			}
			if sc["entryPoint"] != "https://idp.example.com/sso" {
				t.Fatalf("entryPoint %v", sc["entryPoint"])
			}
			if _, ok := sc["certificate"]; !ok || sc["certificate"] == nil {
				t.Fatalf("certificate undefined: %s", r.Raw)
			}
			if s, _ := m["spMetadataUrl"].(string); !strings.Contains(s, "/sso/saml2/sp/metadata") {
				t.Fatalf("spMetadataUrl %v", m["spMetadataUrl"])
			}
		})

		t.Run("should return sanitized OIDC provider with masked clientId", func(t *testing.T) {
			a := p1CreateTestAuth(t, false)
			h := a.getAuthHeaders("owner@example.com", "password123", "Owner")
			a.createOIDCProviderData(a.userID("owner@example.com"), "my-oidc-provider", "my-client-id-12345", "")
			r := a.mustAPI("getSSOProvider", h, nil, map[string]any{"providerId": "my-oidc-provider"})
			m := r.m()
			if m["providerId"] != "my-oidc-provider" || m["type"] != "oidc" {
				t.Fatalf("response %s", r.Raw)
			}
			oc, ok := m["oidcConfig"].(map[string]any)
			if !ok {
				t.Fatalf("oidcConfig missing: %s", r.Raw)
			}
			if oc["clientIdLastFour"] != "****2345" {
				t.Fatalf("clientIdLastFour %v", oc["clientIdLastFour"])
			}
			if oc["discoveryEndpoint"] != "https://idp.example.com/.well-known" {
				t.Fatalf("discoveryEndpoint %v", oc["discoveryEndpoint"])
			}
			if _, ok := oc["clientSecret"]; ok {
				t.Fatalf("clientSecret present")
			}
		})

		t.Run("should not leak clientSecret in response", func(t *testing.T) {
			a := p1CreateTestAuth(t, false)
			h := a.getAuthHeaders("owner@example.com", "password123", "Owner")
			a.createOIDCProviderData(a.userID("owner@example.com"), "my-oidc-provider", "client123", "")
			r := a.mustAPI("getSSOProvider", h, nil, map[string]any{"providerId": "my-oidc-provider"})
			s := p1JSON(t, r.Data)
			if strings.Contains(s, "super-secret-value") || strings.Contains(s, "clientSecret") {
				t.Fatalf("leaked secret: %s", s)
			}
		})

		t.Run("should allow access to provider with organizationId when org plugin is disabled if user owns it", func(t *testing.T) {
			a := p1CreateTestAuth(t, false)
			h := a.getAuthHeaders("owner@example.com", "password123", "Owner")
			a.insert("ssoProvider", map[string]any{
				"id": "provider-with-org-id", "providerId": "my-provider", "issuer": "https://idp.example.com",
				"domain": "example.com", "userId": a.userID("owner@example.com"), "organizationId": "some-org-id",
				"samlConfig": p1SAMLConfigJSON(),
			})
			r := a.mustAPI("getSSOProvider", h, nil, map[string]any{"providerId": "my-provider"})
			if r.m()["providerId"] != "my-provider" {
				t.Fatalf("response %s", r.Raw)
			}
		})

		t.Run("should require org admin access for user-owned provider with organizationId when org plugin enabled", func(t *testing.T) {
			a := p1CreateTestAuth(t, true)
			owner := a.getAuthHeaders("owner@example.com", "password123", "Owner")
			org := a.createOrganization("test-org", owner)
			a.insert("ssoProvider", map[string]any{
				"id": "provider-owned-by-user-in-org", "providerId": "user-owned-org-provider",
				"issuer": "https://idp.example.com", "domain": "example.com",
				"userId": a.userID("owner@example.com"), "organizationId": org, "samlConfig": p1SAMLConfigJSON(),
			})
			r := a.mustAPI("getSSOProvider", owner, nil, map[string]any{"providerId": "user-owned-org-provider"})
			if r.m()["providerId"] != "user-owned-org-provider" {
				t.Fatalf("response %s", r.Raw)
			}
			nonAdmin := a.getAuthHeaders("nonadmin@example.com", "password123", "Non Admin")
			r = a.api("getSSOProvider", nonAdmin, nil, map[string]any{"providerId": "user-owned-org-provider"})
			if r.Status != 403 {
				t.Fatalf("status %d", r.Status)
			}
		})
	})

	t.Run("sanitization", func(t *testing.T) {
		t.Run("should preserve the IdP authority during a nested certificate update", func(t *testing.T) {
			a := p1CreateTestAuth(t, false)
			h := a.getAuthHeaders("owner@example.com", "password123", "Owner")
			if r := a.registerSAMLProvider(h, "manual-saml-provider", ""); r.Err != nil {
				t.Fatalf("register: %d %s", r.Status, r.message())
			}
			a.mustAPI("updateSSOProvider", h, map[string]any{
				"providerId": "manual-saml-provider",
				"samlConfig": map[string]any{"idpMetadata": map[string]any{"cert": p1RotationCert1}},
			}, nil)
			var stored string
			for _, p := range a.rows("ssoProvider") {
				if p["providerId"] == "manual-saml-provider" {
					stored, _ = p["samlConfig"].(string)
				}
			}
			var cfg map[string]any
			if err := json.Unmarshal([]byte(stored), &cfg); err != nil {
				t.Fatalf("stored config %q: %v", stored, err)
			}
			idpMeta, _ := cfg["idpMetadata"].(map[string]any)
			if idpMeta["entityID"] != "https://idp.example.com" {
				t.Fatalf("entityID %v", idpMeta["entityID"])
			}
			if idpMeta["cert"] != p1RotationCert1 {
				t.Fatalf("cert %v", idpMeta["cert"])
			}
		})

		t.Run("should not expose raw certificate PEM", func(t *testing.T) {
			a := p1CreateTestAuth(t, false)
			h := a.getAuthHeaders("owner@example.com", "password123", "Owner")
			if r := a.registerSAMLProvider(h, "my-saml-provider", ""); r.Err != nil {
				t.Fatalf("register: %d %s", r.Status, r.message())
			}
			r := a.mustAPI("getSSOProvider", h, nil, map[string]any{"providerId": "my-saml-provider"})
			s := p1JSON(t, r.Data)
			if strings.Contains(s, "BEGIN CERTIFICATE") || strings.Contains(s, p1TestCert) {
				t.Fatalf("raw cert exposed: %s", s)
			}
		})

		t.Run("should handle certificate parse errors gracefully", func(t *testing.T) {
			a := p1CreateTestAuth(t, false)
			h := a.getAuthHeaders("owner@example.com", "password123", "Owner")
			cfg, _ := json.Marshal(map[string]any{"entryPoint": "https://idp.example.com/sso", "cert": "invalid-cert-data"})
			a.insert("ssoProvider", map[string]any{
				"id": "provider-1", "providerId": "my-saml-provider", "issuer": "https://idp.example.com",
				"domain": "example.com", "userId": a.userID("owner@example.com"), "samlConfig": string(cfg),
			})
			r := a.mustAPI("getSSOProvider", h, nil, map[string]any{"providerId": "my-saml-provider"})
			certs := p1Certs(t, r)
			if len(certs) != 1 {
				t.Fatalf("certs %v", certs)
			}
			if certs[0]["error"] != "Failed to parse certificate" {
				t.Fatalf("error %v", certs[0]["error"])
			}
		})

		t.Run("should report idpMetadata.cert array as multiple parsed certificates", func(t *testing.T) {
			a := p1CreateTestAuth(t, false)
			h := a.getAuthHeaders("owner@example.com", "password123", "Owner")
			cfg, _ := json.Marshal(map[string]any{
				"entryPoint":  "https://idp.example.com/sso",
				"idpMetadata": map[string]any{"cert": []string{p1RotationCert1, p1RotationCert2}},
			})
			a.insert("ssoProvider", map[string]any{
				"id": "provider-rotation", "providerId": "rotation-provider", "issuer": "https://idp.example.com",
				"domain": "example.com", "userId": a.userID("owner@example.com"), "samlConfig": string(cfg),
			})
			r := a.mustAPI("getSSOProvider", h, nil, map[string]any{"providerId": "rotation-provider"})
			certs := p1Certs(t, r)
			if len(certs) != 2 {
				t.Fatalf("certs %v", certs)
			}
			if certs[0]["fingerprintSha256"] == certs[1]["fingerprintSha256"] {
				t.Fatalf("identical fingerprints %v", certs)
			}
		})

		t.Run("should prefer idpMetadata.cert over top-level cert in the sanitized response", func(t *testing.T) {
			a := p1CreateTestAuth(t, false)
			h := a.getAuthHeaders("owner@example.com", "password123", "Owner")
			cfg, _ := json.Marshal(map[string]any{
				"entryPoint":  "https://idp.example.com/sso",
				"cert":        "invalid-fallback-cert",
				"idpMetadata": map[string]any{"cert": p1RotationCert1},
			})
			a.insert("ssoProvider", map[string]any{
				"id": "provider-precedence", "providerId": "precedence-provider", "issuer": "https://idp.example.com",
				"domain": "example.com", "userId": a.userID("owner@example.com"), "samlConfig": string(cfg),
			})
			r := a.mustAPI("getSSOProvider", h, nil, map[string]any{"providerId": "precedence-provider"})
			certs := p1Certs(t, r)
			if len(certs) != 1 {
				t.Fatalf("certs %v", certs)
			}
			if _, ok := certs[0]["error"]; ok {
				t.Fatalf("unexpected error %v", certs[0]["error"])
			}
			if _, ok := certs[0]["fingerprintSha256"]; !ok {
				t.Fatalf("fingerprint missing %v", certs[0])
			}
		})

		t.Run("should mask short clientId with just asterisks", func(t *testing.T) {
			a := p1CreateTestAuth(t, false)
			h := a.getAuthHeaders("owner@example.com", "password123", "Owner")
			a.createOIDCProviderData(a.userID("owner@example.com"), "my-oidc-provider", "abc", "")
			r := a.mustAPI("getSSOProvider", h, nil, map[string]any{"providerId": "my-oidc-provider"})
			oc, _ := r.m()["oidcConfig"].(map[string]any)
			if oc["clientIdLastFour"] != "****" {
				t.Fatalf("clientIdLastFour %v", oc["clientIdLastFour"])
			}
		})
	})
}
