package sso

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

const dnsLabelMaxLength = 63

const defaultTokenPrefix = "better-auth-token"

// lookupTXT resolves DNS TXT records (records joined per entry); replaceable in tests.
var lookupTXT = func(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, name)
}

func verificationIdentifier(o *Options, providerID string) string {
	prefix := defaultTokenPrefix
	if o.DomainVerification != nil && o.DomainVerification.TokenPrefix != "" {
		prefix = o.DomainVerification.TokenPrefix
	}
	return "_" + prefix + "-" + providerID
}

func generateRandomString(n int) string {
	return bacrypto.RandomString(n)
}

func (p *plugin) requestDomainVerification() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "requestDomainVerification", Path: "/sso/request-domain-verification", Methods: []string{"POST"},
		Use:  []betterauth.Middleware{betterauth.SessionMiddleware},
		Body: validate.Object(validate.F("providerId", validate.String())), Metadata: endpointMeta("requestDomainVerification", false),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			rec, err := checkProviderAccess(ctx, ctx.BodyString("providerId"))
			if err != nil {
				return nil, err
			}
			if v, _ := rec["domainVerified"].(bool); v {
				return nil, apiErr("CONFLICT", "message", "Domain has already been verified", "code", "DOMAIN_VERIFIED")
			}
			id := verificationIdentifier(p.o, recString(rec, "providerId"))
			ia := ctx.Auth.InternalAdapter
			active, err := ia.FindVerificationValue(ctx.Context(), id)
			if err != nil {
				return nil, err
			}
			ctx.SetStatus(201)
			if active != nil && active.ExpiresAt.After(time.Now()) {
				return jsonx.O("domainVerificationToken", active.Value), nil
			}
			token := generateRandomString(24)
			if _, err := ia.CreateVerificationValue(ctx.Context(), id, token, time.Now().Add(7*24*time.Hour), nil); err != nil {
				return nil, err
			}
			return jsonx.O("domainVerificationToken", token), nil
		},
	}
}

func (p *plugin) verifyDomain() *betterauth.Endpoint {
	return &betterauth.Endpoint{
		Key: "verifyDomain", Path: "/sso/verify-domain", Methods: []string{"POST"},
		Use:  []betterauth.Middleware{betterauth.SessionMiddleware},
		Body: validate.Object(validate.F("providerId", validate.String())), Metadata: endpointMeta("verifyDomain", false),
		Handler: func(ctx *betterauth.EndpointContext) (any, error) {
			rec, err := checkProviderAccess(ctx, ctx.BodyString("providerId"))
			if err != nil {
				return nil, err
			}
			if v, _ := rec["domainVerified"].(bool); v {
				return nil, apiErr("CONFLICT", "message", "Domain has already been verified", "code", "DOMAIN_VERIFIED")
			}
			id := verificationIdentifier(p.o, recString(rec, "providerId"))
			if len(id) > dnsLabelMaxLength {
				return nil, apiErr("BAD_REQUEST", "message", fmt.Sprintf("Verification identifier exceeds the DNS label limit of %d characters", dnsLabelMaxLength), "code", "IDENTIFIER_TOO_LONG")
			}
			active, err := ctx.Auth.InternalAdapter.FindVerificationValue(ctx.Context(), id)
			if err != nil {
				return nil, err
			}
			if active == nil || !active.ExpiresAt.After(time.Now()) {
				return nil, apiErr("NOT_FOUND", "message", "No pending domain verification exists", "code", "NO_PENDING_VERIFICATION")
			}
			domains := parseProviderDomains(recString(rec, "domain"))
			if domains == nil {
				return nil, apiErr("BAD_REQUEST", "message", "Invalid domain", "code", "INVALID_DOMAIN")
			}
			for _, domain := range domains {
				records, err := lookupTXT(ctx.Context(), id+"."+domain)
				if err != nil {
					ctx.Auth.Logger.Warn("DNS resolution failure while validating domain ownership for "+domain, err)
				}
				want := active.Identifier + "=" + active.Value
				found := false
				for _, r := range records {
					r = strings.TrimSpace(r)
					if r == want || r == active.Value {
						found = true
						break
					}
				}
				if !found {
					return nil, apiErr("BAD_GATEWAY", "message", "Unable to verify domain ownership for "+domain+". Try again later", "code", "DOMAIN_VERIFICATION_FAILED")
				}
			}
			updated, err := ctx.Auth.Adapter.IncrementOne(ctx.Context(), adapter.IncrementInput{Model: "ssoProvider",
				Where:     []adapter.Where{{Field: "id", Value: recString(rec, "id")}, {Field: "domain", Value: recString(rec, "domain")}},
				Increment: map[string]float64{}, Set: adapter.Record{"domainVerified": true}})
			if err != nil {
				return nil, err
			}
			if updated == nil {
				return nil, apiErr("CONFLICT", "code", "SSO_PROVIDER_CHANGED", "message", "SSO provider changed while domain verification was in progress. Reload the provider and try again")
			}
			ctx.SetStatus(204)
			return betterauth.NoContent, nil
		},
	}
}
