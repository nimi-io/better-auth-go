package sso

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/plugins/sso/internal/samlify"
)

type samlifyEntity = samlify.Entity

// normalizedProfile is the normalized SSO profile (NormalizedSSOProfile).
type normalizedProfile struct {
	ProviderType  string
	ProviderID    string
	AccountID     string
	Email         string
	EmailVerified bool
	RawAttributes map[string]any
}

const verifiedProviderPageSize = 100

func getEmailDomain(email string) string {
	normalized := strings.ToLower(strings.TrimSpace(email))
	parts := strings.Split(normalized, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	domain := parts[1]
	if strings.ContainsAny(domain, "/\\:") {
		return ""
	}
	d := parseProviderDomains(domain)
	if len(d) != 1 {
		return ""
	}
	return d[0]
}

func findVerifiedDomainProviders(ctx context.Context, a adapter.Adapter, domain string) ([]adapter.Record, error) {
	var out []adapter.Record
	offset := 0
	for {
		page, err := a.FindMany(ctx, adapter.FindManyInput{Model: "ssoProvider", Where: []adapter.Where{{Field: "domainVerified", Value: true}},
			Limit: verifiedProviderPageSize, Offset: offset, SortBy: &adapter.SortBy{Field: "providerId", Direction: "asc"}})
		if err != nil {
			return nil, err
		}
		for _, r := range page {
			if domainMatches(domain, recString(r, "domain")) {
				out = append(out, r)
			}
		}
		if len(page) < verifiedProviderPageSize {
			return out, nil
		}
		offset += len(page)
	}
}

type assignOptions struct {
	reason             string // provider-bound | verified-domain
	user               *betterauth.User
	profile            *normalizedProfile
	provider           *SSOProvider
	token              *oauth2.Tokens
	provisioning       *OrganizationProvisioning
	domainVerification bool
}

// assignOrganization adds the user to the provider's organization (org-assignment.ts).
func assignOrganization(ctx *betterauth.EndpointContext, o assignOptions) (string, error) {
	if o.provisioning != nil && o.provisioning.Disabled {
		return "provisioning-disabled", nil
	}
	if !ctx.Auth.HasPlugin("organization") {
		return "ineligible-source", nil
	}
	a := ctx.Auth.Adapter
	c := ctx.Context()
	var user *betterauth.User
	var provider *SSOProvider
	var orgID string
	var userInfo map[string]any
	var token *oauth2.Tokens
	if o.reason == "provider-bound" {
		if o.provider.OrganizationID == "" {
			return "no-target", nil
		}
		user, provider, orgID = o.user, o.provider, o.provider.OrganizationID
		userInfo = o.profile.RawAttributes
		if userInfo == nil {
			userInfo = map[string]any{}
		}
		token = o.token
	} else {
		if !o.domainVerification {
			return "provisioning-disabled", nil
		}
		canonical, err := ctx.Auth.InternalAdapter.FindUserByID(c, o.user.ID)
		if err != nil {
			return "", err
		}
		if canonical == nil {
			ctx.Auth.Logger.Error("Unable to assign SSO organization membership because the canonical user was not found", map[string]any{"userId": o.user.ID})
			return "ineligible-source", nil
		}
		if !canonical.EmailVerified {
			return "unverified-identity", nil
		}
		domain := getEmailDomain(canonical.Email)
		if domain == "" {
			return "unverified-identity", nil
		}
		matching, err := findVerifiedDomainProviders(c, a, domain)
		if err != nil {
			return "", err
		}
		var withOrg []adapter.Record
		orgs := map[string]bool{}
		for _, r := range matching {
			if id := recString(r, "organizationId"); id != "" {
				withOrg = append(withOrg, r)
				orgs[id] = true
			}
		}
		if len(orgs) > 1 {
			ctx.Auth.Logger.Warn("Skipped SSO organization provisioning because a verified domain maps to multiple organizations", map[string]any{"domain": domain, "userId": canonical.ID})
			return "ambiguous-target", nil
		}
		if len(withOrg) == 0 {
			return "no-target", nil
		}
		sort.SliceStable(withOrg, func(i, j int) bool { return recString(withOrg[i], "providerId") < recString(withOrg[j], "providerId") })
		p, _, _ := providerFromRecord(withOrg[0])
		user, provider, orgID = canonical, p, p.OrganizationID
		userInfo = map[string]any{}
	}
	member, err := a.FindOne(c, adapter.FindOneInput{Model: "member", Where: []adapter.Where{{Field: "organizationId", Value: orgID}, {Field: "userId", Value: user.ID}}})
	if err != nil {
		return "", err
	}
	if member != nil {
		return "already-member", nil
	}
	inv, err := a.FindOne(c, adapter.FindOneInput{Model: "invitation", Where: []adapter.Where{
		{Field: "organizationId", Value: orgID}, {Field: "email", Value: strings.ToLower(user.Email)},
		{Field: "status", Value: "pending"}, {Field: "expiresAt", Value: time.Now(), Operator: adapter.Gt}}})
	if err != nil {
		return "", err
	}
	if inv != nil {
		return "invitation-pending", nil
	}
	role := "member"
	if o.provisioning != nil {
		if o.provisioning.GetRole != nil {
			r, err := o.provisioning.GetRole(c, ProvisionUserData{User: user, UserInfo: userInfo, Token: token, Provider: provider})
			if err != nil {
				return "", err
			}
			role = r
		} else if o.provisioning.DefaultRole != "" {
			role = o.provisioning.DefaultRole
		}
	}
	if _, err := a.Create(c, adapter.CreateInput{Model: "member", Data: adapter.Record{
		"organizationId": orgID, "userId": user.ID, "role": role, "createdAt": time.Now()}}); err != nil {
		return "", err
	}
	return "assigned", nil
}
