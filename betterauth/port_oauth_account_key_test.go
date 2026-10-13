package betterauth

// Port of better-auth/src/oauth2/account-key.test.ts (resolveOAuthAccountKey).
//
// The Go port of resolveOAuthAccountKey is ResolveAccountID(ctx, provider, tokens, profile)
// (betterauth/routes_account.go): the provider id is the key's providerId and the returned
// string is the accountId. Go has no separate non-API variant: ResolveAccountID already
// maps an invalid subject to the error resolveOAuthAccountKeyForAPI throws for
// OAUTH_ACCOUNT_SUBJECT_INVALID (UNAUTHORIZED / FAILED_TO_GET_USER_INFO).

import (
	"math"
	"reflect"
	"testing"

	"github.com/nimi-io/better-auth-go/oauth2"
)

type poAccountKey struct{ ProviderID, AccountID string }

type poSubjectCall struct {
	Tokens  *oauth2.Tokens
	Profile map[string]any
}

// poAccountKeyProvider mirrors createProvider(): id "company-oauth" and an accountSubject
// returning String(profile.subject) unless overridden.
func poAccountKeyProvider(id string, subject func(tokens *oauth2.Tokens, profile map[string]any) (string, error)) *oauth2.GenericProvider {
	if subject == nil {
		subject = func(_ *oauth2.Tokens, profile map[string]any) (string, error) {
			return oauth2.String(profile, "subject"), nil
		}
	}
	return oauth2.NewProvider(oauth2.Spec{ID: id, Name: "Company OAuth", Subject: subject})
}

var (
	poAccountKeyTokens  = &oauth2.Tokens{AccessToken: "access-token"}
	poAccountKeyProfile = map[string]any{"subject": "provider-subject", "tenant": "acme"}
)

func poResolveAccountKey(p oauth2.Provider, tokens *oauth2.Tokens, profile map[string]any) (poAccountKey, error) {
	id, err := ResolveAccountID(&EndpointContext{}, p, tokens, profile)
	if err != nil {
		return poAccountKey{}, err
	}
	return poAccountKey{ProviderID: p.ID(), AccountID: id}, nil
}

func TestPortOAuthAccountKeyProviderIDAndSubject(t *testing.T) {
	got, err := poResolveAccountKey(poAccountKeyProvider("company-oauth", nil), poAccountKeyTokens, poAccountKeyProfile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := (poAccountKey{ProviderID: "company-oauth", AccountID: "provider-subject"}); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestPortOAuthAccountKeyNormalizesSubject(t *testing.T) {
	// it.each([["provider-subject","provider-subject"],[42,"42"]]): Go subjects are strings, so
	// the numeric case resolves the subject from a numeric profile claim through the
	// provider's default subject resolver (String(profile.sub)).
	cases := []struct {
		name    string
		p       oauth2.Provider
		profile map[string]any
		want    string
	}{
		{"string", poAccountKeyProvider("company-oauth", func(*oauth2.Tokens, map[string]any) (string, error) {
			return "provider-subject", nil
		}), poAccountKeyProfile, "provider-subject"},
		{"number 42", oauth2.NewProvider(oauth2.Spec{ID: "company-oauth"}), map[string]any{"sub": float64(42)}, "42"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := poResolveAccountKey(tc.p, poAccountKeyTokens, tc.profile)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if want := (poAccountKey{ProviderID: "company-oauth", AccountID: tc.want}); got != want {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
	}
}

func TestPortOAuthAccountKeyProviderAliasesSeparate(t *testing.T) {
	web, err := poResolveAccountKey(poAccountKeyProvider("company-web", nil), poAccountKeyTokens, poAccountKeyProfile)
	if err != nil {
		t.Fatal(err)
	}
	mobile, err := poResolveAccountKey(poAccountKeyProvider("company-mobile", nil), poAccountKeyTokens, poAccountKeyProfile)
	if err != nil {
		t.Fatal(err)
	}
	if web == mobile {
		t.Fatalf("aliases must resolve to different keys, both %+v", web)
	}
}

func TestPortOAuthAccountKeyRejectsInvalidSubject(t *testing.T) {
	str := func(s string) oauth2.Provider {
		return poAccountKeyProvider("company-oauth", func(*oauth2.Tokens, map[string]any) (string, error) { return s, nil })
	}
	// Non-finite numbers come from a numeric profile claim through the default resolver.
	num := oauth2.NewProvider(oauth2.Spec{ID: "company-oauth"})
	cases := []struct {
		name    string
		p       oauth2.Provider
		profile map[string]any
	}{
		{`""`, str(""), poAccountKeyProfile},
		{`"   "`, str("   "), poAccountKeyProfile},
		{`"undefined"`, str("undefined"), poAccountKeyProfile},
		{`"null"`, str("null"), poAccountKeyProfile},
		{"NaN", num, map[string]any{"sub": math.NaN()}},
		{"Infinity", num, map[string]any{"sub": math.Inf(1)}},
		{"-Infinity", num, map[string]any{"sub": math.Inf(-1)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := poResolveAccountKey(tc.p, poAccountKeyTokens, tc.profile)
			if err == nil {
				t.Fatalf("expected OAUTH_ACCOUNT_SUBJECT_INVALID rejection, resolved %+v", got)
			}
			e, ok := AsAPIError(err)
			if !ok || e.StatusCode != 401 || e.Code() != ErrFailedToGetUserInfo.Code {
				t.Fatalf("expected UNAUTHORIZED %s, got %v", ErrFailedToGetUserInfo.Code, err)
			}
		})
	}
}

func TestPortOAuthAccountKeyDoesNotExposeMappedUser(t *testing.T) {
	var calls []poSubjectCall
	p := poAccountKeyProvider("company-oauth", func(tokens *oauth2.Tokens, profile map[string]any) (string, error) {
		calls = append(calls, poSubjectCall{tokens, profile})
		return oauth2.String(profile, "subject"), nil
	})
	if _, err := poResolveAccountKey(p, poAccountKeyTokens, poAccountKeyProfile); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 {
		t.Fatalf("accountSubject calls = %d, want 1", len(calls))
	}
	// toHaveBeenCalledWith({tokens, profile}); the resolver signature has no user argument,
	// so mapped local-user fields cannot reach it.
	if !reflect.DeepEqual(*calls[0].Tokens, *poAccountKeyTokens) || !reflect.DeepEqual(calls[0].Profile, poAccountKeyProfile) {
		t.Fatalf("accountSubject called with %+v", calls[0])
	}
	if _, has := calls[0].Profile["user"]; has {
		t.Fatal("profile must not carry a user property")
	}
}
