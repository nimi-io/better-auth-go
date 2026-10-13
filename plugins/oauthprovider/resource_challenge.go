package oauthprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider/oauthcore"
)

// Port of packages/oauth-provider/src/resource-challenge.ts: WWW-Authenticate challenges
// for protected resources (RFC 6750, RFC 9449, RFC 9728).

// ResourceChallengeOptions configure CreateResourceServerChallenge.
type ResourceChallengeOptions struct {
	// ResourceMetadataMappings map non-URL resource identifiers to metadata URLs.
	ResourceMetadataMappings map[string]string
	DPoPSigningAlgorithms    []string
	ChallengeScopes          []string
}

var controlChars = regexp.MustCompile(`[\x00-\x1f\x7f]`)

func quoteAuthParam(v string) (string, error) {
	if controlChars.MatchString(v) {
		return "", errors.New("invalid WWW-Authenticate parameter")
	}
	return strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), `"`, `\"`), nil
}

func errorMessage(e *betterauth.APIError) string { return e.Message() }

func extractDPoPError(e *betterauth.APIError) (string, string) {
	code := errorBodyString(e, "error")
	desc := ""
	if e.Body != nil {
		if v, ok := e.Body.Get("error_description"); ok {
			if s, isStr := v.(string); isStr {
				desc = s
			}
		} else if v, ok := e.Body.Get("message"); ok {
			desc, _ = v.(string)
		}
	}
	if desc == "" {
		desc = errorMessage(e)
	}
	return code, desc
}

func resolveResourceMetadataURL(value string, o *ResourceChallengeOptions) (string, error) {
	if u, err := parseURL(value); err == nil && originOf(u) != "null" {
		p := strings.TrimSuffix(u.EscapedPath(), "/")
		search := ""
		if u.RawQuery != "" {
			search = "?" + u.RawQuery
		}
		return originOf(u) + "/.well-known/oauth-protected-resource" + p + search, nil
	}
	if o != nil {
		if m := o.ResourceMetadataMappings[value]; m != "" {
			return m, nil
		}
	}
	return "", betterauth.NewAPIError("INTERNAL_SERVER_ERROR", jsonx.O("message", "missing resource_metadata mapping for "+value))
}

func buildBearerChallenge(resources []string, o *ResourceChallengeOptions, params func(metadataURL string) ([]string, error)) (string, error) {
	parts := make([]string, 0, len(resources))
	for _, r := range resources {
		u, err := resolveResourceMetadataURL(r, o)
		if err != nil {
			return "", err
		}
		p, err := params(u)
		if err != nil {
			return "", err
		}
		parts = append(parts, "Bearer "+strings.Join(p, ", "))
	}
	return strings.Join(parts, ", "), nil
}

// CreateResourceServerChallenge converts a token verification error into the APIError a
// protected resource should return, with the WWW-Authenticate challenge
// (createResourceServerChallenge). It returns nil when err is not a challengeable error.
func CreateResourceServerChallenge(err error, resources []string, o *ResourceChallengeOptions) (*betterauth.APIError, error) {
	var challengeScope string
	if o != nil && o.ChallengeScopes != nil {
		for _, s := range o.ChallengeScopes {
			if !oauthcore.IsOAuthScopeToken(s) {
				b, _ := json.Marshal(s)
				return nil, fmt.Errorf("invalid challenge scope: %s", b)
			}
		}
		challengeScope = strings.Join(uniqueStrings(o.ChallengeScopes), " ")
	}
	e, ok := betterauth.AsAPIError(err)
	if ok && e.Status == "UNAUTHORIZED" {
		code, desc := extractDPoPError(e)
		if code != "" && (code == "invalid_dpop_proof" || (code == "invalid_token" && strings.Contains(desc, "DPoP"))) {
			algs := oauthcore.DPoPSigningAlgorithms
			if o != nil && o.DPoPSigningAlgorithms != nil {
				algs = o.DPoPSigningAlgorithms
			}
			qc, err := quoteAuthParam(code)
			if err != nil {
				return nil, err
			}
			if !oauthcore.IsValidErrorDescription(desc) {
				return nil, errors.New("invalid error_description")
			}
			qa, err := quoteAuthParam(strings.Join(algs, " "))
			if err != nil {
				return nil, err
			}
			out := betterauth.NewAPIError("UNAUTHORIZED", jsonx.O("message", errorMessage(e)))
			out.Headers.Set("WWW-Authenticate", `DPoP error="`+qc+`", error_description="`+desc+`", algs="`+qa+`"`)
			return out, nil
		}
		h, err := buildBearerChallenge(resources, o, func(u string) ([]string, error) {
			qu, err := quoteAuthParam(u)
			if err != nil {
				return nil, err
			}
			p := []string{`resource_metadata="` + qu + `"`}
			if challengeScope != "" {
				qs, err := quoteAuthParam(challengeScope)
				if err != nil {
					return nil, err
				}
				p = append(p, `scope="`+qs+`"`)
			}
			return p, nil
		})
		if err != nil {
			return nil, err
		}
		out := betterauth.NewAPIError("UNAUTHORIZED", jsonx.O("message", errorMessage(e)))
		out.Headers.Set("WWW-Authenticate", h)
		return out, nil
	}
	if ie, ok := oauthcore.IsInsufficientScopeError(err); ok {
		scope := errorBodyString(ie, "scope")
		desc := errorMessage(ie)
		if ie.Body != nil {
			if v, ok := ie.Body.Get("error_description"); ok {
				s, isStr := v.(string)
				if !isStr {
					return nil, errors.New("invalid error_description")
				}
				desc = s
			}
		}
		if !oauthcore.IsValidErrorDescription(desc) {
			return nil, errors.New("invalid error_description")
		}
		if scope == "" {
			scope = challengeScope
		}
		h, err := buildBearerChallenge(resources, o, func(u string) ([]string, error) {
			p := []string{`error="insufficient_scope"`}
			if scope != "" {
				qs, err := quoteAuthParam(scope)
				if err != nil {
					return nil, err
				}
				p = append(p, `scope="`+qs+`"`)
			}
			qu, err := quoteAuthParam(u)
			if err != nil {
				return nil, err
			}
			p = append(p, `resource_metadata="`+qu+`"`, `error_description="`+desc+`"`)
			return p, nil
		})
		if err != nil {
			return nil, err
		}
		out := betterauth.NewAPIError("FORBIDDEN", jsonx.O("message", desc))
		out.Headers.Set("WWW-Authenticate", h)
		return out, nil
	}
	return nil, nil
}
