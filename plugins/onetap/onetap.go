// Package onetap ports Better Auth's one-tap plugin
// (packages/better-auth/src/plugins/one-tap): sign in with a Google One Tap id token
// (POST /one-tap/callback), verified against Google's JWKS.
package onetap

import (
	"context"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jose"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
	"github.com/nimi-io/better-auth-go/providers/google"
	"github.com/nimi-io/better-auth-go/validate"
)

// Options configure the plugin (OneTapOptions).
type Options struct {
	// DisableSignup rejects One Tap sign-ins for unknown users.
	DisableSignup bool
	// ClientID is the expected audience; defaults to the Google social provider client id.
	ClientID string
}

var callbackBody = validate.Object(
	validate.F("idToken", validate.String()),
	validate.F("callbackURL", validate.Optional(validate.String())),
)

var openapi = map[string]any{
	"summary":     "One tap callback",
	"description": "Use this endpoint to authenticate with Google One Tap",
	"responses": map[string]any{
		"200": map[string]any{"description": "Successful response", "content": map[string]any{"application/json": map[string]any{
			"schema": map[string]any{"type": "object", "properties": map[string]any{
				"session": map[string]any{"$ref": "#/components/schemas/Session"},
				"user":    map[string]any{"$ref": "#/components/schemas/User"},
			}}}}},
		"400": map[string]any{"description": "Invalid token"},
	},
}

// configuredGoogle returns the configured Google social provider (options.socialProviders.google).
func configuredGoogle(a *betterauth.AuthContext) *oauth2.GenericProvider {
	for _, p := range a.Options.SocialProviders {
		if p.ID() == "google" {
			g, _ := p.(*oauth2.GenericProvider)
			return g
		}
	}
	return nil
}

// verifyGoogleIDToken verifies a Google id token (verifyGoogleIdToken) and returns its claims.
func verifyGoogleIDToken(ctx context.Context, token string, audience []string) map[string]any {
	header, err := jose.Header(token)
	if err != nil {
		return nil
	}
	alg, _ := header.Get("alg")
	if alg != "RS256" {
		return nil
	}
	kidV, _ := header.Get("kid")
	kid, _ := kidV.(string)
	set, err := oauth2.FetchJWKS(ctx, google.JWKSEndpoint, kid)
	if err != nil {
		return nil
	}
	_, payload, err := jose.VerifyJWT(token, jose.KeySetFunc(set), jose.VerifyOptions{
		Algorithms: []string{"RS256"}, Issuer: google.Issuers, Audience: audience, MaxTokenAge: time.Hour})
	if err != nil {
		return nil
	}
	return payload.Map()
}

func badRequest(msg string) error { return betterauth.ErrMessage("BAD_REQUEST", msg) }

// New creates the one-tap plugin (oneTap).
func New(o Options) *betterauth.Plugin {
	handler := func(ctx *betterauth.EndpointContext) (any, error) {
		a := ctx.Auth
		idToken := ctx.BodyString("idToken")
		gp := configuredGoogle(a)
		var audience []string
		if o.ClientID != "" {
			audience = []string{o.ClientID}
		} else if gp != nil {
			audience = gp.Options().Audiences()
		}
		if len(audience) == 0 {
			return nil, badRequest("Google client ID is required for One Tap. Set it on the oneTap plugin (clientId) or on socialProviders.google.")
		}
		payload := verifyGoogleIDToken(ctx.Context(), idToken, audience)
		if payload == nil || !validate.Truthy(payload["sub"]) {
			return nil, badRequest("invalid id token")
		}
		if gp != nil && gp.S.IDToken != nil && gp.S.IDToken.VerifyClaims != nil {
			hd, _ := payload["hd"]
			if !gp.S.IDToken.VerifyClaims(jsonx.O("hd", hd)) {
				shown := "<missing>"
				if s, ok := hd.(string); ok && s != "" {
					shown = s
				}
				a.Logger.Error(`Google One Tap sign-in rejected: id token hosted domain (hd) "` + shown + `" does not satisfy the configured "hd" option.`)
				return nil, badRequest("invalid id token")
			}
		}
		rawEmail, _ := payload["email"].(string)
		if rawEmail == "" {
			return nil, badRequest("Email not available in token")
		}
		sub, _ := payload["sub"].(string)
		if sub == "" {
			return nil, badRequest("invalid id token")
		}
		email := strings.ToLower(rawEmail)
		emailVerified := false
		switch v := payload["email_verified"].(type) {
		case bool:
			emailVerified = v
		case string:
			emailVerified = v == "true"
		}
		name, _ := payload["name"].(string)
		picture, _ := payload["picture"].(string)
		disableSignUp := o.DisableSignup || (gp != nil && gp.Options().DisableSignUp)
		res, err := betterauth.HandleOAuthUserInfo(ctx, betterauth.HandleOAuthUserInfoOptions{
			UserInfo:      oauth2.UserInfo{Email: email, EmailVerified: emailVerified, Name: name, Image: picture},
			Account:       betterauth.OAuthAccountData{ProviderID: "google", AccountID: sub, IDToken: idToken, Scope: "openid,profile,email"},
			DisableSignUp: disableSignUp,
			Source:        betterauth.UserInfoSource{Method: "oauth", ProviderID: "google", Profile: payload},
		})
		if err != nil {
			return nil, err
		}
		if res.Error != "" {
			if res.Error == betterauth.OAuthErrEmailNotVerified {
				return nil, betterauth.ErrFrom("FORBIDDEN", betterauth.ErrEmailNotVerified)
			}
			return nil, betterauth.ErrMessage("UNAUTHORIZED", res.Error)
		}
		if err := betterauth.SetSessionCookie(ctx, res.Data, nil, nil); err != nil {
			return nil, err
		}
		return jsonx.O("token", res.Data.Session.Token, "user", a.UserOutput(res.Data.User)), nil
	}
	return &betterauth.Plugin{
		ID:      "one-tap",
		Options: o,
		Endpoints: []*betterauth.Endpoint{{
			Key: "oneTapCallback", Path: "/one-tap/callback", Methods: []string{"POST"}, Body: callbackBody,
			Metadata: map[string]any{"openapi": openapi}, Handler: handler,
		}},
	}
}
