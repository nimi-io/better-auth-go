package oauthprovider

import (
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Ports of consent.ts and continue.ts.

// consentRow is an oauthConsent row.
type consentRow struct {
	ID                      string
	ClientID                string
	UserID                  string
	ReferenceID             string
	Scopes                  []string
	Resources               []string
	RequestedUserInfoClaims []string
}

func consentFromRecord(r adapter.Record) *consentRow {
	if r == nil {
		return nil
	}
	return &consentRow{ID: recStr(r, "id"), ClientID: recStr(r, "clientId"), UserID: recStr(r, "userId"),
		ReferenceID: recStr(r, "referenceId"), Scopes: recStrings(r, "scopes"), Resources: recStrings(r, "resources"),
		RequestedUserInfoClaims: recStrings(r, "requestedUserInfoClaims")}
}

func findConsent(ctx *betterauth.EndpointContext, clientID, userID, referenceID string) (*consentRow, error) {
	where := []adapter.Where{{Field: "clientId", Value: clientID}, {Field: "userId", Value: userID}}
	if referenceID != "" {
		where = append(where, adapter.Where{Field: "referenceId", Value: referenceID})
	}
	r, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: modelConsent, Where: where})
	if err != nil {
		return nil, err
	}
	return consentFromRecord(r), nil
}

func missingOAuthQuery() error {
	return oauthErr("BAD_REQUEST", "invalid_request", "missing oauth query")
}

// authorizeCaller runs the authorization endpoint for a continuation request.
type authorizeCaller func(ctx *betterauth.EndpointContext, settings authorizeSettings, query *jsonx.Object) (any, error)

// consentEndpoint handles POST /oauth2/consent.
func consentEndpoint(ctx *betterauth.EndpointContext, o *resolved, authorize authorizeCaller) (any, error) {
	state := GetOAuthProviderState(ctx)
	if state == nil || state.Query == "" {
		return nil, missingOAuthQuery()
	}
	query := parseSearchParams(state.Query)
	original := []string{}
	if v, ok := query.get("scope"); ok {
		original = strings.Split(v, " ")
	}
	supported := o.supportedClaims()
	var claimsParam any
	if v, ok := query.get("claims"); ok {
		claimsParam = v
	}
	originalClaims := getRequestedUserInfoClaims(claimsParam, supported)
	clientID := query.getString("client_id")
	if clientID == "" {
		return nil, oauthErr("BAD_REQUEST", "invalid_client", "client_id is required")
	}
	body := bodyMap(ctx)
	var requestedScopes []string
	if s, ok := body["scope"].(string); ok {
		requestedScopes = strings.Split(s, " ")
		for _, sc := range requestedScopes {
			if !contains(original, sc) {
				return nil, oauthErr("BAD_REQUEST", "invalid_request", "Scope not originally requested")
			}
		}
	}
	acceptedClaims, hasAcceptedClaims := body["claims"]
	acceptedUserInfoClaims := originalClaims
	if hasAcceptedClaims {
		acceptedUserInfoClaims = getRequestedUserInfoClaims(acceptedClaims, supported)
		for _, c := range acceptedUserInfoClaims {
			if !contains(originalClaims, c) {
				return nil, oauthErr("BAD_REQUEST", "invalid_request", "Claim not originally requested")
			}
		}
	}
	if body["accept"] != true {
		return redirectResult(formatErrorURL(query.getString("redirect_uri"), "access_denied", "User denied access",
			query.getString("state"), getIssuer(ctx, o), "query")), nil
	}
	session, err := betterauth.GetSessionFromCtx(ctx, nil)
	if err != nil {
		return nil, err
	}
	promptSet := parsePrompt(query.getString("prompt"))
	hasLoginPrompt := promptSet["login"]
	var createdAt time.Time
	if session != nil {
		createdAt = session.Session.CreatedAt
	}
	satisfiedLogin := hasLoginPrompt && isSessionFreshForSignedQuery(createdAt, state.SignedQueryIssuedAt)
	if hasLoginPrompt && !satisfiedLogin {
		setAcceptJSON(ctx)
		return authorize(ctx, authorizeSettings{}, searchParamsToQuery(query))
	}
	scopes := requestedScopes
	if scopes == nil {
		scopes = original
	}
	referenceID := ""
	if o.PostLogin != nil && o.PostLogin.ConsentReferenceID != nil {
		usc := UserSessionContext{Ctx: ctx, Headers: ctx.Headers, Scopes: scopes}
		if session != nil {
			usc.User, usc.Session = session.User, session.Session
		}
		referenceID, err = o.PostLogin.ConsentReferenceID(usc)
		if err != nil {
			return nil, err
		}
	}
	userID := ""
	if session != nil {
		userID = session.User.ID
	}
	found, err := findConsent(ctx, clientID, userID, referenceID)
	if err != nil {
		return nil, err
	}
	now := time.Unix(time.Now().Unix(), 0)
	resources := query.getAll("resource")
	var resourcesVal any
	if len(resources) > 0 {
		resourcesVal = stringsToAny(resources)
	}
	if found != nil && found.ID != "" {
		update := adapter.Record{"scopes": stringsToAny(scopes),
			"requestedUserInfoClaims": stringsToAny(acceptedUserInfoClaims), "updatedAt": now}
		if resourcesVal != nil {
			update = adapter.Record{"resources": resourcesVal, "scopes": update["scopes"],
				"requestedUserInfoClaims": update["requestedUserInfoClaims"], "updatedAt": now}
		}
		if _, err := ctx.Auth.Adapter.Update(ctx.Context(), modelConsent, []adapter.Where{{Field: "id", Value: found.ID}}, update); err != nil {
			return nil, err
		}
	} else {
		data := adapter.Record{"clientId": clientID, "userId": userID, "scopes": stringsToAny(scopes),
			"requestedUserInfoClaims": stringsToAny(acceptedUserInfoClaims), "createdAt": now, "updatedAt": now}
		if resourcesVal != nil {
			data["resources"] = resourcesVal
		}
		if referenceID != "" {
			data["referenceId"] = referenceID
		}
		if _, err := ctx.Auth.Adapter.Create(ctx.Context(), adapter.CreateInput{Model: modelConsent, Data: data}); err != nil {
			return nil, err
		}
	}
	if requestedScopes != nil {
		query.set("scope", strings.Join(scopes, " "))
	}
	if hasAcceptedClaims {
		var cv any
		if v, ok := query.get("claims"); ok {
			cv = v
		}
		if cr := filterClaimsRequestUserInfoClaims(cv, acceptedUserInfoClaims); cr != nil {
			b, _ := jsonx.Marshal(cr)
			query.set("claims", string(b))
		} else {
			query.delete("claims")
		}
	}
	setAcceptJSON(ctx)
	next := removePromptFromQuery(query, "consent")
	if satisfiedLogin {
		next = removePromptFromQuery(next, "login")
		next = removeMaxAgeFromQuery(next)
	}
	cleared := state.PostLoginClearedForSession != "" && session != nil && state.PostLoginClearedForSession == session.Session.ID
	return authorize(ctx, authorizeSettings{postLogin: cleared}, searchParamsToQuery(next))
}

// setAcceptJSON is ctx.headers.set("accept", "application/json").
func setAcceptJSON(ctx *betterauth.EndpointContext) {
	if ctx.Headers != nil {
		ctx.Headers.Set("Accept", "application/json")
	}
}

// continueEndpoint handles POST /oauth2/continue.
func continueEndpoint(ctx *betterauth.EndpointContext, authorize authorizeCaller) (any, error) {
	body := bodyMap(ctx)
	switch {
	case body["selected"] == true:
		return continueWith(ctx, authorize, "select_account")
	case body["created"] == true:
		return continueWith(ctx, authorize, "create")
	case body["postLogin"] == true:
		state := GetOAuthProviderState(ctx)
		if state == nil || state.Query == "" {
			return nil, missingOAuthQuery()
		}
		query := parseSearchParams(state.Query)
		setAcceptJSON(ctx)
		session, err := betterauth.GetSessionFromCtx(ctx, nil)
		if err != nil {
			return nil, err
		}
		cleared := state.PostLoginClearedForSession != "" && session != nil && state.PostLoginClearedForSession == session.Session.ID
		return authorize(ctx, authorizeSettings{postLogin: cleared}, searchParamsToQuery(query))
	}
	return nil, oauthErr("BAD_REQUEST", "invalid_request", "Missing parameters")
}

func continueWith(ctx *betterauth.EndpointContext, authorize authorizeCaller, prompt string) (any, error) {
	state := GetOAuthProviderState(ctx)
	if state == nil || state.Query == "" {
		return nil, missingOAuthQuery()
	}
	query := parseSearchParams(state.Query)
	setAcceptJSON(ctx)
	return authorize(ctx, authorizeSettings{}, searchParamsToQuery(removePromptFromQuery(query, prompt)))
}
