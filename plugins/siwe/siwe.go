// Package siwe implements Sign-In with Ethereum (EIP-4361)
// (packages/better-auth/src/plugins/siwe).
package siwe

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/db"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// CacaoHeader is the CACAO header.
type CacaoHeader struct {
	T string `json:"t"`
}

// CacaoPayload is the CACAO payload.
type CacaoPayload struct {
	Domain    string   `json:"domain"`
	Aud       string   `json:"aud"`
	Nonce     string   `json:"nonce"`
	Iss       string   `json:"iss"`
	Version   string   `json:"version,omitempty"`
	Iat       string   `json:"iat,omitempty"`
	Nbf       string   `json:"nbf,omitempty"`
	Exp       string   `json:"exp,omitempty"`
	Statement string   `json:"statement,omitempty"`
	RequestID string   `json:"requestId,omitempty"`
	Resources []string `json:"resources,omitempty"`
	Type      string   `json:"type,omitempty"`
}

// CacaoSignature is the CACAO signature.
type CacaoSignature struct {
	T string `json:"t"`
	S string `json:"s"`
	M string `json:"m,omitempty"`
}

// Cacao is a Chain Agnostic CApability Object.
type Cacao struct {
	H CacaoHeader    `json:"h"`
	P CacaoPayload   `json:"p"`
	S CacaoSignature `json:"s"`
}

// VerifyMessageArgs is passed to Options.VerifyMessage (SIWEVerifyMessageArgs).
type VerifyMessageArgs struct {
	Message   string
	Signature string
	// Address is the EIP-55 checksummed address from the message.
	Address string
	ChainID int64
	Cacao   *Cacao
}

// ENSLookupArgs is passed to Options.ENSLookup.
type ENSLookupArgs struct {
	WalletAddress string
}

// ENSLookupResult is returned by Options.ENSLookup.
type ENSLookupResult struct {
	Name   string
	Avatar string
}

// SchemaOptions renames the walletAddress model and its fields (mergeSchema).
type SchemaOptions struct {
	ModelName string
	// Fields maps logical names (userId, address, chainId, isPrimary, createdAt) to columns.
	Fields map[string]string
}

// Options configures the plugin (SIWEPluginOptions).
type Options struct {
	// Domain is the expected EIP-4361 domain.
	Domain string
	// EmailDomainName builds "<address>@<EmailDomainName>" emails for new users; a
	// "<address>@siwe.placeholder.invalid" placeholder is used otherwise.
	EmailDomainName string
	// Anonymous allows sign-in without an email (default true).
	Anonymous *bool
	// GetNonce returns an ERC-4361 nonce (8+ alphanumeric characters).
	GetNonce func(ctx context.Context) (string, error)
	// VerifyMessage verifies the signature over the message.
	VerifyMessage func(ctx context.Context, args VerifyMessageArgs) (bool, error)
	// ENSLookup resolves the name/avatar of new users.
	ENSLookup func(ctx context.Context, args ENSLookupArgs) (*ENSLookupResult, error)
	Schema    *SchemaOptions
}

const (
	identifierPrefix     = "siwe:"
	identifierMaxLength  = 255
	nonceMaxLength       = identifierMaxLength - len(identifierPrefix)
	mismatchMessage      = "Unauthorized: SIWE message does not match the expected nonce, domain, address, or chain ID"
	mismatchCode         = "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH"
	verificationLifetime = 15 * time.Minute
)

var (
	nonceRe         = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	signedAddressRe = regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`)
)

func isValidNonce(nonce string, present bool) bool {
	return present && len(nonce) >= 8 && len(nonce) <= nonceMaxLength && nonceRe.MatchString(nonce)
}

var nonceBody = validate.Optional(validate.StrictObject())

func (p *plugin) verifyBody() validate.Schema {
	inner := validate.StrictObject(
		validate.F("message", validate.String().Min(1)),
		validate.F("signature", validate.String().Min(1)),
		validate.F("email", validate.Optional(validate.Email())),
	)
	return validate.Custom(func(v any, path []any) (any, []validate.Issue) {
		out, issues := validate.Validate(inner, v)
		for _, is := range issues {
			// zod skips refinements once an aborting issue (wrong type, unknown keys) exists.
			if is.Code != "invalid_format" && is.Code != "too_small" && is.Code != "too_big" {
				return nil, prefix(issues, path)
			}
		}
		m, _ := v.(map[string]any)
		if !p.anonymous() && !truthy(m["email"]) {
			issues = append(issues, validate.NewIssue([]any{"email"}, "custom", "Email is required when the anonymous plugin option is disabled."))
		}
		if len(issues) > 0 {
			return nil, prefix(issues, path)
		}
		if out == nil {
			return validate.Undefined, nil
		}
		return out, nil
	})
}

func prefix(issues []validate.Issue, path []any) []validate.Issue {
	if len(path) == 0 {
		return issues
	}
	out := make([]validate.Issue, len(issues))
	for i, is := range issues {
		is.Path = append(append([]any(nil), path...), is.Path...)
		out[i] = is
	}
	return out
}

func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case bool:
		return t
	case float64:
		return t != 0
	}
	return !validate.IsUndefined(v)
}

type plugin struct {
	opts Options
}

func (p *plugin) anonymous() bool { return p.opts.Anonymous == nil || *p.opts.Anonymous }

// apiError is APIError.fromStatus(status, body): the body is serialised as given
// (including its "status" key).
func apiError(status string, kv ...any) *betterauth.APIError {
	return betterauth.NewAPIError(status, jsonx.O(kv...))
}

func (p *plugin) nonce(ctx *betterauth.EndpointContext) (any, error) {
	nonce, err := p.opts.GetNonce(ctx.Context())
	if err != nil {
		return nil, err
	}
	if !isValidNonce(nonce, true) {
		return nil, apiError("INTERNAL_SERVER_ERROR", "message",
			fmt.Sprintf("SIWE getNonce must return an ERC-4361 nonce: 8-%d alphanumeric characters.", nonceMaxLength),
			"status", 500, "code", "SIWE_INVALID_NONCE")
	}
	if _, err := ctx.Auth.InternalAdapter.CreateVerificationValue(ctx.Context(), identifierPrefix+nonce, nonce,
		time.Now().Add(verificationLifetime), nil); err != nil {
		return nil, err
	}
	return jsonx.O("nonce", nonce), nil
}

func mismatch() *betterauth.APIError {
	return apiError("UNAUTHORIZED", "message", mismatchMessage, "status", 401, "code", mismatchCode)
}

func (p *plugin) verify(ctx *betterauth.EndpointContext) (res any, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, somethingWentWrong(fmt.Sprint(r))
		}
		if err != nil {
			if _, ok := betterauth.AsAPIError(err); !ok {
				err = somethingWentWrong(err.Error())
			}
		}
	}()
	return p.verifyInner(ctx)
}

func somethingWentWrong(msg string) *betterauth.APIError {
	return apiError("UNAUTHORIZED", "message", "Something went wrong. Please try again later.", "error", msg, "status", 401)
}

func findUserByID(ctx *betterauth.EndpointContext, id any) (*betterauth.User, error) {
	rec, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: "user", Where: []adapter.Where{{Field: "id", Operator: adapter.Eq, Value: id}}})
	if err != nil || rec == nil {
		return nil, err
	}
	return betterauth.UserFromRecord(rec), nil
}

func (p *plugin) verifyInner(ctx *betterauth.EndpointContext) (any, error) {
	a := ctx.Auth
	ia := a.InternalAdapter
	c := ctx.Context()
	message := ctx.BodyString("message")
	signature := ctx.BodyString("signature")
	email, hasEmail := ctx.BodyMap()["email"].(string)
	isAnon := p.anonymous()
	if !isAnon && (!hasEmail || email == "") {
		return nil, apiError("BAD_REQUEST", "message", "Email is required when anonymous is disabled.", "status", 400)
	}
	parsed := ParseMessage(message)
	if !isValidNonce(parsed.Nonce, parsed.HasNonce) {
		return nil, mismatch()
	}
	verification, err := ia.ConsumeVerificationValue(c, identifierPrefix+parsed.Nonce)
	if err != nil {
		return nil, err
	}
	if verification == nil {
		return nil, apiError("UNAUTHORIZED", "message", "Unauthorized: Invalid or expired nonce", "status", 401, "code", "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE")
	}
	nonce := parsed.Nonce
	walletAddress := ""
	if len(parsed.Address) == 42 && signedAddressRe.MatchString(parsed.Address) {
		walletAddress = ToChecksumAddress(parsed.Address)
	}
	domainMatches := parsed.Domain != "" && NormalizeDomain(parsed.Domain) == NormalizeDomain(p.opts.Domain)
	if walletAddress == "" || !parsed.HasChainID || parsed.ChainID <= 0 || parsed.ChainID > 9.2e18 || !domainMatches {
		return nil, mismatch()
	}
	chainID := int64(parsed.ChainID)
	now := time.Now()
	if parsed.ExpirationTime != "" {
		if exp, ok := jsonx.ParseJSDate(parsed.ExpirationTime); ok && !now.Before(exp) {
			return nil, apiError("UNAUTHORIZED", "message", "Unauthorized: SIWE message has expired", "status", 401, "code", "UNAUTHORIZED_SIWE_MESSAGE_EXPIRED")
		}
	}
	if parsed.NotBefore != "" {
		if nb, ok := jsonx.ParseJSDate(parsed.NotBefore); ok && now.Before(nb) {
			return nil, apiError("UNAUTHORIZED", "message", "Unauthorized: SIWE message is not yet valid", "status", 401, "code", "UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID")
		}
	}
	verified, err := p.opts.VerifyMessage(c, VerifyMessageArgs{
		Message: message, Signature: signature, Address: walletAddress, ChainID: chainID,
		Cacao: &Cacao{
			H: CacaoHeader{T: "caip122"},
			P: CacaoPayload{Domain: p.opts.Domain, Aud: p.opts.Domain, Nonce: nonce, Iss: p.opts.Domain, Version: "1"},
			S: CacaoSignature{T: "eip191", S: signature},
		},
	})
	if err != nil {
		return nil, err
	}
	if !verified {
		return nil, apiError("UNAUTHORIZED", "message", "Unauthorized: Invalid SIWE signature", "status", 401)
	}

	var user *betterauth.User
	existingWallet, err := a.Adapter.FindOne(c, adapter.FindOneInput{Model: "walletAddress", Where: []adapter.Where{
		{Field: "address", Operator: adapter.Eq, Value: walletAddress}, {Field: "chainId", Operator: adapter.Eq, Value: chainID}}})
	if err != nil {
		return nil, err
	}
	if existingWallet != nil {
		if user, err = findUserByID(ctx, existingWallet["userId"]); err != nil {
			return nil, err
		}
	} else {
		anyWallet, err := a.Adapter.FindOne(c, adapter.FindOneInput{Model: "walletAddress", Where: []adapter.Where{
			{Field: "address", Operator: adapter.Eq, Value: walletAddress}}})
		if err != nil {
			return nil, err
		}
		if anyWallet != nil {
			if user, err = findUserByID(ctx, anyWallet["userId"]); err != nil {
				return nil, err
			}
		}
	}
	accountID := walletAddress + ":" + jsonx.FormatNumber(float64(chainID))
	if user == nil {
		normalizedEmail := strings.ToLower(email)
		walletEmail := walletAddress + "@siwe.placeholder.invalid"
		if p.opts.EmailDomainName != "" {
			walletEmail = walletAddress + "@" + p.opts.EmailDomainName
		} else if !validate.IsEmail(walletEmail) {
			return nil, fmt.Errorf("Invalid placeholder email")
		}
		userEmail := walletEmail
		claimIdentifier := ""
		if !isAnon && normalizedEmail != "" {
			identifier := "siwe-email-claim-" + normalizedEmail
			reserved, rerr := ia.ReserveVerificationValue(c, identifier, walletAddress, time.Now().Add(time.Minute))
			if rerr != nil {
				reserved = false
			}
			if reserved {
				claimIdentifier = identifier
				existing, err := ia.FindUserByEmail(c, normalizedEmail, false)
				if err != nil {
					return nil, err
				}
				if existing == nil {
					userEmail = normalizedEmail
				}
			}
		}
		name, avatar := walletAddress, ""
		if p.opts.ENSLookup != nil {
			r, err := p.opts.ENSLookup(c, ENSLookupArgs{WalletAddress: walletAddress})
			if err != nil {
				return nil, err
			}
			if r != nil {
				name, avatar = r.Name, r.Avatar
			}
		}
		createUser := func(email string) (*betterauth.User, error) {
			return ia.CreateUser(c, adapter.Record{"name": name, "email": email, "image": avatar}, betterauth.UserInfoSource{Method: "siwe"})
		}
		user, err = func() (*betterauth.User, error) {
			defer func() {
				if claimIdentifier != "" {
					_, _ = ia.ConsumeVerificationValue(c, claimIdentifier)
				}
			}()
			u, err := createUser(userEmail)
			if err == nil && u != nil {
				return u, nil
			}
			if err == nil {
				err = fmt.Errorf("Cannot read properties of null (reading 'id')")
			}
			if userEmail != normalizedEmail || normalizedEmail == "" {
				return nil, err
			}
			claimed, ferr := ia.FindUserByEmail(c, normalizedEmail, false)
			if ferr != nil {
				return nil, ferr
			}
			if claimed == nil {
				return nil, err
			}
			userEmail = walletEmail
			return createUser(userEmail)
		}()
		if err != nil {
			return nil, err
		}
		if user == nil {
			return nil, fmt.Errorf("Cannot read properties of null (reading 'id')")
		}
		if _, err := a.Adapter.Create(c, adapter.CreateInput{Model: "walletAddress", Data: adapter.Record{
			"userId": user.ID, "address": walletAddress, "chainId": chainID, "isPrimary": true, "createdAt": time.Now()}}); err != nil {
			return nil, err
		}
		if _, err := ia.CreateAccount(c, adapter.Record{"userId": user.ID, "providerId": "siwe", "accountId": accountID,
			"createdAt": time.Now(), "updatedAt": time.Now()}); err != nil {
			return nil, err
		}
	} else if existingWallet == nil {
		if _, err := a.Adapter.Create(c, adapter.CreateInput{Model: "walletAddress", Data: adapter.Record{
			"userId": user.ID, "address": walletAddress, "chainId": chainID, "isPrimary": false, "createdAt": time.Now()}}); err != nil {
			return nil, err
		}
		if _, err := ia.CreateAccount(c, adapter.Record{"userId": user.ID, "providerId": "siwe", "accountId": accountID,
			"createdAt": time.Now(), "updatedAt": time.Now()}); err != nil {
			return nil, err
		}
	}
	session, err := ia.CreateSession(c, user.ID, nil)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, apiError("INTERNAL_SERVER_ERROR", "message", "Internal Server Error", "status", 500)
	}
	if err := betterauth.SetSessionCookie(ctx, &betterauth.SessionWithUser{Session: session, User: user}, nil, nil); err != nil {
		return nil, err
	}
	return jsonx.O("token", session.Token, "success", true,
		"user", jsonx.O("id", user.ID, "walletAddress", walletAddress, "chainId", chainID)), nil
}

func (p *plugin) schema() []db.PluginTable {
	col := func(name string) string {
		if p.opts.Schema != nil {
			return p.opts.Schema.Fields[name]
		}
		return ""
	}
	t := db.PluginTable{Key: "walletAddress", Fields: []db.Field{
		{Name: "userId", Type: db.TypeString, References: &db.Reference{Model: "user", Field: "id"}, Required: db.True, Index: true, FieldName: col("userId")},
		{Name: "address", Type: db.TypeString, Required: db.True, FieldName: col("address")},
		{Name: "chainId", Type: db.TypeNumber, Required: db.True, FieldName: col("chainId")},
		{Name: "isPrimary", Type: db.TypeBoolean, DefaultValue: false, FieldName: col("isPrimary")},
		{Name: "createdAt", Type: db.TypeDate, Required: db.True, FieldName: col("createdAt")},
	}}
	if p.opts.Schema != nil {
		t.ModelName = p.opts.Schema.ModelName
	}
	return []db.PluginTable{t}
}

// New creates the SIWE plugin.
func New(opts Options) *betterauth.Plugin {
	p := &plugin{opts: opts}
	nonceEndpoint := func(key, path string) *betterauth.Endpoint {
		return &betterauth.Endpoint{Key: key, Path: path, Methods: []string{"POST"}, Body: nonceBody, Handler: p.nonce}
	}
	return &betterauth.Plugin{
		ID:      "siwe",
		Version: "1.7.7",
		Schema:  p.schema(),
		Endpoints: []*betterauth.Endpoint{
			nonceEndpoint("getSiweNonce", "/siwe/nonce"),
			nonceEndpoint("getNonce", "/siwe/get-nonce"),
			{Key: "verifySiweMessage", Path: "/siwe/verify", Methods: []string{"POST"}, Body: p.verifyBody(),
				RequireRequest: true, Handler: p.verify},
		},
		Options: opts,
	}
}
