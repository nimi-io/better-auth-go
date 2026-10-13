// Package haveibeenpwned rejects passwords found in the Have I Been Pwned breach corpus,
// using the k-anonymity range API (packages/better-auth/src/plugins/haveibeenpwned).
package haveibeenpwned

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
)

// ErrPasswordCompromised is the plugin error code.
var ErrPasswordCompromised = betterauth.ErrorCode{Code: "PASSWORD_COMPROMISED",
	Message: "The password you entered has been compromised. Please choose a different password."}

// RangeURL is the k-anonymity range endpoint; the 5-character SHA-1 prefix is appended.
const RangeURL = "https://api.pwnedpasswords.com/range/"

// DefaultPaths are the endpoints whose password hashing is checked.
var DefaultPaths = []string{
	"/sign-up/email",
	"/change-password",
	"/reset-password",
	"/email-otp/reset-password",
	"/phone-number/reset-password",
	"/admin/create-user",
	"/admin/set-user-password",
}

// Options configures the plugin (HaveIBeenPwnedOptions).
type Options struct {
	CustomPasswordCompromisedMessage string
	// Paths replaces DefaultPaths.
	Paths []string
	// Enabled defaults to true.
	Enabled *bool
	// HTTPClient performs the range request (defaults to oauth2.HTTPClient).
	HTTPClient *http.Client
}

var countRe = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
var lineRe = regexp.MustCompile(`\r?\n`)

func errInternal(msg string) *betterauth.APIError {
	return betterauth.NewAPIError("INTERNAL_SERVER_ERROR", jsonx.O("message", msg))
}

// compromiseCount mirrors getPasswordCompromiseCount.
func compromiseCount(response, suffix string) (int64, error) {
	want := strings.ToUpper(suffix) + ":"
	for _, line := range lineRe.Split(response, -1) {
		if len(line) < len(want) || strings.ToUpper(line[:len(want)]) != want {
			continue
		}
		text := line[len(want):]
		n, err := strconv.ParseInt(text, 10, 64)
		if !countRe.MatchString(text) || err != nil || n > 9007199254740991 {
			return 0, fmt.Errorf("Invalid password compromise count")
		}
		return n, nil
	}
	return 0, nil
}

// IsPasswordCompromised queries the range API with the default HTTP client.
func IsPasswordCompromised(ctx context.Context, password string) (bool, error) {
	return isPasswordCompromised(ctx, nil, password)
}

func isPasswordCompromised(ctx context.Context, client *http.Client, password string) (bool, error) {
	if client == nil {
		client = oauth2.HTTPClient
	}
	sum := sha1.Sum([]byte(password))
	hash := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := hash[:5], hash[5:]
	req, err := http.NewRequestWithContext(ctx, "GET", RangeURL+prefix, nil)
	if err != nil {
		return false, errInternal("Failed to check password. Please try again later.")
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "BetterAuth Password Checker")
	res, err := client.Do(req)
	if err != nil {
		return false, errInternal("Failed to check password. Please try again later.")
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return false, errInternal(fmt.Sprintf("Failed to check password. Status: %d", res.StatusCode))
	}
	if err != nil {
		return false, errInternal("Failed to check password. Please try again later.")
	}
	n, err := compromiseCount(string(body), suffix)
	if err != nil {
		return false, errInternal("Failed to check password. Please try again later.")
	}
	return n > 0, nil
}

// New creates the plugin. Upstream wraps ctx.password.hash and inspects the current
// endpoint path; in Go a before hook on the configured paths installs the wrapped hash on
// the request-scoped AuthContext instead, which has the same effect.
func New(opts Options) *betterauth.Plugin {
	paths := opts.Paths
	if paths == nil {
		paths = DefaultPaths
	}
	enabled := opts.Enabled == nil || *opts.Enabled
	return &betterauth.Plugin{
		ID:      "have-i-been-pwned",
		Version: "1.7.7",
		Hooks: betterauth.PluginHooks{Before: []betterauth.Hook{{
			Matcher: func(ctx *betterauth.EndpointContext) bool {
				return enabled && ctx.Path != "" && slices.Contains(paths, ctx.Path)
			},
			Handler: func(ctx *betterauth.EndpointContext) (any, error) {
				original := ctx.Auth.Password.Hash
				reqCtx := ctx.Context()
				ctx.Auth.Password.Hash = func(password string) (string, error) {
					compromised, err := isPasswordCompromised(reqCtx, opts.HTTPClient, password)
					if err != nil {
						return "", err
					}
					if compromised {
						msg := opts.CustomPasswordCompromisedMessage
						if msg == "" {
							msg = ErrPasswordCompromised.Message
						}
						return "", betterauth.ErrFrom("BAD_REQUEST", betterauth.ErrorCode{Code: ErrPasswordCompromised.Code, Message: msg})
					}
					return original(password)
				}
				return nil, nil
			},
		}}},
		ErrorCodes: []betterauth.ErrorCode{ErrPasswordCompromised},
		Options:    opts,
	}
}
