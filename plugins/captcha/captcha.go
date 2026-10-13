// Package captcha protects endpoints with a CAPTCHA (Cloudflare Turnstile, Google
// reCAPTCHA, hCaptcha, CaptchaFox) or Vercel BotID check
// (packages/better-auth/src/plugins/captcha).
package captcha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/oauth2"
)

// Providers.
const (
	CloudflareTurnstile = "cloudflare-turnstile"
	GoogleRecaptcha     = "google-recaptcha"
	HCaptcha            = "hcaptcha"
	CaptchaFox          = "captchafox"
	VercelBotID         = "vercel-botid"
)

// SiteVerifyURLs are the default verification endpoints (siteVerifyMap).
var SiteVerifyURLs = map[string]string{
	CloudflareTurnstile: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	GoogleRecaptcha:     "https://www.google.com/recaptcha/api/siteverify",
	HCaptcha:            "https://api.hcaptcha.com/siteverify",
	CaptchaFox:          "https://api.captchafox.com/siteverify",
}

// DefaultEndpoints are protected when Options.Endpoints is empty.
var DefaultEndpoints = []string{"/sign-up/email", "/sign-in/email", "/request-password-reset"}

// VerifyTimeout bounds each verification (CAPTCHA_VERIFY_TIMEOUT_MS).
const VerifyTimeout = 10 * time.Second

// verifyTimeout is a variable so tests can shorten it.
var verifyTimeout = VerifyTimeout

// External error codes (EXTERNAL_ERROR_CODES).
var (
	ErrVerificationFailed = betterauth.ErrorCode{Code: "VERIFICATION_FAILED", Message: "Captcha verification failed"}
	ErrMissingResponse    = betterauth.ErrorCode{Code: "MISSING_RESPONSE", Message: "Missing CAPTCHA response"}
	ErrUnknownError       = betterauth.ErrorCode{Code: "UNKNOWN_ERROR", Message: "Something went wrong"}
)

// Internal error codes (INTERNAL_ERROR_CODES); they are logged, never returned.
var (
	ErrMissingSecretKey   = betterauth.ErrorCode{Code: "MISSING_SECRET_KEY", Message: "Missing secret key"}
	ErrServiceUnavailable = betterauth.ErrorCode{Code: "SERVICE_UNAVAILABLE", Message: "CAPTCHA service unavailable"}
)

// BotIDVerification is the result of a Vercel BotID check.
type BotIDVerification struct {
	IsBot               bool
	IsVerifiedBot       bool
	VerifiedBotName     string
	VerifiedBotCategory string
}

// ValidateRequestContext is passed to Options.ValidateRequest.
type ValidateRequestContext struct {
	Request      *http.Request
	Verification BotIDVerification
}

// Options configures the plugin (CaptchaOptions).
type Options struct {
	// Provider is one of the provider constants.
	Provider  string
	SecretKey string
	// Endpoints are protected paths ("*" matches one segment, "**" several); defaults to
	// DefaultEndpoints.
	Endpoints             []string
	SiteVerifyURLOverride string
	// MinScore is the reCAPTCHA v3 threshold (default 0.5).
	MinScore *float64
	// ExpectedAction and AllowedHostnames bind Turnstile / reCAPTCHA tokens.
	ExpectedAction   string
	AllowedHostnames []string
	// SiteKey is sent to hCaptcha / CaptchaFox.
	SiteKey string
	// CheckBotID and ValidateRequest configure the vercel-botid provider.
	CheckBotID      func(ctx context.Context) (BotIDVerification, error)
	ValidateRequest func(ctx context.Context, c ValidateRequestContext) (bool, error)
	// HTTPClient performs siteverify requests (defaults to oauth2.HTTPClient).
	HTTPClient *http.Client
}

var multiSlash = regexp.MustCompile(`/{2,}`)

func normalizeEndpointPath(pathname, basePath string) string {
	p := strings.TrimPrefix(pathname, basePath)
	p = multiSlash.ReplaceAllString(p, "/")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if len(p) > 1 && strings.HasSuffix(p, "/") {
		p = p[:len(p)-1]
	}
	return p
}

// middlewareResponse builds a JSON {message, code} response.
func middlewareResponse(code betterauth.ErrorCode, status int) *betterauth.Response {
	body := jsonx.MustMarshal(jsonx.O("message", code.Message, "code", code.Code))
	return &betterauth.Response{Status: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: body}
}

var errServiceUnavailable = errors.New(ErrServiceUnavailable.Message)

type siteVerify struct {
	url, secret, response, remoteIP string
	client                          *http.Client
}

// post sends the siteverify request and decodes the JSON response (betterFetch with the
// shared timeout); any failure is reported as SERVICE_UNAVAILABLE.
func (s siteVerify) post(ctx context.Context, contentType string, body []byte) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", s.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	client := s.client
	if client == nil {
		client = oauth2.HTTPClient
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil || res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, errServiceUnavailable
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil || data == nil {
		return nil, errServiceUnavailable
	}
	return data, nil
}

// formEncode mirrors URLSearchParams serialisation with insertion order.
func formEncode(kv ...string) string {
	var b strings.Builder
	for i := 0; i+1 < len(kv); i += 2 {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(formEscape(kv[i]))
		b.WriteByte('=')
		b.WriteString(formEscape(kv[i+1]))
	}
	return b.String()
}

func formEscape(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '*', c == '-', c == '.', c == '_':
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func str(v any) string { s, _ := v.(string); return s }

func (p *plugin) verificationFailed() *betterauth.Response {
	return middlewareResponse(ErrVerificationFailed, 403)
}

func (p *plugin) turnstile(ctx context.Context, log betterauth.Logger, s siteVerify) (*betterauth.Response, error) {
	payload := jsonx.O("secret", s.secret, "response", s.response)
	if s.remoteIP != "" {
		payload.Set("remoteip", s.remoteIP)
	}
	data, err := s.post(ctx, "application/json", jsonx.MustMarshal(payload))
	if err != nil {
		return nil, errServiceUnavailable
	}
	failed := func(details ...any) *betterauth.Response {
		log.Warn("Cloudflare Turnstile verification failed", jsonx.O(append([]any{"provider", "cloudflare-turnstile"}, details...)...).Map())
		return p.verificationFailed()
	}
	if data["success"] != true {
		codes, ok := data["error-codes"]
		if !ok || codes == nil {
			codes = []any{}
		}
		details := []any{"reason", "siteverify_rejected", "errorCodes", codes}
		if h := str(data["hostname"]); h != "" {
			details = append(details, "hostname", h)
		}
		if a := str(data["action"]); a != "" {
			details = append(details, "action", a)
		}
		return failed(details...), nil
	}
	if p.opts.ExpectedAction != "" && data["action"] != p.opts.ExpectedAction {
		return failed("reason", "action_mismatch", "expectedAction", p.opts.ExpectedAction, "actualAction", data["action"]), nil
	}
	if len(p.opts.AllowedHostnames) > 0 {
		h := str(data["hostname"])
		if h == "" || !slices.Contains(p.opts.AllowedHostnames, h) {
			return failed("reason", "hostname_mismatch", "allowedHostnames", p.opts.AllowedHostnames, "actualHostname", data["hostname"]), nil
		}
	}
	return nil, nil
}

func (p *plugin) recaptcha(ctx context.Context, s siteVerify) (*betterauth.Response, error) {
	kv := []string{"secret", s.secret, "response", s.response}
	if s.remoteIP != "" {
		kv = append(kv, "remoteip", s.remoteIP)
	}
	data, err := s.post(ctx, "application/x-www-form-urlencoded", []byte(formEncode(kv...)))
	if err != nil {
		return nil, errServiceUnavailable
	}
	minScore := 0.5
	if p.opts.MinScore != nil {
		minScore = *p.opts.MinScore
	}
	score, isV3 := data["score"].(float64)
	if data["success"] != true || (isV3 && score < minScore) {
		return p.verificationFailed(), nil
	}
	if p.opts.ExpectedAction != "" && data["action"] != p.opts.ExpectedAction {
		return p.verificationFailed(), nil
	}
	if len(p.opts.AllowedHostnames) > 0 {
		h, ok := data["hostname"].(string)
		if !ok || !slices.Contains(p.opts.AllowedHostnames, h) {
			return p.verificationFailed(), nil
		}
	}
	return nil, nil
}

// simple handles hCaptcha and CaptchaFox (remoteIPKey differs: "remoteip" / "remoteIp").
func (p *plugin) simple(ctx context.Context, s siteVerify, remoteIPKey string) (*betterauth.Response, error) {
	kv := []string{"secret", s.secret, "response", s.response}
	if p.opts.SiteKey != "" {
		kv = append(kv, "sitekey", p.opts.SiteKey)
	}
	if s.remoteIP != "" {
		kv = append(kv, remoteIPKey, s.remoteIP)
	}
	data, err := s.post(ctx, "application/x-www-form-urlencoded", []byte(formEncode(kv...)))
	if err != nil {
		return nil, errServiceUnavailable
	}
	if data["success"] != true {
		return p.verificationFailed(), nil
	}
	return nil, nil
}

// vercelBotID runs checkBotId (and validateRequest) under the shared timeout.
func (p *plugin) vercelBotID(r *http.Request) (*betterauth.Response, error) {
	type result struct {
		ok  bool
		err error
	}
	ctx, cancel := context.WithTimeout(r.Context(), verifyTimeout)
	defer cancel()
	done := make(chan result, 1)
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				done <- result{err: fmt.Errorf("%v", rec)}
			}
		}()
		if p.opts.CheckBotID == nil {
			done <- result{err: errors.New("checkBotId is not a function")}
			return
		}
		v, err := p.opts.CheckBotID(ctx)
		if err != nil {
			done <- result{err: err}
			return
		}
		if p.opts.ValidateRequest != nil {
			ok, err := p.opts.ValidateRequest(ctx, ValidateRequestContext{Request: r, Verification: v})
			done <- result{ok: ok, err: err}
			return
		}
		done <- result{ok: !v.IsBot}
	}()
	select {
	case res := <-done:
		if res.err != nil {
			return nil, fmt.Errorf("%s: %w", ErrServiceUnavailable.Message, res.err)
		}
		if res.ok {
			return nil, nil
		}
		return p.verificationFailed(), nil
	case <-ctx.Done():
		return nil, errServiceUnavailable
	}
}

type plugin struct {
	opts Options
}

func (p *plugin) matches(pathname string) bool {
	endpoints := p.opts.Endpoints
	if len(endpoints) == 0 {
		endpoints = DefaultEndpoints
	}
	for _, e := range endpoints {
		if strings.Contains(e, "*") {
			if wildcardRegexp(e).MatchString(pathname) {
				return true
			}
		} else if e == pathname {
			return true
		}
	}
	return false
}

func (p *plugin) onRequest(r *http.Request, ac *betterauth.AuthContext) (*http.Request, *betterauth.Response, error) {
	res, err := p.check(r, ac)
	if err != nil {
		msg := err.Error()
		ac.Logger.Error(msg, map[string]any{"endpoint": r.URL.String(), "message": err})
		return nil, middlewareResponse(ErrUnknownError, 500), nil
	}
	return nil, res, nil
}

func (p *plugin) check(r *http.Request, ac *betterauth.AuthContext) (res *betterauth.Response, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			res, err = nil, fmt.Errorf("%v", rec)
		}
	}()
	basePath := ac.Options.BasePath
	if basePath == "" {
		basePath = "/api/auth"
	}
	if !p.matches(normalizeEndpointPath(r.URL.EscapedPath(), basePath)) {
		return nil, nil
	}
	if p.opts.Provider == VercelBotID {
		return p.vercelBotID(r)
	}
	if p.opts.SecretKey == "" {
		return nil, errors.New(ErrMissingSecretKey.Message)
	}
	token := r.Header.Get("x-captcha-response")
	remoteIP := betterauth.GetIP(r.Header, ac.Options)
	if token == "" {
		return middlewareResponse(ErrMissingResponse, 400), nil
	}
	url := p.opts.SiteVerifyURLOverride
	if url == "" {
		url = SiteVerifyURLs[p.opts.Provider]
	}
	s := siteVerify{url: url, secret: p.opts.SecretKey, response: token, remoteIP: remoteIP, client: p.opts.HTTPClient}
	switch p.opts.Provider {
	case CloudflareTurnstile:
		return p.turnstile(r.Context(), ac.Logger, s)
	case GoogleRecaptcha:
		return p.recaptcha(r.Context(), s)
	case HCaptcha:
		return p.simple(r.Context(), s, "remoteip")
	case CaptchaFox:
		return p.simple(r.Context(), s, "remoteIp")
	}
	return nil, nil
}

// New creates the captcha plugin.
func New(opts Options) *betterauth.Plugin {
	p := &plugin{opts: opts}
	return &betterauth.Plugin{
		ID:         "captcha",
		Version:    "1.7.7",
		ErrorCodes: []betterauth.ErrorCode{ErrVerificationFailed, ErrMissingResponse, ErrUnknownError},
		OnRequest:  p.onRequest,
		Options:    opts,
	}
}
