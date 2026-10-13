package cimd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider"
)

// Port of packages/cimd/src/client-store.ts: fetching, validating and persisting one
// Client ID Metadata Document.

// ClientDiscoveryID is the client discovery id of CIMD clients (CIMD_CLIENT_DISCOVERY_ID).
const ClientDiscoveryID = "cimd"

const (
	defaultFetchTimeout = 5 * time.Second
	maxResponseBytes    = 5 * 1024
	fetchFailure        = "Failed to fetch metadata document (network error or redirect blocked)"
)

// fetchTimeout is FETCH_TIMEOUT_MS (shortened in tests).
var fetchTimeout = defaultFetchTimeout

var jsonContentTypeRe = regexp.MustCompile(`(?i)^application/(?:[-\w.]+\+)?json\s*(?:;|$)`)

func invalidClient(description string) *betterauth.APIError {
	return betterauth.NewAPIError("BAD_REQUEST", jsonx.O("error", "invalid_client", "error_description", description))
}

func tooLargeError() *betterauth.APIError {
	return invalidClient(fmt.Sprintf("Metadata document exceeds %dKB size limit", maxResponseBytes/1024))
}

func timedOutError() *betterauth.APIError {
	return invalidClient(fmt.Sprintf("Metadata document fetch timed out after %dms", fetchTimeout.Milliseconds()))
}

// responseCacheHeaders are MetadataDocumentResponseCacheHeaders; a missing key is an
// absent header.
type responseCacheHeaders map[string]string

var cacheHeaderNames = []struct{ key, header string }{
	{"cacheControl", "Cache-Control"}, {"vary", "Vary"}, {"expires", "Expires"}, {"date", "Date"},
	{"age", "Age"}, {"etag", "Etag"}, {"lastModified", "Last-Modified"},
}

func readResponseCacheHeaders(h http.Header) responseCacheHeaders {
	out := responseCacheHeaders{}
	for _, n := range cacheHeaderNames {
		if vs := h.Values(n.header); len(vs) > 0 {
			out[n.key] = joinHeader(vs)
		}
	}
	return out
}

func joinHeader(vs []string) string {
	s := vs[0]
	for _, v := range vs[1:] {
		s += ", " + v
	}
	return s
}

func (h responseCacheHeaders) get(k string) (string, bool) {
	v, ok := h[k]
	return v, ok
}

type conditionalValidators struct {
	etag         string
	lastModified string
}

// fetchResult is ClientMetadataDocumentResult: notModified or the validated metadata.
type fetchResult struct {
	notModified  bool
	metadata     *jsonx.Object
	cacheHeaders responseCacheHeaders
}

func parentContext(ctx *betterauth.EndpointContext) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx.Context()
}

type fetchOutcome struct {
	res *http.Response
	err error
}

// readBodyWithLimit reads at most limit bytes, honouring the deadline of ctx even when
// the body ignores cancellation.
func readBodyWithLimit(ctx context.Context, body io.ReadCloser, limit int) ([]byte, error) {
	type readOutcome struct {
		b   []byte
		err error
	}
	ch := make(chan readOutcome, 1)
	go func() {
		b, err := io.ReadAll(io.LimitReader(body, int64(limit)+1))
		ch <- readOutcome{b, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		if len(r.b) > limit {
			if err := body.Close(); err != nil {
				return nil, err
			}
			return nil, tooLargeError()
		}
		return r.b, nil
	case <-ctx.Done():
		go func() { _ = body.Close() }()
		return nil, ctx.Err()
	}
}

// fetchClientMetadataDocument fetches and validates one Client ID Metadata Document.
// Conditional validators are accepted only from the resolver's previously validated cache
// entry, so a 304 response carries no metadata and must be joined with that entry.
func fetchClientMetadataDocument(ctx *betterauth.EndpointContext, clientIDURL string, o *Options, v *conditionalValidators) (*fetchResult, error) {
	if urlError := ValidateClientIDURL(clientIDURL); urlError != "" {
		return nil, invalidClient(urlError)
	}
	if o.IsMetadataDocumentURLAllowed != nil {
		allowed, err := o.IsMetadataDocumentURLAllowed(clientIDURL, ctx)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, invalidClient("client_id URL is not permitted by the server's fetch policy")
		}
	}

	fctx, cancel := context.WithTimeout(parentContext(ctx), fetchTimeout)
	defer cancel()
	timedOut := func() bool { return errors.Is(fctx.Err(), context.DeadlineExceeded) }

	req, err := http.NewRequestWithContext(fctx, http.MethodGet, clientIDURL, nil)
	if err != nil {
		return nil, invalidClient(fetchFailure)
	}
	req.Header.Set("Accept", "application/json")
	if v != nil && v.etag != "" {
		req.Header.Set("If-None-Match", v.etag)
	}
	if v != nil && v.lastModified != "" {
		req.Header.Set("If-Modified-Since", v.lastModified)
	}

	ch := make(chan fetchOutcome, 1)
	go func() {
		var out fetchOutcome
		func() {
			defer func() {
				if r := recover(); r != nil {
					out = fetchOutcome{err: fmt.Errorf("%v", r)}
				}
			}()
			res, err := o.FetchClientMetadataResource(req)
			out = fetchOutcome{res, err}
		}()
		ch <- out
	}()
	var res *http.Response
	select {
	case out := <-ch:
		if out.err != nil || out.res == nil {
			if timedOut() {
				return nil, timedOutError()
			}
			return nil, invalidClient(fetchFailure)
		}
		res = out.res
	case <-fctx.Done():
		go func() {
			if out := <-ch; out.res != nil && out.res.Body != nil {
				_ = out.res.Body.Close()
			}
		}()
		return nil, timedOutError()
	}
	body := res.Body
	if body == nil {
		body = http.NoBody
	}
	closed := false
	defer func() {
		if !closed {
			_ = body.Close()
		}
	}()

	cacheHeaders := readResponseCacheHeaders(res.Header)
	if res.StatusCode == http.StatusNotModified {
		if v == nil || (v.etag == "" && v.lastModified == "") {
			return nil, invalidClient("Metadata document returned 304 without a conditional validator")
		}
		return &fetchResult{notModified: true, cacheHeaders: cacheHeaders}, nil
	}
	if res.StatusCode != http.StatusOK {
		return nil, invalidClient(fmt.Sprintf("Metadata document fetch returned HTTP %d", res.StatusCode))
	}
	contentType := res.Header.Get("Content-Type")
	if !jsonContentTypeRe.MatchString(contentType) {
		shown := contentType
		if shown == "" {
			shown = "(none)"
		}
		return nil, invalidClient(fmt.Sprintf(`Metadata document must be JSON (got Content-Type "%s")`, shown))
	}

	bodyBytes, err := func() ([]byte, error) {
		if cl := res.Header.Get("Content-Length"); cl != "" {
			if n, perr := strconv.ParseInt(leadingInt(cl), 10, 64); perr == nil && n > maxResponseBytes {
				closed = true
				if cerr := body.Close(); cerr != nil {
					return nil, cerr
				}
				return nil, tooLargeError()
			}
		}
		return readBodyWithLimit(fctx, body, maxResponseBytes)
	}()
	if err != nil {
		if timedOut() {
			return nil, timedOutError()
		}
		if e, ok := betterauth.AsAPIError(err); ok {
			return nil, e
		}
		return nil, invalidClient(fetchFailure)
	}
	raw, err := jsonx.Parse(bodyBytes)
	if err != nil {
		return nil, invalidClient("Metadata document is not valid JSON")
	}
	validation := ValidateCimdMetadata(clientIDURL, raw, MetadataValidationOptions{
		OriginBoundFields: o.OriginBoundFields,
		MetadataProfile:   o.MetadataProfile,
	})
	if !validation.Valid {
		return nil, invalidClient(validation.Error)
	}
	if ctx != nil && ctx.Auth != nil && ctx.Auth.Logger != nil {
		for _, w := range validation.Warnings {
			ctx.Auth.Logger.Warn("cimd metadata document warning: " + w)
		}
	}
	return &fetchResult{metadata: validation.Metadata, cacheHeaders: cacheHeaders}, nil
}

// leadingInt mirrors Number.parseInt: the leading decimal digits of s.
func leadingInt(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	j := i
	if j < len(s) && (s[j] == '+' || s[j] == '-') {
		j++
	}
	for j < len(s) && s[j] >= '0' && s[j] <= '9' {
		j++
	}
	return s[i:j]
}

func logError(ctx *betterauth.EndpointContext, msg string, err error) {
	if ctx != nil && ctx.Auth != nil && ctx.Auth.Logger != nil {
		ctx.Auth.Logger.Error(msg, err)
	}
}

// notify runs a best-effort callback, logging returned errors and panics.
func notify(ctx *betterauth.EndpointContext, msg string, fn func() error) {
	defer func() {
		if r := recover(); r != nil {
			logError(ctx, msg, fmt.Errorf("%v", r))
		}
	}()
	if err := fn(); err != nil {
		logError(ctx, msg, err)
	}
}

// persistMetadataDocumentClient creates or refreshes the client row for a validated
// metadata document and runs the notification callbacks.
func persistMetadataDocumentClient(ctx *betterauth.EndpointContext, clientIDURL string, metadata *jsonx.Object, o *Options, existing *oauthprovider.SchemaClient) (*oauthprovider.SchemaClient, error) {
	var previous *oauthprovider.SchemaClient
	if existing != nil {
		previous = existing.Clone()
	}
	md := metadata.Clone()
	if id, ok := metadata.Get("client_id"); ok {
		md.Set("client_id", id)
	}
	if r, ok := metadata.Get("redirect_uris"); ok {
		md.Set("redirect_uris", r)
	} else {
		md.Set("redirect_uris", []any{})
	}
	result, err := oauthprovider.RegisterClientMetadataDocument(ctx, oauthprovider.RegisterClientMetadataDocumentInput{
		ClientID:          clientIDURL,
		ClientDiscoveryID: ClientDiscoveryID,
		Metadata:          md,
		ExistingClient:    existing,
	})
	if err != nil {
		return nil, err
	}
	if result.Created {
		if o.OnClientCreated != nil {
			notify(ctx, "cimd onClientCreated notification failed", func() error {
				return o.OnClientCreated(ClientCreatedEvent{Client: result.Client, ClientMetadataDocument: metadata, Context: ctx})
			})
		}
	} else if previous != nil && o.OnClientRefreshed != nil {
		notify(ctx, "cimd onClientRefreshed notification failed", func() error {
			return o.OnClientRefreshed(ClientRefreshedEvent{Client: result.Client, PreviousClient: previous,
				ClientMetadataDocument: metadata, Context: ctx})
		})
	}
	return result.Client, nil
}
