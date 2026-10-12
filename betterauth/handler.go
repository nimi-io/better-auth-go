package betterauth

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/validate"
)

// ---- routing ----

type route struct {
	ep       *Endpoint
	segments []string
}

type router struct {
	routes map[string][]route // method → routes
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return []string{}
	}
	return strings.Split(p, "/")
}

func newRouter(eps []*Endpoint) *router {
	r := &router{routes: map[string][]route{}}
	for _, ep := range eps {
		if ep.ServerOnly || ep.Path == "" {
			continue
		}
		for _, m := range ep.Methods {
			r.routes[m] = append(r.routes[m], route{ep: ep, segments: splitPath(ep.Path)})
		}
	}
	return r
}

// match returns the best route: static segments beat params beat wildcards.
func (r *router) match(method, path string) (*Endpoint, map[string]string) {
	segs := splitPath(path)
	var best *route
	var bestParams map[string]string
	bestScore := -1
	candidates := append(append([]route(nil), r.routes[method]...), r.routes["*"]...)
	for i := range candidates {
		rt := &candidates[i]
		params, score, ok := matchSegments(rt.segments, segs)
		if ok && score > bestScore {
			best, bestParams, bestScore = rt, params, score
		}
	}
	if best == nil {
		return nil, nil
	}
	return best.ep, bestParams
}

func matchSegments(pattern, segs []string) (map[string]string, int, bool) {
	params := map[string]string{}
	score := 0
	for i, p := range pattern {
		if p == "**" {
			params["_"] = strings.Join(segs[i:], "/")
			return params, score, true
		}
		if i >= len(segs) {
			return nil, 0, false
		}
		switch {
		case strings.HasPrefix(p, ":"):
			v, err := url.PathUnescape(segs[i])
			if err != nil {
				v = segs[i]
			}
			params[p[1:]] = v
			score++
		case p == "*":
			score++
		case p == segs[i]:
			score += 3
		default:
			return nil, 0, false
		}
	}
	if len(pattern) != len(segs) {
		return nil, 0, false
	}
	return params, score, true
}

func pathMatchesMiddleware(pattern, path string) bool {
	_, _, ok := matchSegments(splitPath(pattern), splitPath(path))
	return ok
}

var multiSlash = regexp.MustCompile(`/{2,}`)

// ---- body parsing (better-call getBody) ----

var jsonContentType = regexp.MustCompile(`(?i)^application/([a-z0-9.+-]*\+)?json`)

func readBody(r *http.Request, allowed []string) (any, *APIError) {
	if r.Body == nil || r.Method == http.MethodGet || r.Method == http.MethodHead {
		return validate.Undefined, nil
	}
	ct := r.Header.Get("Content-Type")
	if ct == "" || r.ContentLength == 0 {
		return validate.Undefined, nil
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, ErrMessage("BAD_REQUEST", "Unable to read request body")
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if len(raw) == 0 && r.ContentLength < 0 {
		return validate.Undefined, nil
	}
	lower := strings.ToLower(ct)
	if len(allowed) > 0 {
		base := strings.TrimSpace(strings.SplitN(lower, ";", 2)[0])
		ok := false
		for _, a := range allowed {
			na := strings.ToLower(strings.TrimSpace(a))
			if base == na || strings.Contains(base, na) {
				ok = true
				break
			}
		}
		if !ok {
			return nil, NewAPIError("UNSUPPORTED_MEDIA_TYPE", jsonx.O(
				"message", "Content-Type \""+ct+"\" is not allowed. Allowed types: "+strings.Join(allowed, ", "),
				"code", "UNSUPPORTED_MEDIA_TYPE"))
		}
	}
	switch {
	case jsonContentType.MatchString(lower):
		var v any
		dec := json.NewDecoder(bytes.NewReader(raw))
		if err := dec.Decode(&v); err != nil {
			return nil, ErrFrom("BAD_REQUEST", ErrorCode{Code: "BAD_REQUEST", Message: "Invalid JSON in request body"})
		}
		if dec.More() {
			return nil, ErrFrom("BAD_REQUEST", ErrorCode{Code: "BAD_REQUEST", Message: "Invalid JSON in request body"})
		}
		return v, nil
	case strings.Contains(lower, "application/x-www-form-urlencoded"):
		vals, err := url.ParseQuery(string(raw))
		if err != nil {
			return nil, ErrMessage("BAD_REQUEST", "Invalid form body")
		}
		out := map[string]any{}
		for k, vs := range vals {
			if len(vs) > 0 {
				out[k] = vs[len(vs)-1]
			}
		}
		return out, nil
	case strings.Contains(lower, "multipart/form-data"):
		_, params, _ := mime.ParseMediaType(ct)
		r.Body = io.NopCloser(bytes.NewReader(raw))
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			_ = params
			return nil, ErrMessage("BAD_REQUEST", "Invalid multipart body")
		}
		out := map[string]any{}
		for k, vs := range r.MultipartForm.Value {
			if len(vs) > 0 {
				out[k] = vs[len(vs)-1]
			}
		}
		return out, nil
	}
	return string(raw), nil
}

func parseQuery(u *url.URL) map[string]any {
	out := map[string]any{}
	for _, part := range strings.Split(u.RawQuery, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		k, _ = url.QueryUnescape(k)
		v, _ = url.QueryUnescape(v)
		switch cur := out[k].(type) {
		case nil:
			out[k] = v
		case string:
			out[k] = []any{cur, v}
		case []any:
			out[k] = append(cur, v)
		}
	}
	return out
}

// ---- response rendering (better-call toResponse) ----

var requestOnlyHeaders = []string{"Host", "User-Agent", "Referer", "From", "Expect", "Authorization",
	"Proxy-Authorization", "Cookie", "Origin", "Accept-Charset", "Accept-Encoding", "Accept-Language",
	"If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since", "If-Range", "Range",
	"Max-Forwards", "Connection", "Keep-Alive", "Transfer-Encoding", "Te", "Upgrade", "Trailer",
	"Proxy-Connection", "Content-Length"}

func stripRequestOnly(h http.Header) {
	for _, k := range requestOnlyHeaders {
		h.Del(k)
	}
}

// toResponse renders a handler result as a Response.
func toResponse(data any, headers http.Header, status int) *Response {
	h := http.Header{}
	safe := mergeHeaders(http.Header{}, headers)
	stripRequestOnly(safe)
	switch t := data.(type) {
	case *Response:
		out := &Response{Status: t.Status, Header: mergeHeaders(http.Header{}, t.Header), Body: t.Body}
		if out.Status == 0 {
			out.Status = 200
		}
		for k, vs := range safe {
			if k == "Set-Cookie" {
				for _, v := range vs {
					out.Header.Add(k, v)
				}
			} else {
				out.Header[k] = vs
			}
		}
		return out
	case *APIError:
		hdrs := headers
		if hdrs == nil {
			hdrs = t.Headers
		}
		st := status
		if st == 0 {
			st = t.StatusCode
		}
		if t.Body == nil {
			return toResponse(NoContent, hdrs, st)
		}
		return toResponse(t.Body, hdrs, st)
	}
	for k, vs := range safe {
		h[k] = vs
	}
	if status == 0 {
		status = 200
	}
	var body []byte
	switch t := data.(type) {
	case noContentT:
		h.Set("Content-Type", "application/json")
	case nil, nullT:
		body = []byte("null")
		h.Set("Content-Type", "application/json")
	case string:
		body = []byte(t)
		h.Set("Content-Type", "text/plain")
	case []byte:
		body = t
		h.Set("Content-Type", "application/octet-stream")
	default:
		b, err := jsonx.Marshal(data)
		if err != nil {
			return &Response{Status: 500, Header: http.Header{}}
		}
		body = b
		h.Set("Content-Type", "application/json")
	}
	return &Response{Status: status, Header: h, Body: body}
}

func writeResponse(w http.ResponseWriter, res *Response) {
	for k, vs := range res.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	if res.Status == 0 {
		res.Status = 200
	}
	w.WriteHeader(res.Status)
	if len(res.Body) > 0 {
		_, _ = w.Write(res.Body)
	}
}

func notFound() *Response {
	return &Response{Status: 404, Header: http.Header{}}
}

// ServeHTTP implements http.Handler.
func (a *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res := a.handle(r)
	writeResponse(w, res)
}

// Handler returns the HTTP handler. Mount it at the base path, e.g.
// mux.Handle("/api/auth/", auth.Handler()).
func (a *Auth) Handler() http.Handler { return a }

// requestContext builds the per-request AuthContext (base URL and trusted origins).
func (a *Auth) requestContext(r *http.Request, headers http.Header) (*AuthContext, error) {
	base := a.ctx
	c := base.clone()
	trusted := a.cfg.Advanced != nil && a.cfg.Advanced.TrustedProxyHeaders
	if a.cfg.DynamicBaseURL != nil {
		u, err := resolveDynamicBaseURL(a.cfg.DynamicBaseURL, r, headers, c.Options.BasePath, trusted)
		if err != nil {
			return nil, err
		}
		c.BaseURL = u
		opts := *c.Options
		opts.BaseURL = getOrigin(u)
		c.Options = &opts
		if c.Options.Advanced != nil && c.Options.Advanced.CrossSubDomainCookies != nil && c.Options.Advanced.CrossSubDomainCookies.Enabled {
			gen, err := newCookieGetter(c.Options, a.useSecureCookies(c.Options))
			if err == nil {
				c.cookieGen = gen
				c.AuthCookies = buildAuthCookies(c.Options, gen)
			}
		}
	} else if c.BaseURL == "" && r != nil {
		u, err := getBaseURL("", c.Options.BasePath, r, false, trusted)
		if err != nil {
			return nil, err
		}
		c.BaseURL = u
		opts := *c.Options
		opts.BaseURL = getOrigin(u)
		c.Options = &opts
	}
	// Callbacks receive a Request-like value even for header-only server calls
	// (resolveRequestContext builds `new Request(baseURL, { headers })`).
	cbReq := r
	if cbReq == nil && headers != nil {
		target := c.BaseURL
		if target == "" {
			target = "http://localhost"
		}
		if req, err := http.NewRequest("GET", target, nil); err == nil {
			req.Header = headers.Clone()
			if h := headers.Get("Host"); h != "" {
				req.Host = h
			}
			cbReq = req
		}
	}
	origins, err := a.trustedOrigins(c.Options, cbReq)
	if err != nil {
		return nil, err
	}
	c.TrustedOrigins = origins
	providers, err := a.trustedProviders(cbReq)
	if err != nil {
		return nil, err
	}
	c.TrustedProviders = providers
	return c, nil
}

func (a *Auth) handle(r *http.Request) *Response {
	ac, err := a.requestContext(r, nil)
	if err != nil {
		a.ctx.Logger.Error(err.Error())
		return &Response{Status: 500, Header: http.Header{}}
	}
	basePath := ""
	if u, err := parseJSURL(ac.BaseURL); err == nil {
		basePath = strings.TrimRight(u.Path, "/")
	}
	// onRequest: disabled paths, rate limit, plugins
	norm := normalizePathname(requestURL(r), basePath)
	for _, p := range ac.Options.DisabledPaths {
		if p == norm {
			h := http.Header{}
			h.Set("Content-Type", "text/plain;charset=UTF-8")
			return &Response{Status: 404, Header: h, Body: []byte("Not Found")}
		}
	}
	if res, err := a.onRequestRateLimit(r, ac); err != nil {
		ac.Logger.Error("rate limit error", err)
		return &Response{Status: 500, Header: http.Header{}}
	} else if res != nil {
		return res
	}
	req := r
	for _, p := range ac.plugins {
		if p.OnRequest == nil {
			continue
		}
		nr, res, err := p.OnRequest(req, ac)
		if err != nil {
			return a.errorResponse(ac, err)
		}
		if res != nil {
			return res
		}
		if nr != nil {
			req = nr
		}
	}
	res := a.process(req, ac, basePath)
	for _, p := range ac.plugins {
		if p.OnResponse == nil {
			continue
		}
		nr, err := p.OnResponse(res, ac)
		if err != nil {
			return a.errorResponse(ac, err)
		}
		if nr != nil {
			return nr
		}
	}
	return res
}

func (a *Auth) process(r *http.Request, ac *AuthContext, basePath string) *Response {
	pathname := r.URL.EscapedPath()
	path := pathname
	if basePath != "" {
		if !strings.HasPrefix(pathname, basePath+"/") {
			return notFound()
		}
		path = pathname[len(basePath):]
	}
	if path == "" || multiSlash.MatchString(path) {
		return notFound()
	}
	ep, params := a.router.match(r.Method, path)
	skipTrailing := ac.Options.Advanced != nil && ac.Options.Advanced.SkipTrailingSlashes
	if ep != nil && strings.HasSuffix(path, "/") != strings.HasSuffix(ep.Path, "/") && !skipTrailing {
		return notFound()
	}
	if ep == nil {
		return notFound()
	}
	query := parseQuery(r.URL)
	var body any = validate.Undefined
	if !ep.DisableBody {
		allowed := ep.AllowedMediaTypes
		if len(allowed) == 0 {
			allowed = []string{"application/json"}
		}
		b, apiErr := readBody(r, allowed)
		if apiErr != nil {
			return a.errorResponse(ac, apiErr)
		}
		body = b
	}
	in := callInput{Request: r, Headers: r.Header.Clone(), Body: body, Query: query, Params: params, Method: r.Method, Auth: ac}
	// router middlewares (origin check + plugin middlewares)
	mws := []PathMiddleware{{Path: "/**", Middleware: originCheckMiddleware}}
	for _, p := range ac.plugins {
		mws = append(mws, p.Middlewares...)
	}
	for _, m := range mws {
		if !pathMatchesMiddleware(m.Path, path) {
			continue
		}
		mctx := a.newEndpointContext(r.Context(), &Endpoint{Path: m.Path, Methods: []string{"*"}}, in)
		if err := m.Middleware(mctx); err != nil {
			return a.errorResponse(ac, attachHeaders(err, mctx.ResponseHeaders))
		}
	}
	result, err := a.dispatch(r.Context(), ep, in)
	if err != nil {
		return a.errorResponse(ac, err)
	}
	return toResponse(result.Response, result.Headers, result.Status)
}

func (a *Auth) errorResponse(ac *AuthContext, err error) *Response {
	e, ok := AsAPIError(err)
	if ok && e.Status == "FOUND" {
		return toResponse(e, e.Headers, e.StatusCode)
	}
	if ac.Options.OnAPIError != nil && ac.Options.OnAPIError.OnError != nil {
		ac.Options.OnAPIError.OnError(err, ac)
	} else if ok {
		if e.Status == "INTERNAL_SERVER_ERROR" {
			ac.Logger.Error(e.Status, e)
		}
	} else {
		ac.Logger.Error("internal error", err)
	}
	if ok {
		return toResponse(e, e.Headers, e.StatusCode)
	}
	return &Response{Status: 500, Header: http.Header{}}
}
