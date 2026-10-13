package betterauth

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"unicode"
)

var specialSchemes = map[string]string{"http:": "80", "https:": "443", "ws:": "80", "wss:": "443", "ftp:": "21"}

// parseJSURL parses an absolute URL the way the WHATWG URL parser would for the cases
// Better Auth relies on. It returns an error for relative or malformed input.
func parseJSURL(raw string) (*url.URL, error) {
	s := strings.TrimFunc(raw, func(r rune) bool { return r <= ' ' })
	s = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" {
		return nil, errors.New("Invalid URL")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if _, special := specialSchemes[u.Scheme+":"]; special {
		if u.Host == "" {
			// http:example.com is treated like http://example.com by browsers
			if u.Opaque != "" {
				return parseJSURL(u.Scheme + "://" + strings.TrimLeft(u.Opaque, "/"))
			}
			return nil, errors.New("Invalid URL")
		}
		u.Host = strings.ToLower(u.Host)
		if port := u.Port(); port == specialSchemes[u.Scheme+":"] || strings.HasSuffix(u.Host, ":") {
			u.Host = strings.TrimSuffix(u.Hostname(), ":")
			if strings.Contains(u.Host, ":") {
				u.Host = "[" + u.Host + "]"
			}
		}
		if u.Path == "" {
			u.Path = "/"
		}
	}
	return u, nil
}

// getOrigin mirrors new URL(url).origin ("" for invalid or opaque origins).
func getOrigin(raw string) string {
	u, err := parseJSURL(raw)
	if err != nil {
		return ""
	}
	if _, special := specialSchemes[u.Scheme+":"]; !special {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// getProtocol mirrors new URL(url).protocol ("" when invalid).
func getProtocol(raw string) string {
	u, err := parseJSURL(raw)
	if err != nil {
		return ""
	}
	return u.Scheme + ":"
}

// getHost mirrors new URL(url).host.
func getHost(raw string) string {
	u, err := parseJSURL(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// jsURLHref returns the serialised URL (new URL(x).href).
func jsURLHref(u *url.URL) string { return u.String() }

// resolveURL is new URL(ref, base).href.
func resolveURL(ref, base string) (string, error) {
	b, err := parseJSURL(base)
	if err != nil {
		return "", err
	}
	r, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return "", err
	}
	res := b.ResolveReference(r)
	if res.Path == "" && res.Host != "" {
		res.Path = "/"
	}
	return res.String(), nil
}

func trimTrailingSlashes(s string) string { return strings.TrimRight(s, "/") }

func checkHasPath(raw string) (bool, error) {
	u, err := parseJSURL(raw)
	if err != nil {
		return false, errors.New("Invalid base URL: " + raw + ". Please provide a valid base URL.")
	}
	p := trimTrailingSlashes(u.Path)
	if p == "" {
		p = "/"
	}
	return p != "/", nil
}

func withPath(raw, path string) (string, error) {
	u, err := parseJSURL(raw)
	if err != nil {
		return "", errors.New("Invalid base URL: " + raw + ". Please provide a valid base URL.")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("Invalid base URL: " + raw + ". URL must include 'http://' or 'https://'")
	}
	hasPath, err := checkHasPath(raw)
	if err != nil {
		return "", err
	}
	if hasPath {
		return raw, nil
	}
	trimmed := trimTrailingSlashes(raw)
	if path == "" || path == "/" {
		return trimmed, nil
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return trimmed + path, nil
}

var (
	hostnameRegex  = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*(:[0-9]{1,5})?$`)
	ipv4HostRegex  = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}(:[0-9]{1,5})?$`)
	ipv6HostRegex  = regexp.MustCompile(`^\[[0-9a-fA-F:]+\](:[0-9]{1,5})?$`)
	localhostRegex = regexp.MustCompile(`(?i)^localhost(:[0-9]{1,5})?$`)
)

func validateProxyHeader(header, kind string) bool {
	if strings.TrimSpace(header) == "" {
		return false
	}
	if kind == "proto" {
		return header == "http" || header == "https"
	}
	lower := strings.ToLower(header)
	if strings.Contains(header, "..") || strings.ContainsRune(header, 0) ||
		strings.IndexFunc(header, unicode.IsSpace) >= 0 || strings.HasPrefix(header, ".") ||
		strings.ContainsAny(header, `<>'"`) || strings.Contains(lower, "javascript:") ||
		strings.Contains(lower, "file:") || strings.Contains(lower, "data:") {
		return false
	}
	return hostnameRegex.MatchString(header) || ipv4HostRegex.MatchString(header) ||
		ipv6HostRegex.MatchString(header) || localhostRegex.MatchString(header)
}

func envBaseURL() string {
	for _, k := range []string{"BETTER_AUTH_URL", "NEXT_PUBLIC_BETTER_AUTH_URL", "PUBLIC_BETTER_AUTH_URL",
		"NUXT_PUBLIC_BETTER_AUTH_URL", "NUXT_PUBLIC_AUTH_URL"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	if v := os.Getenv("BASE_URL"); v != "" && v != "/" {
		return v
	}
	return ""
}

// requestURL reconstructs the absolute URL of an incoming request.
func requestURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if r.URL.IsAbs() {
		return r.URL.String()
	}
	return scheme + "://" + r.Host + r.URL.RequestURI()
}

// getBaseURL mirrors utils/url.ts getBaseURL.
func getBaseURL(raw, path string, r *http.Request, loadEnv, trustedProxyHeaders bool) (string, error) {
	if raw != "" {
		return withPath(raw, path)
	}
	if loadEnv {
		if v := envBaseURL(); v != "" {
			return withPath(v, path)
		}
	}
	if r != nil {
		fh, fp := r.Header.Get("X-Forwarded-Host"), r.Header.Get("X-Forwarded-Proto")
		if fh != "" && fp != "" && trustedProxyHeaders && validateProxyHeader(fp, "proto") && validateProxyHeader(fh, "host") {
			if u, err := withPath(fp+"://"+fh, path); err == nil {
				return u, nil
			}
		}
		origin := getOrigin(requestURL(r))
		if origin == "" {
			return "", errors.New("Could not get origin from request. Please provide a valid base URL.")
		}
		return withPath(origin, path)
	}
	return "", nil
}

func getHostFromRequest(r *http.Request, headers http.Header, trustedProxyHeaders bool) string {
	if headers == nil && r != nil {
		headers = r.Header
	}
	if trustedProxyHeaders && headers != nil {
		if fh := headers.Get("X-Forwarded-Host"); fh != "" && validateProxyHeader(fh, "host") {
			return fh
		}
	}
	host := ""
	if headers != nil {
		host = headers.Get("Host")
	}
	if host == "" && r != nil {
		host = r.Host
	}
	if host != "" && validateProxyHeader(host, "host") {
		return host
	}
	if r != nil {
		return getHost(requestURL(r))
	}
	return ""
}

func isLoopbackForDevScheme(host string) bool {
	h := strings.ToLower(host)
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.HasSuffix(h, "]") {
		h = h[:i]
	}
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	return h == "localhost" || strings.HasSuffix(h, ".localhost") || h == "::1" || strings.HasPrefix(h, "127.")
}

func getProtocolFromRequest(r *http.Request, headers http.Header, configProtocol string, trustedProxyHeaders bool) string {
	if configProtocol == "http" || configProtocol == "https" {
		return configProtocol
	}
	if headers == nil && r != nil {
		headers = r.Header
	}
	if trustedProxyHeaders && headers != nil {
		if fp := headers.Get("X-Forwarded-Proto"); fp != "" && validateProxyHeader(fp, "proto") {
			return fp
		}
	}
	if r != nil {
		if r.TLS != nil {
			return "https"
		}
		if r.URL.IsAbs() {
			return r.URL.Scheme
		}
		return "http"
	}
	if h := getHostFromRequest(nil, headers, trustedProxyHeaders); h != "" && isLoopbackForDevScheme(h) {
		return "http"
	}
	return "https"
}

func matchesHostPattern(host, pattern string) bool {
	if host == "" || pattern == "" {
		return false
	}
	norm := func(s string) string {
		s = strings.TrimPrefix(strings.TrimPrefix(s, "http://"), "https://")
		s, _, _ = strings.Cut(s, "/")
		return strings.ToLower(s)
	}
	h, p := norm(host), norm(pattern)
	if strings.ContainsAny(p, "*?") {
		return wildcardMatch(p, h)
	}
	return h == p
}

// resolveDynamicBaseURL mirrors resolveDynamicBaseURL.
func resolveDynamicBaseURL(cfg *DynamicBaseURL, r *http.Request, headers http.Header, basePath string, trusted bool) (string, error) {
	host := getHostFromRequest(r, headers, trusted)
	if host == "" {
		if cfg.Fallback != "" {
			return withPath(cfg.Fallback, basePath)
		}
		return "", errors.New("Could not determine host from request headers. Please provide a fallback URL in your baseURL config.")
	}
	for _, p := range cfg.AllowedHosts {
		if matchesHostPattern(host, p) {
			proto := getProtocolFromRequest(r, headers, cfg.Protocol, trusted)
			return withPath(proto+"://"+host, basePath)
		}
	}
	if cfg.Fallback != "" {
		return withPath(cfg.Fallback, basePath)
	}
	return "", errors.New("Host \"" + host + "\" is not in the allowed hosts list. Allowed hosts: " +
		strings.Join(cfg.AllowedHosts, ", ") + ". Add this host to your allowedHosts config or provide a fallback URL.")
}

// ---- trusted origins (auth/trusted-origins.ts) ----

func hasControlChars(s string) bool {
	for _, r := range s {
		if r <= 0x1f || (r >= 0x7f && r <= 0x9f) {
			return true
		}
	}
	return false
}

func normalizeOriginPath(p string) string {
	decoded := p
	if d, err := DecodeURIComponent(p); err == nil {
		decoded = d
	}
	var segs []string
	for _, s := range strings.Split(decoded, "/") {
		switch s {
		case "..":
			if len(segs) > 0 {
				segs = segs[:len(segs)-1]
			}
		case ".", "":
		default:
			segs = append(segs, s)
		}
	}
	if len(segs) == 0 {
		return ""
	}
	return "/" + strings.Join(segs, "/")
}

type customSchemeOrigin struct{ scheme, authority, path string }

func parseCustomSchemeOrigin(v string) *customSchemeOrigin {
	if hasControlChars(v) {
		return nil
	}
	end := strings.Index(v, ":")
	if end <= 0 {
		return nil
	}
	scheme := strings.ToLower(v[:end])
	rest := v[end+1:]
	authority := ""
	if strings.HasPrefix(rest, "//") {
		rest = rest[2:]
		if i := strings.IndexAny(rest, "/?#"); i == -1 {
			authority, rest = rest, ""
		} else {
			authority, rest = rest[:i], rest[i:]
		}
	}
	if i := strings.IndexAny(rest, "?#"); i != -1 {
		rest = rest[:i]
	}
	return &customSchemeOrigin{scheme: scheme, authority: strings.ToLower(authority), path: normalizeOriginPath(rest)}
}

var encodedSeparator = regexp.MustCompile(`%2[fF]|%5[cC]`)

func isSafeRelativeURL(v string) bool {
	if !strings.HasPrefix(v, "/") || strings.HasPrefix(v, "//") || strings.Contains(v, `\`) || hasControlChars(v) {
		return false
	}
	p := v
	if i := strings.IndexAny(v, "?#"); i != -1 {
		p = v[:i]
	}
	if encodedSeparator.MatchString(p) {
		return false
	}
	res, err := resolveURL(v, "https://better-auth.invalid")
	return err == nil && getOrigin(res) == "https://better-auth.invalid"
}

// matchesOriginPattern mirrors trusted-origins.ts matchesOriginPattern.
func matchesOriginPattern(u, pattern string, allowRelativePaths bool) bool {
	if strings.HasPrefix(u, "/") {
		return allowRelativePaths && isSafeRelativeURL(u)
	}
	if strings.ContainsAny(pattern, "*?") {
		if strings.Contains(pattern, "://") {
			target := getOrigin(u)
			if target == "" {
				target = u
			}
			return wildcardMatch(pattern, target)
		}
		host := getHost(u)
		if host == "" {
			return false
		}
		return wildcardMatch(pattern, host)
	}
	proto := getProtocol(u)
	if proto == "http:" || proto == "https:" || proto == "" {
		o := getOrigin(u)
		return o != "" && pattern == o
	}
	parsed := parseCustomSchemeOrigin(u)
	pp := parseCustomSchemeOrigin(pattern)
	if parsed == nil || pp == nil || parsed.scheme != pp.scheme {
		return false
	}
	if pp.authority != "" && parsed.authority != pp.authority {
		return false
	}
	if pp.path == "" {
		return true
	}
	return parsed.path == pp.path || strings.HasPrefix(parsed.path, pp.path+"/")
}

// ---- wildcard (utils/wildcard.ts without separators) ----

type regexCache struct {
	mu sync.Mutex
	m  map[string]*regexp.Regexp
}

func (c *regexCache) get(pattern string) *regexp.Regexp {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]*regexp.Regexp{}
	}
	re, ok := c.m[pattern]
	if !ok {
		re = wildcardRegexp(pattern)
		c.m[pattern] = re
	}
	return re
}

var wildcardCache regexCache

// wildcardMatch implements upstream wildcardMatch(pattern)(sample) (utils/wildcard.ts) with
// its default separator (true): "/" and "\\" separate segments, "*" matches within one
// segment, "**" spans segments, "?" matches one non-separator character, "\\" escapes.
func wildcardMatch(pattern, sample string) bool {
	re := wildcardCache.get(pattern)
	return re.MatchString(sample)
}

func escapeWildcardChar(c rune) string {
	switch c {
	case '-', '^', '$', '+', '.', '(', ')', '|', '[', ']', '{', '}', '*', '?', '\\':
		return `\` + string(c)
	}
	return regexp.QuoteMeta(string(c))
}

// wildcardRegexp ports transform(pattern, true).
func wildcardRegexp(pattern string) *regexp.Regexp {
	const (
		sepMatcher = `[/\\]`
		wildcard   = `[^/\\]`
		required   = sepMatcher + `+?`
		optional   = sepMatcher + `*?`
	)
	segments := strings.Split(pattern, "/")
	var b strings.Builder
	for i, seg := range segments {
		if seg == "" && i > 0 {
			continue
		}
		var cur string
		switch {
		case i == len(segments)-1:
			cur = optional
		case segments[i+1] != "**":
			cur = required
		}
		if seg == "**" {
			if cur != "" {
				if i != 0 {
					b.WriteString(cur)
				}
				b.WriteString(`(?:` + wildcard + `*?` + cur + `)*?`)
			}
			continue
		}
		rs := []rune(seg)
		for j := 0; j < len(rs); j++ {
			switch c := rs[j]; c {
			case '\\':
				if j < len(rs)-1 {
					b.WriteString(escapeWildcardChar(rs[j+1]))
					j++
				}
			case '?':
				b.WriteString(wildcard)
			case '*':
				b.WriteString(wildcard + `*?`)
			default:
				b.WriteString(escapeWildcardChar(c))
			}
		}
		b.WriteString(cur)
	}
	return regexp.MustCompile(`^(?:` + b.String() + `)$`)
}

func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// normalizePathname mirrors core/utils/url.ts normalizePathname.
func normalizePathname(requestURL, basePath string) string {
	u, err := parseJSURL(requestURL)
	if err != nil {
		return "/"
	}
	p := strings.TrimRight(u.EscapedPath(), "/")
	if p == "" {
		p = "/"
	}
	nb := strings.TrimRight(basePath, "/")
	if nb == "" {
		return p
	}
	if p == nb {
		return "/"
	}
	if strings.HasPrefix(p, nb+"/") {
		r := strings.TrimRight(p[len(nb):], "/")
		if r == "" {
			return "/"
		}
		return r
	}
	return p
}

// appendQueryParams mirrors core/utils/url.ts appendQueryParams.
func appendQueryParams(input string, params url.Values, order []string) (string, error) {
	if strings.HasPrefix(input, "//") || strings.HasPrefix(input, `/\`) {
		return "", errors.New("Expected an absolute or root-relative URL")
	}
	relative := strings.HasPrefix(input, "/")
	var u *url.URL
	var err error
	if relative {
		var s string
		s, err = resolveURL(input, "https://better-auth.invalid")
		if err == nil {
			u, err = url.Parse(s)
		}
		if err == nil && getOrigin(u.String()) != "https://better-auth.invalid" {
			return "", errors.New("Expected an absolute or root-relative URL")
		}
	} else {
		u, err = parseJSURL(input)
	}
	if err != nil {
		return "", err
	}
	q := encodeSearchParams(params, order)
	if q == "" {
		return input, nil
	}
	if u.RawQuery != "" {
		sep := "&"
		if strings.HasSuffix(u.RawQuery, "&") {
			sep = ""
		}
		u.RawQuery = u.RawQuery + sep + q
	} else {
		u.RawQuery = q
	}
	if relative {
		u.Scheme, u.Host = "", ""
		return u.String(), nil
	}
	return u.String(), nil
}

// encodeSearchParams serialises like URLSearchParams.toString (keys in the given order).
func encodeSearchParams(params url.Values, order []string) string {
	var parts []string
	seen := map[string]bool{}
	keys := append([]string(nil), order...)
	for k := range params {
		found := false
		for _, o := range order {
			if o == k {
				found = true
			}
		}
		if !found {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		if seen[k] {
			continue
		}
		seen[k] = true
		for _, v := range params[k] {
			parts = append(parts, formEncode(k)+"="+formEncode(v))
		}
	}
	return strings.Join(parts, "&")
}

// formEncode is application/x-www-form-urlencoded serialisation (URLSearchParams).
func formEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '*' || c == '-' || c == '.' || c == '_':
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			b.WriteString("%" + strings.ToUpper(string("0123456789abcdef"[c>>4])+string("0123456789abcdef"[c&15])))
		}
	}
	return b.String()
}

// setSearchParams sets query params on an absolute URL (url.searchParams.set) and returns href.
func setSearchParams(raw string, kv ...string) (string, error) {
	u, err := parseJSURL(raw)
	if err != nil {
		return "", err
	}
	// preserve existing order, replacing keys that are set
	existing := parseSearchParams(u.RawQuery)
	for i := 0; i+1 < len(kv); i += 2 {
		existing = existing.set(kv[i], kv[i+1])
	}
	u.RawQuery = existing.encode()
	return u.String(), nil
}

type searchParam struct{ k, v string }
type searchParams []searchParam

func parseSearchParams(q string) searchParams {
	var out searchParams
	if q == "" {
		return out
	}
	for _, part := range strings.Split(q, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		k, _ = url.QueryUnescape(k)
		v, _ = url.QueryUnescape(v)
		out = append(out, searchParam{k, v})
	}
	return out
}

func (s searchParams) set(k, v string) searchParams {
	out := searchParams{}
	done := false
	for _, p := range s {
		if p.k == k {
			if !done {
				out = append(out, searchParam{k, v})
				done = true
			}
			continue
		}
		out = append(out, p)
	}
	if !done {
		out = append(out, searchParam{k, v})
	}
	return out
}

func (s searchParams) encode() string {
	parts := make([]string, len(s))
	for i, p := range s {
		parts[i] = formEncode(p.k) + "=" + formEncode(p.v)
	}
	return strings.Join(parts, "&")
}
