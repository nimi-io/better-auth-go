package cimd

import (
	"container/list"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
	"github.com/nimi-io/better-auth-go/plugins/jwt"
	"github.com/nimi-io/better-auth-go/plugins/oauthprovider"
)

// Port of packages/cimd/src/resolver.ts: the per-plugin-instance metadata cache, HTTP
// freshness, conditional revalidation and the bounded fetch governor.

const fetchBudgetWindowMs = 60_000

// nowFunc is Date.now (replaced in tests).
var nowFunc = time.Now

func nowMs() int64 { return nowFunc().UnixMilli() }

func createMetadataFetchUnavailableError(description string) *betterauth.APIError {
	return betterauth.NewAPIError("TOO_MANY_REQUESTS", jsonx.O("error", "temporarily_unavailable", "error_description", description))
}

// durationSeconds converts a number of seconds, a duration string ("60m", "1d") or a
// time.Duration into seconds (toExpJWT(value, now) - now for strings).
func durationSeconds(v any, nowSec int64) (float64, error) {
	switch t := v.(type) {
	case int:
		return float64(t), nil
	case int64:
		return float64(t), nil
	case float64:
		return t, nil
	case time.Duration:
		return t.Seconds(), nil
	case string:
		exp, err := jwt.ToExpJWT(t, nowSec)
		if err != nil {
			return 0, err
		}
		return float64(exp - nowSec), nil
	}
	return 0, fmt.Errorf("unsupported duration %T", v)
}

func parseDurationMs(value any, optionName string) (float64, error) {
	fail := fmt.Errorf("cimd metadataFetchPolicy.%s must be a non-negative number of seconds or duration string", optionName)
	switch value.(type) {
	case int, int64, float64, time.Duration:
		s, _ := durationSeconds(value, 0)
		if math.IsNaN(s) || math.IsInf(s, 0) || s < 0 {
			return 0, fail
		}
		return s * 1000, nil
	}
	nowSec := nowMs() / 1000
	s, err := durationSeconds(value, nowSec)
	if err != nil || math.IsNaN(s) || s < 0 {
		return 0, fail
	}
	return s * 1000, nil
}

func requirePositiveInteger(value *int, def int, optionName string) (int, error) {
	if value == nil {
		return def, nil
	}
	if *value < 1 {
		return 0, fmt.Errorf("cimd metadataFetchPolicy.%s must be a positive integer", optionName)
	}
	return *value, nil
}

type resolvedFetchPolicy struct {
	minimumFetchIntervalMs            float64
	maximumConcurrentFetches          int
	maximumConcurrentFetchesPerOrigin int
	maximumFetchesPerMinute           int
	maximumFetchesPerOriginPerMinute  int
}

func resolveMetadataFetchPolicy(o *Options) (resolvedFetchPolicy, error) {
	var p MetadataFetchPolicy
	if o.MetadataFetchPolicy != nil {
		p = *o.MetadataFetchPolicy
	}
	var r resolvedFetchPolicy
	var err error
	interval := p.MinimumFetchInterval
	if interval == nil {
		interval = 1
	}
	if r.minimumFetchIntervalMs, err = parseDurationMs(interval, "minimumFetchInterval"); err != nil {
		return r, err
	}
	if r.maximumConcurrentFetches, err = requirePositiveInteger(p.MaximumConcurrentFetches, 16, "maximumConcurrentFetches"); err != nil {
		return r, err
	}
	if r.maximumConcurrentFetchesPerOrigin, err = requirePositiveInteger(p.MaximumConcurrentFetchesPerOrigin, 4, "maximumConcurrentFetchesPerOrigin"); err != nil {
		return r, err
	}
	if r.maximumFetchesPerMinute, err = requirePositiveInteger(p.MaximumFetchesPerMinute, 120, "maximumFetchesPerMinute"); err != nil {
		return r, err
	}
	if r.maximumFetchesPerOriginPerMinute, err = requirePositiveInteger(p.MaximumFetchesPerOriginPerMinute, 30, "maximumFetchesPerOriginPerMinute"); err != nil {
		return r, err
	}
	return r, nil
}

func pruneFetchStartTimes(times []int64, now int64) []int64 {
	windowStart := now - fetchBudgetWindowMs
	i := 0
	for i < len(times) && times[i] <= windowStart {
		i++
	}
	return times[i:]
}

func resolveMetadataRevalidationIntervalMs(v any, now int64) (float64, error) {
	s, err := durationSeconds(v, int64(math.Floor(float64(now)/1000)))
	if err != nil {
		return 0, err
	}
	return math.Max(0, s*1000), nil
}

type cacheControl struct {
	directives map[string]string // "" value = directive without argument (true)
	duplicates map[string]bool
}

func (c cacheControl) has(k string) bool { _, ok := c.directives[k]; return ok }

var quoteTrimRe = regexp.MustCompile(`^"|"$`)

func parseCacheControl(value string, present bool) cacheControl {
	c := cacheControl{directives: map[string]string{}, duplicates: map[string]bool{}}
	if !present {
		return c
	}
	for _, raw := range strings.Split(value, ",") {
		parts := strings.Split(strings.TrimSpace(raw), "=")
		name := strings.ToLower(parts[0])
		if name == "" {
			continue
		}
		if c.has(name) {
			c.duplicates[name] = true
		}
		joined := strings.TrimSpace(strings.Join(parts[1:], "="))
		if joined != "" {
			c.directives[name] = "=" + quoteTrimRe.ReplaceAllString(joined, "")
		} else {
			c.directives[name] = ""
		}
	}
	return c
}

var digitsRe = regexp.MustCompile(`^\d+$`)

// parseNonNegativeSeconds parses a directive argument; ok=false is null upstream.
func parseNonNegativeSeconds(v string, present bool) (int64, bool) {
	if !present || !strings.HasPrefix(v, "=") {
		return 0, false
	}
	s := v[1:]
	if !digitsRe.MatchString(s) {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n > 1<<53-1 {
		return 0, false
	}
	return n, true
}

func parseHTTPDate(s string) (int64, bool) {
	t, err := http.ParseTime(s)
	if err != nil {
		if t2, err2 := time.Parse(time.RFC3339, s); err2 == nil {
			return t2.UnixMilli(), true
		}
		return 0, false
	}
	return t.UnixMilli(), true
}

func computeExpiresAt(h responseCacheHeaders, interval any, now int64) (cacheable bool, expiresAt int64, err error) {
	ccValue, ccPresent := h.get("cacheControl")
	cc := parseCacheControl(ccValue, ccPresent)
	variesByEverything := false
	if vary, ok := h.get("vary"); ok {
		for _, f := range strings.Split(vary, ",") {
			if strings.TrimSpace(f) == "*" {
				variesByEverything = true
			}
		}
	}
	if cc.has("no-store") || cc.has("private") || variesByEverything {
		return false, now, nil
	}
	operatorLifetime, err := resolveMetadataRevalidationIntervalMs(interval, now)
	if err != nil {
		return false, 0, err
	}
	if cc.has("no-cache") {
		return true, now, nil
	}
	ageV, ageOK := h.get("age")
	ageSeconds, ok := parseNonNegativeSeconds("="+ageV, ageOK)
	if !ok {
		ageSeconds = 0
	}
	responseDate := float64(now)
	if d, ok := h.get("date"); ok {
		if ms, ok := parseHTTPDate(d); ok {
			responseDate = float64(ms)
		} else {
			responseDate = math.NaN()
		}
	}
	apparentAge := 0.0
	if !math.IsNaN(responseDate) {
		apparentAge = math.Max(0, float64(now)-responseDate)
	}
	currentAge := math.Max(apparentAge, float64(ageSeconds*1000))

	originLifetime := math.NaN()
	hasShared := cc.has("s-maxage")
	sharedMaxAge, sharedOK := parseNonNegativeSeconds(cc.directives["s-maxage"], hasShared)
	hasMaxAge := cc.has("max-age")
	privateMaxAge, privateOK := parseNonNegativeSeconds(cc.directives["max-age"], hasMaxAge)
	var invalidFreshness bool
	if hasShared {
		invalidFreshness = !sharedOK || cc.duplicates["s-maxage"]
	} else {
		invalidFreshness = hasMaxAge && (!privateOK || cc.duplicates["max-age"])
	}
	maxAge, maxAgeOK := privateMaxAge, privateOK
	if hasShared {
		maxAge, maxAgeOK = sharedMaxAge, sharedOK
	}
	switch {
	case invalidFreshness:
		originLifetime = 0
	case maxAgeOK:
		originLifetime = math.Max(0, float64(maxAge*1000)-currentAge)
	default:
		if e, ok := h.get("expires"); ok {
			if expires, ok := parseHTTPDate(e); ok {
				base := responseDate
				if math.IsNaN(base) {
					base = float64(now)
				}
				originLifetime = math.Max(0, float64(expires)-base-currentAge)
			}
		}
	}
	lifetime := operatorLifetime
	if !math.IsNaN(originLifetime) {
		lifetime = math.Min(operatorLifetime, originLifetime)
	}
	return true, now + int64(lifetime), nil
}

func mergeCacheHeaders(previous, revalidated responseCacheHeaders) responseCacheHeaders {
	out := responseCacheHeaders{}
	for _, n := range cacheHeaderNames {
		if v, ok := revalidated[n.key]; ok {
			out[n.key] = v
		} else if v, ok := previous[n.key]; ok {
			out[n.key] = v
		}
	}
	return out
}

type cacheEntry struct {
	metadata     *jsonx.Object
	expiresAt    int64
	etag         string
	lastModified string
	headers      responseCacheHeaders
}

func createCacheEntry(metadata *jsonx.Object, h responseCacheHeaders, interval any, now int64) (*cacheEntry, error) {
	cacheable, expiresAt, err := computeExpiresAt(h, interval, now)
	if err != nil || !cacheable {
		return nil, err
	}
	return &cacheEntry{metadata: metadata, expiresAt: expiresAt, etag: h["etag"], lastModified: h["lastModified"], headers: h}, nil
}

// orderedMap is a Map with insertion order (delete + set moves a key to the end).
type orderedMap[V any] struct {
	order *list.List
	items map[string]*list.Element
}

type orderedItem[V any] struct {
	key   string
	value V
}

func newOrderedMap[V any]() *orderedMap[V] {
	return &orderedMap[V]{order: list.New(), items: map[string]*list.Element{}}
}

func (m *orderedMap[V]) get(k string) (V, bool) {
	if e, ok := m.items[k]; ok {
		return e.Value.(*orderedItem[V]).value, true
	}
	var zero V
	return zero, false
}

func (m *orderedMap[V]) has(k string) bool { _, ok := m.items[k]; return ok }

func (m *orderedMap[V]) delete(k string) {
	if e, ok := m.items[k]; ok {
		m.order.Remove(e)
		delete(m.items, k)
	}
}

func (m *orderedMap[V]) set(k string, v V) {
	if e, ok := m.items[k]; ok {
		e.Value.(*orderedItem[V]).value = v
		return
	}
	m.items[k] = m.order.PushBack(&orderedItem[V]{k, v})
}

func (m *orderedMap[V]) size() int { return len(m.items) }

// each iterates in insertion order until fn returns false.
func (m *orderedMap[V]) each(fn func(k string, v V) bool) {
	for e := m.order.Front(); e != nil; {
		next := e.Next()
		it := e.Value.(*orderedItem[V])
		if !fn(it.key, it.value) {
			return
		}
		e = next
	}
}

type originFetchState struct {
	activeFetchCount int
	fetchStartTimes  []int64
}

type inFlight struct {
	done   chan struct{}
	client *oauthprovider.SchemaClient
	err    error
}

// resolver owns one plugin instance's metadata cache, so separate cimd plugin instances
// never share trust state or conditional validators.
type resolver struct {
	options        *Options
	interval       any
	maxEntries     int
	policy         resolvedFetchPolicy
	mu             sync.Mutex
	cache          *orderedMap[*cacheEntry]
	inFlight       map[string]*inFlight
	lastFetchStart *orderedMap[int64]
	originState    *orderedMap[*originFetchState]
	globalStarts   []int64
	activeFetches  int
}

func newResolver(o *Options) (*resolver, error) {
	interval := o.MetadataRevalidationInterval
	if interval == nil {
		interval = "60m"
	}
	maxEntries := 1000
	if o.MaxCacheEntries != nil {
		maxEntries = *o.MaxCacheEntries
		if maxEntries < 1 {
			return nil, errors.New("cimd maxCacheEntries must be a positive integer")
		}
	}
	policy, err := resolveMetadataFetchPolicy(o)
	if err != nil {
		return nil, err
	}
	return &resolver{options: o, interval: interval, maxEntries: maxEntries, policy: policy,
		cache: newOrderedMap[*cacheEntry](), inFlight: map[string]*inFlight{},
		lastFetchStart: newOrderedMap[int64](), originState: newOrderedMap[*originFetchState]()}, nil
}

// readCacheEntry returns the entry and marks it most recently used (lock held).
func (r *resolver) readCacheEntry(clientID string) *cacheEntry {
	e, ok := r.cache.get(clientID)
	if !ok {
		return nil
	}
	r.cache.delete(clientID)
	r.cache.set(clientID, e)
	return e
}

func (r *resolver) storeCacheEntry(clientID string, e *cacheEntry) {
	r.cache.delete(clientID)
	for r.cache.size() >= r.maxEntries {
		var oldest string
		r.cache.each(func(k string, _ *cacheEntry) bool { oldest = k; return false })
		if oldest == "" {
			break
		}
		r.cache.delete(oldest)
	}
	r.cache.set(clientID, e)
}

func (r *resolver) ensureClientFetchStateCapacity(clientID string, now int64) error {
	if r.lastFetchStart.has(clientID) {
		return nil
	}
	for r.lastFetchStart.size() >= r.maxEntries {
		evicted := false
		r.lastFetchStart.each(func(k string, last int64) bool {
			if _, busy := r.inFlight[k]; busy {
				return true
			}
			if r.policy.minimumFetchIntervalMs > 0 && float64(now-last) < r.policy.minimumFetchIntervalMs {
				return true
			}
			r.lastFetchStart.delete(k)
			evicted = true
			return false
		})
		if !evicted {
			return createMetadataFetchUnavailableError("metadata fetch client state is at capacity")
		}
	}
	return nil
}

func (r *resolver) readOrCreateOriginFetchState(origin string, now int64) (*originFetchState, error) {
	if s, ok := r.originState.get(origin); ok {
		s.fetchStartTimes = pruneFetchStartTimes(s.fetchStartTimes, now)
		r.originState.delete(origin)
		r.originState.set(origin, s)
		return s, nil
	}
	for r.originState.size() >= r.maxEntries {
		evicted := false
		r.originState.each(func(k string, s *originFetchState) bool {
			s.fetchStartTimes = pruneFetchStartTimes(s.fetchStartTimes, now)
			if s.activeFetchCount > 0 || len(s.fetchStartTimes) > 0 {
				return true
			}
			r.originState.delete(k)
			evicted = true
			return false
		})
		if !evicted {
			return nil, createMetadataFetchUnavailableError("metadata fetch origin state is at capacity")
		}
	}
	s := &originFetchState{}
	r.originState.set(origin, s)
	return s, nil
}

// acquireMetadataFetchPermit consumes the fetch budgets (lock held) and returns the
// release function.
func (r *resolver) acquireMetadataFetchPermit(clientID string) (func(), error) {
	now := nowMs()
	if last, ok := r.lastFetchStart.get(clientID); ok && r.policy.minimumFetchIntervalMs > 0 &&
		float64(now-last) < r.policy.minimumFetchIntervalMs {
		return nil, createMetadataFetchUnavailableError("metadata document fetch is within the per-client minimum interval")
	}
	if err := r.ensureClientFetchStateCapacity(clientID, now); err != nil {
		return nil, err
	}
	origin := ""
	if u, err := parseURL(clientID); err == nil {
		origin = originOf(u)
	}
	originState, err := r.readOrCreateOriginFetchState(origin, now)
	if err != nil {
		return nil, err
	}
	r.globalStarts = pruneFetchStartTimes(r.globalStarts, now)
	if r.activeFetches >= r.policy.maximumConcurrentFetches {
		return nil, createMetadataFetchUnavailableError("global metadata fetch concurrency limit exceeded")
	}
	if originState.activeFetchCount >= r.policy.maximumConcurrentFetchesPerOrigin {
		return nil, createMetadataFetchUnavailableError("metadata fetch concurrency limit exceeded for client origin")
	}
	if len(r.globalStarts) >= r.policy.maximumFetchesPerMinute {
		return nil, createMetadataFetchUnavailableError("global metadata fetch rate limit exceeded")
	}
	if len(originState.fetchStartTimes) >= r.policy.maximumFetchesPerOriginPerMinute {
		return nil, createMetadataFetchUnavailableError("metadata fetch rate limit exceeded for client origin")
	}
	r.lastFetchStart.delete(clientID)
	r.lastFetchStart.set(clientID, now)
	r.globalStarts = append(r.globalStarts, now)
	originState.fetchStartTimes = append(originState.fetchStartTimes, now)
	r.activeFetches++
	originState.activeFetchCount++
	released := false
	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if released {
			return
		}
		released = true
		r.activeFetches--
		originState.activeFetchCount--
	}, nil
}

// resolve is the ClientDiscovery resolver.
func (r *resolver) resolve(ctx *betterauth.EndpointContext, clientID string, existing *oauthprovider.SchemaClient) (*oauthprovider.SchemaClient, error) {
	if !IsCimdClientIDURLCandidate(clientID) {
		return nil, nil
	}
	if ctx == nil || ctx.Auth == nil || ctx.Auth.GetPlugin("oauth-provider") == nil {
		return nil, errors.New("cimd discovery invoked without the oauth-provider plugin installed")
	}
	r.mu.Lock()
	cached := r.readCacheEntry(clientID)
	now := nowMs()
	if cached != nil && cached.expiresAt > now {
		r.mu.Unlock()
		if existing != nil {
			return existing, nil
		}
		return persistMetadataDocumentClient(ctx, clientID, cached.metadata, r.options, nil)
	}
	if f, ok := r.inFlight[clientID]; ok {
		r.mu.Unlock()
		<-f.done
		return f.client, f.err
	}
	release, err := r.acquireMetadataFetchPermit(clientID)
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	f := &inFlight{done: make(chan struct{})}
	r.inFlight[clientID] = f
	r.mu.Unlock()

	f.client, f.err = r.fetchAndPersist(ctx, clientID, existing, cached)

	r.mu.Lock()
	if f.err != nil {
		r.lastFetchStart.delete(clientID)
		r.lastFetchStart.set(clientID, nowMs())
	}
	if r.inFlight[clientID] == f {
		delete(r.inFlight, clientID)
	}
	r.mu.Unlock()
	release()
	close(f.done)
	return f.client, f.err
}

func (r *resolver) fetchAndPersist(ctx *betterauth.EndpointContext, clientID string, existing *oauthprovider.SchemaClient, cached *cacheEntry) (client *oauthprovider.SchemaClient, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("%v", p)
		}
	}()
	var validators *conditionalValidators
	if cached != nil {
		validators = &conditionalValidators{etag: cached.etag, lastModified: cached.lastModified}
	}
	fetched, err := fetchClientMetadataDocument(ctx, clientID, r.options, validators)
	if err != nil {
		return nil, err
	}
	if fetched.notModified && cached == nil {
		return nil, invalidClient("Metadata document returned 304 without a validated cached document")
	}
	metadata := fetched.metadata
	headers := fetched.cacheHeaders
	if fetched.notModified {
		metadata = cached.metadata
		headers = mergeCacheHeaders(cached.headers, fetched.cacheHeaders)
	}
	stored, err := persistMetadataDocumentClient(ctx, clientID, metadata, r.options, existing)
	if err != nil {
		return nil, err
	}
	next, err := createCacheEntry(metadata, headers, r.interval, nowMs())
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	if next != nil {
		r.storeCacheEntry(clientID, next)
	} else {
		r.cache.delete(clientID)
	}
	// Successful fetches are governed by HTTP freshness and origin/global budgets. Keep
	// the per-client interval only as failed-fetch backoff.
	r.lastFetchStart.delete(clientID)
	r.mu.Unlock()
	return stored, nil
}
