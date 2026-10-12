package betterauth

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
)

type rlEntry struct {
	count       int
	lastRequest int64
	expiresAt   int64
}

type memoryRateLimiter struct {
	mu   sync.Mutex
	data map[string]rlEntry
}

const memoryStoreMaxEntries = 100_000

func (m *memoryRateLimiter) consume(key string, rule RateLimitRule) (bool, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UnixMilli()
	for k, e := range m.data {
		if now >= e.expiresAt {
			delete(m.data, k)
		}
	}
	if over := len(m.data) - memoryStoreMaxEntries; over > 0 {
		for k := range m.data {
			delete(m.data, k)
			over--
			if over <= 0 {
				break
			}
		}
	}
	window := rule.Window.Milliseconds()
	e, ok := m.data[key]
	if ok && now >= e.expiresAt {
		ok = false
	}
	ttl := rule.Window.Milliseconds()
	switch {
	case !ok:
		m.data[key] = rlEntry{count: 1, lastRequest: now, expiresAt: now + ttl}
		return true, 0
	case now-e.lastRequest >= window:
		m.data[key] = rlEntry{count: 1, lastRequest: now, expiresAt: now + ttl}
		return true, 0
	case e.count >= rule.Max:
		return false, retryAfter(e.lastRequest, rule.Window)
	default:
		m.data[key] = rlEntry{count: e.count + 1, lastRequest: now, expiresAt: now + ttl}
		return true, 0
	}
}

func retryAfter(lastRequest int64, window time.Duration) time.Duration {
	now := time.Now().UnixMilli()
	secs := math.Ceil(float64(lastRequest+window.Milliseconds()-now) / 1000)
	return time.Duration(secs) * time.Second
}

func defaultSpecialRules() []PluginRateLimit {
	return []PluginRateLimit{
		{Window: 10 * time.Second, Max: 3, PathMatcher: func(p string) bool {
			return strings.HasPrefix(p, "/sign-in") || strings.HasPrefix(p, "/sign-up") ||
				strings.HasPrefix(p, "/change-password") || strings.HasPrefix(p, "/change-email")
		}},
		{Window: 60 * time.Second, Max: 3, PathMatcher: func(p string) bool {
			return p == "/request-password-reset" || p == "/send-verification-email" ||
				strings.HasPrefix(p, "/forget-password") || p == "/email-otp/send-verification-otp" ||
				p == "/email-otp/request-password-reset"
		}},
	}
}

func (a *Auth) rateLimitStorage(ac *AuthContext) func(ctx context.Context, key string, rule RateLimitRule) (bool, time.Duration, error) {
	if cs := ac.Options.RateLimit; cs != nil && cs.CustomStorage != nil {
		return cs.CustomStorage.Consume
	}
	switch ac.RateLimit.Storage {
	case "secondary-storage":
		return func(ctx context.Context, key string, rule RateLimitRule) (bool, time.Duration, error) {
			if ac.SecondaryStorage == nil {
				return false, 0, errors.New("Secondary-storage rate limiting requires SecondaryStorage.increment.")
			}
			n, err := ac.SecondaryStorage.Increment(ctx, key, rule.Window)
			if err != nil {
				return false, 0, err
			}
			if int(n) <= rule.Max {
				return true, 0, nil
			}
			return false, rule.Window, nil
		}
	case "memory":
		return func(_ context.Context, key string, rule RateLimitRule) (bool, time.Duration, error) {
			ok, ra := a.memoryRL.consume(key, rule)
			return ok, ra, nil
		}
	}
	return a.databaseRateLimit(ac)
}

func (a *Auth) longestWindow(ac *AuthContext) time.Duration {
	longest := ac.RateLimit.Window
	consider := func(w time.Duration) {
		if w > longest {
			longest = w
		}
	}
	for _, r := range defaultSpecialRules() {
		consider(r.Window)
	}
	for _, p := range ac.plugins {
		for _, r := range p.RateLimit {
			consider(r.Window)
		}
	}
	for _, r := range ac.RateLimit.CustomRules {
		if r.Rule != nil {
			consider(r.Rule.Window)
		}
	}
	if obs := time.Duration(a.observedWindow.Load()) * time.Millisecond; obs > longest {
		longest = obs
	}
	return longest
}

func (a *Auth) databaseRateLimit(ac *AuthContext) func(ctx context.Context, key string, rule RateLimitRule) (bool, time.Duration, error) {
	db := ac.Adapter
	readRow := func(ctx context.Context, key string) (adapter.Record, error) {
		rows, err := db.FindMany(ctx, adapter.FindManyInput{Model: "rateLimit", Where: []adapter.Where{{Field: "key", Value: key}}})
		if err != nil || len(rows) == 0 {
			return nil, err
		}
		return rows[0], nil
	}
	var consume func(ctx context.Context, key string, rule RateLimitRule, depth int) (bool, time.Duration, error)
	consume = func(ctx context.Context, key string, rule RateLimitRule, depth int) (bool, time.Duration, error) {
		if depth > 10 {
			return false, rule.Window, nil
		}
		window := rule.Window.Milliseconds()
		data, err := readRow(ctx, key)
		if err != nil {
			return false, 0, err
		}
		now := time.Now().UnixMilli()
		if data == nil {
			_, err := db.Create(ctx, adapter.CreateInput{Model: "rateLimit", Data: adapter.Record{"key": key, "count": 1, "lastRequest": now}})
			if err != nil {
				if existing, _ := readRow(ctx, key); existing == nil {
					return false, 0, err
				}
				return consume(ctx, key, rule, depth+1)
			}
			return true, 0, nil
		}
		last, _ := adapter.ToInt64(data["lastRequest"])
		if now-last >= window {
			reset, err := db.IncrementOne(ctx, adapter.IncrementInput{Model: "rateLimit",
				Where: []adapter.Where{{Field: "key", Value: key}, {Field: "lastRequest", Operator: adapter.Lte, Value: last}},
				Set:   adapter.Record{"count": 1, "lastRequest": now}})
			if err != nil {
				return false, 0, err
			}
			if reset != nil {
				cutoff := now - a.longestWindow(ac).Milliseconds()
				ac.RunInBackgroundOrAwait(func() error {
					if _, err := db.DeleteMany(context.WithoutCancel(ctx), "rateLimit", []adapter.Where{{Field: "lastRequest", Operator: adapter.Lt, Value: cutoff}}); err != nil {
						ac.Logger.Error("Error pruning rate limit rows", err)
					}
					return nil
				})
				return true, 0, nil
			}
			return consume(ctx, key, rule, depth+1)
		}
		inc, err := db.IncrementOne(ctx, adapter.IncrementInput{Model: "rateLimit",
			Where: []adapter.Where{{Field: "key", Value: key}, {Field: "lastRequest", Operator: adapter.Gt, Value: now - window},
				{Field: "count", Operator: adapter.Lt, Value: rule.Max}},
			Increment: map[string]float64{"count": 1}, Set: adapter.Record{"lastRequest": now}})
		if err != nil {
			return false, 0, err
		}
		if inc != nil {
			return true, 0, nil
		}
		fresh, err := readRow(ctx, key)
		if err != nil {
			return false, 0, err
		}
		if fresh == nil {
			return consume(ctx, key, rule, depth+1)
		}
		fl, _ := adapter.ToInt64(fresh["lastRequest"])
		if now-fl >= window {
			return consume(ctx, key, rule, depth+1)
		}
		return false, retryAfter(fl, rule.Window), nil
	}
	return func(ctx context.Context, key string, rule RateLimitRule) (bool, time.Duration, error) {
		return consume(ctx, key, rule, 0)
	}
}

// onRequestRateLimit returns a 429 response when the request is over the limit.
func (a *Auth) onRequestRateLimit(r *http.Request, ac *AuthContext) (*Response, error) {
	if !ac.RateLimit.Enabled {
		return nil, nil
	}
	basePath := ""
	if u, err := parseJSURL(ac.BaseURL); err == nil {
		basePath = u.Path
	}
	path := normalizePathname(requestURL(r), basePath)
	window, max := ac.RateLimit.Window, ac.RateLimit.Max
	ip := GetIP(r.Header, ac.Options)
	if ip == "" && ac.Options.Advanced != nil && ac.Options.Advanced.IPAddress != nil && ac.Options.Advanced.IPAddress.DisableIPTracking {
		return nil, nil
	}
	if ip == "" {
		a.ipWarnOnce.Do(func() {
			ac.Logger.Warn("Rate limiting could not determine a client IP and is falling back to a single shared per-path bucket. Ensure your runtime forwards a trusted client IP header, then set `advanced.ipAddress.ipAddressHeaders` or `advanced.ipAddress.trustedProxies` so the address can be resolved.")
		})
		ip = "no-trusted-ip"
	}
	key := ip + "|" + path
	for _, rule := range defaultSpecialRules() {
		if rule.PathMatcher(path) {
			window, max = rule.Window, rule.Max
			break
		}
	}
	for _, p := range ac.plugins {
		matched := false
		for _, rule := range p.RateLimit {
			if rule.PathMatcher(path) {
				window, max = rule.Window, rule.Max
				matched = true
				break
			}
		}
		if matched {
			break
		}
	}
	if len(ac.RateLimit.CustomRules) > 0 {
		for p, rule := range ac.RateLimit.CustomRules {
			hit := p == path
			if strings.Contains(p, "*") {
				hit = wildcardMatch(p, path)
			}
			if !hit {
				continue
			}
			if rule.Disabled {
				return nil, nil
			}
			resolved := rule.Rule
			if rule.Func != nil {
				var err error
				resolved, err = rule.Func(r, RateLimitRule{Window: window, Max: max})
				if err != nil {
					return nil, err
				}
				if resolved == nil {
					return nil, nil
				}
			}
			if resolved != nil {
				window, max = resolved.Window, resolved.Max
			}
			break
		}
	}
	for {
		cur := a.observedWindow.Load()
		if window.Milliseconds() <= cur || a.observedWindow.CompareAndSwap(cur, window.Milliseconds()) {
			break
		}
	}
	consume := a.rateLimitStorage(ac)
	allowed, ra, err := consume(r.Context(), key, RateLimitRule{Window: window, Max: max})
	if err != nil {
		return nil, err
	}
	if allowed {
		return nil, nil
	}
	if ra == 0 {
		ra = window
	}
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("X-Retry-After", strconv.Itoa(int(ra/time.Second)))
	return &Response{Status: 429, Header: h, Body: []byte(`{"message":"Too many requests. Please try again later."}`)}, nil
}
