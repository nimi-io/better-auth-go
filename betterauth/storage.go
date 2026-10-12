package betterauth

import (
	"context"
	"sync"
	"time"
)

// SecondaryStorage is a key-value store for sessions, verification values and rate limits
// (secondaryStorage upstream, e.g. Redis). Values are JSON strings written with JavaScript
// JSON.stringify semantics, so a Go and a TypeScript server can share the same store.
type SecondaryStorage interface {
	// Get returns the value and whether it exists.
	Get(ctx context.Context, key string) (string, bool, error)
	// Set stores value; ttl 0 means no expiry.
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	// GetAndDelete atomically reads and removes a key.
	GetAndDelete(ctx context.Context, key string) (string, bool, error)
	// Increment atomically increments a counter, setting ttl when the key is created,
	// and returns the new value.
	Increment(ctx context.Context, key string, ttl time.Duration) (int64, error)
}

// MemoryStorage is an in-process SecondaryStorage, useful for tests and single instances.
type MemoryStorage struct {
	mu   sync.Mutex
	data map[string]memEntry
	now  func() time.Time
}

type memEntry struct {
	value   string
	counter int64
	expires time.Time
}

// NewMemoryStorage returns an empty MemoryStorage.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{data: map[string]memEntry{}, now: time.Now}
}

func (m *MemoryStorage) live(key string) (memEntry, bool) {
	e, ok := m.data[key]
	if !ok {
		return e, false
	}
	if !e.expires.IsZero() && !m.now().Before(e.expires) {
		delete(m.data, key)
		return e, false
	}
	return e, true
}

// Get implements SecondaryStorage.
func (m *MemoryStorage) Get(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.live(key)
	return e.value, ok, nil
}

// Set implements SecondaryStorage.
func (m *MemoryStorage) Set(_ context.Context, key, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := memEntry{value: value}
	if ttl > 0 {
		e.expires = m.now().Add(ttl)
	}
	m.data[key] = e
	return nil
}

// Delete implements SecondaryStorage.
func (m *MemoryStorage) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

// GetAndDelete implements SecondaryStorage.
func (m *MemoryStorage) GetAndDelete(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.live(key)
	delete(m.data, key)
	return e.value, ok, nil
}

// Increment implements SecondaryStorage.
func (m *MemoryStorage) Increment(_ context.Context, key string, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.live(key)
	if !ok {
		e = memEntry{}
		if ttl > 0 {
			e.expires = m.now().Add(ttl)
		}
	}
	e.counter++
	m.data[key] = e
	return e.counter, nil
}

// Keys returns the live keys (for tests).
func (m *MemoryStorage) Keys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k := range m.data {
		if _, ok := m.live(k); ok {
			out = append(out, k)
		}
	}
	return out
}
