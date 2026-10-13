package jwt

import (
	"sort"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
)

// JwksAdapter reads and writes keys (getJwksAdapter): through Options.Adapter when set,
// otherwise the "jwks" model of the database (transaction-aware).
type JwksAdapter struct {
	opts *Options
}

// GetJwksAdapter returns the key store for opts.
func GetJwksAdapter(opts *Options) *JwksAdapter { return &JwksAdapter{opts: opts} }

func (a *JwksAdapter) custom() *AdapterOptions {
	if a.opts == nil || a.opts.Adapter == nil {
		return nil
	}
	return a.opts.Adapter
}

func (a *JwksAdapter) findAll(ctx *betterauth.EndpointContext) ([]*Jwk, error) {
	rows, err := ctx.Auth.Adapter.FindMany(ctx.Context(), adapter.FindManyInput{Model: "jwks"})
	if err != nil {
		return nil, err
	}
	out := make([]*Jwk, 0, len(rows))
	for _, r := range rows {
		out = append(out, jwkFromRecord(r))
	}
	return out, nil
}

// GetAllKeys returns every key.
func (a *JwksAdapter) GetAllKeys(ctx *betterauth.EndpointContext) ([]*Jwk, error) {
	if c := a.custom(); c != nil && c.GetJwks != nil {
		return c.GetJwks(ctx)
	}
	return a.findAll(ctx)
}

func newestLive(keys []*Jwk, match func(*Jwk) bool) *Jwk {
	now := time.Now()
	var live []*Jwk
	for _, k := range keys {
		if k == nil || (k.ExpiresAt != nil && !k.ExpiresAt.After(now)) {
			continue
		}
		if match != nil && !match(k) {
			continue
		}
		live = append(live, k)
	}
	sort.SliceStable(live, func(i, j int) bool { return live[i].CreatedAt.After(live[j].CreatedAt) })
	if len(live) == 0 {
		return nil
	}
	return live[0]
}

// GetLatestKey returns the newest non-expired key of any algorithm.
func (a *JwksAdapter) GetLatestKey(ctx *betterauth.EndpointContext) (*Jwk, error) {
	keys, err := a.GetAllKeys(ctx)
	if err != nil {
		return nil, err
	}
	return newestLive(keys, nil), nil
}

// GetKeyByID returns a key by id (nil when missing).
func (a *JwksAdapter) GetKeyByID(ctx *betterauth.EndpointContext, id string) (*Jwk, error) {
	if c := a.custom(); c != nil && c.GetJwks != nil {
		keys, err := c.GetJwks(ctx)
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			if k != nil && k.ID == id {
				return k, nil
			}
		}
		return nil, nil
	}
	r, err := ctx.Auth.Adapter.FindOne(ctx.Context(), adapter.FindOneInput{Model: "jwks", Where: []adapter.Where{{Field: "id", Value: id}}})
	if err != nil {
		return nil, err
	}
	return jwkFromRecord(r), nil
}

// GetLatestKeyByAlg returns the newest non-expired key for alg. Legacy rows without an alg
// match the configured keyPairConfig.alg.
func (a *JwksAdapter) GetLatestKeyByAlg(ctx *betterauth.EndpointContext, alg string) (*Jwk, error) {
	keys, err := a.GetAllKeys(ctx)
	if err != nil {
		return nil, err
	}
	configAlg := a.opts.primaryAlg()
	return newestLive(keys, func(k *Jwk) bool {
		return k.Alg == alg || (k.Alg == "" && configAlg == alg)
	}), nil
}

// CreateJwk stores a key.
func (a *JwksAdapter) CreateJwk(ctx *betterauth.EndpointContext, key Jwk) (*Jwk, error) {
	if c := a.custom(); c != nil && c.CreateJwk != nil {
		return c.CreateJwk(ctx, key)
	}
	data := key.record()
	data["createdAt"] = time.Now()
	r, err := ctx.Auth.Adapter.Create(ctx.Context(), adapter.CreateInput{Model: "jwks", Data: data})
	if err != nil {
		return nil, err
	}
	return jwkFromRecord(r), nil
}
