package cli

import (
	"reflect"
	"strings"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/oauth2"
)

// sensitiveKeys and allowedKeys are upstream's lists (commands/info.ts), unchanged.
var sensitiveKeys = []string{
	"secret",
	"secrets",
	"secretKey",
	"clientSecret",
	"clientId",
	"authToken",
	"apiKey",
	"apiSecret",
	"privateKey",
	"publicKey",
	"password",
	"token",
	"webhook",
	"connectionString",
	"databaseUrl",
	"databaseURL",
	"TURSO_AUTH_TOKEN",
	"TURSO_DATABASE_URL",
	"MYSQL_DATABASE_URL",
	"DATABASE_URL",
	"POSTGRES_URL",
	"MONGODB_URI",
	"stripeKey",
	"stripeWebhookSecret",
}

var allowedKeys = []string{
	"baseURL",
	"callbackURL",
	"redirectURL",
	"trustedOrigins",
	"appName",
}

const redacted = "[REDACTED]"

func isAllowedKey(key string) bool {
	for _, a := range allowedKeys {
		if strings.EqualFold(key, a) {
			return true
		}
	}
	return false
}

func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, s := range sensitiveKeys {
		ls := strings.ToLower(s)
		if lower == ls || strings.HasSuffix(lower, ls) {
			return true
		}
	}
	return false
}

// redactSensitive is upstream's redactSensitive: values under sensitive keys (exact or
// suffix match, case-insensitive) are replaced unless the key is allow-listed.
func redactSensitive(v any, parentKey string) any {
	switch x := v.(type) {
	case *object:
		out := newObject()
		for _, key := range x.keys {
			value := x.vals[key]
			if isAllowedKey(key) {
				out.set(key, value)
				continue
			}
			if isSensitiveKey(key) {
				switch val := value.(type) {
				case string:
					if val != "" {
						out.set(key, redacted)
					} else {
						out.set(key, val)
					}
				case []any:
					out.set(key, redacted)
				case *object:
					out.set(key, redactSensitive(val, key))
				default:
					out.set(key, value)
				}
				continue
			}
			out.set(key, redactSensitive(value, key))
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = redactSensitive(item, parentKey)
		}
		return out
	case string:
		if parentKey != "" && x != "" {
			if isAllowedKey(parentKey) {
				return x
			}
			if isSensitiveKey(parentKey) {
				return redacted
			}
		}
		return x
	}
	return v
}

// sanitizeConfig is sanitizeBetterAuthConfig for a Go configuration: the options are
// converted to a JSON-like tree (functions dropped, as JSON.stringify does upstream), social
// providers are keyed by id, plugins become {name, config}, and every secret or credential
// is redacted with upstream's rules.
func sanitizeConfig(cfg *betterauth.Config) *object {
	if cfg == nil {
		return nil
	}
	tree := newObject()
	structFields(reflect.ValueOf(cfg).Elem(), tree, 0, map[uintptr]bool{})

	if len(cfg.SocialProviders) > 0 {
		providers := newObject()
		for _, p := range cfg.SocialProviders {
			if p == nil {
				continue
			}
			id := p.ID()
			providers.set(id, redactSensitive(providerValue(p), id))
		}
		tree.set("socialProviders", providers)
	}
	if len(cfg.Plugins) > 0 {
		plugins := make([]any, 0, len(cfg.Plugins))
		for _, pl := range cfg.Plugins {
			if pl == nil {
				plugins = append(plugins, nil)
				continue
			}
			name := pl.ID
			if name == "" {
				name = "unknown"
			}
			var conf any
			if pl.Options != nil {
				conf, _ = toValue(reflect.ValueOf(pl.Options), 0, map[uintptr]bool{})
			}
			if conf == nil {
				o := newObject().set("id", pl.ID)
				if pl.Version != "" {
					o.set("version", pl.Version)
				}
				conf = o
			}
			plugins = append(plugins, newObject().set("name", name).set("config", redactSensitive(conf, "")))
		}
		tree.set("plugins", plugins)
	}
	out, _ := redactSensitive(tree, "").(*object)
	return out
}

// providerValue converts a social provider to its options object (socialProviders[id]
// upstream). A provider accepting several client ids reports clientId as an array, like
// upstream's clientId: string[].
func providerValue(p oauth2.Provider) any {
	var opts *oauth2.ProviderOptions
	if gp, ok := p.(*oauth2.GenericProvider); ok {
		opts = &gp.S.Options
	} else if op, ok := p.(interface{ Options() oauth2.ProviderOptions }); ok {
		o := op.Options()
		opts = &o
	}
	if opts == nil {
		v, ok := toValue(reflect.ValueOf(p), 0, map[uintptr]bool{})
		if !ok {
			return newObject()
		}
		return v
	}
	v, _ := toValue(reflect.ValueOf(*opts), 0, map[uintptr]bool{})
	o, ok := v.(*object)
	if !ok {
		return v
	}
	if len(opts.ClientIDs) > 0 {
		ids := make([]any, 0)
		for _, id := range opts.Audiences() {
			ids = append(ids, id)
		}
		if _, has := o.get("clientId"); has {
			o.set("clientId", ids)
		} else {
			// keep upstream's key order: clientId first
			n := newObject().set("clientId", ids)
			for _, k := range o.keys {
				if k != "clientIds" {
					n.set(k, o.vals[k])
				}
			}
			return n
		}
		delete(o.vals, "clientIds")
		o.keys = removeKey(o.keys, "clientIds")
	}
	return o
}
