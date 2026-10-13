// Package openapi is a port of Better Auth's open-api plugin
// (packages/better-auth/src/plugins/open-api): it serves an OpenAPI 3.1 document describing
// every registered endpoint at /open-api/generate-schema and a Scalar API reference page
// at /reference.
//
// Endpoint documentation comes from each endpoint's Metadata["openapi"] block (the
// metadata.openapi object upstream) and from its Body / Query validators, which are
// converted to JSON Schema the way upstream converts zod schemas. Core endpoints use a
// port of upstream's metadata table when their metadata is unset.
package openapi

import (
	_ "embed"
	"net/http"
	"strings"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

// Scalar themes.
const (
	ThemeAlternate  = "alternate"
	ThemeDefault    = "default"
	ThemeMoon       = "moon"
	ThemePurple     = "purple"
	ThemeSolarized  = "solarized"
	ThemeBluePlanet = "bluePlanet"
	ThemeSaturn     = "saturn"
	ThemeKepler     = "kepler"
	ThemeMars       = "mars"
	ThemeDeepSpace  = "deepSpace"
	ThemeLaserwave  = "laserwave"
	ThemeNone       = "none"
)

// Options configures the plugin (OpenAPIOptions).
type Options struct {
	// Path of the reference page (default "/reference").
	Path string
	// DisableDefaultReference makes the reference page respond 404.
	DisableDefaultReference bool
	// Theme is the Scalar theme (default "default").
	Theme string
	// Nonce is added to the reference page's script tags (CSP).
	Nonce string
}

//go:embed logo.svg
var logo string

// encodeURIComponent matches JavaScript's encodeURIComponent.
func encodeURIComponent(s string) string {
	const keep = "-_.!~*'()"
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte(keep, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&15])
	}
	return b.String()
}

func getHTML(reference []byte, theme, nonce string) string {
	nonceAttr := ""
	if nonce != "" {
		nonceAttr = `nonce="` + nonce + `"`
	}
	if theme == "" {
		theme = "default"
	}
	return `<!doctype html>
<html>
  <head>
    <title>Scalar API Reference</title>
    <meta charset="utf-8" />
    <meta
      name="viewport"
      content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <script
      id="api-reference"
      type="application/json">
    ` + string(reference) + `
    </script>
	 <script ` + nonceAttr + `>
      var configuration = {
	  	favicon: "data:image/svg+xml;utf8,` + encodeURIComponent(logo) + `",
	   	theme: "` + theme + `",
        metaData: {
			title: "Better Auth API",
			description: "API Reference for your Better Auth Instance",
		}
      }

      document.getElementById('api-reference').dataset.configuration =
        JSON.stringify(configuration)
    </script>
	  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference" ` + nonceAttr + `></script>
  </body>
</html>`
}

// New creates the open-api plugin.
func New(opts Options) *betterauth.Plugin {
	path := opts.Path
	if path == "" {
		path = "/reference"
	}
	return &betterauth.Plugin{
		ID:      "open-api",
		Version: betterauth.Version,
		Options: opts,
		Endpoints: []*betterauth.Endpoint{
			{
				Key: "generateOpenAPISchema", Path: "/open-api/generate-schema", Methods: []string{"GET"},
				Handler: func(ctx *betterauth.EndpointContext) (any, error) {
					return Generate(ctx.Auth), nil
				},
			},
			{
				Key: "openAPIReference", Path: path, Methods: []string{"GET"},
				Metadata: map[string]any{"scope": "server"},
				Handler: func(ctx *betterauth.EndpointContext) (any, error) {
					if opts.DisableDefaultReference {
						return nil, betterauth.ErrStatus("NOT_FOUND")
					}
					doc, err := jsonx.Marshal(Generate(ctx.Auth))
					if err != nil {
						return nil, err
					}
					h := http.Header{}
					h.Set("Content-Type", "text/html")
					return &betterauth.Response{Status: 200, Header: h, Body: []byte(getHTML(doc, opts.Theme, opts.Nonce))}, nil
				},
			},
		},
	}
}
