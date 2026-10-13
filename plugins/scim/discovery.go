package scim

import (
	_ "embed"

	"github.com/nimi-io/better-auth-go/betterauth"
	"github.com/nimi-io/better-auth-go/jsonx"
)

//go:embed openapi.json
var openapiJSON []byte

var openapiDocs = func() *jsonx.Object {
	v, err := jsonx.Parse(openapiJSON)
	if err != nil {
		panic(err)
	}
	return v.(*jsonx.Object)
}()

func openapiFor(key string) any {
	v, ok := openapiDocs.Get(key)
	if !ok {
		return nil
	}
	return deepCloneJSON(v)
}

func deepCloneJSON(v any) any { return clonePatchValue(v) }

var scimRequestMediaTypes = []string{"application/json", MediaType}

// scimEndpoint builds a SCIM protocol endpoint (HIDE_METADATA scope "server").
func (p *plugin) scimEndpoint(key, path, method string, body zSchema, query bool, handler func(*betterauth.EndpointContext) (any, error)) *betterauth.Endpoint {
	ep := &betterauth.Endpoint{Key: key, Path: path, Methods: []string{method},
		AllowedMediaTypes: scimRequestMediaTypes,
		Metadata:          map[string]any{"scope": "server", "allowedMediaTypes": scimRequestMediaTypes, "openapi": openapiFor(key)},
		Use:               []betterauth.Middleware{p.connectionMiddleware}, Handler: handler}
	if body != nil {
		ep.Body = zodValidator(body)
	}
	if query {
		ep.Query = zodValidator(zOpt(zObj(
			zf("attributes", zOpt(zUnionT{options: []zSchema{zStr(), zArr(zStr())}})),
			zf("excludedAttributes", zOpt(zUnionT{options: []zSchema{zStr(), zArr(zStr())}})),
			zf("filter", zOpt(zStr())),
			zf("startIndex", zOpt(zUnionT{options: []zSchema{zStr(), zNumberT{}}})),
			zf("count", zOpt(zUnionT{options: []zSchema{zStr(), zNumberT{}}})),
		)))
	}
	return ep
}

func discoveryEndpoint(key, path string, handler func(*betterauth.EndpointContext) (any, error)) *betterauth.Endpoint {
	return &betterauth.Endpoint{Key: key, Path: path, Methods: []string{"GET"}, AllowedMediaTypes: scimRequestMediaTypes,
		Metadata: map[string]any{"scope": "server", "allowedMediaTypes": scimRequestMediaTypes, "openapi": openapiFor(key)},
		Handler:  handler}
}

func withLocation(o *jsonx.Object, baseURL string) *jsonx.Object {
	out := o.Clone()
	meta, _ := getObj(o, "meta")
	m := meta.Clone()
	m.Set("location", getResourceURL(getStr(meta, "location"), baseURL))
	out.Set("meta", m)
	return out
}

func listResponse(resources []any) *jsonx.Object {
	return jsonx.O("schemas", []any{SchemaListResponse}, "totalResults", len(resources), "startIndex", 1,
		"itemsPerPage", len(resources), "Resources", resources)
}

func discoveryEndpoints() []*betterauth.Endpoint {
	return []*betterauth.Endpoint{
		discoveryEndpoint("getSCIMServiceProviderConfig", "/scim/v2/ServiceProviderConfig", func(ctx *betterauth.EndpointContext) (any, error) {
			return withLocation(deepCloneJSON(discovery.serviceProviderConfig).(*jsonx.Object), ctx.BaseURL()), nil
		}),
		discoveryEndpoint("getSCIMSchemas", "/scim/v2/Schemas", func(ctx *betterauth.EndpointContext) (any, error) {
			var out []any
			for _, s := range discovery.schemas {
				out = append(out, withLocation(deepCloneJSON(s).(*jsonx.Object), ctx.BaseURL()))
			}
			return listResponse(out), nil
		}),
		discoveryEndpoint("getSCIMSchema", "/scim/v2/Schemas/:schemaId", func(ctx *betterauth.EndpointContext) (any, error) {
			// The router already decoded the path parameter (decodeURIComponent upstream).
			id := ctx.Params["schemaId"]
			for _, s := range discovery.schemas {
				if getStr(s, "id") == id {
					return withLocation(deepCloneJSON(s).(*jsonx.Object), ctx.BaseURL()), nil
				}
			}
			return nil, scimErr("NOT_FOUND", "Schema not found")
		}),
		discoveryEndpoint("getSCIMResourceTypes", "/scim/v2/ResourceTypes", func(ctx *betterauth.EndpointContext) (any, error) {
			var out []any
			for _, s := range discovery.resourceTypes {
				out = append(out, withLocation(deepCloneJSON(s).(*jsonx.Object), ctx.BaseURL()))
			}
			return listResponse(out), nil
		}),
		discoveryEndpoint("getSCIMResourceType", "/scim/v2/ResourceTypes/:resourceTypeId", func(ctx *betterauth.EndpointContext) (any, error) {
			for _, s := range discovery.resourceTypes {
				if getStr(s, "id") == ctx.Params["resourceTypeId"] {
					return withLocation(deepCloneJSON(s).(*jsonx.Object), ctx.BaseURL()), nil
				}
			}
			return nil, scimErr("NOT_FOUND", "Resource type not found")
		}),
	}
}
