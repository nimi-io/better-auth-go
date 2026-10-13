package betterauth

// Helpers exported for the oauth-provider plugin (plugins/oauthprovider). They expose the
// existing dispatch internals without changing their behaviour.

// OAuthProviderDispatch runs an endpoint from inside another endpoint like upstream's
// dispatchAuthEndpoint: the configured before hooks, then run (the endpoint body, given a
// child context sharing the request, headers, body, session and request state of ctx with
// query replaced), then the after hooks. Response headers produced by the nested call are
// merged into ctx. Errors are returned as *APIError like a direct handler call.
func OAuthProviderDispatch(ctx *EndpointContext, ep *Endpoint, query map[string]any, run func(child *EndpointContext) (any, error)) (any, error) {
	if query == nil {
		query = map[string]any{}
	}
	child := &EndpointContext{
		ctx: ctx.ctx, Path: ep.Path, Method: ctx.Method, Request: ctx.Request, Headers: ctx.Headers,
		Body: ctx.Body, Query: query, Params: ctx.Params, Auth: ctx.Auth, Session: ctx.Session,
		Endpoint: ep, ResponseHeaders: newHeader(), OperationID: operationID(ep),
	}
	merge := func() {
		ctx.ResponseHeaders = mergeHeaders(ctx.ResponseHeaders, child.ResponseHeaders)
		if child.Session != nil {
			ctx.Session = child.Session
		}
	}
	var before, after []Hook
	if a := ctx.Auth.auth; a != nil {
		before, after = a.hooks(ctx.Auth)
	}
	for _, h := range before {
		matched, err := safeMatch(h, child)
		if err != nil || !matched {
			continue
		}
		res, err := h.Handler(child)
		if err != nil {
			merge()
			return nil, err
		}
		if res != nil {
			merge()
			return res, nil
		}
	}
	child.invalidateCookies()
	res, err := run(child)
	if err != nil {
		e, ok := AsAPIError(err)
		if !ok {
			return nil, err
		}
		child.Returned = e
		child.ReturnedStatus = e.StatusCode
		child.ResponseHeaders = mergeHeaders(child.ResponseHeaders, e.Headers)
	} else {
		child.Returned = res
		child.ReturnedStatus = child.status
	}
	for _, h := range after {
		if !h.Matcher(child) {
			continue
		}
		r, herr := h.Handler(child)
		if herr != nil {
			e, ok := AsAPIError(herr)
			if !ok {
				return nil, herr
			}
			child.ResponseHeaders = mergeHeaders(child.ResponseHeaders, e.Headers)
			child.Returned = e
			continue
		}
		if r != nil {
			child.Returned = r
		}
	}
	merge()
	if e, ok := child.Returned.(*APIError); ok {
		return nil, e
	}
	return child.Returned, nil
}
