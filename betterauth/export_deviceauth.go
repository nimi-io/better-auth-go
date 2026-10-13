package betterauth

// Helpers exported for the device-authorization and open-api plugins
// (plugins/deviceauthorization, plugins/openapi). They expose existing core internals
// without changing their behaviour.

// OpenAPICoreEndpoints returns freshly built core endpoints in upstream getEndpoints order
// (base endpoints followed by ok and error), independent of any plugin overrides. The
// open-api generator documents these as the "Default" endpoints.
func OpenAPICoreEndpoints() []*Endpoint {
	return append(coreEndpoints(), okEndpoint(), errorEndpoint())
}
