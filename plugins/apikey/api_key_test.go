package apikey

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nimi-io/better-auth-go/betterauth"
)

// Port of packages/api-key/src/api-key.test.ts, describe("api-key"). Subtests run in
// order and share state like the vitest suite.
func TestAPIKey(t *testing.T) {
	inst := newInstance(t, Options{Configuration: Configuration{
		EnableMetadata: true,
		Permissions:    &Permissions{DefaultPermissions: Statements{"files": {"read"}}},
	}}, nil)
	si := inst.signInWithTestUser()
	headers, userID := si.headers, si.userID

	// =========================================================================
	// CREATE API KEY
	// =========================================================================

	t.Run("should fail to create API keys from client without headers", func(t *testing.T) {
		res := inst.clientCreate(nil, nil)
		if res.Data() != nil {
			t.Fatal("expected no data")
		}
		eq(t, res.Status, 401)
		eq(t, http.StatusText(res.Status), "Unauthorized")
		eq(t, res.Message(), ErrUnauthorizedSession.Message)
	})

	var firstAPIKey map[string]any

	t.Run("should successfully create API keys from client with headers", func(t *testing.T) {
		res := inst.clientCreate(map[string]any{}, headers)
		k := expectOK(t, res)
		firstAPIKey = k
		notNil(t, k["key"])
		eq(t, k["referenceId"], userID)
		isNil(t, k["name"])
		isNil(t, k["prefix"])
		isNil(t, k["refillInterval"])
		isNil(t, k["refillAmount"])
		isNil(t, k["lastRefillAt"])
		eq(t, k["enabled"], true)
		eq(t, k["rateLimitTimeWindow"], float64(86400000))
		eq(t, k["rateLimitMax"], float64(10))
		eq(t, k["requestCount"], float64(0))
		isNil(t, k["remaining"])
		isNil(t, k["lastRequest"])
		isNil(t, k["expiresAt"])
		notNil(t, k["createdAt"])
		notNil(t, k["updatedAt"])
		isNil(t, k["metadata"])
	})

	t.Run("should fail to create API Keys from server without headers and userId", func(t *testing.T) {
		_, e := inst.call("createApiKey", map[string]any{}, nil)
		expectAPIError(t, e, "UNAUTHORIZED", ErrUnauthorizedSession)
		eq(t, e.StatusCode, 401)
	})

	t.Run("should fail to create api keys from the client if user id is provided", func(t *testing.T) {
		s := inst.signInWithTestUser()
		res := inst.clientCreate(map[string]any{"userId": s.userID}, nil)
		eq(t, res.Status, 401)
		newUserID := inst.signUp("new-email@email.com", "password", "test-name")
		res2 := inst.clientCreate(map[string]any{"userId": newUserID}, s.headers)
		eq(t, res2.Status, 401)
	})

	t.Run("should successfully create API keys from server with userId", func(t *testing.T) {
		k := inst.createKey(map[string]any{"userId": userID}, nil)
		notNil(t, k["key"])
		eq(t, k["referenceId"], userID)
		isNil(t, k["name"])
		isNil(t, k["prefix"])
		isNil(t, k["refillInterval"])
		isNil(t, k["refillAmount"])
		isNil(t, k["lastRefillAt"])
		eq(t, k["enabled"], true)
		eq(t, k["rateLimitTimeWindow"], float64(86400000))
		eq(t, k["rateLimitMax"], float64(10))
		eq(t, k["requestCount"], float64(0))
		isNil(t, k["remaining"])
		isNil(t, k["lastRequest"])
		eq(t, k["rateLimitEnabled"], true)
	})

	t.Run("should have the real value from rateLimitEnabled", func(t *testing.T) {
		k := inst.createKey(map[string]any{"userId": userID, "rateLimitEnabled": false}, nil)
		eq(t, k["rateLimitEnabled"], false)
	})

	t.Run("should have true if the rate limit is undefined", func(t *testing.T) {
		k := inst.createKey(map[string]any{"userId": userID}, nil)
		eq(t, k["rateLimitEnabled"], true)
	})

	t.Run("should require name in API keys if configured", func(t *testing.T) {
		in := newInstance(t, Options{Configuration: Configuration{RequireName: true}}, nil)
		s := in.signInWithTestUser()
		_, e := in.call("createApiKey", map[string]any{"userId": s.userID}, nil)
		expectAPIError(t, e, "BAD_REQUEST", ErrNameRequired)
	})

	t.Run("should respect rateLimit configuration from plugin options", func(t *testing.T) {
		in := newInstance(t, Options{Configuration: Configuration{
			RateLimit:      &RateLimit{Enabled: Bool(false), TimeWindow: Float(1000), MaxRequests: Float(10)},
			EnableMetadata: true,
		}}, nil)
		s := in.signInWithTestUser()
		k := in.createKey(map[string]any{"userId": s.userID}, nil)
		eq(t, k["rateLimitEnabled"], false)
		eq(t, k["rateLimitTimeWindow"], float64(1000))
		eq(t, k["rateLimitMax"], float64(10))
	})

	t.Run("should create the API key with the given name", func(t *testing.T) {
		k := inst.createKey(map[string]any{"name": "test-api-key"}, headers)
		eq(t, k["name"], "test-api-key")
	})

	t.Run("should create the API key with a name that's shorter than the allowed minimum", func(t *testing.T) {
		_, e := inst.call("createApiKey", map[string]any{"name": "test-api-key-that-is-shorter-than-the-allowed-minimum"}, headers)
		expectAPIError(t, e, "BAD_REQUEST", ErrInvalidNameLength)
	})

	t.Run("should create the API key with a name that's longer than the allowed maximum", func(t *testing.T) {
		_, e := inst.call("createApiKey", map[string]any{"name": "test-api-key-that-is-longer-than-the-allowed-maximum"}, headers)
		expectAPIError(t, e, "BAD_REQUEST", ErrInvalidNameLength)
	})

	t.Run("should create the API key with the given prefix", func(t *testing.T) {
		prefix := "test-api-key_"
		k := inst.createKey(map[string]any{"prefix": prefix}, headers)
		eq(t, k["prefix"], prefix)
		eq(t, strings.HasPrefix(str(k["key"]), prefix), true)
	})

	t.Run("should create the API key with a prefix that's shorter than the allowed minimum", func(t *testing.T) {
		_, e := inst.call("createApiKey", map[string]any{"prefix": "test-api-key-that-is-shorter-than-the-allowed-minimum"}, headers)
		expectAPIError(t, e, "BAD_REQUEST", ErrInvalidPrefixLength)
	})

	t.Run("should create the API key with a prefix that's longer than the allowed maximum", func(t *testing.T) {
		_, e := inst.call("createApiKey", map[string]any{"prefix": "test-api-key-that-is-longer-than-the-allowed-maximum"}, headers)
		expectAPIError(t, e, "BAD_REQUEST", ErrInvalidPrefixLength)
	})

	t.Run("should create an API key with a custom expiresIn", func(t *testing.T) {
		expiresIn := 60 * 60 * 24 * 7
		expected := time.Now().UnixMilli() + int64(expiresIn)
		k := inst.createKey(map[string]any{"expiresIn": expiresIn}, headers)
		notNil(t, k["expiresAt"])
		if parseTime(t, k["expiresAt"]).UnixMilli() < expected {
			t.Fatal("expiresAt too small")
		}
	})

	t.Run("should support disabling key hashing", func(t *testing.T) {
		in := newInstance(t, Options{Configuration: Configuration{DisableKeyHashing: true}}, nil)
		s := in.signInWithTestUser()
		k := in.createKey(map[string]any{}, s.headers)
		row, err := in.p.dbFindOne(in.ctx(), "id", str(k["id"]))
		if err != nil || row == nil {
			t.Fatalf("findOne: %v", err)
		}
		eq(t, row.Key, k["key"])
	})

	t.Run("should be able to verify with key hashing disabled", func(t *testing.T) {
		in := newInstance(t, Options{Configuration: Configuration{DisableKeyHashing: true}}, nil)
		s := in.signInWithTestUser()
		k := in.createKey(map[string]any{}, s.headers)
		r := in.verify(map[string]any{"key": k["key"]})
		eq(t, r["valid"], true)
	})

	t.Run("should fail to create a key with a custom expiresIn value when customExpiresTime is disabled", func(t *testing.T) {
		in := newInstance(t, Options{Configuration: Configuration{EnableMetadata: true,
			KeyExpiration: &KeyExpiration{DisableCustomExpiresTime: true}}}, nil)
		s := in.signInWithTestUser()
		_, e := in.call("createApiKey", map[string]any{"expiresIn": 10000}, s.headers)
		expectAPIError(t, e, "BAD_REQUEST", ErrKeyDisabledExpiration)
	})

	t.Run("should create an API key with an expiresIn that's smaller than the allowed minimum", func(t *testing.T) {
		_, e := inst.call("createApiKey", map[string]any{"expiresIn": 60 * 60 * 24 * 0.5}, headers)
		expectAPIError(t, e, "BAD_REQUEST", ErrExpiresInIsTooSmall)
	})

	t.Run("should fail to create an API key with an expiresIn that's larger than the allowed maximum", func(t *testing.T) {
		_, e := inst.call("createApiKey", map[string]any{"expiresIn": 60 * 60 * 24 * 365 * 10}, headers)
		expectAPIError(t, e, "BAD_REQUEST", ErrExpiresInIsTooLarge)
	})

	t.Run("should fail to create API key with custom refillAndAmount from client auth", func(t *testing.T) {
		res := inst.clientCreate(map[string]any{"refillAmount": 10}, headers)
		eq(t, res.Status, 400)
		eq(t, res.Message(), ErrServerOnlyProperty.Message)
		res2 := inst.clientCreate(map[string]any{"refillInterval": 1001}, headers)
		eq(t, res2.Status, 400)
		eq(t, res2.Message(), ErrServerOnlyProperty.Message)
	})

	t.Run("should fail to create API key when refill interval is provided, but no refill amount", func(t *testing.T) {
		_, e := inst.call("createApiKey", map[string]any{"refillInterval": 1000, "userId": userID}, nil)
		expectAPIError(t, e, "BAD_REQUEST", ErrRefillIntervalAndAmountRequired)
	})

	t.Run("should fail to create API key when refill amount is provided, but no refill interval", func(t *testing.T) {
		_, e := inst.call("createApiKey", map[string]any{"refillAmount": 10, "userId": userID}, nil)
		expectAPIError(t, e, "BAD_REQUEST", ErrRefillAmountAndIntervalRequired)
	})

	t.Run("should create the API key with the given refill interval & refill amount", func(t *testing.T) {
		k := inst.createKey(map[string]any{"refillInterval": 10000, "refillAmount": 10, "userId": userID}, nil)
		eq(t, k["refillInterval"], float64(10000))
		eq(t, k["refillAmount"], float64(10))
	})

	t.Run("should create API Key with custom remaining", func(t *testing.T) {
		k := inst.createKey(map[string]any{"remaining": 10, "userId": userID}, nil)
		eq(t, k["remaining"], float64(10))
	})

	t.Run("should create API Key with remaining explicitly set to null", func(t *testing.T) {
		k := inst.createKey(map[string]any{"remaining": nil, "userId": userID}, nil)
		isNil(t, k["remaining"])
	})

	t.Run("should create API Key with remaining explicitly set to null and refillAmount and refillInterval are also set", func(t *testing.T) {
		k := inst.createKey(map[string]any{"remaining": nil, "refillAmount": 10, "refillInterval": 1000, "userId": userID}, nil)
		isNil(t, k["remaining"])
		eq(t, k["refillAmount"], float64(10))
		eq(t, k["refillInterval"], float64(1000))
	})

	t.Run("should create API Key with remaining explicitly set to 0 and refillAmount also set", func(t *testing.T) {
		k := inst.createKey(map[string]any{"remaining": 0, "refillAmount": 10, "refillInterval": 1000, "userId": userID}, nil)
		eq(t, k["remaining"], float64(0))
		eq(t, k["refillAmount"], float64(10))
		eq(t, k["refillInterval"], float64(1000))
	})

	t.Run("should create API Key with remaining undefined and default value of null is respected with refillAmount and refillInterval provided", func(t *testing.T) {
		k := inst.createKey(map[string]any{"refillAmount": 10, "refillInterval": 1000, "userId": userID}, nil)
		isNil(t, k["remaining"])
		eq(t, k["refillAmount"], float64(10))
		eq(t, k["refillInterval"], float64(1000))
	})

	t.Run("should create API key with invalid metadata", func(t *testing.T) {
		_, e := inst.call("createApiKey", map[string]any{"metadata": "invalid"}, headers)
		expectAPIError(t, e, "BAD_REQUEST", ErrInvalidMetadataType)
	})

	t.Run("should create API key with valid metadata", func(t *testing.T) {
		k := inst.createKey(map[string]any{"metadata": map[string]any{"test": "test"}}, headers)
		eq(t, obj(k["metadata"])["test"], "test")
		r, e := inst.getKey(str(k["id"]), "", headers)
		if e != nil {
			t.Fatal(e)
		}
		eq(t, obj(r["metadata"])["test"], "test")
		eq(t, len(obj(r["metadata"])), 1)
	})

	t.Run("create API key's returned metadata should be an object", func(t *testing.T) {
		k := inst.createKey(map[string]any{"metadata": map[string]any{"test": "test-123"}}, headers)
		eq(t, obj(k["metadata"])["test"], "test-123")
	})

	t.Run("create API key with with metadata when metadata is disabled (should fail)", func(t *testing.T) {
		in := newInstance(t, Options{Configuration: Configuration{EnableMetadata: false}}, nil)
		s := in.signInWithTestUser()
		_, e := in.call("createApiKey", map[string]any{"metadata": map[string]any{"test": "test-123"}}, s.headers)
		expectAPIError(t, e, "BAD_REQUEST", ErrMetadataDisabled)
	})

	t.Run("should have the first 6 characters of the key as the start property", func(t *testing.T) {
		k := expectOK(t, inst.clientCreate(map[string]any{}, headers))
		eq(t, len(str(k["start"])), 6)
		eq(t, k["start"], str(k["key"])[:6])
	})

	t.Run("should have the start property as null if shouldStore is false", func(t *testing.T) {
		in := newInstance(t, Options{Configuration: Configuration{
			StartingCharactersConfig: &StartingCharactersConfig{ShouldStore: Bool(false)}}}, nil)
		s := in.signInWithTestUser()
		k := expectOK(t, in.clientCreate(map[string]any{}, s.headers))
		isNil(t, k["start"])
	})

	t.Run("should use the defined charactersLength if provided", func(t *testing.T) {
		in := newInstance(t, Options{Configuration: Configuration{
			StartingCharactersConfig: &StartingCharactersConfig{ShouldStore: Bool(true), CharactersLength: Int(3)}}}, nil)
		s := in.signInWithTestUser()
		k := expectOK(t, in.clientCreate(map[string]any{}, s.headers))
		eq(t, len(str(k["start"])), 3)
		eq(t, k["start"], str(k["key"])[:3])
	})

	t.Run("should fail to create API key with custom rate-limit options from client auth", func(t *testing.T) {
		res := inst.clientCreate(map[string]any{"rateLimitMax": 15}, headers)
		eq(t, res.Status, 400)
		eq(t, res.Message(), ErrServerOnlyProperty.Message)
		res2 := inst.clientCreate(map[string]any{"rateLimitTimeWindow": 1001}, headers)
		eq(t, res2.Status, 400)
		eq(t, res2.Message(), ErrServerOnlyProperty.Message)
	})

	t.Run("should successfully apply custom rate-limit options on the newly created API key", func(t *testing.T) {
		k := inst.createKey(map[string]any{"rateLimitMax": 15, "rateLimitTimeWindow": 1000, "userId": userID}, nil)
		eq(t, k["rateLimitMax"], float64(15))
		eq(t, k["rateLimitTimeWindow"], float64(1000))
	})

	// =========================================================================
	// VERIFY API KEY
	// =========================================================================

	t.Run("verify API key without key and userId", func(t *testing.T) {
		r := inst.verify(map[string]any{"key": firstAPIKey["key"]})
		notNil(t, r["key"])
		eq(t, r["valid"], true)
	})

	t.Run("verify API key with invalid key (should fail)", func(t *testing.T) {
		r := inst.verify(map[string]any{"key": "invalid"})
		eq(t, r["valid"], false)
		eq(t, errCode(r), "INVALID_API_KEY")
	})

	rl := newInstance(t, Options{Configuration: Configuration{
		RateLimit: &RateLimit{Enabled: Bool(true), TimeWindow: Float(1000)}}}, nil)
	rlHeaders := rl.signInWithTestUser().headers
	var rateLimitedKey map[string]any

	t.Run("should fail to verify API key 20 times in a row due to rate-limit", func(t *testing.T) {
		k := expectOK(t, rl.clientCreate(map[string]any{}, rlHeaders))
		rateLimitedKey = k
		for i := 0; i < 20; i++ {
			r := rl.mustCall("verifyApiKey", map[string]any{"key": k["key"]}, rlHeaders)
			if i >= 10 {
				eq(t, errCode(r), "RATE_LIMITED")
			} else {
				isNil(t, r["error"])
			}
		}
	})

	t.Run("should allow us to verify API key after rate-limit window has passed", func(t *testing.T) {
		// vi.useFakeTimers() freezes "now" after the previous requests; let at least one
		// millisecond pass so the window is strictly exceeded like upstream.
		time.Sleep(2 * time.Millisecond)
		rl.advance(1000 * time.Millisecond)
		defer rl.useRealTimers()
		r := rl.mustCall("verifyApiKey", map[string]any{"key": rateLimitedKey["key"]}, rlHeaders)
		isNil(t, r["error"])
		eq(t, r["valid"], true)
	})

	// @see https://github.com/better-auth/better-auth/issues/9504
	t.Run("should return 429 when API key rate limit is exceeded via before hook", func(t *testing.T) {
		in := newInstance(t, Options{Configuration: Configuration{EnableSessionForAPIKeys: true,
			RateLimit: &RateLimit{Enabled: Bool(true), TimeWindow: Float(60000), MaxRequests: Float(2)}}}, nil)
		s := in.signInWithTestUser()
		k := expectOK(t, in.clientCreate(map[string]any{}, s.headers))
		h := http.Header{}
		h.Set("x-api-key", str(k["key"]))
		for i := 0; i < 2; i++ {
			res := in.http("GET", "/get-session", nil, h)
			eq(t, res.Status, 200)
		}
		res := in.http("GET", "/get-session", nil, h)
		eq(t, res.Status, 429)
	})

	t.Run("should check if verifying an API key's remaining count does go down", func(t *testing.T) {
		remaining := 10
		res := inst.clientCreate(map[string]any{"remaining": remaining}, headers)
		k := res.Data()
		if k == nil {
			// upstream: remaining is a server-only property, so the client create fails
			// and the test returns early.
			return
		}
		r := inst.mustCall("verifyApiKey", map[string]any{"key": k["key"]}, headers)
		eq(t, r["valid"], true)
		eq(t, obj(r["key"])["remaining"], float64(remaining-1))
		r = inst.mustCall("verifyApiKey", map[string]any{"key": k["key"]}, headers)
		eq(t, r["valid"], true)
		eq(t, obj(r["key"])["remaining"], float64(remaining-2))
	})

	t.Run("should fail if the API key has no remaining", func(t *testing.T) {
		k := inst.createKey(map[string]any{"remaining": 1, "userId": userID}, nil)
		inst.mustCall("verifyApiKey", map[string]any{"key": k["key"]}, headers)
		r := inst.mustCall("verifyApiKey", map[string]any{"key": k["key"]}, headers)
		eq(t, errCode(r), "USAGE_EXCEEDED")
	})

	t.Run("should fail if the API key is expired", func(t *testing.T) {
		inst.useRealTimers()
		s := inst.signInWithTestUser()
		k := expectOK(t, inst.clientCreate(map[string]any{"expiresIn": 60 * 60 * 24}, s.headers))
		inst.advance(time.Hour * 24 * 2)
		defer inst.useRealTimers()
		r := inst.mustCall("verifyApiKey", map[string]any{"key": k["key"]}, s.headers)
		eq(t, errCode(r), "KEY_EXPIRED")
	})

	// =========================================================================
	// UPDATE API KEY
	// =========================================================================

	t.Run("should fail to update API key name without headers or userId", func(t *testing.T) {
		_, e := inst.call("updateApiKey", map[string]any{"keyId": firstAPIKey["id"], "name": "test-api-key"}, nil)
		expectAPIError(t, e, "UNAUTHORIZED", ErrUnauthorizedSession)
		eq(t, e.StatusCode, 401)
	})

	t.Run("should update API key name with headers", func(t *testing.T) {
		k := inst.mustCall("updateApiKey", map[string]any{"keyId": firstAPIKey["id"], "name": "Hello World"}, headers)
		if k["name"] == firstAPIKey["name"] {
			t.Fatal("name not updated")
		}
		eq(t, k["name"], "Hello World")
	})

	t.Run("should fail to update API key name with a length larger than the allowed maximum", func(t *testing.T) {
		_, e := inst.call("updateApiKey", map[string]any{"keyId": firstAPIKey["id"], "name": "test-api-key-that-is-longer-than-the-allowed-maximum"}, headers)
		expectAPIError(t, e, "BAD_REQUEST", ErrInvalidNameLength)
	})

	t.Run("should fail to update API key name with a length smaller than the allowed minimum", func(t *testing.T) {
		_, e := inst.call("updateApiKey", map[string]any{"keyId": firstAPIKey["id"], "name": ""}, headers)
		expectAPIError(t, e, "BAD_REQUEST", ErrInvalidNameLength)
	})

	t.Run("should fail to update API key with no values to update", func(t *testing.T) {
		_, e := inst.call("updateApiKey", map[string]any{"keyId": firstAPIKey["id"]}, headers)
		expectAPIError(t, e, "BAD_REQUEST", ErrNoValuesToUpdate)
	})

	t.Run("should update API key expiresIn value", func(t *testing.T) {
		expiresIn := 60 * 60 * 24 * 7
		expected := time.Now().UnixMilli() + int64(expiresIn)
		k := inst.mustCall("updateApiKey", map[string]any{"keyId": firstAPIKey["id"], "expiresIn": expiresIn}, headers)
		if parseTime(t, k["expiresAt"]).UnixMilli() < expected {
			t.Fatal("expiresAt too small")
		}
	})

	t.Run("should fail to update expiresIn value if `disableCustomExpiresTime` is enabled", func(t *testing.T) {
		in := newInstance(t, Options{Configuration: Configuration{KeyExpiration: &KeyExpiration{DisableCustomExpiresTime: true}}}, nil)
		s := in.signInWithTestUser()
		k := expectOK(t, in.clientCreate(map[string]any{}, s.headers))
		_, e := in.call("updateApiKey", map[string]any{"keyId": k["id"], "expiresIn": 1000 * 60 * 60 * 24 * 7}, s.headers)
		expectAPIError(t, e, "BAD_REQUEST", ErrKeyDisabledExpiration)
	})

	t.Run("should fail to update expiresIn value if it's smaller than the allowed minimum", func(t *testing.T) {
		in := newInstance(t, Options{Configuration: Configuration{KeyExpiration: &KeyExpiration{MinExpiresIn: Float(1)}}}, nil)
		s := in.signInWithTestUser()
		k := expectOK(t, in.clientCreate(map[string]any{}, s.headers))
		_, e := in.call("updateApiKey", map[string]any{"keyId": k["id"], "expiresIn": 1}, s.headers)
		expectAPIError(t, e, "BAD_REQUEST", ErrExpiresInIsTooSmall)
	})

	t.Run("should fail to update expiresIn value if it's larger than the allowed maximum", func(t *testing.T) {
		in := newInstance(t, Options{Configuration: Configuration{KeyExpiration: &KeyExpiration{MaxExpiresIn: Float(1)}}}, nil)
		s := in.signInWithTestUser()
		k := expectOK(t, in.clientCreate(map[string]any{}, s.headers))
		_, e := in.call("updateApiKey", map[string]any{"keyId": k["id"], "expiresIn": 1000 * 60 * 60 * 24 * 365 * 10}, s.headers)
		expectAPIError(t, e, "BAD_REQUEST", ErrExpiresInIsTooLarge)
	})

	t.Run("should update API key remaining count", func(t *testing.T) {
		k := inst.mustCall("updateApiKey", map[string]any{"keyId": firstAPIKey["id"], "remaining": 100, "userId": userID}, nil)
		eq(t, k["remaining"], float64(100))
	})

	t.Run("should fail update the refillInterval value since it requires refillAmount as well", func(t *testing.T) {
		_, e := inst.call("updateApiKey", map[string]any{"keyId": firstAPIKey["id"], "refillInterval": 1000, "userId": userID}, nil)
		expectAPIError(t, e, "BAD_REQUEST", ErrRefillIntervalAndAmountRequired)
	})

	t.Run("should fail update the refillAmount value since it requires refillInterval as well", func(t *testing.T) {
		_, e := inst.call("updateApiKey", map[string]any{"keyId": firstAPIKey["id"], "refillAmount": 10, "userId": userID}, nil)
		expectAPIError(t, e, "BAD_REQUEST", ErrRefillAmountAndIntervalRequired)
	})

	t.Run("should update the refillInterval and refillAmount value", func(t *testing.T) {
		k := inst.mustCall("updateApiKey", map[string]any{"keyId": firstAPIKey["id"], "refillInterval": 10000, "refillAmount": 100, "userId": userID}, nil)
		eq(t, k["refillInterval"], float64(10000))
		eq(t, k["refillAmount"], float64(100))
	})

	t.Run("should update API key enable value", func(t *testing.T) {
		k := inst.mustCall("updateApiKey", map[string]any{"keyId": firstAPIKey["id"], "enabled": false, "userId": userID}, nil)
		eq(t, k["enabled"], false)
	})

	t.Run("should fail to update metadata with invalid metadata type", func(t *testing.T) {
		_, e := inst.call("updateApiKey", map[string]any{"keyId": firstAPIKey["id"], "metadata": "invalid", "userId": userID}, nil)
		expectAPIError(t, e, "BAD_REQUEST", ErrInvalidMetadataType)
	})

	t.Run("should update metadata with valid metadata type", func(t *testing.T) {
		k := inst.mustCall("updateApiKey", map[string]any{"keyId": firstAPIKey["id"], "metadata": map[string]any{"test": "test-123"}, "userId": userID}, nil)
		eq(t, obj(k["metadata"])["test"], "test-123")
	})

	t.Run("update API key's returned metadata should be an object", func(t *testing.T) {
		k := inst.mustCall("updateApiKey", map[string]any{"keyId": firstAPIKey["id"], "metadata": map[string]any{"test": "test-12345"}, "userId": userID}, nil)
		eq(t, obj(k["metadata"])["test"], "test-12345")
	})

	// =========================================================================
	// API KEY LASTREQUEST BUG FIX (#5309)
	// =========================================================================

	t.Run("should not modify lastRequest when updating API key configuration", func(t *testing.T) {
		k := inst.createKey(map[string]any{"userId": userID}, nil)
		isNil(t, k["lastRequest"])
		u := inst.mustCall("updateApiKey", map[string]any{"keyId": k["id"], "name": "updated-name", "userId": userID}, nil)
		isNil(t, u["lastRequest"])
	})

	t.Run("should not auto-decrement remaining when updating API key", func(t *testing.T) {
		k := inst.createKey(map[string]any{"remaining": 100, "userId": userID}, nil)
		eq(t, k["remaining"], float64(100))
		u := inst.mustCall("updateApiKey", map[string]any{"keyId": k["id"], "metadata": map[string]any{"foo": "bar"}, "userId": userID}, nil)
		eq(t, u["remaining"], float64(100))
	})

	t.Run("should allow explicit remaining updates via body parameter", func(t *testing.T) {
		k := inst.createKey(map[string]any{"remaining": 100, "userId": userID}, nil)
		u := inst.mustCall("updateApiKey", map[string]any{"keyId": k["id"], "remaining": 50, "userId": userID}, nil)
		eq(t, u["remaining"], float64(50))
		isNil(t, u["lastRequest"])
	})

	t.Run("verifyApiKey should still update lastRequest", func(t *testing.T) {
		k := inst.createKey(map[string]any{"userId": userID}, nil)
		isNil(t, k["lastRequest"])
		r := inst.verify(map[string]any{"key": k["key"]})
		eq(t, r["valid"], true)
		u, e := inst.getKey(str(k["id"]), "default", headers)
		if e != nil {
			t.Fatal(e)
		}
		parseTime(t, u["lastRequest"])
	})

	t.Run("verifyApiKey should still decrement remaining", func(t *testing.T) {
		k := inst.createKey(map[string]any{"remaining": 100, "userId": userID}, nil)
		inst.verify(map[string]any{"key": k["key"]})
		u, e := inst.getKey(str(k["id"]), "default", headers)
		if e != nil {
			t.Fatal(e)
		}
		eq(t, u["remaining"], float64(99))
	})

	// =========================================================================
	// GET API KEY
	// =========================================================================

	t.Run("should get an API key by id", func(t *testing.T) {
		k := expectOK(t, inst.clientGet("id="+str(firstAPIKey["id"]), headers))
		eq(t, k["id"], firstAPIKey["id"])
	})

	t.Run("should fail to get an API key by ID that doesn't exist", func(t *testing.T) {
		res := inst.clientGet("id=invalid", headers)
		eq(t, res.Status, 404)
	})

	t.Run("should successfully receive an object metadata from an API key", func(t *testing.T) {
		k := expectOK(t, inst.clientGet("id="+str(firstAPIKey["id"]), headers))
		if _, ok := k["metadata"].(map[string]any); !ok {
			t.Fatalf("metadata is not an object: %#v", k["metadata"])
		}
	})

	// =========================================================================
	// LIST API KEY
	// =========================================================================

	t.Run("should fail to list API keys without headers", func(t *testing.T) {
		_, e := inst.call("listApiKeys", nil, nil)
		expectAPIError(t, e, "UNAUTHORIZED", betterauth.ErrorCode{})
	})

	t.Run("should list API keys with headers", func(t *testing.T) {
		r := inst.mustCall("listApiKeys", nil, headers)
		if len(r["apiKeys"].([]any)) == 0 || num(r["total"]) == 0 {
			t.Fatal("expected keys")
		}
	})

	t.Run("should list API keys with metadata as an object", func(t *testing.T) {
		r := inst.mustCall("listApiKeys", nil, headers)
		for _, k := range r["apiKeys"].([]any) {
			if md := obj(k)["metadata"]; md != nil {
				if _, ok := md.(map[string]any); !ok {
					t.Fatalf("metadata not object: %#v", md)
				}
			}
		}
	})

	// =========================================================================
	// LIST API KEY PAGINATION
	// =========================================================================

	t.Run("list API keys pagination", func(t *testing.T) {
		list := func(q map[string]any) map[string]any {
			return inst.mustCall("listApiKeys", nil, headers, q)
		}
		keys := func(r map[string]any) []any { return r["apiKeys"].([]any) }
		t.Run("should return paginated response with total count", func(t *testing.T) {
			r := list(nil)
			if r["apiKeys"] == nil {
				t.Fatal("apiKeys missing")
			}
			if int(num(r["total"])) < len(keys(r)) {
				t.Fatal("total too small")
			}
		})
		t.Run("should limit the number of returned API keys", func(t *testing.T) {
			for _, n := range []string{"pagination-key-1", "pagination-key-2", "pagination-key-3"} {
				inst.createKey(map[string]any{"name": n}, headers)
			}
			r := list(map[string]any{"limit": 2})
			if len(keys(r)) > 2 {
				t.Fatal("too many keys")
			}
			eq(t, r["limit"], float64(2))
			if num(r["total"]) < 3 {
				t.Fatal("total too small")
			}
		})
		t.Run("should skip API keys with offset", func(t *testing.T) {
			all := list(nil)
			off := list(map[string]any{"offset": 1})
			eq(t, off["offset"], float64(1))
			eq(t, len(keys(off)), len(keys(all))-1)
		})
		t.Run("should support pagination with both limit and offset", func(t *testing.T) {
			p1 := list(map[string]any{"limit": 2, "offset": 0})
			p2 := list(map[string]any{"limit": 2, "offset": 2})
			if len(keys(p1)) > 2 || len(keys(p2)) > 2 {
				t.Fatal("page too large")
			}
			eq(t, p1["limit"], float64(2))
			eq(t, p1["offset"], float64(0))
			eq(t, p2["offset"], float64(2))
			ids := map[any]bool{}
			for _, k := range keys(p1) {
				ids[obj(k)["id"]] = true
			}
			for _, k := range keys(p2) {
				if ids[obj(k)["id"]] {
					t.Fatal("pages overlap")
				}
			}
		})
		checkSorted := func(t *testing.T, r map[string]any, asc bool) {
			t.Helper()
			ks := keys(r)
			for i := 1; i < len(ks); i++ {
				prev := parseTime(t, obj(ks[i-1])["createdAt"])
				curr := parseTime(t, obj(ks[i])["createdAt"])
				if asc && curr.Before(prev) || !asc && curr.After(prev) {
					t.Fatalf("not sorted at %d", i)
				}
			}
		}
		t.Run("should sort API keys by createdAt ascending", func(t *testing.T) {
			r := list(map[string]any{"sortBy": "createdAt", "sortDirection": "asc"})
			if len(keys(r)) <= 1 {
				t.Fatal("expected several keys")
			}
			checkSorted(t, r, true)
		})
		t.Run("should sort API keys by createdAt descending", func(t *testing.T) {
			r := list(map[string]any{"sortBy": "createdAt", "sortDirection": "desc"})
			if len(keys(r)) <= 1 {
				t.Fatal("expected several keys")
			}
			checkSorted(t, r, false)
		})
		t.Run("should sort API keys by name", func(t *testing.T) {
			inst.createKey(map[string]any{"name": "aaa-sort-test"}, headers)
			inst.createKey(map[string]any{"name": "zzz-sort-test"}, headers)
			named := func(r map[string]any) []string {
				var out []string
				for _, k := range keys(r) {
					if n := str(obj(k)["name"]); strings.Contains(n, "-sort-test") {
						out = append(out, n)
					}
				}
				return out
			}
			asc := named(list(map[string]any{"sortBy": "name", "sortDirection": "asc"}))
			desc := named(list(map[string]any{"sortBy": "name", "sortDirection": "desc"}))
			eq(t, asc[0], "aaa-sort-test")
			eq(t, desc[0], "zzz-sort-test")
		})
		t.Run("should combine sorting with pagination", func(t *testing.T) {
			r := list(map[string]any{"limit": 3, "offset": 0, "sortBy": "createdAt", "sortDirection": "desc"})
			if len(keys(r)) > 3 {
				t.Fatal("too many")
			}
			eq(t, r["limit"], float64(3))
			checkSorted(t, r, false)
		})
		t.Run("should return empty array when offset exceeds total", func(t *testing.T) {
			all := list(nil)
			r := list(map[string]any{"offset": num(all["total"]) + 100})
			eq(t, len(keys(r)), 0)
			eq(t, r["total"], all["total"])
		})
		t.Run("should handle string query parameters for limit and offset", func(t *testing.T) {
			r := list(map[string]any{"limit": "2", "offset": "1"})
			eq(t, r["limit"], float64(2))
			eq(t, r["offset"], float64(1))
			if len(keys(r)) > 2 {
				t.Fatal("too many")
			}
		})
	})

	// =========================================================================
	// Sessions from API keys
	// =========================================================================

	t.Run("enableSessionForAPIKeys", func(t *testing.T) {
		t.Run("should get session from an API key", func(t *testing.T) {
			in := newInstance(t, Options{Configuration: Configuration{EnableSessionForAPIKeys: true}}, nil)
			s := in.signInWithTestUser()
			k := expectOK(t, in.clientCreate(map[string]any{}, s.headers))
			h := http.Header{}
			h.Set("x-api-key", str(k["key"]))
			sess, err := in.auth.API.GetSession(t.Context(), h)
			if err != nil || sess == nil || sess.Session == nil {
				t.Fatalf("expected session, got %v %v", sess, err)
			}
		})

		t.Run("should run customAPIKeyValidator once on the session path", func(t *testing.T) {
			calls := 0
			in := newInstance(t, Options{Configuration: Configuration{EnableSessionForAPIKeys: true,
				CustomAPIKeyValidator: func(*betterauth.EndpointContext, string) (bool, error) { calls++; return true, nil }}}, nil)
			s := in.signInWithTestUser()
			k := in.createKey(map[string]any{"userId": s.userID}, nil)
			h := http.Header{}
			h.Set("x-api-key", str(k["key"]))
			calls = 0
			if _, err := in.auth.API.GetSession(t.Context(), h); err != nil {
				t.Fatal(err)
			}
			eq(t, calls, 1)
		})

		t.Run("should not grant a session for a key from a different config", func(t *testing.T) {
			in := newInstance(t, Options{Configurations: []Configuration{
				{ConfigID: "primary", EnableSessionForAPIKeys: true},
				{ConfigID: "secondary", EnableSessionForAPIKeys: true},
			}}, nil)
			s := in.signInWithTestUser()
			k := in.createKey(map[string]any{"configId": "secondary", "userId": s.userID}, nil)
			h := http.Header{}
			h.Set("x-api-key", str(k["key"]))
			if _, err := in.auth.API.GetSession(t.Context(), h); err == nil {
				t.Fatal("expected an error")
			}
		})

		t.Run("should not get session from an API key if enableSessionForAPIKeys is false", func(t *testing.T) {
			in := newInstance(t, Options{Configuration: Configuration{EnableSessionForAPIKeys: false}}, nil)
			s := in.signInWithTestUser()
			k := expectOK(t, in.clientCreate(map[string]any{}, s.headers))
			h := http.Header{}
			h.Set("x-api-key", str(k["key"]))
			sess, err := in.auth.API.GetSession(t.Context(), h)
			if err != nil || sess != nil {
				t.Fatalf("expected null session, got %v %v", sess, err)
			}
		})

		t.Run("should get the Response object when asResponse is true", func(t *testing.T) {
			in := newInstance(t, Options{Configuration: Configuration{EnableSessionForAPIKeys: true}}, nil)
			s := in.signInWithTestUser()
			k := expectOK(t, in.clientCreate(map[string]any{}, s.headers))
			h := http.Header{}
			h.Set("x-api-key", str(k["key"]))
			res := in.http("GET", "/get-session", nil, h)
			m := expectOK(t, res)
			eq(t, obj(m["session"])["token"], k["key"])
			eq(t, obj(m["user"])["id"], s.userID)
		})
	})

	// =========================================================================
	// DELETE API KEY
	// =========================================================================

	t.Run("should fail to delete an API key by ID without headers", func(t *testing.T) {
		_, e := inst.call("deleteApiKey", map[string]any{"keyId": firstAPIKey["id"]}, nil)
		expectAPIError(t, e, "UNAUTHORIZED", betterauth.ErrorCode{})
	})

	t.Run("should delete an API key by ID with headers", func(t *testing.T) {
		r := inst.mustCall("deleteApiKey", map[string]any{"keyId": firstAPIKey["id"]}, headers)
		eq(t, r["success"], true)
	})

	t.Run("should delete an API key by ID with headers using auth-client", func(t *testing.T) {
		k := expectOK(t, inst.clientCreate(map[string]any{}, headers))
		r := expectOK(t, inst.clientDelete(map[string]any{"keyId": k["id"]}, headers))
		eq(t, r["success"], true)
	})

	t.Run("should fail to delete an API key by ID that doesn't exist", func(t *testing.T) {
		_, e := inst.call("deleteApiKey", map[string]any{"keyId": "invalid"}, headers)
		expectAPIError(t, e, "NOT_FOUND", ErrKeyNotFound)
	})

	perms := map[string]any{"files": []any{"read", "write"}, "users": []any{"read"}}
	samePerms := func(t *testing.T, got any, want map[string]any) {
		t.Helper()
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("permissions: got %v, want %v", got, want)
		}
	}

	t.Run("should create an API key with permissions", func(t *testing.T) {
		k := inst.createKey(map[string]any{"permissions": perms, "userId": userID}, nil)
		samePerms(t, k["permissions"], perms)
	})

	t.Run("should have permissions as an object from getApiKey", func(t *testing.T) {
		k := inst.createKey(map[string]any{"permissions": perms, "userId": userID}, nil)
		r, e := inst.getKey(str(k["id"]), "", headers)
		if e != nil {
			t.Fatal(e)
		}
		samePerms(t, r["permissions"], perms)
	})

	t.Run("should have permissions as an object from verifyApiKey", func(t *testing.T) {
		k := inst.createKey(map[string]any{"permissions": perms, "userId": userID}, nil)
		r := inst.mustCall("verifyApiKey", map[string]any{"key": k["key"], "permissions": map[string]any{"files": []any{"read"}}}, headers)
		samePerms(t, obj(r["key"])["permissions"], perms)
	})

	t.Run("should create an API key with default permissions", func(t *testing.T) {
		k := inst.createKey(map[string]any{"userId": userID}, nil)
		samePerms(t, k["permissions"], map[string]any{"files": []any{"read"}})
	})

	t.Run("should have valid metadata from key verification results", func(t *testing.T) {
		k := inst.createKey(map[string]any{"userId": userID, "metadata": map[string]any{"test": "hello-world-123"}}, headers)
		r := inst.mustCall("verifyApiKey", map[string]any{"key": k["key"]}, headers)
		eq(t, r["valid"], true)
		isNil(t, r["error"])
		eq(t, obj(obj(r["key"])["metadata"])["test"], "hello-world-123")
	})

	t.Run("should verify an API key with matching permissions", func(t *testing.T) {
		k := inst.createKey(map[string]any{"permissions": perms, "userId": userID}, nil)
		r := inst.verify(map[string]any{"key": k["key"], "permissions": map[string]any{"files": []any{"read"}}})
		eq(t, r["valid"], true)
		isNil(t, r["error"])
		samePerms(t, obj(r["key"])["permissions"], perms)
	})

	t.Run("should fail to verify an API key with non-matching permissions", func(t *testing.T) {
		k := inst.createKey(map[string]any{"permissions": map[string]any{"files": []any{"read"}, "users": []any{"read"}}, "userId": userID}, nil)
		r := inst.verify(map[string]any{"key": k["key"], "permissions": map[string]any{"files": []any{"write"}}})
		eq(t, r["valid"], false)
		eq(t, errCode(r), "KEY_NOT_FOUND")
	})

	t.Run("should fail to verify when required permissions are specified but API key has no permissions", func(t *testing.T) {
		k := inst.createKey(map[string]any{"userId": userID}, nil)
		r := inst.verify(map[string]any{"key": k["key"], "permissions": map[string]any{"files": []any{"write"}}})
		eq(t, r["valid"], false)
		eq(t, errCode(r), "KEY_NOT_FOUND")
	})

	t.Run("should update an API key with permissions", func(t *testing.T) {
		created := inst.createKey(map[string]any{"userId": userID}, nil)
		if fmt.Sprint(created["permissions"]) == fmt.Sprint(perms) {
			t.Fatal("unexpected permissions")
		}
		k := inst.mustCall("updateApiKey", map[string]any{"keyId": created["id"], "permissions": perms, "userId": userID}, nil)
		samePerms(t, k["permissions"], perms)
	})

	t.Run("should refill API key credits after refill interval (milliseconds)", func(t *testing.T) {
		inst.useRealTimers()
		defer inst.useRealTimers()
		refillInterval, refillAmount := 3600000, 5
		k := inst.createKey(map[string]any{"userId": userID, "remaining": 2, "refillInterval": refillInterval, "refillAmount": refillAmount}, nil)
		r := inst.verify(map[string]any{"key": k["key"]})
		eq(t, r["valid"], true)
		eq(t, obj(r["key"])["remaining"], float64(1))
		r = inst.verify(map[string]any{"key": k["key"]})
		eq(t, r["valid"], true)
		eq(t, obj(r["key"])["remaining"], float64(0))
		r = inst.verify(map[string]any{"key": k["key"]})
		eq(t, r["valid"], false)
		eq(t, errCode(r), "USAGE_EXCEEDED")
		inst.advance(time.Duration(refillInterval+1000) * time.Millisecond)
		r = inst.verify(map[string]any{"key": k["key"]})
		eq(t, r["valid"], true)
		eq(t, obj(r["key"])["remaining"], float64(refillAmount-1))
	})

	t.Run("should not refill API key credits before refill interval expires", func(t *testing.T) {
		inst.useRealTimers()
		defer inst.useRealTimers()
		refillInterval, refillAmount := 86400000, 10
		k := inst.createKey(map[string]any{"userId": userID, "remaining": 1, "refillInterval": refillInterval, "refillAmount": refillAmount}, nil)
		r := inst.verify(map[string]any{"key": k["key"]})
		eq(t, r["valid"], true)
		eq(t, obj(r["key"])["remaining"], float64(0))
		inst.advance(time.Duration(refillInterval/2) * time.Millisecond)
		r = inst.verify(map[string]any{"key": k["key"]})
		eq(t, r["valid"], false)
		eq(t, errCode(r), "USAGE_EXCEEDED")
		inst.advance(time.Duration(refillInterval/2+1000) * time.Millisecond)
		r = inst.verify(map[string]any{"key": k["key"]})
		eq(t, r["valid"], true)
		eq(t, obj(r["key"])["remaining"], float64(refillAmount-1))
	})

	t.Run("should handle multiple refill cycles correctly", func(t *testing.T) {
		inst.useRealTimers()
		defer inst.useRealTimers()
		refillInterval, refillAmount := 3600000, 3
		k := inst.createKey(map[string]any{"userId": userID, "remaining": 1, "refillInterval": refillInterval, "refillAmount": refillAmount}, nil)
		r := inst.verify(map[string]any{"key": k["key"]})
		eq(t, r["valid"], true)
		eq(t, obj(r["key"])["remaining"], float64(0))
		inst.advance(time.Duration(refillInterval+1000) * time.Millisecond)
		r = inst.verify(map[string]any{"key": k["key"]})
		eq(t, r["valid"], true)
		eq(t, obj(r["key"])["remaining"], float64(refillAmount-1))
		for i := 0; i < refillAmount-1; i++ {
			r = inst.verify(map[string]any{"key": k["key"]})
			eq(t, r["valid"], true)
		}
		r = inst.verify(map[string]any{"key": k["key"]})
		eq(t, r["valid"], false)
		eq(t, errCode(r), "USAGE_EXCEEDED")
		inst.advance(time.Duration(refillInterval+1000) * time.Millisecond)
		r = inst.verify(map[string]any{"key": k["key"]})
		eq(t, r["valid"], true)
		eq(t, obj(r["key"])["remaining"], float64(refillAmount-1))
	})
}

// ctx returns an endpoint context for direct adapter access in tests.
func (i *instance) ctx() *betterauth.EndpointContext {
	return &betterauth.EndpointContext{Auth: i.auth.Context()}
}

func q(kv ...string) string {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v.Encode()
}
