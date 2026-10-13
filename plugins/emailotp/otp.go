package emailotp

import (
	"strconv"
	"strings"
	"time"

	"github.com/nimi-io/better-auth-go/adapter"
	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
)

// ToOTPIdentifier is the verification identifier for an OTP (toOTPIdentifier).
func ToOTPIdentifier(typ, email string) string { return typ + "-otp-" + email }

// DefaultKeyHasher hashes an OTP with SHA-256 and encodes it as unpadded base64url
// (defaultKeyHasher).
func DefaultKeyHasher(otp string) string {
	return bacrypto.Base64URLNoPad(bacrypto.SHA256([]byte(otp)))
}

// SplitAtLastColon splits "value:attempts" (splitAtLastColon).
func SplitAtLastColon(input string) (string, string) {
	i := strings.LastIndex(input, ":")
	if i == -1 {
		return input, ""
	}
	return input[:i], input[i+1:]
}

// jsParseInt mirrors parseInt(s, 10): leading whitespace, optional sign, leading digits.
func jsParseInt(s string) (int, bool) {
	s = strings.TrimLeft(s, " \t\n\r\v\f")
	end := 0
	if end < len(s) && (s[end] == '+' || s[end] == '-') {
		end++
	}
	start := end
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == start {
		return 0, false
	}
	n, err := strconv.Atoi(s[:end])
	if err != nil {
		return 0, false
	}
	return n, true
}

func defaultOTP(o *Options) string {
	return bacrypto.RandomStringFrom(o.otpLength(), bacrypto.Digits)
}

func generateOTP(ctx *betterauth.EndpointContext, o *Options, email, typ string) string {
	if o.GenerateOTP != nil {
		if otp := o.GenerateOTP(GenerateOTPData{Email: email, Type: typ}, ctx); otp != "" {
			return otp
		}
	}
	return defaultOTP(o)
}

func (s StoreOTP) isHashed() bool { return s.Hash == nil && s.Encrypt == nil && s.Mode == "hashed" }
func (s StoreOTP) isEncrypted() bool {
	return s.Hash == nil && s.Encrypt == nil && s.Mode == "encrypted"
}

// storeOTP transforms an OTP for storage.
func storeOTP(ctx *betterauth.EndpointContext, o *Options, otp string) (string, error) {
	s := o.StoreOTP
	switch {
	case s.isEncrypted():
		return bacrypto.SymmetricEncrypt(ctx.Auth.SecretConfig, otp)
	case s.isHashed():
		return DefaultKeyHasher(otp), nil
	case s.Hash != nil:
		return s.Hash(otp)
	case s.Encrypt != nil:
		return s.Encrypt(otp)
	}
	return otp, nil
}

func constantTimeEqual(a, b string) bool { return bacrypto.ConstantTimeEqual([]byte(a), []byte(b)) }

// verifyStoredOTP compares a provided OTP with the stored value.
func verifyStoredOTP(ctx *betterauth.EndpointContext, o *Options, stored, otp string) (bool, error) {
	s := o.StoreOTP
	switch {
	case s.isEncrypted():
		dec, err := bacrypto.SymmetricDecrypt(ctx.Auth.SecretConfig, stored)
		if err != nil {
			return false, err
		}
		return constantTimeEqual(dec, otp), nil
	case s.isHashed():
		return constantTimeEqual(DefaultKeyHasher(otp), stored), nil
	case s.Hash != nil:
		h, err := s.Hash(otp)
		if err != nil {
			return false, err
		}
		return constantTimeEqual(h, stored), nil
	case s.Decrypt != nil:
		dec, err := s.Decrypt(stored)
		if err != nil {
			return false, err
		}
		return constantTimeEqual(dec, otp), nil
	}
	return constantTimeEqual(otp, stored), nil
}

// retrieveOTP returns the plain OTP for reversible storage modes ("" when hashed).
func retrieveOTP(ctx *betterauth.EndpointContext, o *Options, stored string) (string, error) {
	s := o.StoreOTP
	switch {
	case s.Hash == nil && s.Encrypt == nil && (s.Mode == "" || s.Mode == "plain"):
		return stored, nil
	case s.isEncrypted():
		return bacrypto.SymmetricDecrypt(ctx.Auth.SecretConfig, stored)
	case s.Hash == nil && s.Decrypt != nil:
		return s.Decrypt(stored)
	}
	return "", nil
}

// tryReuseOTP returns the still-valid OTP for identifier, extending its expiry.
func tryReuseOTP(ctx *betterauth.EndpointContext, o *Options, identifier string) (string, error) {
	ia := ctx.Auth.InternalAdapter
	existing, err := ia.FindVerificationValue(ctx.Context(), identifier)
	if err != nil {
		return "", err
	}
	if existing == nil || existing.ExpiresAt.Before(time.Now()) {
		return "", nil
	}
	stored, attempts := SplitAtLastColon(existing.Value)
	if attempts != "" {
		if n, ok := jsParseInt(attempts); ok && n >= o.allowedAttempts() {
			return "", nil
		}
	}
	plain, err := retrieveOTP(ctx, o, stored)
	if err != nil || plain == "" {
		return "", err
	}
	if _, err := ia.UpdateVerificationByIdentifier(ctx.Context(), identifier, adapter.Record{"expiresAt": time.Now().Add(o.expiresIn())}); err != nil {
		return "", err
	}
	return plain, nil
}

// createOTPValue generates, stores and returns a new OTP for identifier (no fallback on
// create failure).
func createOTPValue(ctx *betterauth.EndpointContext, o *Options, email, typ, identifier string) (string, error) {
	otp := generateOTP(ctx, o, email, typ)
	stored, err := storeOTP(ctx, o, otp)
	if err != nil {
		return "", err
	}
	if _, err := ctx.Auth.InternalAdapter.CreateVerificationValue(ctx.Context(), identifier, stored+":0", time.Now().Add(o.expiresIn()), nil); err != nil {
		return "", err
	}
	return otp, nil
}

// resolveOTP returns the OTP to send: the reused one (resendStrategy "reuse") or a new one.
func resolveOTP(ctx *betterauth.EndpointContext, o *Options, email, typ string) (string, error) {
	identifier := ToOTPIdentifier(typ, email)
	if o.ResendStrategy == "reuse" {
		reused, err := tryReuseOTP(ctx, o, identifier)
		if err != nil {
			return "", err
		}
		if reused != "" {
			return reused, nil
		}
	}
	otp := generateOTP(ctx, o, email, typ)
	stored, err := storeOTP(ctx, o, otp)
	if err != nil {
		return "", err
	}
	ia := ctx.Auth.InternalAdapter
	if _, err := ia.CreateVerificationValue(ctx.Context(), identifier, stored+":0", time.Now().Add(o.expiresIn()), nil); err != nil {
		if err := ia.DeleteVerificationByIdentifier(ctx.Context(), identifier); err != nil {
			return "", err
		}
		if _, err := ia.CreateVerificationValue(ctx.Context(), identifier, stored+":0", time.Now().Add(o.expiresIn()), nil); err != nil {
			return "", err
		}
	}
	return otp, nil
}

// atomicVerifyOTP consumes the OTP for identifier; a wrong code re-creates it with the
// attempt counter incremented (atomicVerifyOTP).
func atomicVerifyOTP(ctx *betterauth.EndpointContext, o *Options, identifier, provided string) error {
	ia := ctx.Auth.InternalAdapter
	c := ctx.Context()
	existing, err := ia.FindVerificationValue(c, identifier)
	if err != nil {
		return err
	}
	if existing != nil && existing.ExpiresAt.Before(time.Now()) {
		if err := ia.DeleteVerificationByIdentifier(c, identifier); err != nil {
			return err
		}
		return betterauth.ErrFrom("BAD_REQUEST", ErrOTPExpired)
	}
	consumed, err := ia.ConsumeVerificationValue(c, identifier)
	if err != nil {
		return err
	}
	if consumed == nil {
		return betterauth.ErrFrom("BAD_REQUEST", ErrInvalidOTP)
	}
	value, attempts := SplitAtLastColon(consumed.Value)
	used := 0
	usedNaN := false
	if attempts == "" {
		used = 0
	} else if n, ok := jsParseInt(attempts); ok {
		used = n
	} else {
		usedNaN = true
	}
	if !usedNaN && used >= o.allowedAttempts() {
		return betterauth.ErrFrom("FORBIDDEN", ErrTooManyAttempts)
	}
	ok, err := verifyStoredOTP(ctx, o, value, provided)
	if err != nil {
		return err
	}
	if !ok {
		next := "NaN"
		if !usedNaN {
			next = strconv.Itoa(used + 1)
		}
		if _, err := ia.CreateVerificationValue(c, identifier, value+":"+next, consumed.ExpiresAt, nil); err != nil {
			return err
		}
		return betterauth.ErrFrom("BAD_REQUEST", ErrInvalidOTP)
	}
	return nil
}
