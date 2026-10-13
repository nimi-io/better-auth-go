package twofactor

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // HOTP (RFC 4226) is defined over HMAC-SHA-1
	"encoding/base32"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/nimi-io/better-auth-go/betterauth"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
)

// Defaults of createOTP in @better-auth/utils/otp.
const (
	DefaultTOTPPeriod = 30
	DefaultOTPDigits  = 6
)

// OTP is a port of createOTP from @better-auth/utils/otp (v0.4.2). The secret is used
// verbatim (its UTF-8 bytes) as the HMAC-SHA-1 key; the otpauth URI carries the base32
// encoding of those bytes, so authenticator apps derive the same key.
type OTP struct {
	Secret string
	Digits int
	Period int
	// now overrides the clock (tests).
	now func() time.Time
}

// CreateOTP mirrors createOTP(secret, { digits, period }); zero values use the defaults
// (digits 6, period 30 seconds).
func CreateOTP(secret string, digits, period int) *OTP {
	if digits == 0 {
		digits = DefaultOTPDigits
	}
	if period == 0 {
		period = DefaultTOTPPeriod
	}
	return &OTP{Secret: secret, Digits: digits, Period: period}
}

func (o *OTP) clock() time.Time {
	if o.now != nil {
		return o.now()
	}
	return time.Now()
}

// GenerateHOTP is generateHOTP (SHA-1, dynamic truncation, zero padded).
func GenerateHOTP(secret string, counter uint64, digits int) (string, error) {
	if digits < 1 || digits > 8 {
		return "", errors.New("Digits must be between 1 and 8")
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	truncated := uint32(sum[offset]&127)<<24 | uint32(sum[offset+1])<<16 | uint32(sum[offset+2])<<8 | uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	s := strconv.FormatUint(uint64(truncated%mod), 10)
	if len(s) < digits {
		s = strings.Repeat("0", digits-len(s)) + s
	}
	return s, nil
}

func (o *OTP) counterAt(t time.Time) int64 {
	ms := int64(o.Period) * 1000
	now := t.UnixMilli()
	c := now / ms
	if now%ms != 0 && now < 0 {
		c--
	}
	return c
}

// HOTP generates the code for counter.
func (o *OTP) HOTP(counter uint64) (string, error) { return GenerateHOTP(o.Secret, counter, o.Digits) }

// TOTP generates the code for the current time step.
func (o *OTP) TOTP() (string, error) {
	return GenerateHOTP(o.Secret, uint64(o.counterAt(o.clock())), o.Digits) //nolint:gosec // time steps are positive
}

// Verify checks otp against the current time step and window steps either side
// (verifyTOTP; window defaults to 1). All candidates are always computed.
func (o *OTP) Verify(otp string, window ...int) (bool, error) {
	w := 1
	if len(window) > 0 {
		w = window[0]
	}
	counter := o.counterAt(o.clock())
	matched := false
	for i := -w; i <= w; i++ {
		c := counter + int64(i)
		gen, err := GenerateHOTP(o.Secret, uint64(c), o.Digits) //nolint:gosec // matches BigInt(counter) for positive steps
		if err != nil {
			return false, err
		}
		matched = constantTimeEqualOTP(otp, gen) || matched
	}
	return matched, nil
}

// constantTimeEqualOTP compares UTF-16 code units like the TypeScript implementation.
func constantTimeEqualOTP(input, expected string) bool {
	in := utf16.Encode([]rune(input))
	diff := len(in) ^ len(expected)
	for i := 0; i < len(expected); i++ {
		var c uint16
		if i < len(in) {
			c = in[i]
		}
		diff |= int(c) ^ int(expected[i])
	}
	return diff == 0
}

// URL builds the otpauth:// URI (generateQRCode).
func (o *OTP) URL(issuer, account string) string {
	var b strings.Builder
	b.WriteString("otpauth://totp/")
	b.WriteString(betterauth.EncodeURIComponent(issuer))
	b.WriteString(":")
	b.WriteString(betterauth.EncodeURIComponent(account))
	b.WriteString("?secret=")
	b.WriteString(formEncode(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(o.Secret))))
	b.WriteString("&issuer=")
	b.WriteString(formEncode(issuer))
	b.WriteString("&digits=")
	b.WriteString(strconv.Itoa(o.Digits))
	b.WriteString("&period=")
	b.WriteString(strconv.Itoa(o.Period))
	return b.String()
}

// formEncode is the application/x-www-form-urlencoded byte serializer used by
// URLSearchParams.toString().
func formEncode(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ':
			b.WriteByte('+')
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '*', c == '-', c == '.', c == '_':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&15])
		}
	}
	return b.String()
}

// RandomTOTPSecret generates a TOTP secret like /two-factor/enable (32 characters of
// a-z, 0-9, A-Z, "-" and "_").
func RandomTOTPSecret() string { return bacrypto.RandomString(32) }
