package scim

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"time"

	bacrypto "github.com/nimi-io/better-auth-go/crypto"
)

// createScopedKey is base64url(sha256(JSON.stringify(parts))) without padding.
func createScopedKey(parts ...string) string {
	arr := make([]any, len(parts))
	for i, p := range parts {
		arr[i] = p
	}
	sum := sha256.Sum256([]byte(mustStringify(arr)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// CreateScopedKey is exported for tests and applications (createScopedKey).
func CreateScopedKey(parts ...string) string { return createScopedKey(parts...) }

// CreateUserExternalIDKey is createSCIMUserExternalIdKey.
func CreateUserExternalIDKey(connectionID, externalID string) string {
	return createScopedKey("scim-user-external-id", connectionID, externalID)
}

// CreateConnectionKey is createSCIMConnectionKey.
func CreateConnectionKey(connectionID string) string {
	return createScopedKey("scim-connection", connectionID)
}

// createOrderKey is createSCIMOrderKey: a zero-padded millisecond timestamp plus a random id.
func createOrderKey(createdAt time.Time) string {
	return fmt.Sprintf("%015d:%s", createdAt.UnixMilli(), bacrypto.GenerateID(16))
}

func createUserNameKey(connectionID, userName string) string {
	return createScopedKey("scim-user-name", connectionID, userName)
}

func createExternalIDKey(connectionID, externalID string) *string {
	if externalID == "" {
		return nil
	}
	k := CreateUserExternalIDKey(connectionID, externalID)
	return &k
}

func createConnectionUserKey(connectionID, userID string) string {
	return createScopedKey("scim-user", connectionID, userID)
}

func createGroupExternalIDKey(connectionID, externalID string) *string {
	if externalID == "" {
		return nil
	}
	k := createScopedKey("scim-group-external-id", connectionID, externalID)
	return &k
}

func createGroupDisplayNameKey(connectionID, displayName string) string {
	return createScopedKey("scim-group-display-name", connectionID, jsLower(displayName))
}

func createGroupMembershipKey(connectionID, groupID, scimUserID string) string {
	return createScopedKey("scim-group-member", connectionID, groupID, scimUserID)
}

// createEmailValueToken is createSCIMEmailValueToken.
func createEmailValueToken(email string) string {
	return createScopedKey("scim-email-value", jsLower(jsTrim(email)))
}

// createEmailValueIndex is createSCIMEmailValueIndex.
func createEmailValueIndex(emails []canonicalEmail, typ *string) string {
	var normalizedType *string
	if typ != nil {
		t := jsLower(jsTrim(*typ))
		normalizedType = &t
	}
	seen := map[string]bool{}
	var tokens []string
	for _, e := range emails {
		if normalizedType != nil && (e.Type == nil || *e.Type != *normalizedType) {
			continue
		}
		tok := createEmailValueToken(e.Value)
		if !seen[tok] {
			seen[tok] = true
			tokens = append(tokens, tok)
		}
	}
	sort.Strings(tokens)
	return "|" + strings.Join(tokens, "|") + "|"
}
