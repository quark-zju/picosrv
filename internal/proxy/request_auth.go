package proxy

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
)

type requestAuth struct {
	request    *http.Request
	cookieAuth *cookieSigner
	host       string

	cookieChecked bool
	cookieValid   bool
}

// password provides the SHA-256 encoded representation used for comparison.
// Plain strings are treated as passwords; Sha256Encoded values are already
// encoded and are returned without hashing.
type password interface {
	sha256Encoded() string
}

type plainPassword string

func (p plainPassword) sha256Encoded() string {
	hash := sha256.Sum256([]byte(p))
	return hex.EncodeToString(hash[:])
}

// Sha256Encoded identifies a password that is already encoded as a SHA-256
// hexadecimal digest.
type Sha256Encoded string

func (p Sha256Encoded) sha256Encoded() string { return string(p) }

func (a *requestAuth) HasValidCookie() bool {
	if a.cookieChecked {
		return a.cookieValid
	}
	a.cookieChecked = true
	cookie, err := a.request.Cookie(cookieName)
	a.cookieValid = a.cookieAuth.Validate(cookie, err, a.host)
	return a.cookieValid
}

func (a *requestAuth) ConsumeBasicAuth(expectedUser string, expectedPassword any) bool {
	user, credentialPassword, ok := a.request.BasicAuth()
	if !ok {
		return false
	}

	userHash := sha256.Sum256([]byte(user))
	expectedUserHash := sha256.Sum256([]byte(expectedUser))
	passwordHash := sha256.Sum256([]byte(credentialPassword))
	expectedPasswordValue, ok := expectedPassword.(password)
	if !ok {
		plain, ok := expectedPassword.(string)
		if !ok {
			return false
		}
		expectedPasswordValue = plainPassword(plain)
	}
	expectedPasswordHash := expectedPasswordValue.sha256Encoded()
	valid := subtle.ConstantTimeCompare(userHash[:], expectedUserHash[:]) &
		subtle.ConstantTimeCompare([]byte(hex.EncodeToString(passwordHash[:])), []byte(expectedPasswordHash))
	if valid != 1 {
		return false
	}

	a.request.Header.Del("Authorization")
	return true
}
