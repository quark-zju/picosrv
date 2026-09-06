package proxy

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"

	"picosrv/internal/config"
)

type requestAuth struct {
	request    *http.Request
	cookieAuth *cookieSigner
	host       string

	cookieChecked bool
	cookieValid   bool
}

func (a *requestAuth) HasValidCookie() bool {
	if a.cookieChecked {
		return a.cookieValid
	}
	a.cookieChecked = true
	cookie, err := a.request.Cookie(cookieName)
	a.cookieValid = a.cookieAuth.Validate(cookie, err, a.host)
	return a.cookieValid
}

func (a *requestAuth) ConsumeBasicAuth(expectedUser string, expectedPassword config.Password) bool {
	user, credentialPassword, ok := a.request.BasicAuth()
	if !ok {
		return false
	}

	userHash := sha256.Sum256([]byte(user))
	expectedUserHash := sha256.Sum256([]byte(expectedUser))
	passwordHash := sha256.Sum256([]byte(credentialPassword))
	expectedPasswordHash := expectedPassword.SHA256Encoded()
	valid := subtle.ConstantTimeCompare(userHash[:], expectedUserHash[:]) &
		subtle.ConstantTimeCompare([]byte(hex.EncodeToString(passwordHash[:])), []byte(expectedPasswordHash))
	if valid != 1 {
		return false
	}

	a.request.Header.Del("Authorization")
	return true
}
