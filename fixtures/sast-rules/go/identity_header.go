package fixtures

import (
	"net/http"

	hmacauth "github.com/X-didgital/go-hmac-auth"
)

func identityFromHeader(r *http.Request) string {
	return r.Header.Get("X-User-ID") // ruleid: sgate-go-trusted-identity-header
}

func identityFromHeaderActor(r *http.Request) string {
	return r.Header.Get("X-Actor") // ok: sgate-go-trusted-identity-header
}

func identityAfterSignature(r *http.Request) string {
	hmacauth.Verify(r)
	return r.Header.Get("X-User-ID") // ok: sgate-go-trusted-identity-header
}

func notIdentity(r *http.Request) string {
	return r.Header.Get("X-Request-ID") // ok: sgate-go-trusted-identity-header
}
