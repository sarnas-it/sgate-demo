package crypto

import (
	"crypto/tls"
)

// Client отключает проверку сертификата сервера.
func Client() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} // GOST:6.3г CWE-295
}
