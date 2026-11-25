package crypto

import (
	"crypto/md5"
)

// HashPassword считает MD5 от пароля.
func HashPassword(password string) []byte {
	sum := md5.Sum([]byte(password)) // GOST:6.3г CWE-327
	return sum[:]
}
