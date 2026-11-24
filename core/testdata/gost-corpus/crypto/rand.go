package crypto

import (
	"math/rand"
)

// Token делает токен из предсказуемого генератора.
func Token(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(rand.Intn(256)) // GOST:6.3г CWE-338
	}
	return out
}
