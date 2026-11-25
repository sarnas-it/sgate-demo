package perms

import (
	"os"
)

// Save пишет файл с правами 0777.
func Save(path string, data []byte) error {
	return os.WriteFile(path, data, 0o777) // GOST:6.3г CWE-276
}
