package taint

import (
	"net/http"
	"os"
)

// Read читает файл, имя которого пришло в запросе.
func Read(r *http.Request) ([]byte, error) {
	name := r.URL.Query().Get("file")
	return os.ReadFile(name) // GOST:6.3а CWE-22
}
