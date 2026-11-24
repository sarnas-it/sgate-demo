package taint

import (
	"net/http"
	"os/exec"
)

// Run выполняет команду, пришедшую в параметре запроса.
func Run(r *http.Request) ([]byte, error) {
	cmd := r.URL.Query().Get("cmd")
	return exec.Command("sh", "-c", cmd).Output() // GOST:6.3а CWE-78
}
