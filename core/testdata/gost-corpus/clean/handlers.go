package clean

import (
	"crypto/sha256"
	"database/sql"
	"net/http"
	"os"
)

// Lookup использует параметризованный запрос.
func Lookup(db *sql.DB, r *http.Request) (*sql.Row, error) {
	row := db.QueryRow("SELECT id FROM users WHERE name = $1", r.URL.Query().Get("name"))
	return row, nil
}

// Hash считает SHA-256.
func Hash(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// Save пишет файл с правами 0600.
func Save(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
