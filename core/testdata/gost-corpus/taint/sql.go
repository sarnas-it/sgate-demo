package taint

import (
	"database/sql"
	"net/http"
)

// Lookup ищет пользователя по имени из запроса.
func Lookup(db *sql.DB, r *http.Request) (*sql.Rows, error) {
	name := r.URL.Query().Get("name")
	return db.Query("SELECT id FROM users WHERE name = '" + name + "'") // GOST:6.3а CWE-89
}
