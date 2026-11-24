package taint

import (
	"net/http"
)

// Fetch запрашивает URL из параметра запроса.
func Fetch(r *http.Request) (*http.Response, error) {
	u := r.URL.Query().Get("url")
	return http.Get(u) // GOST:6.3а CWE-918
}
