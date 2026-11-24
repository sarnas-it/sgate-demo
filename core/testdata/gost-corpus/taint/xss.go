package taint

import (
	"fmt"
	"net/http"
)

// Render выводит имя из запроса в HTML без экранирования.
func Render(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<h1>Hello, %s</h1>", name) // GOST:6.3а CWE-79
}
