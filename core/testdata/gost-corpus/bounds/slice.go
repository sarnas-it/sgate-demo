package bounds

import (
	"net/http"
	"strconv"
)

// Item возвращает элемент по индексу из запроса без проверки границ.
func Item(items []string, r *http.Request) string {
	i, _ := strconv.Atoi(r.URL.Query().Get("i"))
	return items[i] // GOST:6.3в CWE-125
}
