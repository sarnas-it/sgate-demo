package fixtures

import (
	"net/http"
	"strconv"
)

func sliceIndex(r *http.Request, items []string) string {
	raw := r.URL.Query().Get("i")
	idx, _ := strconv.Atoi(raw)
	return items[idx] // ruleid: sgate-go-slice-index-from-input
}

func sliceIndexGuarded(r *http.Request, items []string) string {
	raw := r.URL.Query().Get("i")
	idx, _ := strconv.Atoi(raw)
	if idx >= 0 && idx < len(items) {
		return items[idx] // ok: sgate-go-slice-index-from-input
	}
	return ""
}

func sliceIndexFromRange(items []string) string {
	out := ""
	for i := range items {
		out = items[i] // ok: sgate-go-slice-index-from-input
	}
	return out
}
