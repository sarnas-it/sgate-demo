package dast

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPassiveScan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env":
			w.WriteHeader(200)
			w.Write([]byte("APP_ENV=prod\nDB_PASSWORD=secret\n"))
		case "/.git/HEAD":
			w.WriteHeader(200)
			w.Write([]byte("ref: refs/heads/main\n"))
		default:
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "1"})
			w.WriteHeader(200)
			w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()

	s := &Scope{Target: srv.URL, AllowedHosts: []string{"127.0.0.1"}, MaxRPS: 5}
	got, err := PassiveScan(context.Background(), srv.Client(), s)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"passive-csp": false, "passive-env": false, "passive-git": false, "passive-cookie-secure": false}
	for _, f := range got {
		if _, ok := want[f.RuleID]; ok {
			want[f.RuleID] = true
		}
	}
	for rule, seen := range want {
		if !seen {
			t.Errorf("missing %s in %+v", rule, got)
		}
	}
}
