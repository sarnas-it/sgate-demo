package dast

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestParseSources(t *testing.T) {
	base, _ := url.Parse("http://127.0.0.1:3000")
	sitemap, err := ParseSitemap(strings.NewReader(`<urlset><url><loc>/a</loc></url><url><loc>http://127.0.0.1:3000/b</loc></url></urlset>`), base)
	if err != nil || len(sitemap) != 2 {
		t.Fatalf("sitemap: %v %v", sitemap, err)
	}
	htmlURLs, err := ParseHTML(strings.NewReader(`<a href="/c">c</a><script src="/app.js"></script>`), base)
	if err != nil || len(htmlURLs) != 2 {
		t.Fatalf("html: %v %v", htmlURLs, err)
	}
	openapi, err := ParseOpenAPI(strings.NewReader(`{"paths":{"/api/users":{}}}`), base)
	if err != nil || len(openapi) != 1 {
		t.Fatalf("openapi: %v %v", openapi, err)
	}
}

func TestFilterScope(t *testing.T) {
	s := &Scope{Target: "http://127.0.0.1:3000", AllowedHosts: []string{"127.0.0.1"}, Exclusions: []string{"/logout"}}
	got := Filter([]string{
		"http://127.0.0.1:3000/a",
		"http://127.0.0.1:3000/a",
		"http://127.0.0.1:3000/logout",
		"http://example.com/x",
		"http://127.0.0.1:3000/a#frag",
	}, s)
	if len(got) != 1 || got[0] != "http://127.0.0.1:3000/a" {
		t.Fatalf("got %v", got)
	}
}

func TestDiscover(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<a href="/found">x</a>`))
		case "/sitemap.xml":
			w.Write([]byte(`<urlset><url><loc>/from-sitemap</loc></url></urlset>`))
		case "/openapi.json":
			w.Write([]byte(`{"paths":{"/api":{}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	s := &Scope{Target: srv.URL, AllowedHosts: []string{"127.0.0.1"}, MaxRPS: 5}
	got, err := Discover(context.Background(), srv.Client(), s)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %v", got)
	}
}
