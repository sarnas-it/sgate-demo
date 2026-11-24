package dast

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// ParseSitemap читает <loc> из sitemap.xml.
func ParseSitemap(r io.Reader, base *url.URL) ([]string, error) {
	var doc struct {
		URLs []struct {
			Loc string `xml:"loc"`
		} `xml:"url"`
	}
	if err := xml.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse sitemap: %w", err)
	}
	out := make([]string, 0, len(doc.URLs))
	for _, u := range doc.URLs {
		if abs, ok := resolve(base, u.Loc); ok {
			out = append(out, abs)
		}
	}
	return out, nil
}

// ParseHTML собирает href/src/action из HTML.
func ParseHTML(r io.Reader, base *url.URL) ([]string, error) {
	z := html.NewTokenizer(r)
	var out []string
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if z.Err() == io.EOF {
				break
			}
			return out, z.Err()
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		name, hasAttr := z.TagName()
		if !hasAttr {
			continue
		}
		tag := string(name)
		for {
			key, val, more := z.TagAttr()
			attr := string(key)
			if (tag == "a" && attr == "href") || (tag == "form" && attr == "action") || (attr == "src" && (tag == "script" || tag == "img" || tag == "iframe")) {
				if abs, ok := resolve(base, string(val)); ok {
					out = append(out, abs)
				}
			}
			if !more {
				break
			}
		}
	}
	return out, nil
}

// ParseOpenAPI читает paths из JSON OpenAPI/Swagger.
func ParseOpenAPI(r io.Reader, base *url.URL) ([]string, error) {
	var doc struct {
		Paths map[string]any `json:"paths"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse openapi: %w", err)
	}
	out := make([]string, 0, len(doc.Paths))
	for p := range doc.Paths {
		if abs, ok := resolve(base, p); ok {
			out = append(out, abs)
		}
	}
	return out, nil
}

// Discover собирает цели с главной, sitemap.xml, openapi.json и swagger.json.
// Ошибки отдельных источников не фатальны: discovery не должен падать из-за
// отсутствующего sitemap.
func Discover(ctx context.Context, client *http.Client, scope *Scope) ([]string, error) {
	base, err := url.Parse(scope.Target)
	if err != nil {
		return nil, err
	}
	var all []string
	add := func(list []string, err error) {
		if err == nil {
			all = append(all, list...)
		}
	}

	if body, err := get(ctx, client, scope.Target); err == nil {
		add(ParseHTML(strings.NewReader(body), base))
	}
	for _, p := range []string{"/sitemap.xml", "/openapi.json", "/swagger.json"} {
		u := strings.TrimRight(scope.Target, "/") + p
		if !scope.Allowed(u) {
			continue
		}
		body, err := get(ctx, client, u)
		if err != nil {
			continue
		}
		switch p {
		case "/sitemap.xml":
			add(ParseSitemap(strings.NewReader(body), base))
		default:
			add(ParseOpenAPI(strings.NewReader(body), base))
		}
	}
	return Filter(all, scope), nil
}

// Filter убирает дубли, фрагменты и всё, что вне scope.
func Filter(urls []string, scope *Scope) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(urls))
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		u.Fragment = ""
		clean := u.String()
		if seen[clean] || !scope.Allowed(clean) {
			continue
		}
		seen[clean] = true
		out = append(out, clean)
	}
	return out
}

func resolve(base *url.URL, raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "javascript:") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	abs := base.ResolveReference(u)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return "", false
	}
	abs.Fragment = ""
	return abs.String(), true
}

func get(ctx context.Context, client *http.Client, raw string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", raw, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	return string(b), nil
}
