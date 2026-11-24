package dast

import "testing"

func TestAuthHeader(t *testing.T) {
	t.Setenv("DAST_TOKEN", "secret")
	t.Setenv("DAST_COOKIE", "sid=1")
	cases := []struct {
		name string
		auth *Auth
		want string
	}{
		{"none", nil, ""},
		{"bearer", &Auth{Mode: "bearer", TokenEnv: "DAST_TOKEN"}, "Authorization: Bearer secret"},
		{"header", &Auth{Mode: "header", Header: "X-Token", TokenEnv: "DAST_TOKEN"}, "X-Token: secret"},
		{"cookie", &Auth{Mode: "cookie", CookieEnv: "DAST_COOKIE"}, "Cookie: sid=1"},
	}
	for _, c := range cases {
		got, err := (&Scope{Auth: c.auth}).AuthHeader()
		if err != nil || got != c.want {
			t.Errorf("%s: got %q err %v", c.name, got, err)
		}
	}
}

func TestAuthHeaderMissingEnv(t *testing.T) {
	_, err := (&Scope{Auth: &Auth{Mode: "bearer", TokenEnv: "MISSING_DAST_TOKEN"}}).AuthHeader()
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestScanArgsDropsEmptyAuth(t *testing.T) {
	got := scanArgs([]string{"-u", "{{target}}", "-H", "{{auth_header}}"}, "http://x", "")
	if len(got) != 2 || got[1] != "http://x" {
		t.Fatalf("got %v", got)
	}
	got = scanArgs([]string{"-u", "{{target}}", "-H", "{{auth_header}}"}, "http://x", "Authorization: Bearer s")
	if len(got) != 4 || got[3] != "Authorization: Bearer s" {
		t.Fatalf("got %v", got)
	}
}
