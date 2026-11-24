package dast

import (
	"fmt"
	"regexp"
	"strings"
)

var cweDigits = regexp.MustCompile(`\d+`)

// normalizeCWE приводит "79", "CWE-79" и ["79"] к "CWE-79".
func normalizeCWE(v any) string {
	if v == nil {
		return ""
	}
	var s string
	switch x := v.(type) {
	case string:
		s = x
	case []any:
		if len(x) > 0 {
			s = fmt.Sprint(x[0])
		}
	case []string:
		if len(x) > 0 {
			s = x[0]
		}
	default:
		s = fmt.Sprint(x)
	}
	d := cweDigits.FindString(s)
	if d == "" || d == "0" {
		return ""
	}
	return "CWE-" + strings.TrimLeft(d, "0")
}
