package browser

import (
	"errors"
	"strings"
	"testing"
)

func TestRepairExecuteJSCode(t *testing.T) {
	cases := []struct {
		name string
		code string
		err  error
		want string
		ok   bool
	}{
		{"bare return", "return document.title;", errors.New("SyntaxError: Unexpected token 'return'"), "() => {", true},
		{"console expression", "window.__xss", errors.New("TypeError: window.__xss.apply is not a function"), "() => (", true},
		{"iife expression", "(function(){ return document.title; })()", errors.New("TypeError: (intermediate value).apply is not a function"), "() => (", true},
		{"runtime exception", "() => missing.value", errors.New("TypeError: cannot read properties of undefined"), "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := repairExecuteJSCode(tc.code, tc.err)
			if ok != tc.ok || (tc.want != "" && !strings.HasPrefix(got, tc.want)) {
				t.Fatalf("repairExecuteJSCode() = %q, %v; want prefix %q, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}
