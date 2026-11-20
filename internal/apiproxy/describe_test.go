package apiproxy

import (
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

// A write's body is shown when it's JSON of a moderate size; any other is
// said to be there.
func TestDescribeWrite(t *testing.T) {
	describe := func(body io.Reader, kind string) string {
		t.Helper()
		r := httptest.NewRequest("PATCH", "https://api.example/repos/o/r", body)
		if kind != "" {
			r.Header.Set("Content-Type", kind)
		}
		d, err := DescribeWrite(r, "api.example")
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimPrefix(d, "PATCH api.example/repos/o/r")
	}
	big := strings.Repeat("x", maxShown+10)
	for name, c := range map[string]struct {
		body io.Reader
		kind string
		want string
	}{
		"none":         {nil, "", ""},
		"json":         {strings.NewReader(`{"private":false}`), "application/json; charset=utf-8", "\n\n{\n  \"private\": false\n}"},
		"vendor json":  {strings.NewReader(`[1]`), "application/vnd.github+json", "\n\n[\n  1\n]"},
		"untyped json": {strings.NewReader(`{}`), "", "\n\n{}"},
		"untyped":      {strings.NewReader("\x00\x01"), "", "\n\n(a body of 2 bytes, of unknown type, not shown)"},
		"not json":     {strings.NewReader("{"), "application/json", "\n\n{"},
		"binary":       {strings.NewReader("zip"), "application/zip", "\n\n(a body of 3 bytes, application/zip, not shown)"},
		"large":        {strings.NewReader(strings.Repeat("x", maxShownBody+1)), "application/json", fmt.Sprintf("\n\n(a body of %d bytes, application/json, not shown)", maxShownBody+1)},
		"chunked":      {io.MultiReader(strings.NewReader("{}")), "application/json", "\n\n(a body of unknown size, not shown)"},
		"cut":          {strings.NewReader(big), "application/json", "\n\n" + big[:maxShown] + "\n... (10 more bytes, not shown)"},
	} {
		if got := describe(c.body, c.kind); got != c.want {
			t.Errorf("%s: %.200q", name, got)
		}
	}
}
