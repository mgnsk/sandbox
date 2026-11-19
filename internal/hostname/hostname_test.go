package hostname

import "testing"

func TestValidPort(t *testing.T) {
	for hostport, want := range map[string]bool{
		"api.github.com":      true,
		"api.github.com:8443": true,
		"127.0.0.1:22":        true,
		"localhost":           true,
		"a-b.example":         true,
		"API.github.com":      false, // Not lowercase.
		"api.github.com.":     false,
		"api.github.com.:443": false,
		"a b:443":             false,
		"x:0":                 false,
		"x:70000":             false,
		"[::1]:443":           false,
		"exаmple.com":         false, // Cyrillic а.
		"":                    false,
		":443":                false,
	} {
		if got := ValidPort(hostport); got != want {
			t.Errorf("ValidPort(%q) = %v, want %v", hostport, got, want)
		}
	}
}

func TestNormalize(t *testing.T) {
	for value, want := range map[string]string{
		"codeberg.org":            "codeberg.org",
		"https://A.example/x/":    "a.example",
		"a.example:443":           "a.example",
		"http://b.example:3000/f": "b.example:3000",
		" c.example ":             "c.example",
	} {
		if got, ok := Normalize(value); !ok || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", value, got, ok, want)
		}
	}
	for _, bad := range []string{"a b", "", "https://", "x:0"} {
		if got, ok := Normalize(bad); ok {
			t.Errorf("Normalize(%q) = %q, want refused", bad, got)
		}
	}
}
