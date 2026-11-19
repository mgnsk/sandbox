package main

import (
	"context"
	"testing"
)

// What the launcher and init run, and what nothing runs: exit statuses
// before any of it starts.
func TestUsage(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want int
	}{
		{[]string{"--help"}, 0},
		{[]string{"launch", "--help"}, 0},
		{[]string{"nope"}, 2},
		{[]string{"launch"}, 1},
		{[]string{"init", "a", "b"}, 2},
		{[]string{"xdg-open"}, 1},
		{[]string{"xdg-open", "a", "b"}, 1},
		{[]string{"ssh-agent-guard"}, 2},
		{[]string{"open-url-guard", "extra"}, 2},
		{[]string{"secret-service-guard", "bus"}, 2},
	} {
		if got := run(context.Background(), append([]string{"sandbox-bin"}, tc.args...)); got != tc.want {
			t.Errorf("%q: exit %d, want %d", tc.args, got, tc.want)
		}
	}
}
