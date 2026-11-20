package main

import "testing"

func TestGreeting(t *testing.T) {
	if got, want := greeting("sandbox"), "Hello from the sandbox!"; got != want {
		t.Errorf("greeting() = %q, want %q", got, want)
	}
}
