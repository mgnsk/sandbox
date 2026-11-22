// A program to give Claude Code something to work on in the demo.
package main

import "fmt"

func main() {
	fmt.Println(greeting("sandbox"))
}

func greeting(name string) string {
	return "Hello from the " + name + "!"
}
