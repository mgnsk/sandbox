// Package guard is what every guard program shares: how the launcher starts
// it, and how it says it's ready.
//
// The launcher makes a guard's socket itself, before starting it, and hands
// it over as an inherited file, so the socket is there to bind into the
// sandbox as soon as the guard starts. A second inherited file is a pipe the
// guard writes one JSON line to once it serves - its ready message, with
// whatever the launcher needs to know (an HTTPS proxy's secret and CA) - and
// closes. A guard that exits first closes it empty, which the launcher
// reports with the guard's exit status.
package guard

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
)

// The inherited files, as the launcher passes them in ExtraFiles.
const (
	ReadyFD    = 3
	ListenerFD = 4
)

// Main runs the guard name: run gets a context that ends on SIGTERM or
// SIGINT, the launcher's way of stopping it. It returns the exit status, 1
// for run's error, which it reports under name.
func Main(name string, run func(ctx context.Context) error) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		return 1
	}
	return 0
}

// Listener is the socket the launcher made for this guard.
func Listener() (net.Listener, error) {
	f := os.NewFile(ListenerFD, "listener")
	if f == nil {
		return nil, errors.New("no listener from the launcher")
	}
	defer f.Close()
	return net.FileListener(f)
}

// Ready tells the launcher the guard serves, with info for it.
func Ready(info any) error {
	f := os.NewFile(ReadyFD, "ready")
	if f == nil {
		return errors.New("no ready pipe from the launcher")
	}
	defer f.Close()
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	_, err = f.Write(append(data, '\n'))
	return err
}

// Serve hands each connection on ln to handle, in its own goroutine, until
// ctx ends; then it closes ln and returns nil.
func Serve(ctx context.Context, ln net.Listener, handle func(net.Conn)) error {
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go handle(conn)
	}
}
