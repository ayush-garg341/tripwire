//go:build !linux

package main

import "errors"

// This file exists only so the pure logic — packet parsing, the DNS cache, the
// baseline — stays testable on a development machine. Capture itself is
// AF_PACKET, which is Linux only. Build for the target with:
//
//	GOOS=linux GOARCH=arm64 go build

type capture struct{ iface string }

// openCapture always fails off Linux.
//
// in:  interface name
// out: an error explaining that capture requires Linux
func openCapture(iface string) (*capture, error) {
	return nil, errors.New("packet capture requires Linux (AF_PACKET); cross-compile with GOOS=linux")
}

// read is never reached; it exists to satisfy the build.
//
// in:  a buffer
// out: an error
func (c *capture) read(buf []byte) (int, bool, error) {
	return 0, false, errors.New("capture unsupported on this platform")
}

// close is never reached; it exists to satisfy the build.
//
// in:  nothing
// out: nil
func (c *capture) close() error { return nil }
