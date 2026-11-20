//go:build !linux

package main

import "net"

func redirectedFrom(_ *net.TCPConn, _ string) bool { return false }
