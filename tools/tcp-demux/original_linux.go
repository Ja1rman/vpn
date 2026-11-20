//go:build linux

package main

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"
)

// SO_ORIGINAL_DST is the Linux netfilter API option number, not a network port.
const soOriginalDst = 80

func redirectedFrom(conn *net.TCPConn, expected string) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	var address syscall.RawSockaddrInet4
	size := uint32(unsafe.Sizeof(address))
	var socketErr syscall.Errno
	err = raw.Control(func(fd uintptr) {
		_, _, socketErr = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_IP, soOriginalDst, uintptr(unsafe.Pointer(&address)), uintptr(unsafe.Pointer(&size)), 0)
	})
	if err != nil || socketErr != 0 || address.Family != syscall.AF_INET {
		return false
	}
	port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&address.Port))[:])
	return net.JoinHostPort(net.IP(address.Addr[:]).String(), itoa(int(port))) == expected
}
