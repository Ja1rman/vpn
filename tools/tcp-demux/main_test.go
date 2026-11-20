package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func hello(name string) []byte {
	host := append([]byte{0, byte(len(name) >> 8), byte(len(name))}, []byte(name)...)
	names := append([]byte{byte(len(host) >> 8), byte(len(host))}, host...)
	ext := append([]byte{0, 0, byte(len(names) >> 8), byte(len(names))}, names...)
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	return append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}
func record(data []byte) []byte {
	return append([]byte{22, 3, 1, byte(len(data) >> 8), byte(len(data))}, data...)
}
func TestTLSFragmentationSNIReplay(t *testing.T) {
	h := hello("WEB.EXAMPLE")
	input := append(record(h[:11]), record(h[11:])...)
	c := config{DefaultTarget: "original", TLS: map[string]string{"web.example": "web"}, Raw: "dd"}
	target, replay, e := classify(bytes.NewReader(input), c)
	if e != nil || target != "web" || !bytes.Equal(replay, input) {
		t.Fatal("fragmented TLS was not preserved")
	}
	target, _, e = classify(bytes.NewReader(record(hello("other.example"))), c)
	if e != nil || target != "original" {
		t.Fatal("unknown TLS did not retain original backend")
	}
}
func TestSOCKSAndRawReplay(t *testing.T) {
	c := config{DefaultTarget: "vpn", SOCKS: "socks", Raw: "dd"}
	for _, row := range []struct {
		input  []byte
		target string
	}{{[]byte{5, 1, 2}, "socks"}, {[]byte{5, 2, 0, 2}, "socks"}, {[]byte{5, 1, 9}, "dd"}, {[]byte{0x37}, "dd"}, {[]byte{22, 7, 1, 0, 0}, "dd"}} {
		target, replay, e := classify(bytes.NewReader(row.input), c)
		if e != nil || target != row.target || !bytes.Equal(replay, row.input) {
			t.Fatal("incorrect protocol classification")
		}
	}
}
func TestRejectMalformedBoundedHello(t *testing.T) {
	for _, input := range [][]byte{{22, 3, 1, 255, 255}, record([]byte{1, 255, 255, 255}), record([]byte{1, 0, 0, 1, 0}), {22, 3}} {
		if _, _, e := classify(bytes.NewReader(input), config{}); e == nil {
			t.Fatal("accepted malformed TLS")
		}
	}
}
func listener(t *testing.T) *net.TCPListener {
	ips, e := net.LookupIP("localhost")
	if e != nil {
		t.Fatal(e)
	}
	var ip net.IP
	for _, x := range ips {
		if x.To4() != nil {
			ip = x
			break
		}
	}
	l, e := net.ListenTCP("tcp", &net.TCPAddr{IP: ip})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	return l
}
func TestPrivateConfigAndLoopbackBackends(t *testing.T) {
	first, second := listener(t), listener(t)
	c := config{Listen: first.Addr().String(), DefaultTarget: second.Addr().String()}
	if c.validate() != nil {
		t.Fatal("valid endpoints rejected")
	}
	invalid := c
	invalid.DefaultTarget = c.Listen
	if invalid.validate() == nil {
		t.Fatal("same listener port accepted")
	}
	invalid = c
	_, p, _ := net.SplitHostPort(second.Addr().String())
	invalid.DefaultTarget = net.JoinHostPort("localhost", p)
	if invalid.validate() == nil {
		t.Fatal("hostname backend accepted instead of literal loopback")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(path, []byte(`{}`), 0644)
	if _, e := load(path); e == nil {
		t.Fatal("public config permissions accepted")
	}
}
func TestRelayPreservesPrefaceAndHalfClose(t *testing.T) {
	backend, front := listener(t), listener(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := backend.AcceptTCP()
		if e != nil {
			return
		}
		defer c.Close()
		data, _ := io.ReadAll(c)
		c.Write(append([]byte("reply:"), data...))
		c.CloseWrite()
	}()
	go func() {
		c, e := front.AcceptTCP()
		if e == nil {
			relay(c, config{DefaultTarget: backend.Addr().String()})
		}
	}()
	client, e := net.DialTCP("tcp", nil, front.Addr().(*net.TCPAddr))
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	input := record(hello("old.example"))
	input = append(input, []byte("payload")...)
	client.Write(input)
	client.CloseWrite()
	result, e := io.ReadAll(client)
	if e != nil || !bytes.Equal(result, append([]byte("reply:"), input...)) {
		t.Fatal("copy/halfclose lost data")
	}
	<-done
}
func TestRecordLengthParsing(t *testing.T) {
	r := record(hello("x.example"))
	if int(binary.BigEndian.Uint16(r[3:5])) != len(r)-5 {
		t.Fatal("invalid fixture")
	}
}

func TestHalfClosedSilentPeerCannotPinSlot(t *testing.T) {
	backend, front := listener(t), listener(t)
	go func() {
		c, e := backend.AcceptTCP()
		if e != nil {
			return
		}
		defer c.Close()
		b := make([]byte, 1)
		c.Read(b)
		c.CloseWrite()
		io.Copy(io.Discard, c)
	}()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		c, e := front.AcceptTCP()
		if e == nil {
			relayWithGrace(c, config{DefaultTarget: backend.Addr().String()}, 30*time.Millisecond)
		}
	}()
	client, e := net.DialTCP("tcp", nil, front.Addr().(*net.TCPAddr))
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	client.Write([]byte("x"))
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("silent half-closed peer pinned relay")
	}
}
