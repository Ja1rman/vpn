// Route fresh connections by their public protocol preface; never terminate TLS.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const maxPreface = 128 * 1024
const prefaceTimeout = 5 * time.Second
const maxConnections = 512

type config struct {
	Listen         string            `json:"listen"`
	DefaultTarget  string            `json:"default_target"`
	TLS            map[string]string `json:"tls_sni_targets"`
	SOCKS          string            `json:"socks_target,omitempty"`
	Raw            string            `json:"raw_target,omitempty"`
	RedirectedFrom string            `json:"redirected_from,omitempty"`
}

func endpoint(value string, loopback bool) error {
	h, p, e := net.SplitHostPort(value)
	if e != nil {
		return errors.New("invalid endpoint")
	}
	ip := net.ParseIP(h)
	n, e := strconv.Atoi(p)
	if ip == nil || e != nil || n < 1 || n > 65535 || loopback && !ip.IsLoopback() {
		return errors.New("invalid endpoint")
	}
	return nil
}
func (c config) validate() error {
	if c.RedirectedFrom != "" && endpoint(c.RedirectedFrom, false) != nil {
		return errors.New("invalid original destination")
	}
	if endpoint(c.Listen, false) != nil || endpoint(c.DefaultTarget, true) != nil {
		return errors.New("invalid endpoint")
	}
	for name, target := range c.TLS {
		if name == "" || name != strings.ToLower(name) || strings.ContainsAny(name, " /:\t\n") || endpoint(target, true) != nil {
			return errors.New("invalid TLS route")
		}
	}
	for _, target := range append([]string{c.DefaultTarget, c.SOCKS, c.Raw}, mapValues(c.TLS)...) {
		_, listenerPort, _ := net.SplitHostPort(c.Listen)
		_, backendPort, _ := net.SplitHostPort(target)
		if target != "" && (endpoint(target, true) != nil || backendPort == listenerPort) {
			return errors.New("invalid backend")
		}
	}
	return nil
}
func itoa(value int) string { return strconv.Itoa(value) }

func mapValues(m map[string]string) []string {
	v := []string{}
	for _, x := range m {
		v = append(v, x)
	}
	return v
}
func load(path string) (config, error) {
	var c config
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 64*1024 {
		return c, errors.New("unsafe private config")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&c); e != nil {
		return c, e
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return c, errors.New("extra config data")
	}
	return c, c.validate()
}

// A complete TLS handshake body contains version/random/session/cipher/compression/extensions.
func helloSNI(body []byte) (string, error) {
	if len(body) < 34 {
		return "", errors.New("short hello")
	}
	at := 34
	take := func(n int) ([]byte, error) {
		if n < 0 || at+n > len(body) {
			return nil, errors.New("short hello")
		}
		b := body[at : at+n]
		at += n
		return b, nil
	}
	b, e := take(1)
	if e != nil {
		return "", e
	}
	if _, e = take(int(b[0])); e != nil {
		return "", e
	}
	b, e = take(2)
	if e != nil {
		return "", e
	}
	n := int(binary.BigEndian.Uint16(b))
	if n%2 != 0 {
		return "", errors.New("invalid cipher list")
	}
	if _, e = take(n); e != nil {
		return "", e
	}
	b, e = take(1)
	if e != nil {
		return "", e
	}
	if _, e = take(int(b[0])); e != nil {
		return "", e
	}
	if at == len(body) {
		return "", nil
	}
	b, e = take(2)
	if e != nil {
		return "", e
	}
	n = int(binary.BigEndian.Uint16(b))
	if at+n != len(body) {
		return "", errors.New("invalid extension list")
	}
	end := at + n
	for at < end {
		b, e = take(4)
		if e != nil {
			return "", e
		}
		kind := binary.BigEndian.Uint16(b[:2])
		length := int(binary.BigEndian.Uint16(b[2:]))
		value, e := take(length)
		if e != nil {
			return "", e
		}
		if kind != 0 {
			continue
		}
		if len(value) < 2 || int(binary.BigEndian.Uint16(value[:2])) != len(value)-2 {
			return "", errors.New("invalid SNI")
		}
		for p := 2; p < len(value); {
			if p+3 > len(value) {
				return "", errors.New("invalid SNI")
			}
			kind := value[p]
			n := int(binary.BigEndian.Uint16(value[p+1 : p+3]))
			p += 3
			if p+n > len(value) {
				return "", errors.New("invalid SNI")
			}
			if kind == 0 {
				name := strings.ToLower(string(value[p : p+n]))
				if name == "" || strings.ContainsAny(name, "\x00 /:\t\n") {
					return "", errors.New("invalid SNI")
				}
				return name, nil
			}
			p += n
		}
	}
	return "", nil
}

func classify(reader io.Reader, c config) (string, []byte, error) {
	raw := []byte{}
	read := func(n int) ([]byte, error) {
		if len(raw)+n > maxPreface {
			return nil, errors.New("preface too large")
		}
		b := make([]byte, n)
		_, e := io.ReadFull(reader, b)
		raw = append(raw, b...)
		return b, e
	}
	first, e := read(1)
	if e != nil {
		return "", raw, e
	}
	fallback := c.Raw
	if fallback == "" {
		fallback = c.DefaultTarget
	}
	if first[0] == 5 && c.SOCKS != "" {
		count, e := read(1)
		if e != nil {
			return "", raw, e
		}
		if count[0] >= 1 && count[0] <= 8 {
			methods, e := read(int(count[0]))
			if e != nil {
				return "", raw, e
			}
			valid := true
			for _, m := range methods {
				if m != 0 && m != 2 {
					valid = false
				}
			}
			if valid {
				return c.SOCKS, raw, nil
			}
		}
		return fallback, raw, nil
	}
	if first[0] != 22 {
		return fallback, raw, nil
	}
	header, e := read(4)
	if e != nil {
		return "", raw, e
	}
	if header[0] != 3 || header[1] > 4 {
		return fallback, raw, nil
	}
	handshake := []byte{}
	for {
		n := int(binary.BigEndian.Uint16(header[2:]))
		if n == 0 || n > 18432 {
			return "", raw, errors.New("invalid TLS record")
		}
		fragment, e := read(n)
		if e != nil {
			return "", raw, e
		}
		handshake = append(handshake, fragment...)
		if len(handshake) >= 4 {
			if handshake[0] != 1 {
				return "", raw, errors.New("not ClientHello")
			}
			length := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if length+4 > maxPreface {
				return "", raw, errors.New("hello too large")
			}
			if len(handshake) >= length+4 {
				name, e := helloSNI(handshake[4 : length+4])
				if e != nil {
					return "", raw, e
				}
				if target, ok := c.TLS[name]; ok {
					return target, raw, nil
				}
				return c.DefaultTarget, raw, nil
			}
		}
		next, e := read(5)
		if e != nil {
			return "", raw, e
		}
		if next[0] != 22 || next[1] != 3 || next[2] > 4 {
			return "", raw, errors.New("invalid TLS fragment")
		}
		header = next[1:]
	}
}

type activityConn struct {
	net.Conn
	draining *atomic.Bool
	grace    time.Duration
}

func (c activityConn) Read(b []byte) (int, error) {
	if c.draining.Load() {
		c.Conn.SetReadDeadline(time.Now().Add(c.grace))
	}
	return c.Conn.Read(b)
}
func (c activityConn) Write(b []byte) (int, error) {
	if c.draining.Load() {
		c.Conn.SetWriteDeadline(time.Now().Add(c.grace))
	}
	return c.Conn.Write(b)
}
func relay(client *net.TCPConn, c config) { relayWithGrace(client, c, 30*time.Second) }
func relayWithGrace(client *net.TCPConn, c config, grace time.Duration) {
	defer client.Close()
	if c.RedirectedFrom != "" && !redirectedFrom(client, c.RedirectedFrom) {
		return
	}
	client.SetReadDeadline(time.Now().Add(prefaceTimeout))
	target, prefix, e := classify(client, c)
	if e != nil {
		return
	}
	client.SetReadDeadline(time.Time{})
	address, e := net.ResolveTCPAddr("tcp", target)
	if e != nil {
		return
	}
	backend, e := net.DialTimeout("tcp", address.String(), prefaceTimeout)
	if e != nil {
		return
	}
	defer backend.Close()
	backend.SetWriteDeadline(time.Now().Add(prefaceTimeout))
	if _, e = io.Copy(backend, bytes.NewReader(prefix)); e != nil {
		return
	}
	backend.SetWriteDeadline(time.Time{})
	var draining atomic.Bool
	a := activityConn{client, &draining, grace}
	b := activityConn{backend, &draining, grace}
	completed := make(chan error, 2)
	go func() {
		_, err := io.Copy(b, a)
		if t, ok := backend.(*net.TCPConn); ok {
			t.CloseWrite()
		}
		completed <- err
	}()
	go func() { _, err := io.Copy(a, b); client.CloseWrite(); completed <- err }()
	if err := <-completed; err != nil {
		client.Close()
		backend.Close()
	} else {
		draining.Store(true)
		client.SetDeadline(time.Now().Add(grace))
		backend.SetDeadline(time.Now().Add(grace))
	}
	<-completed
}
func serve(listener *net.TCPListener, c config, stopping <-chan os.Signal) {
	var active sync.WaitGroup
	go func() { <-stopping; listener.Close() }()
	limit := make(chan struct{}, maxConnections)
	for {
		conn, e := listener.AcceptTCP()
		if e != nil {
			break
		}
		select {
		case limit <- struct{}{}:
			active.Add(1)
			go func() { defer active.Done(); defer func() { <-limit }(); relay(conn, c) }()
		default:
			conn.Close()
		}
	}
	active.Wait()
}
func main() {
	path := flag.String("config", "", "private JSON configuration")
	check := flag.Bool("check", false, "validate configuration only")
	flag.Parse()
	c, e := load(*path)
	if e != nil {
		os.Stderr.WriteString("Invalid private demux configuration\n")
		os.Exit(1)
	}
	if *check {
		return
	}
	address, e := net.ResolveTCPAddr("tcp", c.Listen)
	if e != nil {
		os.Exit(1)
	}
	listener, e := net.ListenTCP("tcp", address)
	if e != nil {
		os.Stderr.WriteString("Demux listener unavailable\n")
		os.Exit(1)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	serve(listener, c, stop)
}
