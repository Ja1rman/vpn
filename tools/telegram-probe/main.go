// Anonymous connectivity proof: no user login, messages, or persistent session.
// Official client pinned in go.mod; endpoint credentials are private JSON inputs.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gotd/td/session"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/dcs"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/transport"
	"golang.org/x/net/proxy"
)

type forwardingDialer struct {
	dial func(context.Context, string, string) (net.Conn, error)
}

func (d forwardingDialer) Dial(network, address string) (net.Conn, error) {
	return d.dial(context.Background(), network, address)
}
func (d forwardingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dial(ctx, network, address)
}

func readPrivate(path string, output any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("private input unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 65536 {
		return fmt.Errorf("private input must be a small owner-only regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("private input unreadable")
	}
	if err = json.Unmarshal(data, output); err != nil {
		return fmt.Errorf("private input is not valid JSON")
	}
	return nil
}
func failureClass(err error) string {
	if err == nil {
		return ""
	}
	value := strings.ToLower(err.Error())
	for _, category := range []string{"timeout", "deadline", "refused", "authentication", "handshake", "fingerprint", "rpc"} {
		if strings.Contains(value, category) {
			return category
		}
	}
	return "client_failure"
}

type access struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Secret   string `json:"secret"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	mode := flag.String("mode", "", "mtproto, socks, or direct")
	file := flag.String("access", "", "private access JSON file")
	dc := flag.Int("dc", 2, "Telegram data center")
	iface := flag.String("interface", "", "optional physical network interface")
	saveDCs := flag.String("save-dcs", "", "private output for actual Telegram DC options")
	loadDCs := flag.String("dc-config", "", "private input for current Telegram DC options")
	viaSOCKS := flag.String("via-socks", "", "private local SOCKS access for nested MTProxy test")
	flag.Parse()
	row := map[string]any{"library": "gotd/td", "revision": "958b9f670778", "mode": *mode, "dc": *dc, "account_login": false, "session": "memory-only"}
	var a access
	var stateMu sync.Mutex
	states := []string{}
	lastDead := ""
	fail := func(err error) {
		row["status"] = "failed"
		row["error_class"] = failureClass(err)
		json.NewEncoder(os.Stdout).Encode(row)
		os.Exit(1)
	}
	if *dc < 1 || *dc > 5 {
		fail(fmt.Errorf("invalid Telegram DC"))
	}
	if *mode != "direct" {
		if err := readPrivate(*file, &a); err != nil {
			fail(err)
		}
		if a.Server == "" || a.Port < 1 || a.Port > 65535 {
			fail(fmt.Errorf("invalid private proxy endpoint"))
		}
	}
	var resolver dcs.Resolver
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	if *iface != "" {
		physical, err := net.InterfaceByName(*iface)
		if err != nil {
			fail(fmt.Errorf("physical interface unavailable"))
		}
		dialer.Control = func(network, address string, raw syscall.RawConn) error {
			var bound error
			err := raw.Control(func(fd uintptr) {
				switch runtime.GOOS {
				case "darwin":
					// IP_BOUND_IF is a socket option, not a deployment port.
					bound = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 25, physical.Index)
				case "linux":
					// SO_BINDTODEVICE is a socket option, not a deployment port.
					bound = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, 25, physical.Name)
				default:
					bound = fmt.Errorf("interface binding is unsupported on this OS")
				}
			})
			if err != nil {
				return err
			}
			return bound
		}
		row["interface"] = *iface
	}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := dialer.DialContext(ctx, network, address)
		if err == nil {
			c.SetDeadline(time.Now().Add(20 * time.Second))
		}
		return c, err
	}
	if *viaSOCKS != "" {
		var via access
		if err := readPrivate(*viaSOCKS, &via); err != nil {
			fail(err)
		}
		hop, err := proxy.SOCKS5("tcp", net.JoinHostPort(via.Server, strconv.Itoa(via.Port)), &proxy.Auth{User: via.Username, Password: via.Password}, dialer)
		if err != nil {
			fail(err)
		}
		contextual, ok := hop.(proxy.ContextDialer)
		if !ok {
			fail(fmt.Errorf("nested SOCKS has no context support"))
		}
		dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := contextual.DialContext(ctx, network, address)
			if err == nil {
				conn.SetDeadline(time.Now().Add(20 * time.Second))
			}
			return conn, err
		}
		row["nested_via_auto"] = true
	}
	address := net.JoinHostPort(a.Server, strconv.Itoa(a.Port))
	switch *mode {
	case "mtproto":
		secret, err := hex.DecodeString(a.Secret)
		if err != nil {
			fail(fmt.Errorf("invalid private secret encoding"))
		}
		var err2 error
		resolver, err2 = dcs.MTProxy(address, secret, dcs.MTProxyOptions{Dial: dial, Network: "tcp4"})
		if err2 != nil {
			fail(err2)
		}
	case "socks":
		socks, err := proxy.SOCKS5("tcp", address, &proxy.Auth{User: a.Username, Password: a.Password}, forwardingDialer{dial: dial})
		if err != nil {
			fail(err)
		}
		contextual, ok := socks.(proxy.ContextDialer)
		if !ok {
			fail(fmt.Errorf("SOCKS dialer has no context support"))
		}
		resolver = dcs.Plain(dcs.PlainOptions{Dial: contextual.DialContext, Protocol: transport.Abridged, Obfuscated: true, Network: "tcp4"})
	case "direct":
		resolver = dcs.Plain(dcs.PlainOptions{Dial: dial, Protocol: transport.Abridged, Obfuscated: true, Network: "tcp4"})
	default:
		fail(fmt.Errorf("unsupported probe mode"))
	}
	dcList := dcs.Prod()
	if *loadDCs != "" {
		var options []tg.DCOption
		if err := readPrivate(*loadDCs, &options); err != nil {
			fail(err)
		}
		dcList = dcs.List{Options: options}
		row["dc_list"] = "live-help.getConfig"
	}
	client := telegram.NewClient(telegram.TestAppID, telegram.TestAppHash, telegram.Options{DC: *dc, DCList: dcList, Resolver: resolver, NoUpdates: true, SessionStorage: &session.StorageMemory{}, DialTimeout: 8 * time.Second, ExchangeTimeout: 8 * time.Second, Device: telegram.DeviceTDesktopWindows(), OnConnectionState: func(state telegram.ConnectionState) {
		stateMu.Lock()
		states = append(states, state.String())
		stateMu.Unlock()
	}, OnDead: func(err error) { stateMu.Lock(); lastDead = err.Error(); stateMu.Unlock() }})
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	started := time.Now()
	err := client.Run(ctx, func(ctx context.Context) error {
		row["key_exchange"] = "passed"
		nearest, err := client.API().HelpGetNearestDC(ctx)
		if err != nil {
			return err
		}
		row["rpc"] = "help.getNearestDC"
		row["this_dc"] = nearest.ThisDC
		row["nearest_dc"] = nearest.NearestDC
		if *saveDCs != "" {
			config, err := client.API().HelpGetConfig(ctx)
			if err != nil {
				return err
			}
			data, err := json.Marshal(config.DCOptions)
			if err != nil {
				return err
			}
			if err = os.WriteFile(*saveDCs, data, 0600); err != nil {
				return err
			}
			row["live_dc_options"] = len(config.DCOptions)
		}
		return nil
	})
	row["elapsed_ms"] = time.Since(started).Milliseconds()
	stateMu.Lock()
	row["states"] = states
	if lastDead != "" {
		row["last_connection_error_class"] = failureClass(fmt.Errorf("%s", lastDead))
	}
	stateMu.Unlock()
	if err != nil {
		fail(err)
	}
	row["status"] = "passed"
	json.NewEncoder(os.Stdout).Encode(row)
}
