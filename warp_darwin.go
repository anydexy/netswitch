//go:build darwin

package main

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

// awgTunName — macOS сама выдаёт свободный utunN.
const awgTunName = "utun"

func awgPrepare() error { return nil }

func routeCmd(args ...string) error {
	out, err := run(10*time.Second, "/sbin/route", append([]string{"-q", "-n"}, args...)...)
	if err != nil {
		return fmt.Errorf("route %s: %s", strings.Join(args, " "), strings.TrimSpace(out))
	}
	return nil
}

// awgRoutesUp: адреса utun, весь трафик — в туннель (0.0.0.0/1 + 128.0.0.0/1, для IPv6 — ::/1 +
// 8000::/1), сервер WARP — через прежний шлюз, DNS из конфига — во все подключённые службы.
func awgRoutesUp(tdev tun.Device, name string, c awgConf, ep netip.AddrPort) (func(), error) {
	fam := "-inet"
	if ep.Addr().Is6() {
		fam = "-inet6"
	}
	o, _ := run(5*time.Second, "/sbin/route", "-n", "get", fam, "default")
	gw := parseRouteGateway(o)
	if gw == "" {
		return nil, errors.New("нет шлюза по умолчанию — нет подключения к сети или включён другой VPN")
	}
	epHost := ep.Addr().String()
	_ = routeCmd("delete", fam, "-host", epHost)
	if err := routeCmd("add", fam, "-host", epHost, gw); err != nil {
		return nil, err
	}
	down := func() {
		_ = routeCmd("delete", fam, "-host", epHost)
		if err := resetSystemDNS(); err != nil {
			logf("WARP: %v", err)
		}
	}
	fail := func(err error) (func(), error) {
		down()
		return nil, err
	}
	hasV6 := false
	for _, a := range c.Address {
		ip := a.Addr().String()
		var out string
		var err error
		if a.Addr().Is4() {
			out, err = run(10*time.Second, "/sbin/ifconfig", name, "inet", ip+"/32", ip, "alias")
		} else {
			hasV6 = true
			out, err = run(10*time.Second, "/sbin/ifconfig", name, "inet6", ip, "prefixlen", "128", "alias")
		}
		if err != nil {
			return fail(fmt.Errorf("ifconfig %s: %s", name, strings.TrimSpace(out)))
		}
	}
	if out, err := run(10*time.Second, "/sbin/ifconfig", name, "mtu", fmt.Sprint(c.MTU), "up"); err != nil {
		return fail(fmt.Errorf("ifconfig %s up: %s", name, strings.TrimSpace(out)))
	}
	for _, p := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := routeCmd("add", "-inet", p, "-interface", name); err != nil {
			return fail(err)
		}
	}
	if hasV6 {
		for _, p := range []string{"::/1", "8000::/1"} {
			if err := routeCmd("add", "-inet6", p, "-interface", name); err != nil {
				return fail(err)
			}
		}
	}
	var v4, v6 []string
	for _, d := range c.DNS {
		if ip, err := netip.ParseAddr(d); err == nil {
			if ip.Is4() {
				v4 = append(v4, ip.String())
			} else if hasV6 {
				v6 = append(v6, ip.String())
			}
		}
	}
	if len(v4) == 0 {
		v4 = []string{"1.1.1.1", "1.0.0.1"}
	}
	if err := setSystemDNS(v4, v6, ""); err != nil {
		return fail(err)
	}
	return down, nil
}
