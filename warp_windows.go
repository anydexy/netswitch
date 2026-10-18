//go:build windows

package main

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

// awgTunName — имя адаптера WARP в «Сетевых подключениях».
const awgTunName = "NetSwitch WARP"

// wintun.dll — драйвер виртуального адаптера (wintun.net), третья сторона: third_party/wintun.
// Сайт wintun.net из России часто не скачивается, поэтому библиотека встроена в exe.
//
//go:embed third_party/wintun/wintun.dll
var wintunDLL []byte

var procConvertInterfaceLuidToIndex = iphlpapi.NewProc("ConvertInterfaceLuidToIndex")

// awgPrepare кладёт wintun.dll рядом с exe: amneziawg-go загружает её оттуда.
func awgPrepare() error {
	p := filepath.Join(appDir(), "wintun.dll")
	if b, err := os.ReadFile(p); err == nil && bytes.Equal(b, wintunDLL) {
		return nil
	}
	if err := os.WriteFile(p, wintunDLL, 0644); err != nil {
		return fmt.Errorf("не удалось записать wintun.dll: %v", err)
	}
	return nil
}

func luidIndex(luid uint64) (uint32, error) {
	var idx uint32
	if r, _, _ := procConvertInterfaceLuidToIndex.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&idx))); r != 0 {
		return 0, fmt.Errorf("ConvertInterfaceLuidToIndex: %d", r)
	}
	return idx, nil
}

// awgRoutesUp: адрес и DNS адаптера WARP, весь трафик — в туннель (0.0.0.0/1 + 128.0.0.0/1 и
// так же для IPv6 — точнее маршрута по умолчанию), а сам сервер WARP — мимо туннеля, через
// прежний шлюз.
func awgRoutesUp(tdev tun.Device, name string, c awgConf, ep netip.AddrPort) (func(), error) {
	nt, ok := tdev.(*tun.NativeTun)
	if !ok {
		return nil, errors.New("неизвестный адаптер WARP")
	}
	idx, err := luidIndex(nt.LUID())
	if err != nil {
		return nil, err
	}
	fam, host, zero := "IPv4", "/32", "0.0.0.0"
	if ep.Addr().Is6() {
		fam, host, zero = "IPv6", "/128", "::"
	}
	epPrefix := ep.Addr().String() + host
	var sb strings.Builder
	sb.WriteString("$ErrorActionPreference='Stop'; try {")
	// маршрут к серверу через текущий шлюз (кроме самого адаптера WARP)
	sb.WriteString(fmt.Sprintf(`$r = Get-NetRoute -AddressFamily %s -DestinationPrefix %s -ErrorAction SilentlyContinue | Where-Object { $_.ifIndex -ne %d } | Sort-Object { $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily %s).InterfaceMetric } | Select-Object -First 1;`,
		fam, psQuote(zero+"/0"), idx, fam))
	sb.WriteString(`if (-not $r) { throw 'нет маршрута по умолчанию — нет подключения к сети' };`)
	sb.WriteString(fmt.Sprintf(`Remove-NetRoute -DestinationPrefix %s -Confirm:$false -ErrorAction SilentlyContinue;`, psQuote(epPrefix)))
	sb.WriteString(fmt.Sprintf(`New-NetRoute -DestinationPrefix %s -InterfaceIndex $r.ifIndex -NextHop $r.NextHop -RouteMetric 0 -PolicyStore ActiveStore | Out-Null;`, psQuote(epPrefix)))
	hasV6 := false
	for _, a := range c.Address {
		pl := 32
		if a.Addr().Is6() {
			pl, hasV6 = 128, true
		}
		sb.WriteString(fmt.Sprintf(`New-NetIPAddress -InterfaceIndex %d -IPAddress %s -PrefixLength %d -PolicyStore ActiveStore | Out-Null;`, idx, psQuote(a.Addr().String()), pl))
	}
	sb.WriteString(fmt.Sprintf(`Set-NetIPInterface -InterfaceIndex %d -AddressFamily IPv4 -InterfaceMetric 1 -NlMtuBytes %d;`, idx, c.MTU))
	routes := []string{"0.0.0.0/1", "128.0.0.0/1"}
	if hasV6 {
		sb.WriteString(fmt.Sprintf(`Set-NetIPInterface -InterfaceIndex %d -AddressFamily IPv6 -InterfaceMetric 1 -NlMtuBytes %d;`, idx, c.MTU))
		routes = append(routes, "::/1", "8000::/1")
	}
	for _, p := range routes {
		nh := "0.0.0.0"
		if strings.Contains(p, ":") {
			nh = "::"
		}
		sb.WriteString(fmt.Sprintf(`New-NetRoute -DestinationPrefix %s -InterfaceIndex %d -NextHop %s -RouteMetric 0 -PolicyStore ActiveStore | Out-Null;`, psQuote(p), idx, psQuote(nh)))
	}
	dns := c.DNS
	if len(dns) == 0 {
		dns = []string{"1.1.1.1", "1.0.0.1"}
	}
	var dl []string
	for _, d := range dns {
		if ip, err := netip.ParseAddr(d); err == nil && (ip.Is4() || hasV6) {
			dl = append(dl, psQuote(ip.String()))
		}
	}
	sb.WriteString(fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceIndex %d -ServerAddresses @(%s);`, idx, strings.Join(dl, ",")))
	sb.WriteString(`Clear-DnsClientCache; Write-Output 'OK' } catch { Write-Output $_.Exception.Message }`)
	out, err := ps(40*time.Second, sb.String())
	down := func() {
		_, _ = ps(20*time.Second, fmt.Sprintf(`Remove-NetRoute -DestinationPrefix %s -Confirm:$false -ErrorAction SilentlyContinue; Clear-DnsClientCache`, psQuote(epPrefix)))
	}
	if err != nil || strings.TrimSpace(out) != "OK" {
		down()
		return nil, fmt.Errorf("не удалось настроить маршруты WARP: %s", strings.TrimSpace(out))
	}
	return down, nil
}
