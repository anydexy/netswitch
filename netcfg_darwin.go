//go:build darwin

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const networksetup = "/usr/sbin/networksetup"

// macServices — включённые сетевые службы с устройством; active — только подключённые сейчас.
func macServices(active bool) ([]macService, error) {
	out, err := run(10*time.Second, networksetup, "-listnetworkserviceorder")
	if err != nil {
		return nil, fmt.Errorf("networksetup: %v %s", err, strings.TrimSpace(out))
	}
	all := parseServiceOrder(out)
	if !active {
		return all, nil
	}
	def := ""
	if o, err := run(5*time.Second, "/sbin/route", "-n", "get", "default"); err == nil {
		def = parseRouteIface(o)
	}
	var r []macService
	for _, s := range all {
		if s.Device == def {
			r = append(r, s)
			continue
		}
		if o, err := run(5*time.Second, "/sbin/ifconfig", s.Device); err == nil && parseIfconfigActive(o) {
			r = append(r, s)
		}
	}
	return r, nil
}

// serviceDNS — DNS, прописанные в службе вручную (пусто — автоматически от роутера).
func serviceDNS(name string) []string {
	out, _ := run(5*time.Second, networksetup, "-getdnsservers", name)
	return parseIPList(out)
}

// macCmdFailed — networksetup пишет ошибки в вывод, а код возврата бывает нулевым.
func macCmdFailed(out string) bool {
	l := strings.ToLower(out)
	return strings.Contains(l, "error") || strings.Contains(l, "requires admin") || strings.Contains(l, "not a recognized network service")
}

// listAdapters — подключённые сетевые службы (Wi-Fi, Ethernet) и DNS, которыми они пользуются.
func listAdapters() ([]Adapter, error) {
	svcs, err := macServices(true)
	if err != nil {
		return nil, err
	}
	var eff []string
	var a []Adapter
	for i, s := range svcs {
		dns := serviceDNS(s.Name)
		if len(dns) == 0 { // DNS от роутера — берём те, которыми система пользуется сейчас
			if eff == nil {
				o, _ := run(5*time.Second, "/usr/sbin/scutil", "--dns")
				eff = parseScutilDNS(o)
			}
			dns = eff
		}
		a = append(a, Adapter{Index: i, Alias: s.Name, Desc: s.Device, DNS: dns})
	}
	return a, nil
}

func flushDNS() {
	_, _ = run(10*time.Second, "/usr/bin/dscacheutil", "-flushcache")
	_, _ = run(10*time.Second, "/usr/bin/killall", "-HUP", "mDNSResponder")
}

// setSystemDNS прописывает DNS во все подключённые сетевые службы (IPv4 и IPv6).
// Шифрованный DNS (DoH) в macOS ставится только профилем конфигурации — здесь не используется.
func setSystemDNS(v4, v6 []string, doh string) error {
	addrs := append([]string{}, v4...)
	if getCfg().SetIPv6 {
		addrs = append(addrs, v6...)
	}
	svcs, err := macServices(true)
	if err != nil {
		return err
	}
	n := 0
	var errs []string
	for _, s := range svcs {
		out, err := run(15*time.Second, networksetup, append([]string{"-setdnsservers", s.Name}, addrs...)...)
		if err != nil || macCmdFailed(out) {
			errs = append(errs, s.Name+": "+strings.TrimSpace(out))
			continue
		}
		n++
	}
	flushDNS()
	if n == 0 {
		if len(errs) > 0 {
			return fmt.Errorf("не удалось прописать DNS: %s", strings.Join(errs, "; "))
		}
		return fmt.Errorf("нет подключённых сетевых служб")
	}
	return nil
}

// resetSystemDNS — вернуть DNS «автоматически» (от роутера) в подключённых службах и в тех,
// где ещё прописан DNS одного из способов NetSwitch.
func resetSystemDNS() error {
	all, err := macServices(false)
	if err != nil {
		return err
	}
	act, _ := macServices(true)
	known := map[string]bool{}
	for _, p := range getCfg().Providers {
		for _, ip := range append(append([]string{}, p.IPv4...), p.IPv6...) {
			known[strings.ToLower(ip)] = true
		}
	}
	var errs []string
	for _, s := range all {
		cur := serviceDNS(s.Name)
		if len(cur) == 0 {
			continue
		}
		mine := slices.ContainsFunc(cur, func(ip string) bool { return known[strings.ToLower(ip)] })
		if !mine && !slices.Contains(act, s) {
			continue
		}
		if out, err := run(15*time.Second, networksetup, "-setdnsservers", s.Name, "Empty"); err != nil || macCmdFailed(out) {
			errs = append(errs, s.Name+": "+strings.TrimSpace(out))
		}
	}
	flushDNS()
	if len(errs) > 0 {
		return fmt.Errorf("не удалось сбросить DNS: %s", strings.Join(errs, "; "))
	}
	return nil
}

const resolverDir = "/etc/resolver"

// setDNSBypass ставит исключения DNS файлами /etc/resolver/<домен>: macOS резолвит домен
// и его поддомены через указанные серверы. Свои файлы NetSwitch помечает и снимает только их.
func setDNSBypass(domains, servers []string) error {
	if len(domains) > 0 && len(servers) == 0 {
		return fmt.Errorf("не заданы DNS-серверы для исключений")
	}
	changed := false
	if ents, err := os.ReadDir(resolverDir); err == nil {
		for _, e := range ents {
			p := filepath.Join(resolverDir, e.Name())
			if b, err := os.ReadFile(p); err == nil && isOurResolver(string(b)) && !slices.Contains(domains, e.Name()) {
				if err := os.Remove(p); err != nil {
					return fmt.Errorf("не удалось снять исключение DNS %s: %v", e.Name(), err)
				}
				changed = true
			}
		}
	}
	var foreign []string
	if len(domains) > 0 {
		if err := os.MkdirAll(resolverDir, 0755); err != nil {
			return fmt.Errorf("не удалось настроить исключения DNS: %v", err)
		}
		content := resolverFile(servers)
		for _, d := range domains {
			p := filepath.Join(resolverDir, d)
			if b, err := os.ReadFile(p); err == nil {
				if !isOurResolver(string(b)) {
					foreign = append(foreign, d)
					continue
				}
				if string(b) == content {
					continue
				}
			}
			if err := os.WriteFile(p, []byte(content), 0644); err != nil {
				return fmt.Errorf("не удалось настроить исключения DNS: %v", err)
			}
			changed = true
		}
	}
	if changed {
		flushDNS()
	}
	if len(foreign) > 0 {
		return fmt.Errorf("в /etc/resolver уже есть чужие настройки для %s — NetSwitch их не трогает", strings.Join(foreign, ", "))
	}
	return nil
}
