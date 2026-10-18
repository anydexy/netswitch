package main

// Разбор вывода системных утилит macOS и тексты файлов для них. Без build-тегов,
// чтобы тесты проверяли это на любой системе.

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// macService — сетевая служба macOS (Wi-Fi, Ethernet…) и её устройство (en0…).
type macService struct {
	Name   string
	Device string
}

// parseServiceOrder разбирает `networksetup -listnetworkserviceorder`: включённые службы
// с устройством. Выключенные помечены "(*)", у VPN и подобных устройства нет.
func parseServiceOrder(out string) []macService {
	var r []macService
	cur, ok := "", false
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(ln, "(Hardware Port:"):
			if ok {
				dev := ""
				if i := strings.Index(ln, "Device:"); i >= 0 {
					dev = strings.TrimSpace(strings.TrimSuffix(ln[i+len("Device:"):], ")"))
				}
				if dev != "" {
					r = append(r, macService{cur, dev})
				}
			}
			ok = false
		case strings.HasPrefix(ln, "("):
			ok = false
			if i := strings.Index(ln, ")"); i > 1 {
				if _, err := strconv.Atoi(ln[1:i]); err == nil {
					cur, ok = strings.TrimSpace(ln[i+1:]), true
				}
			}
		}
	}
	return r
}

// parseIPList — IP-адреса из вывода по одному в строке (`networksetup -getdnsservers`);
// "There aren't any DNS Servers set on Wi-Fi." даёт пустой список.
func parseIPList(out string) []string {
	var r []string
	for _, ln := range strings.Split(out, "\n") {
		if ip := net.ParseIP(strings.TrimSpace(ln)); ip != nil {
			r = append(r, ip.String())
		}
	}
	return r
}

// parseScutilDNS — серверы основного резолвера (resolver #1) из `scutil --dns`.
func parseScutilDNS(out string) []string {
	var r []string
	in := false
	for _, ln := range strings.Split(out, "\n") {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "resolver #") {
			if in {
				break
			}
			in = t == "resolver #1"
			continue
		}
		if !in || !strings.HasPrefix(t, "nameserver[") {
			continue
		}
		if i := strings.Index(t, ":"); i >= 0 {
			v := strings.TrimSpace(t[i+1:])
			if j := strings.Index(v, "%"); j >= 0 { // fe80::1%en0
				v = v[:j]
			}
			if ip := net.ParseIP(v); ip != nil {
				r = append(r, ip.String())
			}
		}
	}
	return r
}

// parseIfconfigActive — интерфейс подключён: есть адрес IPv4 и нет "status: inactive".
func parseIfconfigActive(out string) bool {
	return strings.Contains(out, "\tinet ") && !strings.Contains(out, "status: inactive")
}

// parseRouteIface — интерфейс маршрута по умолчанию из `route -n get default`.
func parseRouteIface(out string) string {
	for _, ln := range strings.Split(out, "\n") {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "interface:") {
			return strings.TrimSpace(t[len("interface:"):])
		}
	}
	return ""
}

var rePingTime = regexp.MustCompile(`time[=<]([0-9.]+) ms`)

// parsePing — время ответа из `ping -c 1`, мс (не меньше 1).
func parsePing(out string) (int, bool) {
	m := rePingTime.FindStringSubmatch(out)
	if m == nil {
		return 0, false
	}
	f, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	ms := int(f + 0.5)
	if ms < 1 {
		ms = 1
	}
	return ms, true
}

// parsePS разбирает `ps -axo pid=,ppid=,comm=`: в comm полный путь, в нём бывают пробелы.
func parsePS(out string) []procEntry {
	var r []procEntry
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) < 3 {
			continue
		}
		pid, e1 := strconv.ParseUint(f[0], 10, 32)
		ppid, e2 := strconv.ParseUint(f[1], 10, 32)
		if e1 != nil || e2 != nil {
			continue
		}
		rest := strings.TrimSpace(ln)
		for i := 0; i < 2; i++ {
			rest = strings.TrimLeft(rest[strings.IndexAny(rest, " \t"):], " \t")
		}
		r = append(r, procEntry{PID: uint32(pid), PPID: uint32(ppid), Name: rest})
	}
	return r
}

// resolverMark — первая строка файлов /etc/resolver, которые создаёт NetSwitch: по ней находим
// и снимаем только свои.
const resolverMark = "# NetSwitch"

// resolverFile — файл /etc/resolver/<домен>: домен и его поддомены резолвятся через servers.
func resolverFile(servers []string) string {
	var sb strings.Builder
	sb.WriteString(resolverMark + ": исключение DNS\n")
	for _, s := range servers {
		sb.WriteString("nameserver " + s + "\n")
	}
	return sb.String()
}

func isOurResolver(content string) bool { return strings.HasPrefix(content, resolverMark) }

// pfRules — правила PF для tpws в прозрачном режиме (docs/bsd.md из zapret): исходящие
// соединения на 80/443 всех, кроме root, уходят на tpws. Сам tpws работает от root, поэтому
// его соединения идут напрямую, без петли.
func pfRules(port int) string {
	return fmt.Sprintf(`rdr pass on lo0 inet proto tcp from !127.0.0.0/8 to any port {80,443} -> 127.0.0.1 port %d
rdr pass on lo0 inet6 proto tcp from !::1 to any port {80,443} -> fe80::1 port %d
pass out route-to (lo0 127.0.0.1) inet proto tcp from any to any port {80,443} user { >root }
pass out route-to (lo0 fe80::1) inet6 proto tcp from any to any port {80,443} user { >root }
`, port, port)
}

var rePFToken = regexp.MustCompile(`Token\s*:\s*(\d+)`)

// parsePFToken — токен из `pfctl -E`: по нему PF выключается, только если его больше никто не включал.
func parsePFToken(out string) string {
	if m := rePFToken.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

// shQuote — строка в одинарных кавычках для sh.
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// appleScriptQuote — строка в двойных кавычках для AppleScript.
func appleScriptQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// launchdPlist — задание launchd, которое запускает программу с аргументами при загрузке системы.
func launchdPlist(label string, args []string) string {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + xmlEsc(label) + `</string>
	<key>ProgramArguments</key>
	<array>
`)
	for _, a := range args {
		sb.WriteString("\t\t<string>" + xmlEsc(a) + "</string>\n")
	}
	sb.WriteString(`	</array>
	<key>RunAtLoad</key>
	<true/>
</dict>
</plist>
`)
	return sb.String()
}
