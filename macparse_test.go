package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseServiceOrder(t *testing.T) {
	out := `An asterisk (*) denotes that a network service is disabled.
(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(2) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en7)

(*) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

(3) Cloudflare WARP
(Hardware Port: com.cloudflare.1dot1dot1dot1.macos, Device: )
`
	got := parseServiceOrder(out)
	want := []macService{{"Wi-Fi", "en0"}, {"USB 10/100/1000 LAN", "en7"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseServiceOrder = %#v, нужно %#v", got, want)
	}
}

func TestParseIPList(t *testing.T) {
	if got := parseIPList("There aren't any DNS Servers set on Wi-Fi.\n"); len(got) != 0 {
		t.Errorf("пустой список: %v", got)
	}
	got := parseIPList("83.220.169.155\n212.109.195.93\n2606:4700:4700::1111\n")
	want := []string{"83.220.169.155", "212.109.195.93", "2606:4700:4700::1111"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseIPList = %v", got)
	}
}

func TestParseScutilDNS(t *testing.T) {
	out := `DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : fe80::1%en0
  if_index : 6 (en0)
  flags    : Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : local
  options  : mdns
`
	got := parseScutilDNS(out)
	want := []string{"192.168.1.1", "fe80::1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseScutilDNS = %v", got)
	}
}

func TestParseIfconfigActive(t *testing.T) {
	up := "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tether 3c:22:fb:00:00:01\n\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255\n\tstatus: active\n"
	down := "en7: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tether 00:e0:4c:00:00:02\n\tmedia: autoselect (none)\n\tstatus: inactive\n"
	if !parseIfconfigActive(up) || parseIfconfigActive(down) {
		t.Error("parseIfconfigActive: неверно определено подключение")
	}
}

func TestParseRouteIface(t *testing.T) {
	out := "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n"
	if got := parseRouteIface(out); got != "en0" {
		t.Errorf("parseRouteIface = %q", got)
	}
}

func TestParsePing(t *testing.T) {
	out := "PING 1.1.1.1 (1.1.1.1): 56 data bytes\n64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=12.613 ms\n\n--- 1.1.1.1 ping statistics ---\n"
	if ms, ok := parsePing(out); !ok || ms != 13 {
		t.Errorf("parsePing = %d %v", ms, ok)
	}
	if _, ok := parsePing("Request timeout for icmp_seq 0\n"); ok {
		t.Error("parsePing: таймаут принят за ответ")
	}
	if ms, ok := parsePing("64 bytes from 10.0.0.1: icmp_seq=0 ttl=64 time=0.081 ms"); !ok || ms != 1 {
		t.Errorf("parsePing (меньше 1 мс) = %d %v", ms, ok)
	}
}

func TestParsePS(t *testing.T) {
	out := "    1     0 /sbin/launchd\n  812     1 /Users/me/Library/Application Support/NetSwitch/tgws/TG WS Proxy.app/Contents/MacOS/TgWsProxy\n bad line\n"
	got := parsePS(out)
	if len(got) != 2 || got[1].PID != 812 || got[1].PPID != 1 ||
		got[1].Name != "/Users/me/Library/Application Support/NetSwitch/tgws/TG WS Proxy.app/Contents/MacOS/TgWsProxy" {
		t.Errorf("parsePS = %#v", got)
	}
}

func TestResolverFile(t *testing.T) {
	f := resolverFile([]string{"8.8.8.8", "1.1.1.1"})
	if !isOurResolver(f) || !strings.Contains(f, "\nnameserver 8.8.8.8\nnameserver 1.1.1.1\n") {
		t.Errorf("resolverFile:\n%s", f)
	}
	if isOurResolver("nameserver 10.0.0.1\n") {
		t.Error("чужой файл /etc/resolver принят за свой")
	}
}

func TestPFRules(t *testing.T) {
	r := pfRules(988)
	for _, s := range []string{"-> 127.0.0.1 port 988", "-> fe80::1 port 988", "user { >root }"} {
		if !strings.Contains(r, s) {
			t.Errorf("в правилах PF нет %q:\n%s", s, r)
		}
	}
	if got := parsePFToken("No ALTQ support in kernel\nALTQ related functions disabled\npf enabled\nToken : 15762189375302474493\n"); got != "15762189375302474493" {
		t.Errorf("parsePFToken = %q", got)
	}
}

func TestQuoting(t *testing.T) {
	if got := shQuote(`/Applications/Net Switch.app/it's`); got != `'/Applications/Net Switch.app/it'\''s'` {
		t.Errorf("shQuote = %s", got)
	}
	if got := appleScriptQuote(`a "b" \c`); got != `"a \"b\" \\c"` {
		t.Errorf("appleScriptQuote = %s", got)
	}
	p := launchdPlist("com.netswitch.app", []string{"/Applications/NetSwitch.app/Contents/MacOS/NetSwitch", "--home", "/Users/a&b"})
	if !strings.Contains(p, "<string>/Users/a&amp;b</string>") || !strings.Contains(p, "<key>RunAtLoad</key>") {
		t.Errorf("launchdPlist:\n%s", p)
	}
}
