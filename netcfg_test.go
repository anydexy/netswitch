package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestBypassScript(t *testing.T) {
	s := bypassScript([]string{"figma.com", "example.org"}, []string{"8.8.8.8", "1.1.1.1"})
	for _, want := range []string{
		`@(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object {$_.Comment -eq 'NetSwitch'}) | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction Stop; $n++ };`,
		`Add-DnsClientNrptRule -Namespace '.figma.com','figma.com' -NameServers '8.8.8.8','1.1.1.1' -Comment 'NetSwitch' -DisplayName 'NetSwitch: figma.com' -ErrorAction Stop;`,
		`Add-DnsClientNrptRule -Namespace '.example.org','example.org' -NameServers '8.8.8.8','1.1.1.1' -Comment 'NetSwitch' -DisplayName 'NetSwitch: example.org' -ErrorAction Stop;`,
		`if($n){Clear-DnsClientCache; ipconfig /flushdns | Out-Null}; Write-Output "OK $n"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("в скрипте нет\n  %s\nскрипт:\n  %s", want, s)
		}
	}
	// без прав администратора Add-DnsClientNrptRule падает, но скрипт без try всё равно дошёл бы до "OK"
	if !strings.HasPrefix(s, "try{") || !strings.HasSuffix(s, `}catch{ Write-Output $_.Exception.Message }`) {
		t.Errorf("скрипт не обёрнут в try/catch: %s", s)
	}
	// снять старые правила — до того, как ставить новые
	if strings.Index(s, "Remove-DnsClientNrptRule") > strings.Index(s, "Add-DnsClientNrptRule") {
		t.Error("правила ставятся раньше, чем снимаются старые")
	}

	s = bypassScript(nil, []string{"8.8.8.8"})
	if strings.Contains(s, "Add-DnsClientNrptRule") || !strings.Contains(s, "Remove-DnsClientNrptRule") {
		t.Errorf("пустой список должен только снимать правила: %s", s)
	}
}

func TestNormDomains(t *testing.T) {
	ok, bad := normDomains([]string{
		" https://www.Figma.com/files/recent ", "*.figma.com", ".figma.com.", "figma.com", "FIGMA.COM:443",
		"api.example-1.org", "", "  ",
		"сайт.рф", "com", "a..b.com", "-x.com", "x-.com", "figma.com'; Remove-Item C:\\ -Recurse #", "under_score.com",
	})
	if want := []string{"www.figma.com", "figma.com", "api.example-1.org"}; !reflect.DeepEqual(ok, want) {
		t.Errorf("ok = %q, ожидалось %q", ok, want)
	}
	if len(bad) != 7 {
		t.Errorf("bad = %q, ожидалось 7 записей", bad)
	}
	if ok, _ := normDomains(nil); ok == nil {
		t.Error("пустой список должен остаться пустым, а не nil: иначе при загрузке вернутся исключения по умолчанию")
	}
}

func TestNormServers(t *testing.T) {
	got := normServers([]string{" 8.8.8.8", "1.1.1.1", "8.8.8.8", "dns.google", "2001:4860:4860::8888", "1.2.3"})
	if want := []string{"8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"}; !reflect.DeepEqual(got, want) {
		t.Errorf("normServers = %q, ожидалось %q", got, want)
	}
}

func TestParseConfigDNSBypass(t *testing.T) {
	def := defaultSettings()
	cases := []struct {
		name, json      string
		bypass, servers []string
	}{
		{"файла нет", "", def.DNSBypass, def.DNSBypassServers},
		{"конфиг 1.2.0 без поля", `{"providers":[{"id":"comss","name":"Comss DNS","kind":"dns","ipv4":["83.220.169.155"]}],"auto_interval":30}`, []string{"figma.com"}, []string{"8.8.8.8", "1.1.1.1"}},
		{"поле null", `{"dns_bypass":null}`, []string{"figma.com"}, []string{"8.8.8.8", "1.1.1.1"}},
		{"пользователь убрал все исключения", `{"dns_bypass":[],"dns_bypass_servers":["9.9.9.9"]}`, []string{}, []string{"9.9.9.9"}},
		{"свой список", `{"dns_bypass":["https://www.notion.so/x","figma.com","bad host"],"dns_bypass_servers":["нет"]}`, []string{"www.notion.so", "figma.com"}, []string{"8.8.8.8", "1.1.1.1"}},
		{"битый json", `{"dns_bypass":`, def.DNSBypass, def.DNSBypassServers},
	}
	for _, tc := range cases {
		c := parseConfig([]byte(tc.json))
		if !reflect.DeepEqual(c.DNSBypass, tc.bypass) {
			t.Errorf("%s: dns_bypass = %q, ожидалось %q", tc.name, c.DNSBypass, tc.bypass)
		}
		if !reflect.DeepEqual(c.DNSBypassServers, tc.servers) {
			t.Errorf("%s: dns_bypass_servers = %q, ожидалось %q", tc.name, c.DNSBypassServers, tc.servers)
		}
		if len(c.Providers) == 0 || len(c.SeenDefaults) != len(def.Providers) {
			t.Errorf("%s: способы подключения не загружены: %d, seen %d", tc.name, len(c.Providers), len(c.SeenDefaults))
		}
	}
}
