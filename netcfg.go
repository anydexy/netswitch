package main

import (
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"
)

type Adapter struct {
	Index int      `json:"InterfaceIndex"`
	Alias string   `json:"InterfaceAlias"`
	Desc  string   `json:"InterfaceDescription"`
	DNS   []string `json:"DNS"`
}

// listAdapters — физические сетевые адаптеры, которые сейчас подключены.
func listAdapters() ([]Adapter, error) {
	script := `$r=@(); Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Up'} | ForEach-Object {
  $d=@(Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue | ForEach-Object {$_.ServerAddresses});
  $r += [pscustomobject]@{InterfaceIndex=$_.ifIndex;InterfaceAlias=$_.Name;InterfaceDescription=$_.InterfaceDescription;DNS=@($d)} };
ConvertTo-Json -InputObject @($r) -Compress -Depth 4`
	out, err := ps(20*time.Second, script)
	if err != nil {
		return nil, fmt.Errorf("PowerShell: %v %s", err, strings.TrimSpace(out))
	}
	out = strings.TrimSpace(out)
	if i := strings.Index(out, "["); i > 0 {
		out = out[i:]
	}
	var a []Adapter
	if err := json.Unmarshal([]byte(out), &a); err != nil {
		return nil, fmt.Errorf("адаптеры: %v", err)
	}
	return a, nil
}

// setSystemDNS прописывает DNS на все активные физические адаптеры (IPv4 и IPv6).
func setSystemDNS(v4, v6 []string, doh string) error {
	c := getCfg()
	addrs := append([]string{}, v4...)
	if c.SetIPv6 {
		addrs = append(addrs, v6...)
	}
	list := make([]string, len(addrs))
	for i, a := range addrs {
		list[i] = psQuote(a)
	}
	var sb strings.Builder
	// Шифрованный DNS (DoH) — только Windows 11; на Windows 10 команда просто не сработает.
	if c.UseDoH && doh != "" {
		for _, a := range addrs {
			sb.WriteString(fmt.Sprintf("try{Remove-DnsClientDohServerAddress -ServerAddress %s -ErrorAction SilentlyContinue}catch{};try{Add-DnsClientDohServerAddress -ServerAddress %s -DohTemplate %s -AllowFallbackToUdp $true -AutoUpgrade $true -ErrorAction Stop}catch{};",
				psQuote(a), psQuote(a), psQuote(doh)))
		}
	}
	sb.WriteString(`$n=0; Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses @(` + strings.Join(list, ",") + `) -ErrorAction Stop; $n++ };`)
	sb.WriteString(`Clear-DnsClientCache; ipconfig /flushdns | Out-Null; Write-Output "OK $n"`)
	out, err := ps(40*time.Second, sb.String())
	if err != nil || !strings.Contains(out, "OK ") {
		return fmt.Errorf("не удалось прописать DNS: %s", strings.TrimSpace(out))
	}
	if strings.Contains(out, "OK 0") {
		return fmt.Errorf("нет активных сетевых адаптеров")
	}
	return nil
}

// resetSystemDNS — вернуть DNS "автоматически" (от провайдера/роутера).
func resetSystemDNS() error {
	out, err := ps(40*time.Second, `Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses }; Clear-DnsClientCache; ipconfig /flushdns | Out-Null; Write-Output OK`)
	if err != nil || !strings.Contains(out, "OK") {
		return fmt.Errorf("не удалось сбросить DNS: %s", strings.TrimSpace(out))
	}
	return nil
}

// nrptMark — метка (Comment) правил NRPT, которые ставит NetSwitch: по ней находим и снимаем только свои.
const nrptMark = "NetSwitch"

// bypassScript — PowerShell: снять свои правила NRPT и поставить новые — домены из списка
// (и их поддомены) резолвятся через servers, а не через DNS адаптеров. Пустой список — только снять.
func bypassScript(domains, servers []string) string {
	var sb strings.Builder
	// -ErrorAction Stop прерывает только свою команду, без try скрипт пошёл бы дальше и ответил "OK"
	sb.WriteString(`try{ $n=0; @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object {$_.Comment -eq ` + psQuote(nrptMark) + `}) | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction Stop; $n++ };`)
	if len(domains) > 0 {
		list := make([]string, len(servers))
		for i, s := range servers {
			list[i] = psQuote(s)
		}
		for _, d := range domains {
			// ".figma.com" — все поддомены, "figma.com" — сам домен
			sb.WriteString(fmt.Sprintf("Add-DnsClientNrptRule -Namespace %s,%s -NameServers %s -Comment %s -DisplayName %s -ErrorAction Stop; $n++;",
				psQuote("."+d), psQuote(d), strings.Join(list, ","), psQuote(nrptMark), psQuote("NetSwitch: "+d)))
		}
	}
	sb.WriteString(`if($n){Clear-DnsClientCache; ipconfig /flushdns | Out-Null}; Write-Output "OK $n" }catch{ Write-Output $_.Exception.Message }`)
	return sb.String()
}

// setDNSBypass ставит исключения DNS через таблицу политик разрешения имён Windows (NRPT).
// Chrome и Edge при наличии правил NRPT сами переходят на системный резолвер, если в них не включён «Безопасный DNS».
func setDNSBypass(domains, servers []string) error {
	if len(domains) > 0 && len(servers) == 0 {
		return fmt.Errorf("не заданы DNS-серверы для исключений")
	}
	out, err := ps(40*time.Second, bypassScript(domains, servers))
	if err != nil || !strings.Contains(out, "OK ") {
		return fmt.Errorf("не удалось настроить исключения DNS: %s", strings.TrimSpace(out))
	}
	return nil
}

// normDomains приводит записи списка исключений к виду "figma.com" (без схемы, пути, "*." и
// точек по краям) и убирает повторы. bad — записи, которые доменом не являются.
func normDomains(list []string) (ok, bad []string) {
	ok = []string{}
	seen := map[string]bool{}
	for _, s := range list {
		d := strings.ToLower(strings.TrimSpace(s))
		if i := strings.Index(d, "://"); i >= 0 {
			d = d[i+3:]
		}
		if i := strings.IndexAny(d, "/?#:"); i >= 0 {
			d = d[:i]
		}
		d = strings.Trim(strings.TrimPrefix(d, "*."), ".")
		if d == "" {
			continue
		}
		if !validDomain(d) {
			bad = append(bad, strings.TrimSpace(s))
			continue
		}
		if !seen[d] {
			seen[d] = true
			ok = append(ok, d)
		}
	}
	return ok, bad
}

// validDomain — имя из латиницы, цифр и дефисов, не меньше двух частей (зону вроде "com" целиком не отдаём).
func validDomain(d string) bool {
	parts := strings.Split(d, ".")
	if len(d) > 253 || len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 63 || p[0] == '-' || p[len(p)-1] == '-' {
			return false
		}
		for _, r := range p {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// normServers — только корректные IP-адреса, без повторов.
func normServers(list []string) []string {
	out := []string{}
	for _, s := range list {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip != nil && !slices.Contains(out, ip.String()) {
			out = append(out, ip.String())
		}
	}
	return out
}

// detectActiveDNS — какой провайдер сейчас прописан в системе (по IP).
func detectActiveDNS(adapters []Adapter) string {
	for _, a := range adapters {
		for _, d := range a.DNS {
			for _, p := range getCfg().Providers {
				if p.Kind != "dns" {
					continue
				}
				for _, ip := range append(append([]string{}, p.IPv4...), p.IPv6...) {
					if strings.EqualFold(ip, d) {
						return p.ID
					}
				}
			}
		}
	}
	return ""
}
