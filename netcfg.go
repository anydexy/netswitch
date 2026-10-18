package main

import (
	"fmt"
	"net"
	"slices"
	"strings"
)

// Смена DNS и исключения DNS зависят от системы: netcfg_windows.go (PowerShell, NRPT)
// и netcfg_darwin.go (networksetup, /etc/resolver).

type Adapter struct {
	Index int      `json:"InterfaceIndex"`
	Alias string   `json:"InterfaceAlias"`
	Desc  string   `json:"InterfaceDescription"`
	DNS   []string `json:"DNS"`
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
