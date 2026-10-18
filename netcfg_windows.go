//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

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
