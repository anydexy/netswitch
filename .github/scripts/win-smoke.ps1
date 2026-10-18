# Проверка NetSwitch на Windows (раннер GitHub, администратор): DNS, WARP через AmneziaWG
# (wintun, маршруты, DNS туннеля), выход. Раннер одноразовый — систему менять можно.
param([string]$Bin)
$ErrorActionPreference = 'Stop'
$dir = Split-Path $Bin
$log = Join-Path $dir 'netswitch.log'

Start-Process $Bin -ArgumentList '--tray'
$inst = "$env:LOCALAPPDATA\NetSwitch\instance.json"
for ($i = 0; $i -lt 60 -and -not (Test-Path $inst); $i++) { Start-Sleep 1 }
$url = (Get-Content $inst | ConvertFrom-Json).url
$base = $url.Split('?')[0].TrimEnd('/'); $tok = $url.Split('t=')[-1]

function Api($p, $body = '{}') {
	Invoke-RestMethod -Method Post -Uri "$base$p" -Headers @{ 'X-Token' = $tok } -Body $body -ContentType 'application/json; charset=utf-8' -TimeoutSec 90
}
function Fail($m) {
	Write-Host "::error::$m"
	if (Test-Path $log) { Get-Content $log -Encoding UTF8 }
	exit 1
}
function Trace() {
	(Invoke-WebRequest https://www.cloudflare.com/cdn-cgi/trace -UseBasicParsing -TimeoutSec 20).Content
}

'== состояние'
for ($i = 0; $i -lt 60; $i++) { $s = (Api '/api/state').data; if ($s.app.adapters.Count -gt 0) { break }; Start-Sleep 1 }
$s | Select-Object version, admin, platform | Format-List
$s.app | Select-Object internet, adapters, system_dns | Format-List
if (-not $s.admin) { Fail 'нет прав администратора' }

'== Cloudflare DNS'
$r = Api '/api/connect' '{"id":"cloudflare"}'
if (-not $r.ok) { Fail "DNS: $($r.error)" }
Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object ServerAddresses | Format-Table InterfaceAlias, ServerAddresses
$r = Api '/api/disconnect'

'== WARP (AmneziaWG)'
$r = Api '/api/connect' '{"id":"warp"}'
if (-not $r.ok) { Fail "WARP: $($r.error)" }
(Api '/api/state').data.warp | Format-List
Get-NetAdapter -Name 'NetSwitch WARP' | Format-Table Name, InterfaceDescription, Status, ifIndex
Get-NetRoute -DestinationPrefix '0.0.0.0/1', '128.0.0.0/1' | Format-Table DestinationPrefix, InterfaceAlias, NextHop
Get-NetIPAddress -InterfaceAlias 'NetSwitch WARP' | Format-Table IPAddress, PrefixLength, AddressState, SkipAsSource
Get-NetIPInterface -InterfaceAlias 'NetSwitch WARP' | Format-Table AddressFamily, InterfaceMetric, NlMtu, Dhcp, ConnectionState
Get-DnsClientServerAddress -InterfaceAlias 'NetSwitch WARP' | Format-Table AddressFamily, ServerAddresses
try { Find-NetRoute -RemoteIPAddress 1.1.1.1 | Format-Table IPAddress, InterfaceAlias, DestinationPrefix, NextHop } catch { "Find-NetRoute: $_" }
ping -n 3 1.1.1.1
try { Resolve-DnsName www.cloudflare.com -Server 1.1.1.1 -Type A -DnsOnly | Format-Table Name, IPAddress } catch { "Resolve-DnsName: $_" }
(Api '/api/state').data.warp | Select-Object handshake, rx, tx | Format-List
$t = Trace
$t -split "`n" | Where-Object { $_ -match '^(ip|loc|warp)=' }
if ($t -notmatch 'warp=on') { Fail 'трафик идёт не через WARP' }
if (-not (Test-Path (Join-Path $dir 'wintun.dll'))) { Fail 'нет wintun.dll' }

$r = Api '/api/disconnect'
Start-Sleep 2
$t = Trace
$t -split "`n" | Where-Object { $_ -match '^warp=' }
if ($t -notmatch 'warp=off') { Fail 'после отключения трафик всё ещё в WARP' }
if (Get-NetAdapter -Name 'NetSwitch WARP' -ErrorAction SilentlyContinue) { Fail 'адаптер WARP не удалён' }

'== выход'
try { Api '/api/exit' | Out-Null } catch {}
Start-Sleep 3
if (Get-Process -Name NetSwitch -ErrorAction SilentlyContinue) { Fail 'программа не вышла' }
Get-Content $log -Encoding UTF8
'OK'
