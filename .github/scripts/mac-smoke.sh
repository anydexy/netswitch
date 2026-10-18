#!/bin/bash
# Проверка NetSwitch на настоящем macOS (раннер GitHub): запуск от root, DNS, исключения DNS,
# zapret (tpws + PF), тест стратегии, TG WS Proxy, выход. Раннер одноразовый — систему менять можно.
set -euo pipefail

BIN="$1"
DATA="$HOME/Library/Application Support/NetSwitch"
rm -rf "$DATA"

sudo env GITHUB_TOKEN="${GITHUB_TOKEN:-}" "$BIN" --tray --uid "$(id -u)" --gid "$(id -g)" --home "$HOME" >/tmp/netswitch.out 2>&1 &
for i in $(seq 60); do [ -s "$DATA/instance.json" ] && break; sleep 1; done
URL=$(jq -r .url "$DATA/instance.json")
BASE=${URL%%/\?*}
T=${URL##*t=}

api() {
	local body='{}'
	[ $# -ge 2 ] && body=$2
	curl -sfS -X POST -H "X-Token: $T" -H 'Content-Type: application/json' -d "$body" "$BASE$1"
}
state() { api /api/state | jq "$1"; }
fail() {
	echo "::error::$1"
	api /api/state | jq -c '.data | {zapret: .zapret.download_msg, tgws: .tgws.download_msg}' || true
	echo "--- netswitch.log"; cat "$DATA/netswitch.log" || true
	exit 1
}
wait_for() { # wait_for <jq-условие> <секунд>
	for i in $(seq "$2"); do [ "$(state "$1")" = true ] && return 0; sleep 1; done
	fail "не дождались: $1"
}

echo "== состояние после запуска"
wait_for '.data.app.adapters | length > 0' 60
state '.data | {version, admin, platform, app: (.app | {internet, adapters, system_dns, active})}'
[ "$(state .data.admin)" = true ] || fail "нет прав администратора"
[ "$(state .data.platform)" = '"darwin"' ] || fail "не darwin"
[ "$(stat -f %Su "$DATA/netswitch.json")" = "$(id -un)" ] || fail "netswitch.json принадлежит не пользователю"

echo "== проверка способов"
wait_for '.data.app.provs.cloudflare.checked != null and .data.app.provs.cloudflare.checked != ""' 90
state '.data.app.provs.cloudflare | {alive, internet, dns_ms, ping_ms, best, geo_ok}'
[ "$(state .data.app.provs.cloudflare.alive)" = true ] || fail "Cloudflare DNS не ответил"
[ "$(state '.data.app.provs.cloudflare.ping_ms > 0')" = true ] || fail "ping не разобран"

echo "== подключение Cloudflare DNS"
api /api/connect '{"id":"cloudflare"}' | jq -c .
scutil --dns | grep -m3 nameserver
networksetup -listallnetworkservices | tail -n +2 | while read -r s; do echo "$s: $(networksetup -getdnsservers "$s" | tr '\n' ' ')"; done
scutil --dns | grep -q '1\.1\.1\.1\|1\.0\.0\.1' || fail "DNS 1.1.1.1 не прописан"
[ -f /etc/resolver/figma.com ] || fail "нет исключения /etc/resolver/figma.com"
cat /etc/resolver/figma.com
scutil --dns | grep -A3 'domain   : figma.com' || fail "macOS не видит исключение figma.com"
dscacheutil -q host -a name www.figma.com | head -3
wait_for '.data.app.active == "cloudflare"' 30

echo "== отключение"
api /api/disconnect | jq -c .
[ ! -f /etc/resolver/figma.com ] || fail "исключение не снято"
scutil --dns | grep -m3 nameserver

echo "== zapret: скачивание"
api /api/zapret/download | jq -c .
wait_for '.data.zapret.installed and (.data.zapret.downloading | not)' 180
state '.data.zapret | {local_version, strategies, download_msg}'
file "$DATA/zapret/tpws"

echo "== zapret: запуск"
api /api/zapret/start '{}' | jq -c .
[ "$(state .data.zapret.running)" = true ] || fail "zapret не запустился"
pgrep -fl tpws
sudo pfctl -a com.apple/netswitch -s nat
sudo pfctl -a com.apple/netswitch -s rules
sudo pfctl -a com.apple/netswitch -s nat | grep -q 'port = 988\|port 988' || fail "нет правил PF"
sudo pfctl -a com.apple/netswitch -s rules | grep -q 'block drop out quick proto udp' || fail "QUIC не блокируется"
code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 https://www.youtube.com/)
echo "youtube через tpws: HTTP $code"
[ "$code" != 000 ] || fail "сайт не открылся при включённом zapret"
sudo pfctl -ss | grep -c '988' || true
echo "--- tpws.log"; cat "$DATA/zapret/tpws.log" || true

echo "== zapret: остановка"
api /api/zapret/stop | jq -c .
[ -z "$(sudo pfctl -a com.apple/netswitch -s rules 2>/dev/null)" ] || fail "правила PF не сняты"
! pgrep -x tpws || fail "tpws не остановлен"
curl -sS -o /dev/null -w 'после остановки: HTTP %{http_code}\n' --max-time 20 https://www.youtube.com/

echo "== zapret: тест стратегии"
api /api/zapret/test '{"only":["Разрез SNI"]}' | jq -c .
sleep 2
wait_for '.data.zapret.test.running | not' 180
state '.data.zapret.test | {finished, results: [.results[] | {name, ok, total, details}]}'
[ "$(state '[.data.zapret.test.results[] | select(.name == "Разрез SNI") | .ok] | first > 0')" = true ] || fail "через tpws (SOCKS) сайты не открылись"

echo "== TG WS Proxy"
api /api/tgws/download | jq -c .
wait_for '.data.tgws.installed and (.data.tgws.downloading | not)' 240
state '.data.tgws | {local_version, download_msg}'
ls "$DATA/tgws"
api /api/tgws/start | jq -c . || true
sleep 8
state '.data.tgws | {running, listening, host, port, link}'
ps -axo pid,user,comm | grep -i tgwsproxy | grep -v grep || true
[ "$(state .data.tgws.running)" = true ] || echo "::warning::TG WS Proxy не запустился (на раннере без экрана это возможно)"
api /api/tgws/stop | jq -c . || true

echo "== WARP (AmneziaWG)"
before=$(netstat -rn -f inet | grep -c utun || true)
res=$(api /api/connect '{"id":"warp"}'); echo "$res" | jq -c .
[ "$(echo "$res" | jq .ok)" = true ] || fail "WARP не подключился: $(echo "$res" | jq -r .error)"
state '.data.warp'
[ "$(state '.data.warp.up and .data.warp.handshake >= 0')" = true ] || fail "нет рукопожатия WARP"
netstat -rn -f inet | grep -E '^(0/1|128.0/1|162\.159)' || true
trace=$(curl -sS --max-time 20 https://www.cloudflare.com/cdn-cgi/trace)
echo "$trace" | grep -E '^(ip|loc|warp)='
echo "$trace" | grep -q '^warp=on' || fail "трафик идёт не через WARP"
scutil --dns | grep -m2 nameserver
[ -f "$DATA/warp.conf" ] || fail "нет warp.conf"
grep -q '^I1 = <b 0x' "$DATA/warp.conf" || fail "в конфиге нет I1"
api /api/disconnect | jq -c .
sleep 1
trace=$(curl -sS --max-time 20 https://www.cloudflare.com/cdn-cgi/trace)
echo "$trace" | grep -E '^(warp)='
echo "$trace" | grep -q '^warp=off' || fail "после отключения трафик всё ещё в WARP"
! netstat -rn -f inet | grep -q '^162\.159\.192\.1 ' || fail "остался маршрут к серверу WARP"
scutil --dns | grep -m2 nameserver

echo "== выход"
api /api/exit | jq -c . || true
sleep 3
! pgrep -f "$BIN --tray" || fail "программа не вышла"
echo "--- netswitch.log"; cat "$DATA/netswitch.log"
echo "OK"
