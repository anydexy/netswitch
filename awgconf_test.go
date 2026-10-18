package main

import (
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
)

func TestWarpConfRoundTrip(t *testing.T) {
	priv := base64.StdEncoding.EncodeToString(make([]byte, 32))
	peer := base64.StdEncoding.EncodeToString([]byte("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")[:32])
	text := warpConfText(priv, "172.16.0.2/32", "2606:4700:110:8a36::1/128", peer)
	c, err := parseAWGConf(text)
	if err != nil {
		t.Fatal(err)
	}
	if c.MTU != 1280 || c.Endpoint != "162.159.192.1:500" || len(c.Address) != 2 || len(c.DNS) != 4 {
		t.Errorf("конфиг разобран неверно: %+v", c)
	}
	if len(c.Obf) != 10 || c.Obf[0] != [2]string{"s1", "0"} || c.Obf[9][0] != "i1" || !strings.HasPrefix(c.Obf[9][1], "<b 0xc2") {
		t.Errorf("параметры AmneziaWG: %v", c.Obf[:3])
	}
	ep, err := c.resolveEndpoint()
	if err != nil || ep != netip.MustParseAddrPort("162.159.192.1:500") {
		t.Fatalf("endpoint %v %v", ep, err)
	}
	u, err := c.uapi(ep)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		"private_key=" + strings.Repeat("00", 32) + "\n",
		"jc=120\njmin=23\njmax=911\n",
		"h4=4\ni1=<b 0xc2",
		"replace_peers=true\npublic_key=",
		"endpoint=162.159.192.1:500\npersistent_keepalive_interval=25\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n",
	} {
		if !strings.Contains(u, s) {
			t.Errorf("в UAPI нет %q", s)
		}
	}
	// параметры устройства должны идти до public_key, иначе amneziawg-go отнесёт их к пиру
	if strings.Index(u, "i1=") > strings.Index(u, "public_key=") {
		t.Error("i1 после public_key")
	}
}

func TestParseAWGConfErrors(t *testing.T) {
	for name, text := range map[string]string{
		"нет пира":     "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\n",
		"плохой ключ":  "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = abc\nEndpoint = 1.2.3.4:500\n",
		"нет endpoint": "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
		"не конфиг":    "привет",
		"два пира":     "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nEndpoint = 1.2.3.4:500\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
	} {
		if _, err := parseAWGConf(text); err == nil {
			t.Errorf("%s: ошибки нет", name)
		}
	}
	// конфиг AmneziaVPN с комментариями, без AllowedIPs и адресом без маски
	c, err := parseAWGConf("# WARP\r\n[Interface]\r\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\nAddress = 172.16.0.2\r\nJc = 4\r\n\r\n[Peer]\r\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\nEndpoint = engage.cloudflareclient.com:2408\r\nPersistentKeepalive = 15\r\n")
	if err != nil || c.Address[0].String() != "172.16.0.2/32" || len(c.AllowedIPs) != 2 || c.Keepalive != 15 {
		t.Errorf("конфиг AmneziaVPN: %+v %v", c, err)
	}
}
