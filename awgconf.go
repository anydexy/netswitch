package main

// Конфиг AmneziaWG (формат .conf, как у wg-quick/awg-quick) и регистрация WARP — то же,
// что делает github.com/ImMALWARE/bash-warp-generator (warp_generator.sh).

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

type awgConf struct {
	PrivateKey   string // base64
	Address      []netip.Prefix
	DNS          []string
	MTU          int
	Obf          [][2]string // jc, jmin, jmax, s1–s4, h1–h4, i1–i5 — в порядке из файла
	PeerKey      string      // base64
	PresharedKey string
	AllowedIPs   []string
	Endpoint     string // host:port
	Keepalive    int
}

var awgObfKeys = map[string]bool{"jc": true, "jmin": true, "jmax": true, "s1": true, "s2": true, "s3": true, "s4": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "i1": true, "i2": true, "i3": true, "i4": true, "i5": true}

// parseAWGConf разбирает конфиг AmneziaWG/WireGuard с одним пиром.
func parseAWGConf(text string) (awgConf, error) {
	c := awgConf{MTU: 1280}
	sec := ""
	peers := 0
	for _, ln := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, ";") {
			continue
		}
		if strings.HasPrefix(ln, "[") && strings.HasSuffix(ln, "]") {
			sec = strings.ToLower(strings.Trim(ln, "[] "))
			if sec == "peer" {
				peers++
			}
			continue
		}
		i := strings.Index(ln, "=")
		if i < 0 {
			return c, fmt.Errorf("непонятная строка: %q", ln)
		}
		key, val := strings.ToLower(strings.TrimSpace(ln[:i])), strings.TrimSpace(ln[i+1:])
		list := func() []string {
			var r []string
			for _, p := range strings.Split(val, ",") {
				if p = strings.TrimSpace(p); p != "" {
					r = append(r, p)
				}
			}
			return r
		}
		switch {
		case sec == "interface" && key == "privatekey":
			c.PrivateKey = val
		case sec == "interface" && key == "address":
			for _, a := range list() {
				p, err := netip.ParsePrefix(a)
				if err != nil {
					ip, err2 := netip.ParseAddr(a)
					if err2 != nil {
						return c, fmt.Errorf("адрес %q: %v", a, err)
					}
					p = netip.PrefixFrom(ip, ip.BitLen())
				}
				c.Address = append(c.Address, p)
			}
		case sec == "interface" && key == "dns":
			c.DNS = list()
		case sec == "interface" && key == "mtu":
			n, err := strconv.Atoi(val)
			if err != nil || n < 576 || n > 1500 {
				return c, fmt.Errorf("MTU %q", val)
			}
			c.MTU = n
		case sec == "interface" && awgObfKeys[key]:
			c.Obf = append(c.Obf, [2]string{key, val})
		case sec == "peer" && key == "publickey":
			c.PeerKey = val
		case sec == "peer" && key == "presharedkey":
			c.PresharedKey = val
		case sec == "peer" && key == "allowedips":
			c.AllowedIPs = list()
		case sec == "peer" && key == "endpoint":
			c.Endpoint = val
		case sec == "peer" && key == "persistentkeepalive":
			c.Keepalive, _ = strconv.Atoi(val)
		}
	}
	switch {
	case peers != 1:
		return c, errors.New("в конфиге должен быть ровно один [Peer]")
	case c.PrivateKey == "" || c.PeerKey == "":
		return c, errors.New("в конфиге нет PrivateKey или PublicKey")
	case len(c.Address) == 0:
		return c, errors.New("в конфиге нет Address")
	case c.Endpoint == "":
		return c, errors.New("в конфиге нет Endpoint")
	}
	for _, k := range []string{c.PrivateKey, c.PeerKey} {
		if _, err := keyHex(k); err != nil {
			return c, err
		}
	}
	if len(c.AllowedIPs) == 0 {
		c.AllowedIPs = []string{"0.0.0.0/0", "::/0"}
	}
	return c, nil
}

func keyHex(b64 string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("неверный ключ %q", b64)
	}
	return hex.EncodeToString(b), nil
}

// endpointHost и endpointPort — части Endpoint (IPv6 — в квадратных скобках).
func (c awgConf) endpointHostPort() (string, string, error) {
	return net.SplitHostPort(c.Endpoint)
}

// uapi — настройки для amneziawg-go (протокол UAPI). ep — адрес сервера с уже найденным IP.
func (c awgConf) uapi(ep netip.AddrPort) (string, error) {
	var sb strings.Builder
	priv, err := keyHex(c.PrivateKey)
	if err != nil {
		return "", err
	}
	peer, err := keyHex(c.PeerKey)
	if err != nil {
		return "", err
	}
	sb.WriteString("private_key=" + priv + "\n")
	for _, kv := range c.Obf {
		sb.WriteString(kv[0] + "=" + kv[1] + "\n")
	}
	sb.WriteString("replace_peers=true\npublic_key=" + peer + "\n")
	if c.PresharedKey != "" {
		psk, err := keyHex(c.PresharedKey)
		if err != nil {
			return "", err
		}
		sb.WriteString("preshared_key=" + psk + "\n")
	}
	sb.WriteString("endpoint=" + ep.String() + "\n")
	ka := c.Keepalive
	if ka == 0 {
		ka = 25 // за NAT без этого туннель засыпает
	}
	sb.WriteString("persistent_keepalive_interval=" + strconv.Itoa(ka) + "\n")
	sb.WriteString("replace_allowed_ips=true\n")
	for _, a := range c.AllowedIPs {
		if _, err := netip.ParsePrefix(a); err != nil {
			return "", fmt.Errorf("AllowedIPs %q: %v", a, err)
		}
		sb.WriteString("allowed_ip=" + a + "\n")
	}
	return sb.String(), nil
}

// resolveEndpoint — IP сервера (сначала IPv4: в сетях без IPv6 так надёжнее).
func (c awgConf) resolveEndpoint() (netip.AddrPort, error) {
	host, port, err := c.endpointHostPort()
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("Endpoint %q: %v", c.Endpoint, err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("порт %q", port)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(ip, uint16(p)), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("не удалось найти адрес %s: %v", host, err)
	}
	best := ips[0]
	for _, ip := range ips {
		if ip.To4() != nil {
			best = ip
			break
		}
	}
	a, _ := netip.AddrFromSlice(best)
	return netip.AddrPortFrom(a.Unmap(), uint16(p)), nil
}

// --- регистрация WARP ---

const (
	warpAPI      = "https://api.cloudflareclient.com/v0i1909051800"
	warpEndpoint = "162.159.192.1:500"
	// warpI1 — пакет-маскировка AmneziaWG 1.5 из warp_generator.sh: с ним рукопожатие WARP
	// выглядит для DPI как начало QUIC-соединения.
	warpI1 = "<b 0xc2000000011419fa4bb3599f336777de79f81ca9a8d80d91eeec000044c635cef024a885dcb66d1420a91a8c427e87d6cf8e08b563932f449412cddf77d3e2594ea1c7a183c238a89e9adb7ffa57c133e55c59bec101634db90afb83f75b19fe703179e26a31902324c73f82d9354e1ed8da39af610afcb27e6590a44341a0828e5a3d2f0e0f7b0945d7bf3402feea0ee6332e19bdf48ffc387a97227aa97b205a485d282cd66d1c384bafd63dc42f822c4df2109db5b5646c458236ddcc01ae1c493482128bc0830c9e1233f0027a0d262f92b49d9d8abd9a9e0341f6e1214761043c021d7aa8c464b9d865f5fbe234e49626e00712031703a3e23ef82975f014ee1e1dc428521dc23ce7c6c13663b19906240b3efe403cf30559d798871557e4e60e86c29ea4504ed4d9bb8b549d0e8acd6c334c39bb8fb42ede68fb2aadf00cfc8bcc12df03602bbd4fe701d64a39f7ced112951a83b1dbbe6cd696dd3f15985c1b9fef72fa8d0319708b633cc4681910843ce753fac596ed9945d8b839aeff8d3bf0449197bd0bb22ab8efd5d63eb4a95db8d3ffc796ed5bcf2f4a136a8a36c7a0c65270d511aebac733e61d414050088a1c3d868fb52bc7e57d3d9fd132d78b740a6ecdc6c24936e92c28672dbe00928d89b891865f885aeb4c4996d50c2bbbb7a99ab5de02ac89b3308e57bcecf13f2da0333d1420e18b66b4c23d625d836b538fc0c221d6bd7f566a31fa292b85be96041d8e0bfe655d5dc1afed23eb8f2b3446561bbee7644325cc98d31cea38b865bdcc507e48c6ebdc7553be7bd6ab963d5a14615c4b81da7081c127c791224853e2d19bafdc0d9f3f3a6de898d14abb0e2bc849917e0a599ed4a541268ad0e60ea4d147dc33d17fa82f22aa505ccb53803a31d10a7ca2fea0b290a52ee92c7bf4aab7cea4e3c07b1989364eed87a3c6ba65188cd349d37ce4eefde9ec43bab4b4dc79e03469c2ad6b902e28e0bbbbf696781ad4edf424ffb35ce0236d373629008f142d04b5e08a124237e03e3149f4cdde92d7fae581a1ac332e26b2c9c1a6bdec5b3a9c7a2a870f7a0c25fc6ce245e029b686e346c6d862ad8df6d9b62474fbc31dbb914711f78074d4441f4e6e9edca3c52315a5c0653856e23f681558d669f4a4e6915bcf42b56ce36cb7dd3983b0b1d6fdf0f8efddb68e7ca0ae9dd4570fe6978fbb524109f6ec957ca61f1767ef74eb803b0f16abd0087cf2d01bc1db1c01d97ac81b3196c934586963fe7cf2d310e0739621e8bd00dc23fded18576d8c8f285d7bb5f43b547af3c76235de8b6f757f817683b2151600b11721219212bf27558edd439e73fce951f61d582320e5f4d6c315c71129b719277fc144bbe8ded25ab6d29b6e189c9bd9b16538faf60cc2aab3c3bb81fc2213657f2dd0ceb9b3b871e1423d8d3e8cc008721ef03b28e0ee7bb66b8f2a2ac01ef88df1f21ed49bf1ce435df31ac34485936172567488812429c269b49ee9e3d99652b51a7a614b7c460bf0d2d64d8349ded7345bedab1ea0a766a8470b1242f38d09f7855a32db39516c2bd4bcc538c52fa3a90c8714d4b006a15d9c7a7d04919a1cab48da7cce0d5de1f9e5f8936cffe469132991c6eb84c5191d1bcf69f70c58d9a7b66846440a9f0eef25ee6ab62715b50ca7bef0bc3013d4b62e1639b5028bdf757454356e9326a4c76dabfb497d451a3a1d2dbd46ec283d255799f72dfe878ae25892e25a2542d3ca9018394d8ca35b53ccd94947a8>"
)

// warpConfText — конфиг в том же виде, что выдаёт warp_generator.sh.
func warpConfText(priv, v4, v6, peer string) string {
	addr := v4
	if v6 != "" {
		addr += ", " + v6
	}
	return "[Interface]\nPrivateKey = " + priv + "\nS1 = 0\nS2 = 0\nJc = 120\nJmin = 23\nJmax = 911\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\nMTU = 1280\nI1 = " + warpI1 +
		"\nAddress = " + addr + "\nDNS = 1.1.1.1, 2606:4700:4700::1111, 1.0.0.1, 2606:4700:4700::1001\n\n[Peer]\nPublicKey = " + peer +
		"\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = " + warpEndpoint + "\n"
}

// warpRegister регистрирует новое устройство WARP у Cloudflare и возвращает готовый конфиг.
func warpRegister() (string, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", err
	}
	priv[0] &= 248
	priv[31] = priv[31]&127 | 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	privB64, pubB64 := base64.StdEncoding.EncodeToString(priv[:]), base64.StdEncoding.EncodeToString(pub)

	c := httpClientVia("", 15*time.Second)
	call := func(method, path, token string, body any, out any) error {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, warpAPI+"/"+path, bytes.NewReader(b))
		req.Header.Set("User-Agent", "okhttp/3.12.1")
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := c.Do(req)
		if err != nil {
			return shortErr(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("Cloudflare ответил HTTP %d", resp.StatusCode)
		}
		return json.Unmarshal(data, out)
	}
	var reg struct {
		Result struct{ ID, Token string } `json:"result"`
	}
	if err := call("POST", "reg", "", map[string]string{"install_id": "", "tos": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"key": pubB64, "fcm_token": "", "type": "ios", "locale": "en_US"}, &reg); err != nil {
		return "", fmt.Errorf("регистрация WARP: %v", err)
	}
	if reg.Result.ID == "" || reg.Result.Token == "" {
		return "", errors.New("регистрация WARP: Cloudflare не выдал устройство")
	}
	var cfg struct {
		Result struct {
			Config struct {
				Peers []struct {
					PublicKey string `json:"public_key"`
				} `json:"peers"`
				Interface struct {
					Addresses struct{ V4, V6 string } `json:"addresses"`
				} `json:"interface"`
			} `json:"config"`
		} `json:"result"`
	}
	if err := call("PATCH", "reg/"+reg.Result.ID, reg.Result.Token, map[string]bool{"warp_enabled": true}, &cfg); err != nil {
		return "", fmt.Errorf("включение WARP: %v", err)
	}
	r := cfg.Result.Config
	if len(r.Peers) == 0 || r.Peers[0].PublicKey == "" || r.Interface.Addresses.V4 == "" {
		return "", errors.New("Cloudflare не прислал настройки WARP")
	}
	return warpConfText(privB64, r.Interface.Addresses.V4, r.Interface.Addresses.V6, r.Peers[0].PublicKey), nil
}
