package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// dnsQueryA отправляет A-запрос напрямую на сервер (UDP/53) и возвращает IP-адреса и время ответа.
func dnsQueryA(server, name string, timeout time.Duration) ([]net.IP, time.Duration, error) {
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])

	msg := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(msg[0:], id)
	binary.BigEndian.PutUint16(msg[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(msg[4:], 1)      // QDCOUNT
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, 0, errors.New("bad name")
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0, 0, 1, 0, 1) // root, QTYPE=A, QCLASS=IN

	start := time.Now()
	conn, err := net.DialTimeout("udp", net.JoinHostPort(server, "53"), timeout)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(msg); err != nil {
		return nil, 0, err
	}
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, 0, err
		}
		if n < 12 || binary.BigEndian.Uint16(buf[0:]) != id {
			continue
		}
		rtt := time.Since(start)
		ips, err := parseDNSAnswer(buf[:n])
		return ips, rtt, err
	}
}

func skipName(b []byte, off int) (int, error) {
	for {
		if off >= len(b) {
			return 0, errors.New("short")
		}
		l := int(b[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xC0 == 0xC0:
			return off + 2, nil
		default:
			off += 1 + l
		}
	}
}

func parseDNSAnswer(b []byte) ([]net.IP, error) {
	rcode := b[3] & 0x0F
	if rcode != 0 {
		return nil, fmt.Errorf("rcode %d", rcode)
	}
	qd := int(binary.BigEndian.Uint16(b[4:]))
	an := int(binary.BigEndian.Uint16(b[6:]))
	off := 12
	var err error
	for i := 0; i < qd; i++ {
		if off, err = skipName(b, off); err != nil {
			return nil, err
		}
		off += 4
	}
	var ips []net.IP
	for i := 0; i < an; i++ {
		if off, err = skipName(b, off); err != nil {
			return nil, err
		}
		if off+10 > len(b) {
			return nil, errors.New("short")
		}
		typ := binary.BigEndian.Uint16(b[off:])
		rdlen := int(binary.BigEndian.Uint16(b[off+8:]))
		off += 10
		if off+rdlen > len(b) {
			return nil, errors.New("short")
		}
		if typ == 1 && rdlen == 4 {
			ip := net.IPv4(b[off], b[off+1], b[off+2], b[off+3])
			ips = append(ips, ip)
		}
		off += rdlen
	}
	if len(ips) == 0 {
		return nil, errors.New("нет ответа")
	}
	return ips, nil
}

func bogusIP(ip net.IP) bool {
	return ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"

// httpClientVia — HTTP-клиент, который резолвит имена через указанный DNS-сервер
// (server == "" — системный резолвер).
func httpClientVia(server string, timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{
		Proxy:               nil,
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     &tls.Config{},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if server == "" {
				return d.DialContext(ctx, network, addr)
			}
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if net.ParseIP(host) == nil {
				ips, _, err := dnsQueryA(server, host, 3*time.Second)
				if err != nil {
					return nil, fmt.Errorf("DNS: %v", err)
				}
				if bogusIP(ips[0]) {
					return nil, fmt.Errorf("DNS вернул заглушку %s", ips[0])
				}
				host = ips[0].String()
			}
			return d.DialContext(ctx, "tcp4", net.JoinHostPort(host, port))
		},
	}
	return &http.Client{Transport: tr, Timeout: timeout + 2*time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// cfTrace запрашивает https://<domain>/cdn-cgi/trace и возвращает страну (loc=), которую видит сайт.
func cfTrace(c *http.Client, domain string) (string, time.Duration, error) {
	req, _ := http.NewRequest("GET", "https://"+domain+"/cdn-cgi/trace", nil)
	req.Header.Set("User-Agent", browserUA)
	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return "", 0, shortErr(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	dt := time.Since(start)
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "loc=") {
			return strings.TrimSpace(line[4:]), dt, nil
		}
	}
	if resp.StatusCode == 403 || resp.StatusCode == 451 {
		return "", dt, fmt.Errorf("доступ запрещён (%d)", resp.StatusCode)
	}
	return "", dt, fmt.Errorf("HTTP %d", resp.StatusCode)
}

// netCheck — есть ли интернет (через указанный DNS или системный).
// netCheckFallbacks — запасные адреса проверки на других CDN. Узел одного CDN бывает недоступен
// у провайдера (так бывает с частью адресов Akamai у msftconnecttest, которые отдаёт Comss),
// и по одному адресу программа ошибочно решала, что интернета нет.
var netCheckFallbacks = []string{
	"http://cp.cloudflare.com/generate_204",
	"http://connectivitycheck.gstatic.com/generate_204",
}

// netCheck — есть ли интернет (через DNS server или системный): параллельно проверяет net_test
// и запасные адреса, достаточно одного ответа. Время — самого быстрого.
func netCheck(server string) (bool, time.Duration) {
	urls := []string{getCfg().NetTest}
	for _, u := range netCheckFallbacks {
		if u != urls[0] {
			urls = append(urls, u)
		}
	}
	type result struct {
		ok bool
		dt time.Duration
	}
	ch := make(chan result, len(urls))
	for _, u := range urls {
		go func(u string) {
			start := time.Now()
			resp, err := httpClientVia(server, 5*time.Second).Get(u)
			if err != nil {
				ch <- result{}
				return
			}
			resp.Body.Close()
			ch <- result{resp.StatusCode < 500, time.Since(start)}
		}(u)
	}
	for range urls {
		if r := <-ch; r.ok {
			return true, r.dt
		}
	}
	return false, 0
}

func shortErr(err error) error {
	if err == nil {
		return nil
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "timeout") || strings.Contains(s, "deadline"):
		return errors.New("таймаут")
	case strings.Contains(s, "connection reset") || strings.Contains(s, "forcibly closed"):
		return errors.New("соединение сброшено (DPI)")
	case strings.Contains(s, "refused"):
		return errors.New("соединение отклонено")
	case strings.Contains(s, "DNS"):
		if i := strings.Index(s, "DNS"); i >= 0 {
			return errors.New(s[i:])
		}
	}
	if len(s) > 80 {
		s = s[len(s)-80:]
	}
	return errors.New(s)
}
