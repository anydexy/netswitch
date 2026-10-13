package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func withNetTest(t *testing.T, main string, fallbacks ...string) {
	t.Helper()
	cfgMu.Lock()
	prev := cfg
	cfg.NetTest = main
	cfgMu.Unlock()
	old := netCheckFallbacks
	netCheckFallbacks = fallbacks
	t.Cleanup(func() {
		cfgMu.Lock()
		cfg = prev
		cfgMu.Unlock()
		netCheckFallbacks = old
	})
}

func TestNetCheckFallback(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer ok.Close()
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(4 * time.Second):
		}
	}))
	defer hang.Close()
	const dead = "http://127.0.0.1:1/connecttest.txt"

	withNetTest(t, dead, ok.URL)
	if got, _ := netCheck(""); !got {
		t.Error("основной адрес недоступен, запасной отвечает — интернет должен быть")
	}

	withNetTest(t, hang.URL, ok.URL)
	start := time.Now()
	if got, _ := netCheck(""); !got || time.Since(start) > 2*time.Second {
		t.Errorf("основной висит, запасной отвечает: %v за %v — ждать зависший не нужно", got, time.Since(start))
	}

	withNetTest(t, dead, "http://127.0.0.1:1/generate_204")
	if got, _ := netCheck(""); got {
		t.Error("все адреса недоступны — интернета быть не должно")
	}
}

// Только чтение сети: NETSWITCH_LIVE=1 go test -run LiveNetCheck -v
func TestLiveNetCheck(t *testing.T) {
	if os.Getenv("NETSWITCH_LIVE") == "" {
		t.Skip("NETSWITCH_LIVE не задан")
	}
	loadConfig()
	for _, srv := range []string{"", "83.220.169.155", "212.109.195.93", "8.8.8.8"} {
		ok, dt := netCheck(srv)
		t.Logf("DNS %-15q интернет: %v, %v", srv, ok, dt.Round(time.Millisecond))
		for _, u := range append([]string{getCfg().NetTest}, netCheckFallbacks...) {
			start := time.Now()
			resp, err := httpClientVia(srv, 5*time.Second).Get(u)
			if err != nil {
				t.Logf("    ✗ %s — %v", u, shortErr(err))
				continue
			}
			resp.Body.Close()
			t.Logf("    ✓ %s — HTTP %d, %v", u, resp.StatusCode, time.Since(start).Round(time.Millisecond))
		}
	}
}
