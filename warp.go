package main

// Cloudflare WARP через AmneziaWG: NetSwitch сам регистрирует устройство WARP (как
// bash-warp-generator), хранит конфиг в warp.conf и поднимает туннель встроенным amneziawg-go.
// Отдельный клиент WARP или AmneziaWG не нужен. Туннель работает, пока запущен NetSwitch.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func warpConfPath() string { return filepath.Join(appDir(), "warp.conf") }

// warpConf — конфиг WARP; если его ещё нет — регистрирует новое устройство.
func warpConf(generate bool) (awgConf, error) {
	b, err := os.ReadFile(warpConfPath())
	if err != nil {
		if !generate {
			return awgConf{}, errors.New("нет конфига WARP")
		}
		text, err := warpRegister()
		if err != nil {
			return awgConf{}, fmt.Errorf("%v. Конфиг можно сделать в GitHub Codespaces (bash warp_generator.sh) и вставить на вкладке WARP", err)
		}
		if err := warpSaveConf(text); err != nil {
			return awgConf{}, err
		}
		logf("WARP: зарегистрировано новое устройство")
		b = []byte(text)
	}
	return parseAWGConf(string(b))
}

// warpSaveConf проверяет и сохраняет конфиг (свой или сгенерированный).
func warpSaveConf(text string) error {
	if _, err := parseAWGConf(text); err != nil {
		return err
	}
	p := warpConfPath()
	if err := os.WriteFile(p, []byte(strings.TrimSpace(text)+"\n"), 0600); err != nil {
		return err
	}
	fixOwner(p)
	return nil
}

// WarpInfo — что показать на вкладке WARP.
type WarpInfo struct {
	HasConf   bool   `json:"has_conf"`
	Endpoint  string `json:"endpoint"`
	Address   string `json:"address"`
	Obf       bool   `json:"obf"` // есть параметры маскировки AmneziaWG
	Up        bool   `json:"up"`
	Handshake int    `json:"handshake"` // секунд с последнего рукопожатия, -1 — не было
	RxBytes   int64  `json:"rx"`
	TxBytes   int64  `json:"tx"`
	Err       string `json:"err,omitempty"`
}

func warpInfo() WarpInfo {
	wi := WarpInfo{Handshake: -1}
	if b, err := os.ReadFile(warpConfPath()); err == nil {
		wi.HasConf = true
		if c, err := parseAWGConf(string(b)); err == nil {
			wi.Endpoint = c.Endpoint
			var a []string
			for _, p := range c.Address {
				a = append(a, p.Addr().String())
			}
			wi.Address = strings.Join(a, ", ")
			wi.Obf = len(c.Obf) > 0
		} else {
			wi.Err = err.Error()
		}
	}
	up, hs, rx, tx := awgInfo()
	wi.Up, wi.RxBytes, wi.TxBytes = up, rx, tx
	if hs > 0 {
		wi.Handshake = int(hs.Seconds())
	}
	return wi
}

// warpEndpointHost — адрес сервера WARP для пинга.
func warpEndpointHost() string {
	if c, err := warpConf(false); err == nil {
		if h, _, err := c.endpointHostPort(); err == nil {
			return h
		}
	}
	h, _, _ := strings.Cut(warpEndpoint, ":")
	return h
}

// warpStatus: installed (можно подключить), connected, текст статуса.
func warpStatus() (bool, bool, string) {
	up, hs, _, _ := awgInfo()
	switch {
	case up && hs > 0 && hs < 3*time.Minute:
		return true, true, "Подключён (AmneziaWG)"
	case up && hs > 0:
		return true, false, "Нет связи с сервером WARP"
	case up:
		return true, false, "Подключается…"
	}
	if _, err := os.Stat(warpConfPath()); err != nil {
		return true, false, "Конфиг создастся при подключении"
	}
	return true, false, "Отключён"
}

func warpConnect() error {
	c, err := warpConf(true)
	if err != nil {
		return err
	}
	// официальный клиент WARP со своим туннелем мешал бы — отключить его
	if cli := warpCLI(); cli != "" {
		_, _ = run(15*time.Second, cli, "--accept-tos", "disconnect")
	}
	if err := awgUp(c); err != nil {
		return err
	}
	if err := awgWaitHandshake(12 * time.Second); err != nil {
		awgDown()
		return err
	}
	return nil
}

func warpDisconnect() { awgDown() }
