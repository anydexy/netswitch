package main

// Туннель AmneziaWG внутри NetSwitch (github.com/amnezia-vpn/amneziawg-go): виртуальный сетевой
// адаптер (wintun в Windows, utun в macOS), шифрование и маскировка трафика. Адреса, маршруты
// и DNS туннеля ставит awgRoutesUp (warp_windows.go, warp_darwin.go).

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
)

type awgTunnel struct {
	dev     *device.Device
	name    string
	ep      netip.AddrPort
	down    func() // снять маршруты и DNS
	started time.Time
}

var (
	awgMu  sync.Mutex
	awgCur *awgTunnel
)

// awgUp поднимает туннель по конфигу. Повторный вызов при работающем туннеле ничего не делает.
func awgUp(c awgConf) error {
	awgMu.Lock()
	defer awgMu.Unlock()
	if awgCur != nil {
		return nil
	}
	ep, err := c.resolveEndpoint()
	if err != nil {
		return err
	}
	uapi, err := c.uapi(ep)
	if err != nil {
		return err
	}
	if err := awgPrepare(); err != nil {
		return err
	}
	tdev, err := tun.CreateTUN(awgTunName, c.MTU)
	if err != nil {
		return fmt.Errorf("не удалось создать сетевой адаптер WARP: %v", err)
	}
	name, _ := tdev.Name()
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "awg: "))
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return fmt.Errorf("настройки AmneziaWG: %v", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("запуск AmneziaWG: %v", err)
	}
	down, err := awgRoutesUp(tdev, name, c, ep)
	if err != nil {
		dev.Close()
		return err
	}
	awgCur = &awgTunnel{dev: dev, name: name, ep: ep, down: down, started: time.Now()}
	return nil
}

// awgDown закрывает туннель: адаптер исчезает вместе со своими маршрутами.
func awgDown() {
	awgMu.Lock()
	t := awgCur
	awgCur = nil
	awgMu.Unlock()
	if t == nil {
		return
	}
	t.dev.Close()
	if t.down != nil {
		t.down()
	}
}

// awgInfo — работает ли туннель и сколько прошло с последнего рукопожатия (0 — его ещё не было).
func awgInfo() (up bool, handshake time.Duration, rx, tx int64) {
	awgMu.Lock()
	t := awgCur
	awgMu.Unlock()
	if t == nil {
		return false, 0, 0, 0
	}
	s, err := t.dev.IpcGet()
	if err != nil {
		return true, 0, 0, 0
	}
	var sec int64
	for _, ln := range strings.Split(s, "\n") {
		k, v, _ := strings.Cut(ln, "=")
		n, _ := strconv.ParseInt(v, 10, 64)
		switch k {
		case "last_handshake_time_sec":
			sec = n
		case "rx_bytes":
			rx = n
		case "tx_bytes":
			tx = n
		}
	}
	if sec == 0 {
		return true, 0, rx, tx
	}
	return true, time.Since(time.Unix(sec, 0)), rx, tx
}

// awgWaitHandshake ждёт первого рукопожатия с сервером.
func awgWaitHandshake(timeout time.Duration) error {
	end := time.Now().Add(timeout)
	for time.Now().Before(end) {
		if up, hs, _, _ := awgInfo(); !up {
			return errors.New("туннель закрыт")
		} else if hs > 0 {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("сервер WARP не ответил — возможно, адрес заблокирован. Попробуйте другой Endpoint в конфиге")
}
