package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func warpCLI() string {
	for _, base := range []string{os.Getenv("ProgramFiles"), `C:\Program Files`, os.Getenv("ProgramFiles(x86)")} {
		if base == "" {
			continue
		}
		p := filepath.Join(base, "Cloudflare", "Cloudflare WARP", "warp-cli.exe")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// warpStatus: installed, connected, текст статуса.
func warpStatus() (bool, bool, string) {
	cli := warpCLI()
	if cli == "" {
		return false, false, "WARP не установлен"
	}
	out, err := run(8*time.Second, cli, "--accept-tos", "status")
	s := strings.ToLower(out)
	switch {
	case strings.Contains(s, "registration missing") || strings.Contains(s, "missing registration"):
		return true, false, "Не зарегистрирован"
	case strings.Contains(s, "disconnected"):
		return true, false, "Отключён"
	case strings.Contains(s, "connecting"):
		return true, false, "Подключается…"
	case strings.Contains(s, "connected"):
		return true, true, "Подключён"
	}
	if err != nil {
		return true, false, "Служба WARP не отвечает"
	}
	return true, false, strings.TrimSpace(out)
}

func warpConnect() error {
	cli := warpCLI()
	if cli == "" {
		return errors.New("Cloudflare WARP не установлен — нажмите «Скачать WARP»")
	}
	_, _, st := warpStatus()
	if st == "Не зарегистрирован" {
		if out, err := run(30*time.Second, cli, "--accept-tos", "registration", "new"); err != nil {
			// старые версии клиента
			if out2, err2 := run(30*time.Second, cli, "--accept-tos", "register"); err2 != nil {
				return errors.New("регистрация WARP: " + strings.TrimSpace(out+" "+out2))
			}
		}
	}
	_, _ = run(10*time.Second, cli, "--accept-tos", "mode", "warp+doh")
	if out, err := run(15*time.Second, cli, "--accept-tos", "connect"); err != nil {
		return errors.New("warp-cli connect: " + strings.TrimSpace(out))
	}
	for i := 0; i < 20; i++ {
		time.Sleep(time.Second)
		if _, ok, _ := warpStatus(); ok {
			return nil
		}
	}
	return errors.New("WARP не подключился за 20 секунд (возможно, заблокирован)")
}

func warpDisconnect() {
	if cli := warpCLI(); cli != "" {
		_, _ = run(15*time.Second, cli, "--accept-tos", "disconnect")
	}
}
