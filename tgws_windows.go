//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Под Windows TG WS Proxy работает в портативном режиме: tgws\TgWsProxy.exe,
// настройки и secret — в tgws\TgWsProxy_data, а не в %APPDATA%.
const (
	tgwsExeName = "TgWsProxy.exe"
	tgwsAsset   = "TgWsProxy_windows.exe" // Windows 10+ x64
)

func tgwsExe() string     { return filepath.Join(tgwsDir(), tgwsExeName) }
func tgwsDataDir() string { return filepath.Join(tgwsDir(), tgwsDataName) }

// tgwsStdDir — где хранит настройки отдельно установленный TG WS Proxy.
func tgwsStdDir() string { return filepath.Join(os.Getenv("APPDATA"), "TgWsProxy") }

func tgwsCommand() *exec.Cmd { return exec.Command(tgwsExe()) }

// tgwsInstall ставит скачанный exe на место старого.
func tgwsInstall(tmp string) error {
	old := tgwsExe() + ".old"
	_ = os.Remove(old)
	if _, err := os.Stat(tgwsExe()); err == nil {
		if err := os.Rename(tgwsExe(), old); err != nil {
			return errors.New("не удалось заменить TgWsProxy.exe (файл занят): " + shortErr(err).Error())
		}
	}
	if err := os.Rename(tmp, tgwsExe()); err != nil {
		_ = os.Rename(old, tgwsExe())
		return errors.New("ошибка замены: " + shortErr(err).Error())
	}
	_ = os.Remove(old)
	return nil
}

// tgwsRemoveForeignAutostart убирает автозапуск отдельного TG WS Proxy (его настройка «Автозапуск»),
// чтобы при входе в Windows он не занимал порт раньше NetSwitch.
// Через PowerShell, а не reg.exe: тот выводит путь в OEM-кодировке, и кириллица в пути не сравнится.
func tgwsRemoveForeignAutostart() {
	key := psQuote(`HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`)
	out, err := ps(15*time.Second, "(Get-ItemProperty -Path "+key+" -Name TgWsProxy -ErrorAction Stop).TgWsProxy")
	out = strings.ToLower(strings.TrimSpace(out))
	if err != nil || out == "" || strings.Contains(out, strings.ToLower(tgwsExe())) {
		return
	}
	if _, err := ps(15*time.Second, "Remove-ItemProperty -Path "+key+" -Name TgWsProxy -ErrorAction Stop"); err == nil {
		logf("TG WS Proxy: отключён автозапуск отдельного экземпляра")
	}
}
