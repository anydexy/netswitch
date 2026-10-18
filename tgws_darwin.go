//go:build darwin

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Под macOS TG WS Proxy — приложение «TG WS Proxy.app» из официального образа .dmg. NetSwitch
// кладёт его в tgws и запускает от имени пользователя. Настройки — в обычной папке
// ~/Library/Application Support/TgWsProxy (портативный режим требовал бы писать внутрь .app).
const (
	tgwsAsset   = "TgWsProxy_macos_universal.dmg" // Intel и Apple Silicon
	tgwsAppName = "TG WS Proxy.app"
)

func tgwsExe() string {
	return filepath.Join(tgwsDir(), tgwsAppName, "Contents", "MacOS", "TgWsProxy")
}

func tgwsStdDir() string {
	return filepath.Join(userHome, "Library", "Application Support", "TgWsProxy")
}
func tgwsDataDir() string { return tgwsStdDir() }

func tgwsCommand() *exec.Cmd { return runAsUser(tgwsExe()) }

// tgwsRemoveForeignAutostart — у отдельного TG WS Proxy под macOS своего автозапуска нет.
func tgwsRemoveForeignAutostart() {}

// tgwsInstall достаёт приложение из скачанного образа .dmg и ставит его в tgws.
func tgwsInstall(dmg string) error {
	mnt, err := os.MkdirTemp("", "netswitch-tgws-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(mnt)
	if out, err := run(3*time.Minute, "/usr/bin/hdiutil", "attach", "-nobrowse", "-readonly", "-noautoopen", "-mountpoint", mnt, dmg); err != nil {
		return errors.New("не удалось открыть образ: " + strings.TrimSpace(out))
	}
	defer func() { _, _ = run(time.Minute, "/usr/bin/hdiutil", "detach", mnt, "-force") }()

	src := ""
	if ents, err := os.ReadDir(mnt); err == nil {
		for _, e := range ents {
			if e.IsDir() && strings.HasSuffix(e.Name(), ".app") {
				src = filepath.Join(mnt, e.Name())
				break
			}
		}
	}
	if src == "" {
		return errors.New("в образе нет приложения TG WS Proxy")
	}
	dst := filepath.Join(tgwsDir(), tgwsAppName)
	tmp, old := dst+".new", dst+".old"
	_ = os.RemoveAll(tmp)
	_ = os.RemoveAll(old)
	if out, err := run(3*time.Minute, "/usr/bin/ditto", src, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return errors.New("не удалось скопировать приложение: " + strings.TrimSpace(out))
	}
	if _, err := os.Stat(dst); err == nil {
		if err := os.Rename(dst, old); err != nil {
			_ = os.RemoveAll(tmp)
			return errors.New("не удалось заменить приложение: " + shortErr(err).Error())
		}
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Rename(old, dst)
		return errors.New("ошибка замены: " + shortErr(err).Error())
	}
	_ = os.RemoveAll(old)
	_, _ = run(30*time.Second, "/usr/bin/xattr", "-dr", "com.apple.quarantine", dst)
	return nil
}
