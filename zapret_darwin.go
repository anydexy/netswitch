//go:build darwin

package main

// zapret для macOS — tpws из оригинального zapret (github.com/bol-van/zapret, binaries/mac64).
// winws и WinDivert под macOS нет, а tpws работает прозрачным прокси: правила PF отправляют на него
// исходящие соединения на порты 80 и 443, и он режет запросы так, что DPI их не распознаёт.
// Правила ставятся во встроенную ветку com.apple/* — /etc/pf.conf не меняется, после перезагрузки
// или выхода из NetSwitch правил нет. UDP (QUIC, голос Discord) tpws не обрабатывает.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	zapretSupported = true
	tpwsPort        = 988  // прозрачный режим
	tpwsTestPort    = 9899 // SOCKS-режим для теста стратегий
	pfAnchor        = "com.apple/netswitch"
	pfctl           = "/sbin/pfctl"
)

func zapretRepo() string { return "bol-van/zapret" }

func tpwsPath() string { return filepath.Join(zapretDir(), "tpws") }

// tpwsStrategies — наборы параметров tpws, из которых выбирают как из .bat-стратегий под Windows.
// Перебор как у blockcheck из zapret: место разреза запроса (1, 2, начало SNI, середина домена),
// disorder (первая часть уходит с TTL=1 и доходит повтором — DPI видит части не по порядку),
// OOB-байт, разбиение ClientHello на две TLS-записи и маленький MSS (сервер шлёт ответ мелкими
// пакетами). Первые шесть — прежние названия, сохранённые в настройках.
var tpwsStrategies = []struct {
	Name string
	Args []string
}{
	{"Разрез SNI", []string{"--split-pos=1,midsld"}},
	{"Разрез SNI + disorder", []string{"--split-pos=1,midsld", "--disorder"}},
	{"TLS-записи", []string{"--tlsrec=sniext+1", "--split-pos=1,midsld"}},
	{"TLS-записи + disorder", []string{"--tlsrec=sniext+1", "--split-pos=1,midsld", "--disorder"}},
	{"OOB", []string{"--split-pos=1,midsld", "--oob"}},
	{"HTTP host + разрез SNI", []string{"--split-pos=method+2,midsld", "--hostcase"}},
	{"Разрез 1", []string{"--split-pos=1"}},
	{"Разрез 2 + disorder", []string{"--split-pos=2", "--disorder"}},
	{"Разрез у SNI", []string{"--split-pos=sniext+1"}},
	{"Разрез у SNI + disorder", []string{"--split-pos=sniext+1", "--disorder"}},
	{"Разрез 1 + disorder", []string{"--split-pos=1", "--disorder"}},
	{"Несколько разрезов + disorder", []string{"--split-pos=1,sniext+1,host+1,midsld", "--disorder"}},
	{"OOB у SNI", []string{"--split-pos=sniext+1", "--oob"}},
	{"TLS-записи у SNI", []string{"--tlsrec=sniext"}},
	{"TLS-записи + OOB", []string{"--tlsrec=sniext+1", "--split-pos=1,midsld", "--oob"}},
	{"Маленький MSS", []string{"--mss=88", "--split-pos=1,midsld"}},
}

func tpwsArgs(name string) ([]string, bool) {
	for _, s := range tpwsStrategies {
		if s.Name == name {
			return s.Args, true
		}
	}
	return nil, false
}

// defaultHostlist — сайты, к которым применяется обход. Свои добавляются в list-user.txt.
var defaultHostlist = []string{
	"youtube.com", "youtu.be", "youtube-nocookie.com", "ytimg.com", "googlevideo.com", "ggpht.com", "youtubei.googleapis.com",
	"discord.com", "discord.gg", "discord.media", "discordapp.com", "discordapp.net", "discord.dev", "discord.gift", "discordcdn.com", "discordstatus.com", "dis.gd",
	"instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net", "x.com", "twitter.com", "twimg.com", "t.co",
}

var (
	pfToken  string
	zTestCmd *exec.Cmd
)

func zapretLocalVersion() string {
	if _, err := os.Stat(tpwsPath()); err != nil {
		return ""
	}
	b, _ := os.ReadFile(filepath.Join(zapretDir(), "version.txt"))
	if v := strings.TrimSpace(string(b)); reVer.MatchString(v) {
		return v
	}
	return "?"
}

func zapretStrategies() []string {
	if _, err := os.Stat(tpwsPath()); err != nil {
		return nil
	}
	r := make([]string, len(tpwsStrategies))
	for i, s := range tpwsStrategies {
		r[i] = s.Name
	}
	return r
}

// zapretEnsureUserLists — общий список сайтов обновляется вместе с программой, свой — не трогается.
func zapretEnsureUserLists() {
	_ = os.MkdirAll(zapretDir(), 0755)
	_ = os.WriteFile(filepath.Join(zapretDir(), "list-general.txt"), []byte(strings.Join(defaultHostlist, "\n")+"\n"), 0644)
	p := filepath.Join(zapretDir(), "list-user.txt")
	if _, err := os.Stat(p); err != nil {
		_ = os.WriteFile(p, []byte("# Свои сайты для обхода, по одному в строке (поддомены учитываются)\n"), 0644)
		fixOwner(p) // список правит пользователь; сам tpws остаётся файлом root
	}
}

func winwsRunning() bool {
	zMu.Lock()
	defer zMu.Unlock()
	return zProc != nil
}

// pfOn загружает правила для tpws в ветку com.apple/netswitch и включает PF.
func pfOn() error {
	rules := filepath.Join(zapretDir(), "pf.conf")
	if err := os.WriteFile(rules, []byte(pfRules(tpwsPort)), 0644); err != nil {
		return err
	}
	// ветка com.apple/* есть в стандартном /etc/pf.conf; если основной набор правил не загружен — загрузить
	if out, _ := run(10*time.Second, pfctl, "-s", "Anchors"); !strings.Contains(out, "com.apple") {
		if out, err := run(15*time.Second, pfctl, "-f", "/etc/pf.conf"); err != nil {
			return errors.New("PF: не удалось загрузить /etc/pf.conf: " + strings.TrimSpace(out))
		}
	}
	if out, err := run(15*time.Second, pfctl, "-a", pfAnchor, "-f", rules); err != nil {
		return errors.New("PF: " + strings.TrimSpace(out))
	}
	out, err := run(10*time.Second, pfctl, "-E")
	if err != nil {
		pfOff("")
		return errors.New("PF: не удалось включить: " + strings.TrimSpace(out))
	}
	zMu.Lock()
	pfToken = parsePFToken(out)
	zMu.Unlock()
	return nil
}

// pfOff снимает правила NetSwitch; PF выключается, только если его больше никто не включал.
func pfOff(token string) {
	_, _ = run(10*time.Second, pfctl, "-a", pfAnchor, "-F", "all")
	if token != "" {
		_, _ = run(10*time.Second, pfctl, "-X", token)
	}
}

func killStrayTpws() {
	for _, p := range listProcs() {
		if p.Name == "tpws" && procPath(p.PID) == tpwsPath() {
			killPID(p.PID)
		}
	}
}

func killWinws() {
	zMu.Lock()
	p, tok := zProc, pfToken
	zProc, pfToken = nil, ""
	zMu.Unlock()
	pfOff(tok) // сначала правила: без tpws они оставили бы сайты без связи
	if p != nil && p.Process != nil {
		_ = p.Process.Kill()
	}
	killStrayTpws()
}

// platformStart — после сбоя или принудительного закрытия NetSwitch могли остаться правила PF
// без tpws: снять их до того, как программа решит, запускать ли zapret.
func platformStart() {
	if _, ok := tpwsArgs(getCfg().ZapretStrategy); !ok { // по умолчанию — стратегия Windows (general.bat)
		updateCfg(func(c *Settings) { c.ZapretStrategy = tpwsStrategies[0].Name })
	}
	if isAdmin() {
		pfOff("")
		killStrayTpws()
	}
}

// startTpws запускает tpws и ждёт, не завершится ли он сразу (тогда — ошибка с его выводом).
func startTpws(args []string) (*exec.Cmd, error) {
	logPath := filepath.Join(zapretDir(), "tpws.log")
	lf, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	c := exec.Command(tpwsPath(), args...)
	c.Dir = zapretDir()
	c.Stdout, c.Stderr = lf, lf
	if err := c.Start(); err != nil {
		lf.Close()
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait(); lf.Close() }()
	select {
	case <-done:
		b, _ := os.ReadFile(logPath)
		msg := strings.TrimSpace(string(b))
		if len(msg) > 200 {
			msg = msg[len(msg)-200:]
		}
		return nil, errors.New("tpws сразу завершился: " + msg)
	case <-time.After(time.Second):
	}
	go func() {
		<-done
		zMu.Lock()
		mine, tok := zProc == c, pfToken
		if mine {
			zProc, pfToken = nil, ""
		}
		zMu.Unlock()
		if mine {
			pfOff(tok) // tpws упал — без правил сайты откроются напрямую, сторож перезапустит zapret
		}
	}()
	return c, nil
}

// zapretStartProcess запускает tpws в прозрачном режиме со стратегией и включает правила PF.
func zapretStartProcess(strategy string) error {
	if _, err := os.Stat(tpwsPath()); err != nil {
		return errors.New("zapret не скачан — нажмите «Скачать последнюю версию»")
	}
	if !isAdmin() {
		return errors.New("zapret на macOS нужны права администратора — перезапустите NetSwitch и введите пароль")
	}
	sargs, ok := tpwsArgs(strategy)
	if !ok {
		sargs = tpwsStrategies[0].Args
	}
	zapretEnsureUserLists()
	killWinws()
	args := append([]string{"--user=root", fmt.Sprintf("--port=%d", tpwsPort), "--bind-addr=127.0.0.1",
		"--bind-iface6=lo0", "--bind-linklocal=force",
		"--hostlist=" + filepath.Join(zapretDir(), "list-general.txt"),
		"--hostlist=" + filepath.Join(zapretDir(), "list-user.txt")}, sargs...)
	c, err := startTpws(args)
	if err != nil {
		return err
	}
	zMu.Lock()
	zProc = c
	zMu.Unlock()
	if err := pfOn(); err != nil {
		killWinws()
		return err
	}
	return nil
}

// Службы, как в Windows, нет: zapret работает вместе с NetSwitch, а NetSwitch можно запускать
// при загрузке системы (Настройки → автозапуск).
func zapretServiceInstall(strategy string) error {
	return errors.New("на macOS zapret работает вместе с NetSwitch — включите автозапуск NetSwitch в настройках")
}
func zapretServiceRemove(withDriver bool) {}
func zapretServiceStrategy() string       { return "" }

func zapretDownload() error {
	zBusy.Lock()
	defer zBusy.Unlock()
	setDL(true, 0, "Проверка последней версии…")
	defer func() { zMu.Lock(); zStat.Downloading = false; zMu.Unlock() }()
	fail := func(msg string, err error) error {
		setDL(false, 0, msg+shortErr(err).Error())
		return err
	}

	ver, link, err := zapretLatest(true)
	if err != nil {
		return fail("Ошибка: ", err)
	}
	zMu.Lock()
	sum := zLatest.sum
	zMu.Unlock()
	req, _ := http.NewRequest("GET", link, nil)
	req.Header.Set("User-Agent", "NetSwitch")
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		return fail("Ошибка загрузки: ", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fail("Ошибка загрузки: ", fmt.Errorf("HTTP %d", resp.StatusCode))
	}
	tmpZip := filepath.Join(appDir(), "zapret_download.zip")
	f, err := os.Create(tmpZip)
	if err != nil {
		return fail("Ошибка: ", err)
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), &progressReader{r: resp.Body, of: resp.ContentLength,
		set: func(pct int, msg string) { setDL(true, pct, msg) }})
	f.Close()
	defer os.Remove(tmpZip)
	if err != nil {
		return fail("Ошибка загрузки: ", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); sum != "" && got != sum {
		return fail("Ошибка: ", errors.New("контрольная сумма не совпала с указанной на GitHub — файл не установлен"))
	}

	setDL(true, 100, "Распаковка…")
	newDir := filepath.Join(appDir(), "zapret_new")
	_ = os.RemoveAll(newDir)
	defer os.RemoveAll(newDir)
	if err := unzip(tmpZip, newDir); err != nil {
		return fail("Ошибка распаковки: ", err)
	}
	src := ""
	_ = filepath.Walk(newDir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && src == "" && !fi.IsDir() && fi.Name() == "tpws" && filepath.Base(filepath.Dir(p)) == "mac64" {
			src = p
		}
		return nil
	})
	if src == "" {
		return fail("Ошибка: ", errors.New("в архиве нет binaries/mac64/tpws"))
	}

	setDL(true, 100, "Остановка zapret и замена файлов…")
	wasRunning := winwsRunning()
	killWinws()
	if err := os.MkdirAll(zapretDir(), 0755); err != nil {
		return fail("Ошибка: ", err)
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return fail("Ошибка: ", err)
	}
	tmp := tpwsPath() + ".new"
	if err := os.WriteFile(tmp, b, 0755); err != nil {
		return fail("Ошибка: ", err)
	}
	if err := os.Rename(tmp, tpwsPath()); err != nil {
		_ = os.Remove(tmp)
		return fail("Ошибка замены: ", err)
	}
	_ = os.WriteFile(filepath.Join(zapretDir(), "version.txt"), []byte(ver), 0644)
	zapretEnsureUserLists()

	msg := "Установлена версия " + ver
	if wasRunning {
		if err := zapretStartProcess(getCfg().ZapretStrategy); err != nil {
			msg += " (запуск: " + err.Error() + ")"
		}
	}
	logf("zapret: %s", msg)
	setDL(false, 100, msg)
	return nil
}

// --- тест стратегий ---
// Соединения от root правила PF пропускают мимо tpws, а NetSwitch работает от root, поэтому
// для теста каждая стратегия запускается отдельным tpws в режиме SOCKS и сайты проверяются через него.

func zapretPauseForTest() func() {
	was := winwsRunning()
	killWinws()
	return func() {
		if was {
			_ = zapretStartProcess(getCfg().ZapretStrategy)
		}
	}
}

func zapretTestRun(strategy string) (func() *http.Client, error) {
	sargs, ok := tpwsArgs(strategy)
	if !ok {
		return nil, errors.New("нет такой стратегии")
	}
	args := append([]string{"--socks", fmt.Sprintf("--port=%d", tpwsTestPort), "--bind-addr=127.0.0.1"}, sargs...)
	c, err := startTpws(args)
	if err != nil {
		return nil, err
	}
	zTestCmd = c
	proxy := &url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", tpwsTestPort)}
	return func() *http.Client {
		return &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true,
				ForceAttemptHTTP2: true, TLSHandshakeTimeout: 8 * time.Second},
			Timeout:       10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}, nil
}

func zapretTestKill() {
	if c := zTestCmd; c != nil && c.Process != nil {
		_ = c.Process.Kill()
		time.Sleep(200 * time.Millisecond)
	}
	zTestCmd = nil
}
