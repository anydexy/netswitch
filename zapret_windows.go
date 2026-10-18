//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// zapret для Windows — сборка Flowseal/zapret-discord-youtube: winws.exe с драйвером WinDivert,
// стратегии — .bat-файлы, можно поставить службой Windows.
var reVersion = regexp.MustCompile(`(?i)set\s+"LOCAL_VERSION=([^"]+)"`)

func zapretLocalVersion() string {
	b, err := os.ReadFile(filepath.Join(zapretDir(), "service.bat"))
	if err != nil {
		return ""
	}
	if m := reVersion.FindSubmatch(b); m != nil {
		return strings.TrimSpace(string(m[1]))
	}
	return "?"
}

func zapretStrategies() []string {
	ents, err := os.ReadDir(zapretDir())
	if err != nil {
		return nil
	}
	var r []string
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.EqualFold(filepath.Ext(n), ".bat") || strings.HasPrefix(strings.ToLower(n), "service") {
			continue
		}
		r = append(r, n)
	}
	sort.Slice(r, func(i, j int) bool { return naturalKey(r[i]) < naturalKey(r[j]) })
	return r
}

func zapretEnsureUserLists() {
	l := filepath.Join(zapretDir(), "lists")
	_ = os.MkdirAll(l, 0755)
	files := map[string]string{
		"ipset-exclude-user.txt": "203.0.113.113/32\r\n",
		"list-general-user.txt":  "# Never leave this file empty\r\ndomain.example.abc\r\n",
		"list-exclude-user.txt":  "domain.example.abc\r\n",
	}
	for n, c := range files {
		p := filepath.Join(l, n)
		if _, err := os.Stat(p); err != nil {
			_ = os.WriteFile(p, []byte(c), 0644)
		}
	}
}

func winwsRunning() bool {
	out, _ := run(8*time.Second, "tasklist", "/FI", "IMAGENAME eq winws.exe", "/NH")
	return strings.Contains(strings.ToLower(out), "winws.exe")
}

func killWinws() {
	zMu.Lock()
	p := zProc
	zProc = nil
	zMu.Unlock()
	if p != nil && p.Process != nil {
		_ = p.Process.Kill()
	}
	_, _ = run(10*time.Second, "taskkill", "/IM", "winws.exe", "/F")
	for i := 0; i < 20 && winwsRunning(); i++ {
		time.Sleep(250 * time.Millisecond)
	}
}

// zapretStartProcess запускает winws.exe со стратегией (без службы).
func zapretStartProcess(strategy string) error {
	root := zapretDir()
	if _, err := os.Stat(filepath.Join(root, "bin", "winws.exe")); err != nil {
		return errors.New("zapret не скачан — нажмите «Скачать последнюю версию»")
	}
	args, err := parseStrategy(root, strategy)
	if err != nil {
		return fmt.Errorf("%s: %v", strategy, err)
	}
	zapretEnsureUserLists()
	_, _ = run(10*time.Second, "netsh", "interface", "tcp", "set", "global", "timestamps=enabled")
	killWinws()
	c := exec.Command(filepath.Join(root, "bin", "winws.exe"), args...)
	c.Dir = filepath.Join(root, "bin")
	hideCmd(c)
	if err := c.Start(); err != nil {
		return err
	}
	zMu.Lock()
	zProc = c
	zMu.Unlock()
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case <-done:
		zMu.Lock()
		if zProc == c {
			zProc = nil
		}
		zMu.Unlock()
		return errors.New("winws.exe сразу завершился (нужны права администратора, или конфликт с другим обходом/антивирусом)")
	case <-time.After(1500 * time.Millisecond):
	}
	go func() {
		<-done
		zMu.Lock()
		if zProc == c {
			zProc = nil
		}
		zMu.Unlock()
	}()
	return nil
}

func zapretServiceInstall(strategy string) error {
	root := zapretDir()
	args, err := parseStrategy(root, strategy)
	if err != nil {
		return err
	}
	zapretEnsureUserLists()
	killWinws()
	zapretServiceRemove(false)
	_, _ = run(10*time.Second, "netsh", "interface", "tcp", "set", "global", "timestamps=enabled")
	parts := []string{escapeArg(filepath.Join(root, "bin", "winws.exe"))}
	for _, a := range args {
		parts = append(parts, escapeArg(a))
	}
	bin := strings.Join(parts, " ")
	if out, err := run(20*time.Second, "sc", "create", zapretService, "binPath=", bin, "DisplayName=", "zapret", "start=", "auto"); err != nil {
		return fmt.Errorf("sc create: %s", strings.TrimSpace(out))
	}
	_, _ = run(10*time.Second, "sc", "description", zapretService, "Zapret DPI bypass (NetSwitch: "+strategy+")")
	_, _ = run(10*time.Second, "sc", "failure", zapretService, "reset=", "0", "actions=", "restart/5000/restart/5000/restart/5000")
	_, _ = run(10*time.Second, "reg", "add", `HKLM\System\CurrentControlSet\Services\zapret`, "/v", "zapret-discord-youtube", "/t", "REG_SZ", "/d", strings.TrimSuffix(strategy, ".bat"), "/f")
	if out, err := run(20*time.Second, "sc", "start", zapretService); err != nil {
		return fmt.Errorf("служба создана, но не запустилась: %s", strings.TrimSpace(out))
	}
	return nil
}

func zapretServiceRemove(withDriver bool) {
	if serviceState(zapretService) != 0 {
		_, _ = run(20*time.Second, "net", "stop", zapretService)
		_, _ = run(10*time.Second, "sc", "delete", zapretService)
	}
	if withDriver {
		for _, d := range []string{"WinDivert", "WinDivert14"} {
			_, _ = run(15*time.Second, "net", "stop", d)
			_, _ = run(10*time.Second, "sc", "delete", d)
		}
	}
}

func zapretServiceStrategy() string {
	out, err := run(5*time.Second, "reg", "query", `HKLM\System\CurrentControlSet\Services\zapret`, "/v", "zapret-discord-youtube")
	if err != nil {
		return ""
	}
	for _, ln := range strings.Split(out, "\n") {
		if i := strings.Index(ln, "REG_SZ"); i >= 0 {
			return strings.TrimSpace(ln[i+6:]) + ".bat"
		}
	}
	return ""
}

func zapretDownload() error {
	zBusy.Lock()
	defer zBusy.Unlock()
	setDL(true, 0, "Проверка последней версии…")
	defer func() { zMu.Lock(); zStat.Downloading = false; zMu.Unlock() }()

	ver, url, err := zapretLatest(true)
	if err != nil {
		setDL(false, 0, "Ошибка: "+err.Error())
		return err
	}
	c := &http.Client{Timeout: 10 * time.Minute}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "NetSwitch")
	resp, err := c.Do(req)
	if err != nil {
		setDL(false, 0, "Ошибка загрузки: "+shortErr(err).Error())
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		setDL(false, 0, fmt.Sprintf("Ошибка загрузки: HTTP %d", resp.StatusCode))
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	tmpZip := filepath.Join(appDir(), "zapret_download.zip")
	f, err := os.Create(tmpZip)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, &progressReader{r: resp.Body, of: resp.ContentLength,
		set: func(pct int, msg string) { setDL(true, pct, msg) }})
	f.Close()
	defer os.Remove(tmpZip)
	if err != nil {
		setDL(false, 0, "Ошибка загрузки: "+shortErr(err).Error())
		return err
	}

	setDL(true, 100, "Распаковка…")
	newDir := filepath.Join(appDir(), "zapret_new")
	_ = os.RemoveAll(newDir)
	if err := unzip(tmpZip, newDir); err != nil {
		setDL(false, 0, "Ошибка распаковки: "+err.Error())
		return err
	}
	src := findRoot(newDir)
	if src == "" {
		_ = os.RemoveAll(newDir)
		setDL(false, 0, "В архиве нет service.bat — неожиданный формат")
		return errors.New("bad archive")
	}

	// Остановить текущий zapret, запомнить состояние
	setDL(true, 100, "Остановка zapret и замена файлов…")
	wasService := serviceState(zapretService) != 0
	svcStrat := zapretServiceStrategy()
	wasProc := winwsRunning() && !wasService
	killWinws()
	zapretServiceRemove(true)
	time.Sleep(time.Second)

	old := zapretDir()
	// перенести пользовательские списки
	for _, rel := range []string{"lists/ipset-exclude-user.txt", "lists/list-general-user.txt", "lists/list-exclude-user.txt"} {
		if b, err := os.ReadFile(filepath.Join(old, rel)); err == nil {
			_ = os.MkdirAll(filepath.Dir(filepath.Join(src, rel)), 0755)
			_ = os.WriteFile(filepath.Join(src, rel), b, 0644)
		}
	}
	backup := filepath.Join(appDir(), "zapret_old")
	_ = os.RemoveAll(backup)
	if _, err := os.Stat(old); err == nil {
		if err := os.Rename(old, backup); err != nil {
			setDL(false, 0, "Не удалось заменить папку zapret (файлы заняты): "+err.Error())
			return err
		}
	}
	if err := os.Rename(src, old); err != nil {
		_ = os.Rename(backup, old)
		setDL(false, 0, "Ошибка замены: "+err.Error())
		return err
	}
	_ = os.RemoveAll(newDir)
	_ = os.RemoveAll(backup)
	zapretEnsureUserLists()

	msg := "Установлена версия " + ver
	if wasService {
		st := svcStrat
		if st == "" {
			st = getCfg().ZapretStrategy
		}
		if err := zapretServiceInstall(st); err != nil {
			msg += " (служба: " + err.Error() + ")"
		}
	} else if wasProc {
		if err := zapretStartProcess(getCfg().ZapretStrategy); err != nil {
			msg += " (запуск: " + err.Error() + ")"
		}
	}
	logf("zapret: %s", msg)
	setDL(false, 100, msg)
	return nil
}

// findRoot — папка внутри архива, где лежит service.bat.
func findRoot(dir string) string {
	var found string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && found == "" && !d.IsDir() && strings.EqualFold(d.Name(), "service.bat") {
			found = filepath.Dir(p)
		}
		return nil
	})
	return found
}

func zapretRepo() string { return getCfg().ZapretRepo }

// zapretPauseForTest останавливает zapret на время теста стратегий и возвращает функцию,
// которая вернёт всё как было.
func zapretPauseForTest() func() {
	wasService := serviceState(zapretService) == 4
	wasProc := !wasService && winwsRunning()
	if wasService {
		_, _ = run(20*time.Second, "net", "stop", zapretService)
	}
	killWinws()
	return func() {
		if wasService {
			_, _ = run(20*time.Second, "sc", "start", zapretService)
		} else if wasProc {
			_ = zapretStartProcess(getCfg().ZapretStrategy)
		}
	}
}

// zapretTestRun запускает стратегию для теста; winws перехватывает весь трафик системы,
// поэтому сайты проверяются обычным клиентом.
func zapretTestRun(strategy string) (func() *http.Client, error) {
	if err := zapretStartProcess(strategy); err != nil {
		return nil, err
	}
	time.Sleep(1500 * time.Millisecond)
	return directTestClient, nil
}

func zapretTestKill() { killWinws() }
