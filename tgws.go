package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TG WS Proxy (github.com/Flowseal/tg-ws-proxy) — локальный MTProto-прокси для Telegram Desktop.
// NetSwitch скачивает официальную сборку в папку tgws и запускает её сам. Что зависит от системы
// (имя файла в релизе, установка, где лежат настройки, запуск) — в tgws_windows.go и tgws_darwin.go.

const (
	tgwsDataName = "TgWsProxy_data" // наличие папки рядом с exe включает портативный режим
	tgwsMutex    = `Local\TgWsProxy_SingleInstance`
	tgwsWMStop   = 0x400 + 10 // WM_STOP у pystray: штатный выход, как «Выход» в меню его значка
)

func tgwsDir() string { return filepath.Join(appDir(), "tgws") }

type TgwsStatus struct {
	Installed     bool   `json:"installed"`
	LocalVersion  string `json:"local_version"`
	LatestVersion string `json:"latest_version"`
	LatestErr     string `json:"latest_err,omitempty"`
	UpToDate      bool   `json:"up_to_date"`
	Running       bool   `json:"running"`            // работает наш tgws\TgWsProxy.exe
	Listening     bool   `json:"listening"`          // порт прокси принимает подключения
	External      string `json:"external,omitempty"` // запущен отдельный TG WS Proxy (имя exe)
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Secret        string `json:"secret"`
	Link          string `json:"link"`
	Downloading   bool   `json:"downloading"`
	DownloadPct   int    `json:"download_pct"`
	DownloadMsg   string `json:"download_msg"`
}

type procEntry struct {
	PID, PPID uint32
	Name      string
}

var (
	tMu     sync.Mutex
	tProc   *exec.Cmd // процесс, запущенный этим экземпляром NetSwitch
	tStat   TgwsStatus
	tLatest struct {
		ver, url, sum, err string
		at                 time.Time
	}
	tBusy sync.Mutex // старт/стоп/обновление не пересекаются
)

var errTgwsBusy = errors.New("TG WS Proxy сейчас занят (идёт обновление)")

// --- настройки TG WS Proxy ---

type tgwsConf struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Secret string `json:"secret"`
}

func readTgwsConf(dataDir string) tgwsConf {
	c := tgwsConf{Host: "127.0.0.1", Port: 1443}
	if b, err := os.ReadFile(filepath.Join(dataDir, "config.json")); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	return c
}

// localHost — адрес, по которому к прокси подключаться с этого компьютера.
func (c tgwsConf) localHost() string {
	if c.Host == "" || c.Host == "0.0.0.0" || c.Host == "::" {
		return "127.0.0.1"
	}
	return c.Host
}

// tgwsLink — ссылка, по которой Telegram Desktop сам добавит прокси.
func tgwsLink(c tgwsConf) string {
	if c.Secret == "" || c.Port == 0 {
		return ""
	}
	return fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=dd%s", c.localHost(), c.Port, c.Secret)
}

// tgwsPrepare готовит портативную папку настроек перед запуском.
func tgwsPrepare(src string, force bool) error {
	if src == "" {
		src = tgwsStdDir()
	}
	err := tgwsPrepareIn(tgwsDataDir(), src, force)
	fixOwnerTree(tgwsDataDir()) // прокси запускается от имени пользователя, а не администратора
	return err
}

// tgwsPrepareIn переносит настройки из src (обычно %APPDATA%\TgWsProxy), чтобы сохранился secret,
// под которым Telegram уже настроен; при force — даже поверх своих. Затем отключает собственную
// проверку обновлений (обновляет NetSwitch) и окна первого запуска — их заменяет вкладка в NetSwitch.
func tgwsPrepareIn(data, src string, force bool) error {
	if err := os.MkdirAll(data, 0755); err != nil {
		return err
	}
	cf := filepath.Join(data, "config.json")
	_, haveOwn := os.Stat(cf)
	if haveOwn != nil || force {
		if b, err := os.ReadFile(filepath.Join(src, "config.json")); err == nil && json.Valid(b) {
			if err := os.WriteFile(cf, b, 0644); err != nil {
				return err
			}
			logf("TG WS Proxy: перенесены настройки из %s", src)
		}
	}
	m := map[string]any{}
	if b, err := os.ReadFile(cf); err == nil {
		if json.Unmarshal(b, &m) != nil {
			return errors.New("испорчен файл настроек " + cf)
		}
	}
	changed := false
	if s, _ := m["secret"].(string); s == "" {
		var b [16]byte
		_, _ = rand.Read(b[:])
		m["secret"] = hex.EncodeToString(b[:])
		changed = true
	}
	if v, ok := m["check_updates"].(bool); !ok || v {
		m["check_updates"] = false
		changed = true
	}
	if changed {
		var buf strings.Builder
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(m); err != nil {
			return err
		}
		if err := os.WriteFile(cf, []byte(buf.String()), 0644); err != nil {
			return err
		}
	}
	for _, mk := range []string{".first_run_done_mtproto", ".ipv6_warned"} {
		p := filepath.Join(data, mk)
		if _, err := os.Stat(p); err != nil {
			_ = os.WriteFile(p, nil, 0644)
		}
	}
	return nil
}

// --- процессы ---

// tgwsProcs — процессы TG WS Proxy: наш tgws\TgWsProxy.exe и запущенные отдельно.
// Сборка PyInstaller onefile — это два процесса: загрузчик и дочерний с самим прокси.
func tgwsProcs() (ours []uint32, ext []procEntry) {
	me := tgwsExe()
	for _, p := range listProcs() {
		if !strings.Contains(strings.ToLower(p.Name), "tgwsproxy") {
			continue
		}
		if strings.EqualFold(procPath(p.PID), me) {
			ours = append(ours, p.PID)
		} else {
			ext = append(ext, p)
		}
	}
	return ours, ext
}

func pidsGone(pids map[uint32]bool, wait time.Duration) bool {
	end := time.Now().Add(wait)
	for {
		alive := false
		for _, p := range listProcs() {
			if pids[p.PID] {
				alive = true
				break
			}
		}
		if !alive {
			return true
		}
		if time.Now().After(end) {
			return false
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// stopTgwsPIDs закрывает TG WS Proxy штатно (значок уходит из трея, временные файлы удаляются),
// а если не вышло — принудительно.
func stopTgwsPIDs(pids []uint32) {
	if len(pids) == 0 {
		return
	}
	set := map[uint32]bool{}
	for _, p := range pids {
		set[p] = true
	}
	postToProcWindows(set, "TgWsProxy", "SystemTrayIcon", tgwsWMStop)
	if pidsGone(set, 6*time.Second) {
		return
	}
	// сначала дочерний процесс: загрузчик PyInstaller тогда сам удалит распакованные файлы
	for _, p := range listProcs() {
		if set[p.PID] && set[p.PPID] {
			killPID(p.PID)
		}
	}
	if pidsGone(set, 3*time.Second) {
		return
	}
	for p := range set {
		killPID(p)
	}
	pidsGone(set, 3*time.Second)
}

// tgwsStop останавливает наш TG WS Proxy.
func tgwsStop() {
	tMu.Lock()
	tProc = nil // своя остановка — не считать её выходом из меню в трее
	tMu.Unlock()
	ours, _ := tgwsProcs()
	stopTgwsPIDs(ours)
}

// tgwsStartProcess запускает tgws\TgWsProxy.exe.
func tgwsStartProcess() error {
	if _, err := os.Stat(tgwsExe()); err != nil {
		return errors.New("TG WS Proxy не скачан — нажмите «Скачать последнюю версию»")
	}
	ours, ext := tgwsProcs()
	if len(ours) > 0 {
		return nil
	}
	if len(ext) > 0 || mutexExists(tgwsMutex) {
		return errors.New("TG WS Proxy уже запущен отдельно — нажмите «Перенести в NetSwitch» или закройте его через значок в трее")
	}
	if err := tgwsPrepare("", false); err != nil {
		return err
	}
	c := tgwsCommand()
	c.Dir = tgwsDir()
	if err := c.Start(); err != nil {
		return err
	}
	tMu.Lock()
	tProc = c
	tMu.Unlock()
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case err := <-done:
		tMu.Lock()
		if tProc == c {
			tProc = nil
		}
		tMu.Unlock()
		return fmt.Errorf("TG WS Proxy сразу завершился (%v) — подробности в журнале прокси", err)
	case <-time.After(2 * time.Second):
	}
	go func() {
		err := <-done
		tMu.Lock()
		mine := tProc == c
		if mine {
			tProc = nil
		}
		tMu.Unlock()
		if mine && err == nil {
			// код 0 — пользователь выбрал «Выход» в меню значка TG WS Proxy: не перезапускать
			updateCfg(func(c *Settings) { c.TgwsWanted = false })
			logf("TG WS Proxy закрыт из меню его значка в трее")
			refreshTgwsStatus()
			updateTray()
		}
	}()
	return nil
}

// tgwsTakeOver закрывает отдельно запущенный TG WS Proxy, забирает его настройки
// (Telegram перенастраивать не нужно) и запускает экземпляр NetSwitch.
func tgwsTakeOver() error {
	if _, err := os.Stat(tgwsExe()); err != nil {
		return errors.New("сначала скачайте TG WS Proxy")
	}
	_, ext := tgwsProcs()
	if len(ext) == 0 {
		return tgwsStartProcess()
	}
	src := ""
	var pids []uint32
	for _, p := range ext {
		pids = append(pids, p.PID)
		if path := procPath(p.PID); path != "" && src == "" {
			if fi, err := os.Stat(filepath.Join(filepath.Dir(path), tgwsDataName)); err == nil && fi.IsDir() {
				src = filepath.Join(filepath.Dir(path), tgwsDataName) // тот был портативным
			}
		}
	}
	stopTgwsPIDs(pids)
	if _, ext := tgwsProcs(); len(ext) > 0 {
		return errors.New("не удалось закрыть отдельный TG WS Proxy — закройте его через значок в трее")
	}
	tgwsRemoveForeignAutostart()
	if err := tgwsPrepare(src, true); err != nil {
		return err
	}
	logf("TG WS Proxy: отдельный экземпляр закрыт, дальше им управляет NetSwitch")
	return tgwsStartProcess()
}

// --- версия и обновление ---

func tgwsLocalVersion() string {
	if _, err := os.Stat(tgwsExe()); err != nil {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(tgwsDir(), "version.txt"))
	if v := strings.TrimSpace(string(b)); err == nil && reVer.MatchString(v) {
		return v
	}
	return "?"
}

// tgwsLatest — последняя версия на GitHub (кэш 10 минут): версия, ссылка на exe, его SHA-256.
func tgwsLatest(force bool) (string, string, string, error) {
	tMu.Lock()
	if !force && time.Since(tLatest.at) < 10*time.Minute && tLatest.ver != "" {
		v, u, s := tLatest.ver, tLatest.url, tLatest.sum
		tMu.Unlock()
		return v, u, s, nil
	}
	tMu.Unlock()
	fail := func(err error) (string, string, string, error) {
		err = shortErr(err)
		tMu.Lock()
		tLatest.err = err.Error()
		tMu.Unlock()
		return "", "", "", err
	}
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/"+getCfg().TgwsRepo+"/releases/latest", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "NetSwitch")
	resp, err := httpClientVia("", 12*time.Second).Do(req)
	if err != nil {
		return fail(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fail(fmt.Errorf("GitHub API: HTTP %d", resp.StatusCode))
	}
	var rel struct {
		Tag    string `json:"tag_name"`
		Assets []struct {
			Name   string `json:"name"`
			URL    string `json:"browser_download_url"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return fail(err)
	}
	ver := strings.TrimPrefix(rel.Tag, "v")
	if !reVer.MatchString(ver) {
		return fail(errors.New("не удалось узнать версию"))
	}
	var url, sum string
	for _, a := range rel.Assets {
		if a.Name == tgwsAsset {
			url, sum = a.URL, strings.TrimPrefix(strings.ToLower(a.Digest), "sha256:")
		}
	}
	if url == "" {
		return fail(errors.New("в релизе нет " + tgwsAsset))
	}
	tMu.Lock()
	tLatest.ver, tLatest.url, tLatest.sum, tLatest.err, tLatest.at = ver, url, sum, "", time.Now()
	tMu.Unlock()
	return ver, url, sum, nil
}

func setTDL(on bool, pct int, msg string) {
	tMu.Lock()
	tStat.Downloading, tStat.DownloadPct, tStat.DownloadMsg = on, pct, msg
	tMu.Unlock()
}

func tgwsDownload() error {
	tBusy.Lock()
	defer tBusy.Unlock()
	setTDL(true, 0, "Проверка последней версии…")
	defer func() { tMu.Lock(); tStat.Downloading = false; tMu.Unlock() }()
	fail := func(msg string, err error) error {
		setTDL(false, 0, msg+shortErr(err).Error())
		return err
	}

	ver, url, sum, err := tgwsLatest(true)
	if err != nil {
		return fail("Ошибка: ", err)
	}
	if err := os.MkdirAll(tgwsDir(), 0755); err != nil {
		return fail("Ошибка: ", err)
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "NetSwitch")
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		return fail("Ошибка загрузки: ", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fail("Ошибка загрузки: ", fmt.Errorf("HTTP %d", resp.StatusCode))
	}
	tmp := filepath.Join(tgwsDir(), tgwsAsset+".download")
	f, err := os.Create(tmp)
	if err != nil {
		return fail("Ошибка: ", err)
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), &progressReader{r: resp.Body, of: resp.ContentLength,
		set: func(pct int, msg string) { setTDL(true, pct, msg) }})
	f.Close()
	defer os.Remove(tmp)
	if err != nil {
		return fail("Ошибка загрузки: ", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); sum != "" && got != sum {
		err := errors.New("контрольная сумма не совпала с указанной на GitHub — файл не установлен")
		setTDL(false, 0, "Ошибка: "+err.Error())
		return err
	}

	setTDL(true, 100, "Замена файла…")
	ours, _ := tgwsProcs()
	wasRunning := len(ours) > 0
	tgwsStop()
	if err := tgwsInstall(tmp); err != nil {
		setTDL(false, 0, "Ошибка: "+err.Error())
		return err
	}
	_ = os.WriteFile(filepath.Join(tgwsDir(), "version.txt"), []byte(ver), 0644)
	fixOwnerTree(tgwsDir())
	_ = tgwsPrepare("", false)

	msg := "Установлена версия " + ver
	if wasRunning {
		if err := tgwsStartProcess(); err != nil {
			msg += " (запуск: " + err.Error() + ")"
		}
	}
	logf("TG WS Proxy: %s", msg)
	setTDL(false, 100, msg)
	return nil
}

// --- состояние ---

func refreshTgwsStatus() {
	st := TgwsStatus{}
	st.LocalVersion = tgwsLocalVersion()
	st.Installed = st.LocalVersion != ""
	ours, ext := tgwsProcs()
	st.Running = len(ours) > 0
	if len(ext) > 0 {
		st.External = ext[0].Name
	}
	c := readTgwsConf(tgwsDataDir())
	st.Host, st.Port, st.Secret, st.Link = c.localHost(), c.Port, c.Secret, tgwsLink(c)
	if st.Running {
		if conn, err := net.DialTimeout("tcp", net.JoinHostPort(st.Host, strconv.Itoa(st.Port)), 500*time.Millisecond); err == nil {
			conn.Close()
			st.Listening = true
		}
	}
	tMu.Lock()
	st.LatestVersion, st.LatestErr = tLatest.ver, tLatest.err
	st.UpToDate = st.Installed && st.LatestVersion != "" && st.LatestVersion == st.LocalVersion
	st.Downloading, st.DownloadPct, st.DownloadMsg = tStat.Downloading, tStat.DownloadPct, tStat.DownloadMsg
	tStat = st
	tMu.Unlock()
}

func getTgwsStatus() TgwsStatus {
	tMu.Lock()
	defer tMu.Unlock()
	return tStat
}
