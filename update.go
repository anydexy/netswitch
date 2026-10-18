package main

// Обновление NetSwitch: последний релиз github.com/anydexy/netswitch, архив для своей системы
// (updateAsset: NetSwitch-windows.zip или NetSwitch-mac.zip) с проверкой SHA-256, указанной GitHub.
// Новые файлы ставятся переименованием поверх старых (работающий exe переименовывать можно),
// затем программа запускает себя заново с --updated и выходит. Новый экземпляр занимает тот же
// порт с тем же токеном, поэтому открытое окно переподключается само.

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const updateRepo = "anydexy/netswitch"

type UpdateStatus struct {
	Current    string `json:"current"`
	Latest     string `json:"latest"`
	Available  bool   `json:"available"`
	Checking   bool   `json:"checking"`
	Checked    string `json:"checked"` // время последней проверки
	Busy       bool   `json:"busy"`    // скачивание и установка
	Pct        int    `json:"pct"`
	Msg        string `json:"msg"`
	Err        string `json:"err,omitempty"`
	Notes      string `json:"notes"` // описание релиза
	Restarting bool   `json:"restarting"`
}

var (
	uMu   sync.Mutex
	uStat = UpdateStatus{Current: appVersion}
	uRel  struct{ ver, url, sum string }
	uBusy sync.Mutex
)

func getUpdateStatus() UpdateStatus {
	uMu.Lock()
	defer uMu.Unlock()
	return uStat
}

func setUpdate(f func(u *UpdateStatus)) {
	uMu.Lock()
	f(&uStat)
	uMu.Unlock()
}

// newerVersion — версия a новее b ("1.10.0" > "1.9.2"; хвост вроде "-beta" не учитывается).
func newerVersion(a, b string) bool {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x > y
		}
	}
	return false
}

func versionParts(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+ "); i >= 0 {
		v = v[:i]
	}
	var r []int
	for _, p := range strings.Split(v, ".") {
		n, _ := strconv.Atoi(p)
		r = append(r, n)
	}
	return r
}

// githubLatestRequest — запрос последнего релиза репозитория через API GitHub. Без токена GitHub
// отвечает 60 раз в час с одного адреса; если задан GITHUB_TOKEN (так NetSwitch проверяется в CI,
// где адрес общий), запрос идёт с ним.
func githubLatestRequest(repo string) *http.Request {
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/"+repo+"/releases/latest", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "NetSwitch/"+appVersion)
	if t := os.Getenv("GITHUB_TOKEN"); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	return req
}

// updateCheck узнаёт последнюю версию на GitHub.
func updateCheck() (UpdateStatus, error) {
	setUpdate(func(u *UpdateStatus) { u.Checking, u.Err = true, "" })
	defer setUpdate(func(u *UpdateStatus) { u.Checking = false })
	fail := func(err error) (UpdateStatus, error) {
		err = shortErr(err)
		setUpdate(func(u *UpdateStatus) { u.Err = err.Error() })
		return getUpdateStatus(), err
	}
	if updateAsset == "" {
		return fail(errors.New("обновление не поддерживается в этой системе"))
	}
	req := githubLatestRequest(updateRepo)
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
		Body   string `json:"body"`
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
	var link, sum string
	for _, a := range rel.Assets {
		if a.Name == updateAsset {
			link, sum = a.URL, strings.TrimPrefix(strings.ToLower(a.Digest), "sha256:")
		}
	}
	uMu.Lock()
	uRel.ver, uRel.url, uRel.sum = ver, link, sum
	uStat.Latest, uStat.Notes = ver, releaseNotes(rel.Body)
	uStat.Available = link != "" && newerVersion(ver, appVersion)
	uStat.Checked = time.Now().Format("15:04")
	uMu.Unlock()
	return getUpdateStatus(), nil
}

// releaseNotes — раздел «Что нового» из описания релиза, без разметки Markdown, коротко.
func releaseNotes(body string) string {
	var out []string
	in := false
	for _, ln := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "## ") {
			if in {
				break
			}
			in = strings.Contains(strings.ToLower(t), "нового") || strings.Contains(strings.ToLower(t), "исправлено")
			continue
		}
		if in && t != "" {
			out = append(out, strings.NewReplacer("**", "", "`", "").Replace(t))
		}
	}
	s := strings.Join(out, "\n")
	if r := []rune(s); len(r) > 700 {
		s = string(r[:700]) + "…"
	}
	return s
}

// updateInstall скачивает и ставит последнюю версию, затем перезапускает программу.
func updateInstall() error {
	if !uBusy.TryLock() {
		return errors.New("обновление уже идёт")
	}
	defer uBusy.Unlock()
	fail := func(msg string, err error) error {
		setUpdate(func(u *UpdateStatus) { u.Busy, u.Msg, u.Err = false, "", msg+shortErr(err).Error() })
		logf("Обновление: %s%v", msg, err)
		return err
	}
	setUpdate(func(u *UpdateStatus) {
		u.Busy, u.Pct, u.Msg, u.Err = true, 0, "Проверка последней версии…", ""
	})
	if _, err := updateCheck(); err != nil {
		return fail("", err)
	}
	uMu.Lock()
	ver, link, sum := uRel.ver, uRel.url, uRel.sum
	uMu.Unlock()
	if !newerVersion(ver, appVersion) {
		setUpdate(func(u *UpdateStatus) { u.Busy, u.Msg = false, "Установлена последняя версия" })
		return nil
	}
	if link == "" || sum == "" {
		return fail("", errors.New("в релизе "+ver+" нет "+updateAsset+" с контрольной суммой"))
	}
	if !isAdmin() {
		return fail("", errors.New("нужны права администратора — перезапустите NetSwitch"))
	}
	if u, err := url.Parse(link); err != nil || u.Scheme != "https" {
		return fail("", errors.New("неверная ссылка на архив"))
	}

	setUpdate(func(u *UpdateStatus) { u.Msg = "Скачивание " + ver + "…" })
	req, _ := http.NewRequest("GET", link, nil)
	req.Header.Set("User-Agent", "NetSwitch/"+appVersion)
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		return fail("Ошибка загрузки: ", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fail("Ошибка загрузки: ", fmt.Errorf("HTTP %d", resp.StatusCode))
	}
	tmp := filepath.Join(dataDir(), "update.zip")
	f, err := os.Create(tmp)
	if err != nil {
		return fail("", err)
	}
	defer os.Remove(tmp)
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), &progressReader{r: resp.Body, of: resp.ContentLength,
		set: func(pct int, msg string) { setUpdate(func(u *UpdateStatus) { u.Pct, u.Msg = pct, msg }) }})
	f.Close()
	if err != nil {
		return fail("Ошибка загрузки: ", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != sum {
		return fail("", errors.New("контрольная сумма не совпала с указанной на GitHub — обновление не установлено"))
	}

	setUpdate(func(u *UpdateStatus) { u.Pct, u.Msg = 100, "Установка…" })
	zr, err := zip.OpenReader(tmp)
	if err != nil {
		return fail("Архив повреждён: ", err)
	}
	err = updateApply(&zr.Reader)
	zr.Close()
	if err != nil {
		return fail("Не удалось установить: ", err)
	}
	logf("Обновление: установлена версия %s, перезапуск", ver)
	restartForUpdate()
	return nil
}

// zipFile — содержимое файла из архива обновления.
func zipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, 200<<20))
}

// replaceFile ставит новый файл на место path переименованием: работающий exe так заменить можно,
// а на macOS у нового файла своя подпись кода, не испорченная записью поверх.
func replaceFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	old := path + ".old"
	_ = os.Remove(old)
	if _, err := os.Stat(path); err == nil {
		if err := os.Rename(path, old); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Rename(old, path)
		return err
	}
	_ = os.Remove(old) // под Windows работающий exe удалить нельзя — уберётся при следующем запуске
	return nil
}

// updateCleanup убирает старый exe, оставшийся после обновления.
func updateCleanup() {
	if exe, err := os.Executable(); err == nil {
		_ = os.Remove(exe + ".old")
	}
}

// restartForUpdate останавливает то, что живёт вместе с программой, отдаёт блокировку
// единственного экземпляра и запускает новую версию.
func restartForUpdate() {
	setUpdate(func(u *UpdateStatus) { u.Restarting, u.Msg = true, "Перезапуск…" })
	time.Sleep(1500 * time.Millisecond) // окно успеет показать «Перезапуск»
	c := getCfg()
	if z := getZapretStatus(); z.ServiceState == 0 && z.Running && c.ZapretWanted {
		killWinws()
	}
	if getTgwsStatus().Running {
		tgwsStop()
	}
	warpDisconnect() // новая версия подключит WARP снова
	trayRemove()
	if httpLn != nil {
		_ = httpLn.Close()
	}
	releaseInstance()
	exe, _ := os.Executable()
	args := []string{}
	for _, a := range os.Args[1:] {
		if a != "--updated" {
			args = append(args, a)
		}
	}
	cmd := exec.Command(exe, append(args, "--updated")...)
	detachCmd(cmd)
	if err := cmd.Start(); err != nil {
		logf("Обновление: не удалось запустить новую версию: %v", err)
	}
	os.Exit(0)
}

// updateLoop — проверка при запуске и дальше раз в 12 часов. В авто-режиме обновление ставится само.
func updateLoop() {
	time.Sleep(8 * time.Second)
	for {
		if u, err := updateCheck(); err == nil && u.Available {
			logf("Доступна версия %s", u.Latest)
			if getCfg().ManualUpdate {
				trayBalloon("NetSwitch", "Доступна версия "+u.Latest+". Обновить — в окне программы или в Настройках")
			} else {
				for getZapretStatus().Test.Running || snapshot().Busy != "" { // не мешать тесту и переключению
					time.Sleep(10 * time.Second)
				}
				trayBalloon("NetSwitch", "Обновляюсь до версии "+u.Latest+"…")
				_ = updateInstall()
			}
		}
		time.Sleep(12 * time.Hour)
	}
}

// updatedRestart — запуск после обновления: подождать, пока прежний экземпляр выйдет,
// и вернуть порт и токен, на которых работало окно.
func updatedRestart() (port int, tok string) {
	for i := 0; i < 60 && alreadyRunning(); i++ {
		time.Sleep(250 * time.Millisecond)
	}
	b, err := os.ReadFile(filepath.Join(dataDir(), "instance.json"))
	if err != nil {
		return 0, ""
	}
	var ii instanceInfo
	if json.Unmarshal(b, &ii) != nil {
		return 0, ""
	}
	u, err := url.Parse(ii.URL)
	if err != nil {
		return 0, ""
	}
	port, _ = strconv.Atoi(u.Port())
	return port, u.Query().Get("t")
}
