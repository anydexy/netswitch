package main

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const zapretService = "zapret"

func zapretDir() string { return filepath.Join(appDir(), "zapret") }

type ZapretStatus struct {
	Installed      bool     `json:"installed"`
	LocalVersion   string   `json:"local_version"`
	LatestVersion  string   `json:"latest_version"`
	LatestErr      string   `json:"latest_err,omitempty"`
	UpToDate       bool     `json:"up_to_date"`
	Strategies     []string `json:"strategies"`
	Running        bool     `json:"running"`       // winws.exe работает (любым способом)
	ServiceState   int      `json:"service_state"` // 0 нет, 1 стоп, 4 работает
	ServiceStrat   string   `json:"service_strategy"`
	Downloading    bool     `json:"downloading"`
	DownloadPct    int      `json:"download_pct"`
	DownloadMsg    string   `json:"download_msg"`
	Test           ZTest    `json:"test"`
	OtherInstalled string   `json:"other,omitempty"` // конфликтующие программы
}

type StratResult struct {
	Name    string   `json:"name"`
	OK      int      `json:"ok"`
	Total   int      `json:"total"`
	AvgMs   int      `json:"avg_ms"`
	Details []string `json:"details"`
}

type ZTest struct {
	Running  bool          `json:"running"`
	Current  string        `json:"current"`
	Done     int           `json:"done"`
	Total    int           `json:"total"`
	Results  []StratResult `json:"results"`
	Best     string        `json:"best"`
	Finished string        `json:"finished"`
}

var (
	zMu     sync.Mutex
	zProc   *exec.Cmd
	zStat   ZapretStatus
	zLatest struct {
		ver, url, err string
		at            time.Time
	}
	zTestStop bool
	zBusy     sync.Mutex // старт/стоп/обновление/тест не пересекаются
)

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

// zapretLatest — последняя версия на GitHub (кэш 10 минут).
func zapretLatest(force bool) (string, string, error) {
	zMu.Lock()
	if !force && time.Since(zLatest.at) < 10*time.Minute && zLatest.ver != "" {
		v, u := zLatest.ver, zLatest.url
		zMu.Unlock()
		return v, u, nil
	}
	zMu.Unlock()
	repo := getCfg().ZapretRepo
	c := httpClientVia("", 12*time.Second)
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/"+repo+"/releases/latest", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "NetSwitch")
	var ver, url string
	resp, err := c.Do(req)
	if err == nil && resp.StatusCode != 200 {
		resp.Body.Close()
		err = fmt.Errorf("GitHub API: HTTP %d", resp.StatusCode)
	}
	if err == nil {
		var rel struct {
			Tag    string `json:"tag_name"`
			Assets []struct {
				Name string `json:"name"`
				URL  string `json:"browser_download_url"`
			} `json:"assets"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&rel)
		resp.Body.Close()
		ver = strings.TrimPrefix(rel.Tag, "v")
		for _, a := range rel.Assets {
			if strings.HasSuffix(strings.ToLower(a.Name), ".zip") {
				url = a.URL
				break
			}
		}
	}
	if ver == "" { // запасной вариант — version.txt из репозитория
		r2, err2 := c.Get("https://raw.githubusercontent.com/" + repo + "/main/.service/version.txt")
		if err2 != nil {
			if err == nil {
				err = err2
			}
			zMu.Lock()
			zLatest.err = shortErr(err).Error()
			zMu.Unlock()
			return "", "", shortErr(err)
		}
		b, _ := io.ReadAll(io.LimitReader(r2.Body, 100))
		r2.Body.Close()
		if r2.StatusCode == 200 {
			ver = strings.TrimSpace(string(b))
		}
	}
	if !reVer.MatchString(ver) {
		if err == nil {
			err = errors.New("не удалось узнать версию")
		}
		zMu.Lock()
		zLatest.err = shortErr(err).Error()
		zMu.Unlock()
		return "", "", shortErr(err)
	}
	if ver == "" {
		return "", "", errors.New("не удалось узнать версию")
	}
	if url == "" {
		name := filepath.Base(repo)
		url = fmt.Sprintf("https://github.com/%s/releases/download/%s/%s-%s.zip", repo, ver, name, ver)
	}
	zMu.Lock()
	zLatest.ver, zLatest.url, zLatest.err, zLatest.at = ver, url, "", time.Now()
	zMu.Unlock()
	return ver, url, nil
}

var reNum = regexp.MustCompile(`\d+`)
var reVer = regexp.MustCompile(`^[0-9][0-9A-Za-z.\-]{0,20}$`)

func naturalKey(s string) string {
	return reNum.ReplaceAllStringFunc(strings.ToLower(s), func(n string) string { return fmt.Sprintf("%08s", n) })
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

func gameFilterVals() (all, tcp, udp string) {
	switch getCfg().GameFilter {
	case "all":
		return "1024-65535", "1024-65535", "1024-65535"
	case "tcp":
		return "1024-65535", "1024-65535", "12"
	case "udp":
		return "1024-65535", "12", "1024-65535"
	}
	return "12", "12", "12"
}

// parseStrategy достаёт аргументы winws.exe из .bat-файла стратегии.
func parseStrategy(root, batName string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(root, batName))
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	var joined strings.Builder
	capture := false
	for _, ln := range lines {
		t := strings.TrimRight(ln, " \t")
		if !capture {
			low := strings.ToLower(t)
			i := strings.Index(low, "winws.exe")
			if i < 0 || strings.HasPrefix(strings.TrimSpace(low), "::") || strings.HasPrefix(strings.TrimSpace(low), "rem ") {
				continue
			}
			capture = true
			t = t[i+len("winws.exe"):]
			t = strings.TrimPrefix(t, `"`)
		}
		if strings.HasSuffix(t, "^") {
			joined.WriteString(strings.TrimSuffix(t, "^"))
			joined.WriteByte(' ')
			continue
		}
		joined.WriteString(t)
		break
	}
	if !capture {
		return nil, errors.New("в файле нет запуска winws.exe")
	}
	s := joined.String()
	gf, gt, gu := gameFilterVals()
	bin := filepath.Join(root, "bin") + `\`
	lists := filepath.Join(root, "lists") + `\`
	repl := strings.NewReplacer(
		"%BIN%", bin, "%LISTS%", lists, "%~dp0", root+`\`,
		"%GameFilter%", gf, "%GameFilterTCP%", gt, "%GameFilterUDP%", gu,
		"^!", "!", "^&", "&", "^|", "|", "^^", "^",
	)
	s = repl.Replace(s)
	// разбивка с учётом кавычек
	var args []string
	var cur strings.Builder
	inQ, has := false, false
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
			has = true
		case (r == ' ' || r == '\t') && !inQ:
			if has {
				args = append(args, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	if has {
		args = append(args, cur.String())
	}
	if len(args) == 0 {
		return nil, errors.New("пустые параметры")
	}
	return args, nil
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

// --- скачивание / обновление ---

func setDL(on bool, pct int, msg string) {
	zMu.Lock()
	zStat.Downloading, zStat.DownloadPct, zStat.DownloadMsg = on, pct, msg
	zMu.Unlock()
}

type progressReader struct {
	r     io.Reader
	n, of int64
	set   func(pct int, msg string)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.n += int64(n)
	if p.of > 0 {
		p.set(int(p.n*100/p.of), fmt.Sprintf("Скачивание… %d / %d КБ", p.n/1024, p.of/1024))
	} else {
		p.set(0, fmt.Sprintf("Скачивание… %d КБ", p.n/1024))
	}
	return n, err
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

func unzip(zipPath, dst string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()
	dstAbs, _ := filepath.Abs(dst)
	for _, f := range r.File {
		p := filepath.Join(dst, filepath.FromSlash(f.Name))
		pa, _ := filepath.Abs(p)
		if pa != dstAbs && !strings.HasPrefix(pa, dstAbs+string(os.PathSeparator)) {
			continue // защита от путей вида ../
		}
		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(p, 0755)
			continue
		}
		_ = os.MkdirAll(filepath.Dir(p), 0755)
		rc, err := f.Open()
		if err != nil {
			return err
		}
		w, err := os.Create(p)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(w, rc)
		rc.Close()
		w.Close()
		if err != nil {
			return err
		}
	}
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

// --- тест стратегий ---

func testURL(c *http.Client, u string) (bool, int, string) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return false, 0, "плохой URL"
	}
	req.Header.Set("User-Agent", browserUA)
	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return false, 0, shortErr(err).Error()
	}
	// Читаем до 160 КБ: DPI часто пропускает начало и рвёт соединение после ~16 КБ.
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 160*1024))
	resp.Body.Close()
	ms := int(time.Since(start).Milliseconds())
	if err != nil {
		return false, ms, fmt.Sprintf("обрыв после %d КБ (%s)", n/1024, shortErr(err))
	}
	return true, ms, fmt.Sprintf("HTTP %d, %d мс", resp.StatusCode, ms)
}

func runSiteTests() StratResult {
	urls := getCfg().ZapretTests
	res := StratResult{Total: len(urls), Details: make([]string, len(urls))}
	var wg sync.WaitGroup
	var mu sync.Mutex
	sum := 0
	for i, u := range urls {
		wg.Add(1)
		go func(i int, u string) {
			defer wg.Done()
			ok, ms, d := testURL(httpClientVia("", 8*time.Second), u)
			host := u
			if p := strings.Index(u, "//"); p >= 0 {
				host = strings.SplitN(u[p+2:], "/", 2)[0]
			}
			mark := "✗"
			if ok {
				mark = "✓"
			}
			mu.Lock()
			res.Details[i] = mark + " " + host + " — " + d
			if ok {
				res.OK++
				sum += ms
			}
			mu.Unlock()
		}(i, u)
	}
	wg.Wait()
	if res.OK > 0 {
		res.AvgMs = sum / res.OK
	}
	return res
}

func setTest(f func(t *ZTest)) {
	zMu.Lock()
	f(&zStat.Test)
	zMu.Unlock()
}

func zapretTestAll(only []string) {
	if !zBusy.TryLock() {
		return
	}
	defer zBusy.Unlock()
	strats := zapretStrategies()
	if len(only) > 0 {
		strats = only
	}
	if len(strats) == 0 {
		setTest(func(t *ZTest) { t.Finished = "Сначала скачайте zapret" })
		return
	}
	zMu.Lock()
	zTestStop = false
	zMu.Unlock()
	wasService := serviceState(zapretService) == 4
	wasProc := !wasService && winwsRunning()
	if wasService {
		_, _ = run(20*time.Second, "net", "stop", zapretService)
	}
	killWinws()
	setTest(func(t *ZTest) { *t = ZTest{Running: true, Total: len(strats) + 1, Current: "без zapret"} })
	logf("zapret: тест %d стратегий", len(strats))

	base := runSiteTests()
	base.Name = "(без zapret)"
	setTest(func(t *ZTest) { t.Results = append(t.Results, base); t.Done = 1 })

	for _, s := range strats {
		zMu.Lock()
		stop := zTestStop
		zMu.Unlock()
		if stop {
			break
		}
		setTest(func(t *ZTest) { t.Current = s })
		var r StratResult
		if err := zapretStartProcess(s); err != nil {
			r = StratResult{Total: len(getCfg().ZapretTests), Details: []string{"✗ " + err.Error()}}
		} else {
			time.Sleep(1500 * time.Millisecond)
			r = runSiteTests()
		}
		r.Name = s
		killWinws()
		setTest(func(t *ZTest) { t.Results = append(t.Results, r); t.Done++ })
	}

	var best string
	zMu.Lock()
	rs := append([]StratResult(nil), zStat.Test.Results...)
	zMu.Unlock()
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].OK != rs[j].OK {
			return rs[i].OK > rs[j].OK
		}
		return rs[i].AvgMs < rs[j].AvgMs
	})
	for _, r := range rs {
		if r.Name != "(без zapret)" && r.OK > 0 {
			best = r.Name
			break
		}
	}
	msg := "Готово. "
	if best != "" {
		for _, r := range rs {
			if r.Name == best {
				msg += "Лучше всего: " + best + " (" + strconv.Itoa(r.OK) + "/" + strconv.Itoa(r.Total) + " сайтов, " + strconv.Itoa(r.AvgMs) + " мс)"
			}
		}
	} else {
		msg += "Ни одна стратегия не помогла."
	}
	setTest(func(t *ZTest) {
		t.Running, t.Current, t.Best, t.Results = false, "", best, rs
		t.Finished = msg
	})
	logf("zapret: %s", msg)

	// вернуть как было
	if wasService {
		_, _ = run(20*time.Second, "sc", "start", zapretService)
	} else if wasProc {
		_ = zapretStartProcess(getCfg().ZapretStrategy)
	}
}

func refreshZapretStatus() {
	st := ZapretStatus{}
	st.LocalVersion = zapretLocalVersion()
	st.Installed = st.LocalVersion != ""
	st.Strategies = zapretStrategies()
	st.Running = winwsRunning()
	st.ServiceState = serviceState(zapretService)
	if st.ServiceState != 0 {
		st.ServiceStrat = zapretServiceStrategy()
	}
	for _, svc := range []string{"GoodbyeDPI", "WinDivert1.4"} {
		if serviceState(svc) == 4 {
			st.OtherInstalled = svc
		}
	}
	zMu.Lock()
	st.LatestVersion, st.LatestErr = zLatest.ver, zLatest.err
	st.UpToDate = st.Installed && st.LatestVersion != "" && st.LatestVersion == st.LocalVersion
	st.Downloading, st.DownloadPct, st.DownloadMsg, st.Test = zStat.Downloading, zStat.DownloadPct, zStat.DownloadMsg, zStat.Test
	zStat = st
	zMu.Unlock()
}

func getZapretStatus() ZapretStatus {
	zMu.Lock()
	defer zMu.Unlock()
	s := zStat
	s.Test.Results = append([]StratResult(nil), zStat.Test.Results...)
	return s
}
