//go:build darwin

package main

// macOS: NetSwitch запускается от имени пользователя, спрашивает пароль администратора
// (как UAC в Windows) и перезапускает себя от root через osascript. Процесс от root
// работает сервером без окна; окно, ссылки и уведомления открываются от имени пользователя.
// Значка в строке меню нет: окно снова открывается запуском NetSwitch, выход — в Настройках.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	userUID, userGID = -1, -1
	userHome         string
	instanceLock     *os.File
)

// platformInit — от чьего имени работать с окнами и файлами. Процессу от root пользователя
// передают в аргументах --uid, --gid и --home (их ставит relaunchAsAdmin и задание автозапуска).
func platformInit() {
	userUID, userGID = os.Getuid(), os.Getgid()
	userHome, _ = os.UserHomeDir()
	args := os.Args[1:]
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "--uid":
			if n, err := strconv.Atoi(args[i+1]); err == nil {
				userUID = n
			}
		case "--gid":
			if n, err := strconv.Atoi(args[i+1]); err == nil {
				userGID = n
			}
		case "--home":
			userHome = args[i+1]
		}
	}
	if userHome == "" {
		userHome = os.TempDir()
	}
}

func hasArg(a string) bool {
	for _, x := range os.Args[1:] {
		if x == a {
			return true
		}
	}
	return false
}

func hideCmd(c *exec.Cmd) {}

func isAdmin() bool { return os.Geteuid() == 0 }

// dataDir — ~/Library/Application Support/NetSwitch: настройки, журнал, zapret, TG WS Proxy.
// Внутри NetSwitch.app ничего не пишется — так подпись программы остаётся целой.
func dataDir() string {
	d := filepath.Join(userHome, "Library", "Application Support", "NetSwitch")
	if _, err := os.Stat(d); err != nil {
		_ = os.MkdirAll(d, 0755)
		fixOwner(d)
	}
	return d
}

func appDir() string { return dataDir() }

// fixOwner отдаёт пользователю файл, созданный процессом от root в его домашней папке.
func fixOwner(path string) {
	if os.Geteuid() == 0 && userUID > 0 {
		_ = os.Lchown(path, userUID, userGID)
	}
}

func fixOwnerTree(path string) {
	if os.Geteuid() != 0 || userUID <= 0 {
		return
	}
	_ = filepath.Walk(path, func(p string, _ os.FileInfo, err error) error {
		if err == nil {
			_ = os.Lchown(p, userUID, userGID)
		}
		return nil
	})
}

// runAsUser — команда от имени пользователя в его сеансе (окна, буфер обмена, уведомления).
func runAsUser(name string, args ...string) *exec.Cmd {
	if os.Geteuid() == 0 && userUID > 0 {
		uid := strconv.Itoa(userUID)
		a := append([]string{"asuser", uid, "/usr/bin/sudo", "-u", "#" + uid, "-H", "--", name}, args...)
		return exec.Command("/bin/launchctl", a...)
	}
	return exec.Command(name, args...)
}

func startDetached(c *exec.Cmd) error {
	if err := c.Start(); err != nil {
		return err
	}
	go func() { _ = c.Wait() }()
	return nil
}

// relaunchAsAdmin спрашивает пароль администратора и запускает копию от root без окна,
// затем открывает окно, когда та ответит.
func relaunchAsAdmin() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		exe = p
	}
	cmd := fmt.Sprintf("%s --tray --uid %d --gid %d --home %s >/dev/null 2>&1 &",
		shQuote(exe), os.Getuid(), os.Getgid(), shQuote(userHome))
	script := "do shell script " + appleScriptQuote(cmd) +
		" with prompt " + appleScriptQuote("NetSwitch нужен пароль администратора, чтобы менять DNS и запускать zapret.") +
		" with administrator privileges"
	if out, err := run(10*time.Minute, "/usr/bin/osascript", "-e", script); err != nil {
		return fmt.Errorf("osascript: %v %s", err, strings.TrimSpace(out))
	}
	if hasArg("--tray") {
		return nil
	}
	for i := 0; i < 120; i++ {
		time.Sleep(250 * time.Millisecond)
		if u := runningURL(); u != "" {
			openWindow(u)
			return nil
		}
	}
	return nil
}

// runningURL — адрес интерфейса уже запущенного NetSwitch, если он отвечает.
func runningURL() string {
	b, err := os.ReadFile(filepath.Join(dataDir(), "instance.json"))
	if err != nil {
		return ""
	}
	var ii instanceInfo
	if json.Unmarshal(b, &ii) != nil || ii.URL == "" {
		return ""
	}
	resp, err := (&http.Client{Timeout: 1500 * time.Millisecond}).Get(ii.URL)
	if err != nil {
		return ""
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	return ii.URL
}

func alreadyRunning() bool { return runningURL() != "" }

// claimInstance — блокировка файла: второй экземпляр её не получит.
func claimInstance() bool {
	p := filepath.Join(dataDir(), "instance.lock")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return true
	}
	fixOwner(p)
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		f.Close()
		return false
	}
	instanceLock = f
	return true
}

func openURL(u string) { _ = startDetached(runAsUser("/usr/bin/open", u)) }

// openWindow открывает интерфейс отдельным окном Chrome, Edge или Brave (режим приложения),
// иначе — в браузере по умолчанию.
func openWindow(url string) {
	w, h := windowSize()
	for _, name := range []string{"Google Chrome", "Microsoft Edge", "Brave Browser", "Chromium"} {
		for _, dir := range []string{"/Applications", filepath.Join(userHome, "Applications")} {
			app := filepath.Join(dir, name+".app")
			if _, err := os.Stat(app); err != nil {
				continue
			}
			c := runAsUser("/usr/bin/open", "-na", app, "--args", "--app="+url, fmt.Sprintf("--window-size=%d,%d", w, h),
				"--user-data-dir="+filepath.Join(dataDir(), "ui-profile"), "--no-first-run", "--no-default-browser-check")
			if c.Run() == nil {
				return
			}
		}
	}
	openURL(url)
}

func setClipboard(s string) error {
	c := runAsUser("/usr/bin/pbcopy")
	c.Stdin = strings.NewReader(s)
	return c.Run()
}

func serviceState(name string) int { return 0 }
func mutexExists(name string) bool { return false }

func icmpPing(ip string, timeoutMs int) (int, error) {
	out, _ := run(time.Duration(timeoutMs+1500)*time.Millisecond, "/sbin/ping", "-c", "1", "-n", "-W", strconv.Itoa(timeoutMs), ip)
	if ms, ok := parsePing(out); ok {
		return ms, nil
	}
	return 0, errors.New("нет ответа")
}

func listProcs() []procEntry {
	out, err := run(10*time.Second, "/bin/ps", "-axo", "pid=,ppid=,comm=")
	if err != nil {
		return nil
	}
	ps := parsePS(out)
	for i := range ps {
		ps[i].Name = filepath.Base(ps[i].Name)
	}
	return ps
}

func procPath(pid uint32) string {
	out, err := run(5*time.Second, "/bin/ps", "-o", "comm=", "-p", strconv.Itoa(int(pid)))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func killPID(pid uint32) { _ = syscall.Kill(int(pid), syscall.SIGKILL) }

// postToProcWindows — штатное закрытие: на macOS вместо сообщения окну значка шлём SIGTERM.
func postToProcWindows(pids map[uint32]bool, prefix, suffix string, msg uint32) int {
	n := 0
	for p := range pids {
		if syscall.Kill(int(p), syscall.SIGTERM) == nil {
			n++
		}
	}
	return n
}

// Значка в строке меню нет (для него нужен cgo): окно снова открывается запуском NetSwitch.
func runTray(onOpen, onFastest, onOff, onExit func()) {}
func trayRemove()                                     {}
func trayUpdate(color uint32, tip string)             {}

func trayBalloon(title, text string) {
	_ = startDetached(runAsUser("/usr/bin/osascript", "-e",
		"display notification "+appleScriptQuote(text)+" with title "+appleScriptQuote(title)))
}

func warpCLI() string {
	for _, p := range []string{"/usr/local/bin/warp-cli", "/Applications/Cloudflare WARP.app/Contents/Resources/warp-cli", "/opt/homebrew/bin/warp-cli"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// --- автозапуск: задание launchd от root, NetSwitch стартует при загрузке без запроса пароля ---

const (
	launchdLabel = "com.netswitch.app"
	launchdPath  = "/Library/LaunchDaemons/com.netswitch.app.plist"
)

func autostartEnabled() bool {
	_, err := os.Stat(launchdPath)
	return err == nil
}

func setAutostart(on bool) error {
	if !isAdmin() {
		return errors.New("нужны права администратора — перезапустите NetSwitch и введите пароль")
	}
	if !on {
		if err := os.Remove(launchdPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		exe = p
	}
	if strings.Contains(exe, "/AppTranslocation/") {
		return errors.New("macOS запустила NetSwitch из временной копии. Перенесите NetSwitch.app в «Программы», запустите снова и включите автозапуск")
	}
	args := []string{exe, "--tray", "--uid", strconv.Itoa(userUID), "--gid", strconv.Itoa(userGID), "--home", userHome}
	return os.WriteFile(launchdPath, []byte(launchdPlist(launchdLabel, args)), 0644)
}
