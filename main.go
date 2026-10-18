package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const appVersion = "1.4.0"

//go:embed ui
var uiFS embed.FS

var (
	token   string
	baseURL string
)

// dataDir, appDir, openWindow и прочее, что зависит от системы, — в app_windows.go и sys_darwin.go.

type instanceInfo struct {
	URL string `json:"url"`
}

func main() {
	platformInit()
	trayOnly := false
	for _, a := range os.Args[1:] {
		if a == "--tray" {
			trayOnly = true
		}
	}

	// Уже запущено — просто открыть окно.
	if alreadyRunning() {
		if !trayOnly {
			if b, err := os.ReadFile(filepath.Join(dataDir(), "instance.json")); err == nil {
				var ii instanceInfo
				if json.Unmarshal(b, &ii) == nil && ii.URL != "" {
					openWindow(ii.URL)
				}
			}
		}
		return
	}
	if !isAdmin() {
		if err := relaunchAsAdmin(); err == nil {
			return
		}
		// пользователь отказал в UAC — работаем как есть, но многое не сработает
	}
	if !claimInstance() {
		return
	}

	loadConfig()
	logf("NetSwitch %s запущен (администратор: %v)", appVersion, isAdmin())
	platformStart()

	var tb [16]byte
	_, _ = rand.Read(tb[:])
	token = hex.EncodeToString(tb[:])

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Println(err)
		return
	}
	baseURL = fmt.Sprintf("http://127.0.0.1:%d/?t=%s", ln.Addr().(*net.TCPAddr).Port, token)
	b, _ := json.Marshal(instanceInfo{URL: baseURL})
	_ = os.WriteFile(filepath.Join(dataDir(), "instance.json"), b, 0600)
	fixOwner(filepath.Join(dataDir(), "instance.json"))

	sub, _ := fs.Sub(uiFS, "ui")
	mux := http.NewServeMux()
	registerAPI(mux)
	mux.Handle("/", http.FileServer(http.FS(sub)))
	srv := &http.Server{Handler: guard(mux, ln.Addr().String()), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	go runTray(
		func() { openWindow(baseURL) },
		func() {
			if err := connectFastest(); err != nil {
				trayBalloon("NetSwitch", err.Error())
			} else {
				trayBalloon("NetSwitch", "Подключено: "+activeName())
			}
		},
		func() { _ = disconnect() },
		quit,
	)

	// Начальные проверки
	go func() {
		refreshZapretStatus()
		c := getCfg()
		z := getZapretStatus()
		if c.ZapretWanted && z.Installed && z.ServiceState == 0 && !z.Running {
			if err := zapretStartProcess(c.ZapretStrategy); err != nil {
				logf("zapret: %v", err)
			} else {
				logf("zapret запущен (%s)", c.ZapretStrategy)
			}
		}
		refreshTgwsStatus()
		if t := getTgwsStatus(); c.TgwsWanted && t.Installed && !t.Running && t.External == "" {
			if err := tgwsStartProcess(); err != nil {
				logf("TG WS Proxy: %v", err)
			} else {
				logf("TG WS Proxy запущен")
			}
		}
		refreshAll()
		// исключения DNS — после обновления программы, правки netswitch.json или смены DNS в обход NetSwitch
		if err := syncDNSBypass(); err != nil {
			logf("Исключения DNS: %v", err)
		}
		if zapretSupported {
			_, _, _ = zapretLatest(false)
			refreshZapretStatus()
		}
		_, _, _, _ = tgwsLatest(false)
		refreshTgwsStatus()
		updateTray()
	}()
	go func() {
		for {
			time.Sleep(4 * time.Second)
			refreshZapretStatus()
			refreshTgwsStatus()
		}
	}()
	go autoLoop()

	if !trayOnly {
		openWindow(baseURL)
	}
	select {}
}

func activeName() string {
	if p, ok := findProvider(snapshot().Active); ok {
		return p.Name
	}
	return "—"
}

func quit() {
	c := getCfg()
	z := getZapretStatus()
	if z.ServiceState == 0 && z.Running && c.ZapretWanted {
		killWinws() // zapret без службы живёт только вместе с программой
	}
	if getTgwsStatus().Running {
		tgwsStop() // TG WS Proxy тоже
	}
	logf("Выход")
	trayRemove()
	os.Exit(0)
}

// windowSize — размер окна интерфейса: компактный вид — узкое окно, как у телефона.
func windowSize() (int, int) {
	if getCfg().UICompact {
		return 400, 780
	}
	return 1180, 800
}

// guard — защита локального сервера: только 127.0.0.1 и только с токеном для API.
func guard(h http.Handler, host string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != host {
			http.Error(w, "forbidden", 403)
			return
		}
		if len(r.URL.Path) >= 5 && r.URL.Path[:5] == "/api/" && r.Header.Get("X-Token") != token {
			http.Error(w, "bad token", 403)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}
