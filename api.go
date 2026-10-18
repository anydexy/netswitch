package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type apiReq struct {
	ID       string          `json:"id"`
	Strategy string          `json:"strategy"`
	Only     []string        `json:"only"`
	URL      string          `json:"url"`
	Settings json.RawMessage `json:"settings"`
	Conf     string          `json:"conf"`
	Page     string          `json:"-"` // окно интерфейса (заголовок X-Page)
}

var (
	pagesMu sync.Mutex
	pages   = map[string]time.Time{} // окно → когда оно последний раз спрашивало состояние
)

// newestPage запоминает окно интерфейса и возвращает самое новое из открытых. Окно сообщает
// "<время открытия, мс>-<случайное>"; старые окна, увидев, что есть новее, закрываются сами —
// так окна не копятся, если NetSwitch открыли ещё раз.
func newestPage(id string) string {
	now := time.Now()
	pagesMu.Lock()
	defer pagesMu.Unlock()
	if id != "" && len(id) < 64 {
		pages[id] = now
	}
	newest, best := "", int64(-1)
	for k, seen := range pages {
		if now.Sub(seen) > 10*time.Second {
			delete(pages, k)
			continue
		}
		created, _ := strconv.ParseInt(strings.SplitN(k, "-", 2)[0], 10, 64)
		if created > best {
			newest, best = k, created
		}
	}
	return newest
}

func reply(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": v})
}

var errBusy = errors.New("zapret сейчас занят (идёт тест или обновление)")

func registerAPI(mux *http.ServeMux) {
	h := func(path string, f func(r apiReq) (any, error)) {
		mux.HandleFunc(path, func(w http.ResponseWriter, req *http.Request) {
			var r apiReq
			if req.Method == "POST" {
				_ = json.NewDecoder(req.Body).Decode(&r)
			}
			r.Page = req.Header.Get("X-Page")
			if !zapretSupported && strings.HasPrefix(path, "/api/zapret/") {
				reply(w, nil, errors.New("zapret работает только в Windows"))
				return
			}
			v, err := f(r)
			reply(w, v, err)
		})
	}

	h("/api/state", func(r apiReq) (any, error) {
		s := snapshot()
		return map[string]any{"app": s, "cfg": getCfg(), "zapret": getZapretStatus(), "tgws": getTgwsStatus(), "version": appVersion, "admin": isAdmin(), "platform": runtime.GOOS, "update": getUpdateStatus(), "newest_page": newestPage(r.Page), "warp": warpInfo()}, nil
	})
	h("/api/refresh", func(r apiReq) (any, error) {
		if r.ID != "" {
			if p, ok := findProvider(r.ID); ok {
				go func() { checkProvider(p); refreshSystem() }()
				return nil, nil
			}
		}
		go func() { setBusy("Проверка всех способов…"); refreshAll(); setBusy("") }()
		return nil, nil
	})
	h("/api/connect", func(r apiReq) (any, error) { return nil, connect(r.ID) })
	h("/api/disconnect", func(r apiReq) (any, error) { return nil, disconnect() })
	h("/api/fastest", func(r apiReq) (any, error) {
		err := connectFastest()
		return activeName(), err
	})
	h("/api/settings", func(r apiReq) (any, error) {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(r.Settings, &m); err != nil {
			return nil, err
		}
		if v, ok := m["autostart"]; ok {
			var on bool
			_ = json.Unmarshal(v, &on)
			if err := setAutostart(on); err != nil {
				return nil, err
			}
			stMu.Lock()
			st.Autostart = on
			stMu.Unlock()
			delete(m, "autostart")
		}
		var err error
		var bad []string
		updateCfg(func(c *Settings) {
			b, _ := json.Marshal(c)
			var cur map[string]json.RawMessage
			_ = json.Unmarshal(b, &cur)
			for k, v := range m {
				cur[k] = v
			}
			b, _ = json.Marshal(cur)
			var n Settings
			if err = json.Unmarshal(b, &n); err == nil {
				if n.AutoInterval < 10 {
					n.AutoInterval = 10
				}
				n.DNSBypass, bad = normDomains(n.DNSBypass)
				if n.DNSBypassServers = normServers(n.DNSBypassServers); len(n.DNSBypassServers) == 0 {
					n.DNSBypassServers = defaultSettings().DNSBypassServers
				}
				*c = n
			}
		})
		if err != nil {
			return nil, err
		}
		_, d1 := m["dns_bypass"]
		_, d2 := m["dns_bypass_servers"]
		if d1 || d2 {
			if err := syncDNSBypass(); err != nil {
				logf("Исключения DNS: %v", err)
				return nil, err
			}
			if c := getCfg(); len(c.DNSBypass) > 0 {
				logf("Исключения DNS: %s → %s", strings.Join(c.DNSBypass, ", "), strings.Join(c.DNSBypassServers, ", "))
			} else {
				logf("Исключения DNS убраны")
			}
		}
		if d1 && len(bad) > 0 {
			return nil, fmt.Errorf("Исключения DNS: пропущено «%s» — нужен домен латиницей, например figma.com", strings.Join(bad, "», «"))
		}
		return nil, nil
	})
	h("/api/reset-providers", func(r apiReq) (any, error) {
		updateCfg(func(c *Settings) {
			c.Providers = defaultSettings().Providers
		})
		go refreshAll()
		return nil, nil
	})

	// --- zapret ---
	h("/api/zapret/check", func(r apiReq) (any, error) {
		v, _, err := zapretLatest(true)
		refreshZapretStatus()
		return v, err
	})
	h("/api/zapret/download", func(r apiReq) (any, error) {
		if getZapretStatus().Downloading {
			return nil, errBusy
		}
		setDL(true, 0, "Запуск загрузки…")
		go func() {
			if err := zapretDownload(); err != nil {
				logf("zapret: загрузка: %v", err)
			}
			refreshZapretStatus()
		}()
		return nil, nil
	})
	h("/api/zapret/start", func(r apiReq) (any, error) { return nil, zapretOn(r.Strategy) })
	h("/api/zapret/stop", func(r apiReq) (any, error) { return nil, zapretOff() })
	h("/api/zapret/service/install", func(r apiReq) (any, error) {
		if !zBusy.TryLock() {
			return nil, errBusy
		}
		defer zBusy.Unlock()
		s := r.Strategy
		if s == "" {
			s = getCfg().ZapretStrategy
		}
		err := zapretServiceInstall(s)
		if err == nil {
			updateCfg(func(c *Settings) { c.ZapretStrategy = s; c.ZapretWanted = false })
			logf("zapret установлен как служба: %s", s)
		}
		refreshZapretStatus()
		return nil, err
	})
	h("/api/zapret/service/remove", func(r apiReq) (any, error) {
		if !zBusy.TryLock() {
			return nil, errBusy
		}
		defer zBusy.Unlock()
		zapretServiceRemove(true)
		killWinws()
		logf("Служба zapret удалена")
		refreshZapretStatus()
		return nil, nil
	})
	h("/api/zapret/strategy", func(r apiReq) (any, error) {
		updateCfg(func(c *Settings) { c.ZapretStrategy = r.Strategy })
		return nil, nil
	})
	h("/api/zapret/test", func(r apiReq) (any, error) {
		if getZapretStatus().Test.Running {
			return nil, errBusy
		}
		go func() { zapretTestAll(r.Only); refreshZapretStatus() }()
		return nil, nil
	})
	h("/api/zapret/test/stop", func(r apiReq) (any, error) {
		zMu.Lock()
		zTestStop = true
		zMu.Unlock()
		return nil, nil
	})
	h("/api/zapret/folder", func(r apiReq) (any, error) {
		openURL(zapretDir())
		return nil, nil
	})

	// --- TG WS Proxy ---
	h("/api/tgws/check", func(r apiReq) (any, error) {
		v, _, _, err := tgwsLatest(true)
		refreshTgwsStatus()
		return v, err
	})
	h("/api/tgws/download", func(r apiReq) (any, error) {
		if getTgwsStatus().Downloading {
			return nil, errTgwsBusy
		}
		setTDL(true, 0, "Запуск загрузки…")
		go func() {
			if err := tgwsDownload(); err != nil {
				logf("TG WS Proxy: загрузка: %v", err)
			}
			refreshTgwsStatus()
		}()
		return nil, nil
	})
	h("/api/tgws/start", func(r apiReq) (any, error) { return nil, tgwsSwitch("запущен", true, tgwsStartProcess) })
	h("/api/tgws/takeover", func(r apiReq) (any, error) {
		return nil, tgwsSwitch("запущен из NetSwitch", true, tgwsTakeOver)
	})
	h("/api/tgws/stop", func(r apiReq) (any, error) {
		return nil, tgwsSwitch("остановлен", false, func() error { tgwsStop(); return nil })
	})
	h("/api/tgws/telegram", func(r apiReq) (any, error) {
		l := tgwsLink(readTgwsConf(tgwsDataDir()))
		if l == "" {
			return nil, errors.New("сначала запустите TG WS Proxy")
		}
		openURL(l)
		return nil, nil
	})
	h("/api/tgws/copy", func(r apiReq) (any, error) {
		l := tgwsLink(readTgwsConf(tgwsDataDir()))
		if l == "" {
			return nil, errors.New("сначала запустите TG WS Proxy")
		}
		return nil, setClipboard(l)
	})
	h("/api/tgws/folder", func(r apiReq) (any, error) {
		_ = os.MkdirAll(tgwsDir(), 0755)
		openURL(tgwsDir())
		return nil, nil
	})
	h("/api/tgws/log", func(r apiReq) (any, error) {
		p := filepath.Join(tgwsDataDir(), "proxy.log")
		if _, err := os.Stat(p); err != nil {
			return nil, errors.New("журнала пока нет — он появится после запуска")
		}
		openURL(p)
		return nil, nil
	})
	h("/api/open", func(r apiReq) (any, error) {
		if strings.HasPrefix(r.URL, "https://") {
			openURL(r.URL)
		}
		return nil, nil
	})
	// --- WARP (AmneziaWG) ---
	warpReconnect := func() error { // применить новый конфиг, если WARP подключён
		if snapshot().Active == "warp" {
			return connect("warp")
		}
		return nil
	}
	h("/api/warp/conf", func(r apiReq) (any, error) {
		b, err := os.ReadFile(warpConfPath())
		if err != nil {
			return "", nil
		}
		return string(b), nil
	})
	h("/api/warp/generate", func(r apiReq) (any, error) {
		text, err := warpRegister()
		if err != nil {
			return nil, fmt.Errorf("%v. Конфиг можно сделать в GitHub Codespaces (bash warp_generator.sh) и вставить сюда", err)
		}
		if err := warpSaveConf(text); err != nil {
			return nil, err
		}
		logf("WARP: зарегистрировано новое устройство")
		warpDisconnect()
		return nil, warpReconnect()
	})
	h("/api/warp/save", func(r apiReq) (any, error) {
		if err := warpSaveConf(r.Conf); err != nil {
			return nil, err
		}
		logf("WARP: сохранён свой конфиг")
		warpDisconnect()
		return nil, warpReconnect()
	})

	// --- обновление NetSwitch ---
	h("/api/update/check", func(r apiReq) (any, error) { return updateCheck() })
	h("/api/update/install", func(r apiReq) (any, error) {
		if getUpdateStatus().Busy {
			return nil, errors.New("обновление уже идёт")
		}
		setUpdate(func(u *UpdateStatus) { u.Busy, u.Msg, u.Err = true, "Запуск обновления…", "" })
		go func() { _ = updateInstall() }()
		return nil, nil
	})
	h("/api/exit", func(r apiReq) (any, error) {
		go quit()
		return nil, nil
	})
}

func init() {
	// автозапуск — узнаём при старте
	go func() {
		on := autostartEnabled()
		stMu.Lock()
		st.Autostart = on
		stMu.Unlock()
	}()
}
