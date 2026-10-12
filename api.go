package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type apiReq struct {
	ID       string          `json:"id"`
	Strategy string          `json:"strategy"`
	Only     []string        `json:"only"`
	URL      string          `json:"url"`
	Settings json.RawMessage `json:"settings"`
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
			v, err := f(r)
			reply(w, v, err)
		})
	}

	h("/api/state", func(r apiReq) (any, error) {
		s := snapshot()
		return map[string]any{"app": s, "cfg": getCfg(), "zapret": getZapretStatus(), "version": appVersion, "admin": isAdmin()}, nil
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
				*c = n
			}
		})
		return nil, err
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
	h("/api/zapret/start", func(r apiReq) (any, error) {
		if !zBusy.TryLock() {
			return nil, errBusy
		}
		defer zBusy.Unlock()
		s := r.Strategy
		if s == "" {
			s = getCfg().ZapretStrategy
		}
		if serviceState(zapretService) != 0 {
			zapretServiceRemove(false)
		}
		err := zapretStartProcess(s)
		if err == nil {
			updateCfg(func(c *Settings) { c.ZapretStrategy = s; c.ZapretWanted = true })
			logf("zapret запущен: %s", s)
		}
		refreshZapretStatus()
		updateTray()
		return nil, err
	})
	h("/api/zapret/stop", func(r apiReq) (any, error) {
		if !zBusy.TryLock() {
			return nil, errBusy
		}
		defer zBusy.Unlock()
		updateCfg(func(c *Settings) { c.ZapretWanted = false })
		if serviceState(zapretService) == 4 {
			_, _ = run(20e9, "net", "stop", zapretService)
		}
		killWinws()
		logf("zapret остановлен")
		refreshZapretStatus()
		updateTray()
		return nil, nil
	})
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
	h("/api/open", func(r apiReq) (any, error) {
		if strings.HasPrefix(r.URL, "https://") {
			openURL(r.URL)
		}
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
