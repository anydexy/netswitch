package main

// Включение и выключение zapret и TG WS Proxy — общие для окна и меню в трее, и само меню.

// zapretOn запускает zapret со стратегией (пусто — выбранная в настройках) без службы.
func zapretOn(strategy string) error {
	if !zBusy.TryLock() {
		return errBusy
	}
	defer zBusy.Unlock()
	if strategy == "" {
		strategy = getCfg().ZapretStrategy
	}
	if serviceState(zapretService) != 0 {
		zapretServiceRemove(false)
	}
	err := zapretStartProcess(strategy)
	if err == nil {
		updateCfg(func(c *Settings) { c.ZapretStrategy = strategy; c.ZapretWanted = true })
		logf("zapret запущен: %s", strategy)
	}
	refreshZapretStatus()
	updateTray()
	return err
}

// zapretOff останавливает zapret (и службу Windows, если он работает ею).
func zapretOff() error {
	if !zBusy.TryLock() {
		return errBusy
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
	return nil
}

// tgwsSwitch выполняет f (запуск или остановку TG WS Proxy) и запоминает, нужен ли он.
func tgwsSwitch(name string, wanted bool, f func() error) error {
	if !tBusy.TryLock() {
		return errTgwsBusy
	}
	defer tBusy.Unlock()
	err := f()
	if err == nil {
		updateCfg(func(c *Settings) { c.TgwsWanted = wanted })
		logf("TG WS Proxy %s", name)
	}
	refreshTgwsStatus()
	updateTray()
	return err
}

// trayItem — пункт меню в трее. Sep — разделитель.
type trayItem struct {
	Title    string
	Checked  bool
	Disabled bool
	Sep      bool
	Do       func()
}

// trayDo выполняет действие из меню и сообщает результат всплывающим уведомлением.
func trayDo(ok string, f func() error) {
	if err := f(); err != nil {
		trayBalloon("NetSwitch", err.Error())
	} else if ok != "" {
		trayBalloon("NetSwitch", ok)
	}
}

// trayMenu — меню значка в трее, собирается при каждом открытии.
func trayMenu() []trayItem {
	s, z, t := snapshot(), getZapretStatus(), getTgwsStatus()
	warp := s.Active == "warp"
	items := []trayItem{
		{Title: "Открыть NetSwitch", Do: func() { openWindow(baseURL) }},
		{Sep: true},
		{Title: "Подключить самый быстрый", Do: func() {
			trayDo("", func() error {
				if err := connectFastest(); err != nil {
					return err
				}
				trayBalloon("NetSwitch", "Подключено: "+activeName())
				return nil
			})
		}},
		{Title: "Cloudflare WARP", Checked: warp, Do: func() {
			if warp {
				trayDo("WARP отключён", disconnect)
			} else {
				trayDo("WARP подключён", func() error { return connect("warp") })
			}
		}},
		{Title: "Отключить (DNS провайдера)", Disabled: s.Active == "", Do: func() { trayDo("", disconnect) }},
		{Sep: true},
	}
	if zapretSupported {
		zt := "Zapret"
		if !z.Installed {
			zt = "Zapret — сначала скачайте в окне"
		}
		items = append(items, trayItem{Title: zt, Checked: z.Running, Disabled: !z.Installed || z.Test.Running || z.Downloading, Do: func() {
			if z.Running {
				trayDo("zapret остановлен", zapretOff)
			} else {
				trayDo("zapret запущен", func() error { return zapretOn("") })
			}
		}})
	}
	tt := "TG WS Proxy"
	if !t.Installed {
		tt = "TG WS Proxy — сначала скачайте в окне"
	}
	items = append(items, trayItem{Title: tt, Checked: t.Running, Disabled: !t.Installed || t.Downloading, Do: func() {
		if t.Running {
			trayDo("TG WS Proxy остановлен", func() error {
				return tgwsSwitch("остановлен", false, func() error { tgwsStop(); return nil })
			})
		} else if t.External != "" {
			trayDo("TG WS Proxy перенесён в NetSwitch", func() error { return tgwsSwitch("запущен из NetSwitch", true, tgwsTakeOver) })
		} else {
			trayDo("TG WS Proxy запущен", func() error { return tgwsSwitch("запущен", true, tgwsStartProcess) })
		}
	}})
	items = append(items, trayItem{Sep: true}, trayItem{Title: "Выход", Do: quit})
	return items
}
