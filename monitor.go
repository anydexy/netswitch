package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type IPResult struct {
	IP     string `json:"ip"`
	PingMs int    `json:"ping_ms"` // -1 — нет ICMP-ответа
	DNSMs  int    `json:"dns_ms"`  // -1 — DNS не ответил
}

type GeoResult struct {
	Domain string `json:"domain"`
	Loc    string `json:"loc"`
	OK     bool   `json:"ok"`
	Ms     int    `json:"ms"`
	Err    string `json:"err,omitempty"`
}

type ProvState struct {
	ID       string      `json:"id"`
	Checking bool        `json:"checking"`
	Checked  string      `json:"checked"`
	PingMs   int         `json:"ping_ms"`
	DNSMs    int         `json:"dns_ms"`
	Alive    bool        `json:"alive"`    // сервер отвечает
	Internet bool        `json:"internet"` // через него есть интернет
	GeoOK    int         `json:"geo_ok"`
	GeoTotal int         `json:"geo_total"`
	Geo      []GeoResult `json:"geo"`
	IPs      []IPResult  `json:"ips"`
	Best     []string    `json:"best"` // лучшие IPv4, которые будут прописаны
	Status   string      `json:"status"`
	// WARP
	Installed bool `json:"installed"`
	Connected bool `json:"connected"`
}

type AppState struct {
	Active     string                `json:"active"`
	Busy       string                `json:"busy"`
	Internet   bool                  `json:"internet"`
	NetMs      int                   `json:"net_ms"`
	Loc        string                `json:"loc"`
	SystemDNS  []string              `json:"system_dns"`
	Adapters   []string              `json:"adapters"`
	Provs      map[string]*ProvState `json:"provs"`
	Log        []string              `json:"log"`
	Autostart  bool                  `json:"autostart"`
	LastSwitch string                `json:"last_switch"`
}

var (
	stMu        sync.Mutex
	st          = AppState{Provs: map[string]*ProvState{}}
	opMu        sync.Mutex // подключение/отключение по одному
	fails       int
	noNetLogged bool

	lastTrayColor uint32 = 0x8e8e93
	lastTrayTip          = "NetSwitch"
)

func logf(format string, a ...any) {
	line := time.Now().Format("15:04:05") + "  " + fmt.Sprintf(format, a...)
	stMu.Lock()
	st.Log = append(st.Log, line)
	if len(st.Log) > 300 {
		st.Log = st.Log[len(st.Log)-300:]
	}
	stMu.Unlock()
	p := filepath.Join(appDir(), "netswitch.log")
	_, missing := os.Stat(p)
	if f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		fmt.Fprintln(f, time.Now().Format("2006-01-02 ")+line)
		f.Close()
		if missing != nil {
			fixOwner(p)
		}
	}
}

func provState(id string) *ProvState {
	p := st.Provs[id]
	if p == nil {
		p = &ProvState{ID: id, PingMs: -1, DNSMs: -1}
		st.Provs[id] = p
	}
	return p
}

func setBusy(s string) { stMu.Lock(); st.Busy = s; stMu.Unlock() }

func snapshot() AppState {
	stMu.Lock()
	defer stMu.Unlock()
	s := st
	s.Provs = map[string]*ProvState{}
	for k, v := range st.Provs {
		c := *v
		s.Provs[k] = &c
	}
	s.Log = append([]string(nil), st.Log...)
	return s
}

// checkGeo — проверка гео-доступа: через сервер server (или системный DNS, если "").
func checkGeo(server string) ([]GeoResult, int) {
	c := getCfg()
	res := make([]GeoResult, len(c.GeoTests))
	var wg sync.WaitGroup
	for i, d := range c.GeoTests {
		wg.Add(1)
		go func(i int, d string) {
			defer wg.Done()
			loc, dt, err := cfTrace(httpClientVia(server, 6*time.Second), d)
			g := GeoResult{Domain: d, Loc: loc, Ms: int(dt.Milliseconds())}
			if err != nil {
				g.Err = err.Error()
			} else {
				g.OK = !strings.EqualFold(loc, c.MyCountry)
			}
			res[i] = g
		}(i, d)
	}
	wg.Wait()
	ok := 0
	for _, g := range res {
		if g.OK {
			ok++
		}
	}
	return res, ok
}

func checkProvider(p Provider) {
	stMu.Lock()
	provState(p.ID).Checking = true
	stMu.Unlock()
	ps := ProvState{ID: p.ID, PingMs: -1, DNSMs: -1}

	if p.Kind == "warp" {
		inst, conn, txt := warpStatus()
		ps.Installed, ps.Connected, ps.Status = inst, conn, txt
		if ms, err := icmpPing("162.159.192.1", 1500); err == nil {
			ps.PingMs = ms
		}
		ps.Alive = inst
		if conn {
			ok, ms := netCheck("")
			ps.Internet = ok
			ps.DNSMs = int(ms.Milliseconds())
			ps.Geo, ps.GeoOK = checkGeo("")
			ps.GeoTotal = len(ps.Geo)
		}
	} else {
		ips := make([]IPResult, len(p.IPv4))
		var wg sync.WaitGroup
		for i, ip := range p.IPv4 {
			wg.Add(1)
			go func(i int, ip string) {
				defer wg.Done()
				r := IPResult{IP: ip, PingMs: -1, DNSMs: -1}
				if ms, err := icmpPing(ip, 1500); err == nil {
					r.PingMs = ms
				}
				best := time.Duration(0)
				for k := 0; k < 2; k++ { // два запроса, берём лучший
					if _, dt, err := dnsQueryA(ip, "www.google.com", 2*time.Second); err == nil && (best == 0 || dt < best) {
						best = dt
					}
				}
				if best > 0 {
					r.DNSMs = int(best.Milliseconds())
					if r.DNSMs == 0 {
						r.DNSMs = 1
					}
				}
				ips[i] = r
			}(i, ip)
		}
		wg.Wait()
		sort.SliceStable(ips, func(i, j int) bool {
			a, b := ips[i].DNSMs, ips[j].DNSMs
			if (a < 0) != (b < 0) {
				return a >= 0
			}
			return a < b
		})
		ps.IPs = ips
		for _, r := range ips {
			if r.DNSMs >= 0 && len(ps.Best) < 2 {
				ps.Best = append(ps.Best, r.IP)
			}
		}
		if len(ps.Best) > 0 {
			ps.Alive = true
			ps.DNSMs = ips[0].DNSMs
			ps.PingMs = ips[0].PingMs
			ok, _ := netCheck(ps.Best[0])
			ps.Internet = ok
			ps.Geo, ps.GeoOK = checkGeo(ps.Best[0])
			ps.GeoTotal = len(ps.Geo)
			switch {
			case !ok:
				ps.Status = "DNS отвечает, но интернета нет"
			case ps.GeoOK == ps.GeoTotal && ps.GeoTotal > 0:
				ps.Status = "Работает, гео-блоки обходит"
			case ps.GeoOK > 0:
				ps.Status = "Работает, гео-блоки частично"
			default:
				ps.Status = "Работает (гео-блоки не обходит)"
			}
		} else {
			ps.Status = "Серверы не отвечают (заблокирован?)"
		}
	}
	ps.Checked = time.Now().Format("15:04:05")
	stMu.Lock()
	st.Provs[p.ID] = &ps
	stMu.Unlock()
}

// refreshAll — проверить все способы параллельно.
func refreshAll() {
	c := getCfg()
	var wg sync.WaitGroup
	for _, p := range c.Providers {
		if p.Off {
			continue
		}
		wg.Add(1)
		go func(p Provider) { defer wg.Done(); checkProvider(p) }(p)
	}
	wg.Add(1)
	go func() { defer wg.Done(); refreshSystem() }()
	wg.Wait()
}

func refreshSystem() {
	ok, ms := netCheck("")
	loc := ""
	if ok {
		if l, _, err := cfTrace(httpClientVia("", 5*time.Second), "www.cloudflare.com"); err == nil {
			loc = l
		}
		// страна, которую видит ChatGPT (с учётом DNS-подмены)
		if g, _ := checkGeo(""); len(g) > 0 && g[0].Loc != "" {
			loc = g[0].Loc
		}
	}
	ads, _ := listAdapters()
	var dns, names []string
	for _, a := range ads {
		names = append(names, a.Alias)
		dns = append(dns, a.DNS...)
	}
	active := detectActiveDNS(ads)
	if _, conn, _ := warpStatus(); conn {
		active = "warp"
	}
	stMu.Lock()
	st.Internet, st.NetMs, st.Loc = ok, int(ms.Milliseconds()), loc
	st.SystemDNS, st.Adapters = dns, names
	st.Active = active
	stMu.Unlock()
	if active != getCfg().Active {
		updateCfg(func(c *Settings) { c.Active = active })
	}
	updateTray()
}

func updateTray() {
	s := snapshot()
	name := "не подключено (DNS провайдера)"
	if p, ok := findProvider(s.Active); ok {
		name = p.Name
	}
	color := uint32(0x8e8e93)
	switch {
	case !s.Internet:
		color = 0xff3b30
	case s.Active != "":
		color = 0x34c759
	}
	z := getZapretStatus()
	tip := "NetSwitch: " + name
	if z.Running {
		tip += " + zapret"
		if s.Active == "" && s.Internet {
			color = 0x007aff
		}
	}
	if getTgwsStatus().Running {
		tip += " + TG WS Proxy"
	}
	if !s.Internet {
		tip += " — нет интернета"
	}
	lastTrayColor, lastTrayTip = color, tip
	trayUpdate(color, tip)
}

// connect — включить способ подключения (DNS или WARP). Взаимоисключающие.
func connect(id string) error {
	opMu.Lock()
	defer opMu.Unlock()
	p, ok := findProvider(id)
	if !ok {
		return fmt.Errorf("нет способа %q", id)
	}
	setBusy("Подключение: " + p.Name)
	defer setBusy("")
	var err error
	if p.Kind == "warp" {
		_ = resetSystemDNS()
		if e := setDNSBypass(nil, nil); e != nil {
			logf("Исключения DNS: %v", e)
		}
		err = warpConnect()
	} else {
		warpDisconnect()
		stMu.Lock()
		best := append([]string(nil), provState(id).Best...)
		stMu.Unlock()
		if len(best) == 0 {
			checkProvider(p)
			stMu.Lock()
			best = append([]string(nil), provState(id).Best...)
			stMu.Unlock()
		}
		if len(best) == 0 {
			best = p.IPv4
			if len(best) > 2 {
				best = best[:2]
			}
		}
		v6 := p.IPv6
		if len(v6) > 2 {
			v6 = v6[:2]
		}
		err = setSystemDNS(best, v6, p.DoH)
		if err == nil {
			c := getCfg()
			if e := setDNSBypass(c.DNSBypass, c.DNSBypassServers); e != nil {
				logf("Исключения DNS: %v", e)
			}
		}
	}
	if err != nil {
		logf("Ошибка подключения %s: %v", p.Name, err)
		return err
	}
	updateCfg(func(c *Settings) { c.Active = id })
	stMu.Lock()
	st.Active = id
	st.LastSwitch = time.Now().Format("15:04:05")
	stMu.Unlock()
	fails = 0
	logf("Подключено: %s", p.Name)
	go func() { checkProvider(p); refreshSystem() }()
	return nil
}

func disconnect() error {
	opMu.Lock()
	defer opMu.Unlock()
	setBusy("Отключение…")
	defer setBusy("")
	warpDisconnect()
	err := resetSystemDNS()
	if e := setDNSBypass(nil, nil); e != nil {
		logf("Исключения DNS: %v", e)
		if err == nil {
			err = e
		}
	}
	updateCfg(func(c *Settings) { c.Active = "" })
	stMu.Lock()
	st.Active = ""
	stMu.Unlock()
	logf("Отключено: DNS снова от провайдера")
	go refreshSystem()
	return err
}

// syncDNSBypass приводит исключения DNS к настройкам: при подключённом DNS-способе ставит их, иначе снимает.
func syncDNSBypass() error {
	opMu.Lock()
	defer opMu.Unlock()
	c := getCfg()
	if p, ok := findProvider(snapshot().Active); ok && p.Kind == "dns" {
		return setDNSBypass(c.DNSBypass, c.DNSBypassServers)
	}
	return setDNSBypass(nil, nil)
}

// score — чем больше, тем лучше: сначала обход гео-блоков, затем наличие интернета, затем скорость.
func score(p Provider, s *ProvState) float64 {
	if s == nil || !s.Alive || !s.Internet {
		return -1
	}
	if p.Kind == "warp" && !s.Installed {
		return -1
	}
	lat := s.DNSMs
	if lat < 0 {
		lat = 999
	}
	if p.Kind == "warp" {
		lat = s.PingMs
		if lat < 0 {
			lat = 300
		}
		lat += 30 // туннель обычно медленнее прямого DNS
	}
	return float64(s.GeoOK)*10000 + 1000 - float64(lat)
}

// fastest — лучший рабочий способ по последней проверке.
func fastest(exclude string) (Provider, bool) {
	s := snapshot()
	var best Provider
	bestScore := -1.0
	for _, p := range getCfg().Providers {
		if p.Off || p.ID == exclude {
			continue
		}
		ps := s.Provs[p.ID]
		if p.Kind == "warp" && ps != nil && ps.Installed && !ps.Connected {
			// WARP не проверить, пока не подключён — считаем запасным вариантом
			if bestScore < 0 {
				best, bestScore = p, 0
			}
			continue
		}
		if sc := score(p, ps); sc > bestScore {
			best, bestScore = p, sc
		}
	}
	return best, bestScore >= 0
}

func connectFastest() error {
	setBusy("Проверка всех способов…")
	refreshAll()
	setBusy("")
	p, ok := fastest("")
	if !ok {
		return fmt.Errorf("ни один способ сейчас не работает")
	}
	logf("Самый быстрый: %s", p.Name)
	return connect(p.ID)
}

// healthy — работает ли активный способ прямо сейчас.
func healthy(active string) bool {
	p, ok := findProvider(active)
	if !ok {
		return true
	}
	if p.Kind == "warp" {
		_, conn, _ := warpStatus()
		if !conn {
			return false
		}
		ok, _ := netCheck("")
		return ok
	}
	stMu.Lock()
	best := append([]string(nil), provState(active).Best...)
	stMu.Unlock()
	if len(best) == 0 {
		best = p.IPv4
	}
	for _, ip := range best {
		if _, _, err := dnsQueryA(ip, "www.google.com", 3*time.Second); err == nil {
			ok, _ := netCheck(ip)
			return ok
		}
	}
	return false
}

// autoLoop — фоновый сторож: следит за активным способом и zapret, переключает при сбое.
func autoLoop() {
	tick := 0
	for {
		c := getCfg()
		time.Sleep(time.Duration(c.AutoInterval) * time.Second)
		tick++
		refreshSystem()
		refreshZapretStatus()

		// zapret включён вручную (не служба), но процесс умер — перезапустить
		z := getZapretStatus()
		if c.ZapretWanted && !z.Running && z.ServiceState == 0 && !z.Test.Running && !z.Downloading && z.Installed {
			if zBusy.TryLock() {
				if err := zapretStartProcess(c.ZapretStrategy); err == nil {
					logf("zapret упал — перезапущен (%s)", c.ZapretStrategy)
				}
				zBusy.Unlock()
			}
		}

		// TG WS Proxy включён, но процесс умер — перезапустить
		refreshTgwsStatus()
		if t := getTgwsStatus(); getCfg().TgwsWanted && t.Installed && !t.Running && t.External == "" && !t.Downloading {
			if tBusy.TryLock() {
				if err := tgwsStartProcess(); err == nil {
					logf("TG WS Proxy упал — перезапущен")
				}
				tBusy.Unlock()
			}
		}

		if !c.Auto {
			continue
		}
		active := snapshot().Active
		if active == "" {
			if !snapshot().Internet {
				if !noNetLogged {
					logf("Авто: нет интернета — ищу рабочий способ")
				}
				if err := connectFastest(); err != nil {
					noNetLogged = true
				} else {
					noNetLogged = false
				}
			} else {
				noNetLogged = false
			}
			continue
		}
		if healthy(active) {
			fails = 0
			if tick%10 == 0 { // раз в ~5 минут обновляем замеры всех способов
				refreshAll()
			}
			continue
		}
		fails++
		if fails < 2 {
			continue
		}
		old, _ := findProvider(active)
		logf("Авто: %s не работает — переключаюсь", old.Name)
		setBusy("Авто-переключение…")
		refreshAll()
		setBusy("")
		if p, ok := fastest(active); ok {
			if err := connect(p.ID); err == nil {
				trayBalloon("NetSwitch", old.Name+" перестал работать.\nПереключено на "+p.Name)
			}
		} else {
			logf("Авто: рабочих способов не найдено")
			trayBalloon("NetSwitch", old.Name+" не работает, а замены не нашлось")
		}
		fails = 0
	}
}

// xmlEsc — экранирование текста для XML (задание Планировщика, plist автозапуска).
func xmlEsc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}
