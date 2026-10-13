package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Provider — один способ подключения (DNS-сервис или WARP).
type Provider struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Kind string   `json:"kind"` // "dns" | "warp"
	Note string   `json:"note"`
	IPv4 []string `json:"ipv4,omitempty"`
	IPv6 []string `json:"ipv6,omitempty"`
	DoH  string   `json:"doh,omitempty"` // шаблон DoH (только порт 443, Windows 11)
	Off  bool     `json:"off,omitempty"` // скрыть вкладку
}

type Settings struct {
	Providers []Provider `json:"providers"`

	Auto         bool `json:"auto"`          // авто-переключение при падении
	AutoInterval int  `json:"auto_interval"` // секунд между проверками
	UseDoH       bool `json:"use_doh"`       // включать шифрованный DNS, если поддерживается
	SetIPv6      bool `json:"set_ipv6"`      // прописывать IPv6 DNS

	MyCountry string   `json:"my_country"` // код страны, из которой нужно "выйти" (обычно RU)
	GeoTests  []string `json:"geo_tests"`  // домены на Cloudflare: проверка через /cdn-cgi/trace
	NetTest   string   `json:"net_test"`   // проверка интернета

	DNSBypass        []string `json:"dns_bypass"`         // исключения: домены (с поддоменами), которые и при DNS-способе резолвятся через обычный DNS
	DNSBypassServers []string `json:"dns_bypass_servers"` // через какие серверы

	ZapretRepo     string   `json:"zapret_repo"`
	ZapretStrategy string   `json:"zapret_strategy"` // имя .bat
	ZapretWanted   bool     `json:"zapret_wanted"`   // пользователь включил запрет (без службы) — следим, чтобы работал
	GameFilter     string   `json:"game_filter"`     // off | tcp | udp | all
	ZapretTests    []string `json:"zapret_tests"`    // URL для теста стратегий

	TgwsRepo   string `json:"tgws_repo"`
	TgwsWanted bool   `json:"tgws_wanted"` // пользователь включил TG WS Proxy — следим, чтобы работал

	Active string `json:"active"` // id активного способа

	SeenDefaults []string `json:"seen_defaults"` // стандартные способы, которые уже добавлялись (новые в обновлениях добавятся сами)
}

// v1Defaults — способы, которые были в версии 1.0.
var v1Defaults = []string{"xbox", "geohide", "comss", "malw", "warp", "cloudflare", "google"}

func defaultSettings() Settings {
	return Settings{
		Providers: []Provider{
			{ID: "xbox", Name: "Xbox DNS", Kind: "dns", Note: "xbox-dns.ru — с 7 октября 2026 у сервиса отключили серверы, нейросети через него могут не открываться",
				IPv4: []string{"111.88.96.54", "111.88.96.55", "111.88.96.50", "111.88.96.51"},
				IPv6: []string{"2a00:ab00:1233:26::50", "2a00:ab00:1233:26::51"},
				DoH:  "https://xbox-dns.ru/dns-query"},
			{ID: "geohide", Name: "GeoHide DNS", Kind: "dns", Note: "geohide.ru — несколько серверов, программа выбирает 2 самых быстрых",
				IPv4: []string{"159.194.200.33", "193.233.112.88", "45.155.204.190", "37.230.192.51", "46.8.158.6", "193.233.112.67", "193.233.112.68", "95.182.120.241"}},
			{ID: "comss", Name: "Comss DNS", Kind: "dns", Note: "dns.comss.one — обход гео-блоков + блок рекламы",
				IPv4: []string{"83.220.169.155", "212.109.195.93"},
				DoH:  "https://dns.comss.one/dns-query"},
			{ID: "dnsai", Name: "DNS-AI", Kind: "dns", Note: "dns-ai.ru — DNS для нейросетей (ChatGPT, Claude и др.; Gemini может не работать)",
				IPv4: []string{"192.144.59.14", "186.246.49.127"},
				IPv6: []string{"2a0d:8480:0:67c::14", "2a0a:2b41:0:500d::53"},
				DoH:  "https://dns.dns-ai.ru/dns-query"},
			{ID: "malw", Name: "MALW DNS", Kind: "dns", Note: "dns.malw.link — обход гео-блоков",
				IPv4: []string{"84.21.189.133", "193.23.209.189"},
				DoH:  "https://dns.malw.link/dns-query"},
			{ID: "warp", Name: "Cloudflare WARP", Kind: "warp", Note: "VPN-туннель Cloudflare. Нужен установленный клиент WARP (1.1.1.1)."},
			{ID: "cloudflare", Name: "Cloudflare DNS", Kind: "dns", Note: "1.1.1.1 — быстрый обычный DNS (не обходит гео-блоки)",
				IPv4: []string{"1.1.1.1", "1.0.0.1"},
				IPv6: []string{"2606:4700:4700::1111", "2606:4700:4700::1001"},
				DoH:  "https://cloudflare-dns.com/dns-query"},
			{ID: "google", Name: "Google DNS", Kind: "dns", Note: "8.8.8.8 — обычный DNS (не обходит гео-блоки)",
				IPv4: []string{"8.8.8.8", "8.8.4.4"},
				IPv6: []string{"2001:4860:4860::8888", "2001:4860:4860::8844"},
				DoH:  "https://dns.google/dns-query"},
			{ID: "controld", Name: "ControlD Uncensored", Kind: "dns", Note: "freedns.controld.com — без цензуры DNS (не обходит гео-блоки, но отдаёт настоящие адреса заблокированных сайтов)",
				IPv4: []string{"76.76.2.5", "76.76.10.5"},
				DoH:  "https://freedns.controld.com/uncensored"},
			{ID: "adguard", Name: "AdGuard DNS", Kind: "dns", Note: "94.140.14.14 — блокирует рекламу и трекеры (не обходит гео-блоки)",
				IPv4: []string{"94.140.14.14", "94.140.15.15"},
				IPv6: []string{"2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"},
				DoH:  "https://dns.adguard-dns.com/dns-query"},
			{ID: "quad9", Name: "Quad9", Kind: "dns", Note: "9.9.9.9 — блокирует вредоносные сайты (не обходит гео-блоки)",
				IPv4: []string{"9.9.9.9", "149.112.112.112"},
				IPv6: []string{"2620:fe::fe", "2620:fe::9"},
				DoH:  "https://dns.quad9.net/dns-query"},
		},
		AutoInterval:   30,
		SetIPv6:        true,
		MyCountry:      "RU",
		GeoTests:       []string{"chatgpt.com", "claude.ai"},
		NetTest:        "http://www.msftconnecttest.com/connecttest.txt",
		ZapretRepo:     "Flowseal/zapret-discord-youtube",
		ZapretStrategy: "general.bat",
		GameFilter:     "off",
		ZapretTests: []string{
			"https://www.youtube.com/",
			"https://i.ytimg.com/vi/dQw4w9WgXcQ/maxresdefault.jpg",
			"https://discord.com/",
			"https://cdn.discordapp.com/",
			"https://www.instagram.com/",
			"https://x.com/",
		},
		TgwsRepo: "Flowseal/tg-ws-proxy",
		// Comss отдаёт Figma через свой прокси для нейросетей, и она еле грузится, а напрямую доступна
		DNSBypass:        []string{"figma.com"},
		DNSBypassServers: []string{"8.8.8.8", "1.1.1.1"},
	}
}

var (
	cfgMu sync.Mutex
	cfg   Settings
)

func appDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func cfgPath() string { return filepath.Join(appDir(), "netswitch.json") }

func loadConfig() {
	b, _ := os.ReadFile(cfgPath())
	c := parseConfig(b)
	cfgMu.Lock()
	cfg = c
	cfgMu.Unlock()
}

// parseConfig — настройки из содержимого netswitch.json (пусто — файла нет) с дополнением
// полей, появившихся в новых версиях.
func parseConfig(b []byte) Settings {
	d := defaultSettings()
	var c Settings
	if len(b) == 0 || json.Unmarshal(b, &c) != nil {
		for _, p := range d.Providers {
			d.SeenDefaults = append(d.SeenDefaults, p.ID)
		}
		return d
	}
	if len(c.Providers) == 0 {
		c.Providers = d.Providers
	}
	if c.AutoInterval < 10 {
		c.AutoInterval = d.AutoInterval
	}
	if c.MyCountry == "" {
		c.MyCountry = d.MyCountry
	}
	if c.NetTest == "" {
		c.NetTest = d.NetTest
	}
	if c.ZapretRepo == "" {
		c.ZapretRepo = d.ZapretRepo
	}
	if c.TgwsRepo == "" {
		c.TgwsRepo = d.TgwsRepo
	}
	if c.GameFilter == "" {
		c.GameFilter = "off"
	}
	if c.GeoTests == nil {
		c.GeoTests = d.GeoTests
	}
	if c.ZapretTests == nil {
		c.ZapretTests = d.ZapretTests
	}
	if c.DNSBypass == nil { // пустой список — пользователь сам убрал все исключения
		c.DNSBypass = d.DNSBypass
	}
	c.DNSBypass, _ = normDomains(c.DNSBypass)
	if c.DNSBypassServers = normServers(c.DNSBypassServers); len(c.DNSBypassServers) == 0 {
		c.DNSBypassServers = d.DNSBypassServers
	}
	// добавить новые стандартные способы, появившиеся в обновлении программы
	seen := map[string]bool{}
	list := c.SeenDefaults
	if list == nil {
		list = v1Defaults
	}
	for _, id := range list {
		seen[id] = true
	}
	have := map[string]bool{}
	for _, p := range c.Providers {
		have[p.ID] = true
	}
	c.SeenDefaults = nil
	for _, p := range d.Providers {
		if !seen[p.ID] && !have[p.ID] {
			c.Providers = append(c.Providers, p)
		}
		c.SeenDefaults = append(c.SeenDefaults, p.ID)
	}
	return c
}

func saveConfig() {
	cfgMu.Lock()
	b, _ := json.MarshalIndent(cfg, "", "  ")
	cfgMu.Unlock()
	_ = os.WriteFile(cfgPath(), b, 0644)
}

func getCfg() Settings {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	c := cfg
	c.Providers = append([]Provider(nil), cfg.Providers...)
	return c
}

func updateCfg(f func(c *Settings)) {
	cfgMu.Lock()
	f(&cfg)
	cfgMu.Unlock()
	saveConfig()
}

func findProvider(id string) (Provider, bool) {
	for _, p := range getCfg().Providers {
		if p.ID == id {
			return p, true
		}
	}
	return Provider{}, false
}
