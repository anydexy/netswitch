package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func readJSON(t *testing.T, p string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	return m
}

func TestTgwsPrepareMigratesSecret(t *testing.T) {
	dir := t.TempDir()
	src, data := filepath.Join(dir, "appdata"), filepath.Join(dir, "tgws", tgwsDataName)
	_ = os.MkdirAll(src, 0755)
	orig := `{"host":"127.0.0.1","port":1443,"secret":"0123456789abcdef0123456789abcdef","check_updates":true,"dc_ip":["4:149.154.167.220"],"cfproxy_user_domain":["a.example"]}`
	_ = os.WriteFile(filepath.Join(src, "config.json"), []byte(orig), 0644)

	if err := tgwsPrepareIn(data, src, false); err != nil {
		t.Fatal(err)
	}
	m := readJSON(t, filepath.Join(data, "config.json"))
	if m["secret"] != "0123456789abcdef0123456789abcdef" {
		t.Errorf("secret не перенесён: %v", m["secret"])
	}
	if m["check_updates"] != false {
		t.Errorf("check_updates = %v, ожидалось false", m["check_updates"])
	}
	if m["port"] != float64(1443) || len(m["dc_ip"].([]any)) != 1 || m["cfproxy_user_domain"].([]any)[0] != "a.example" {
		t.Errorf("остальные настройки испорчены: %v", m)
	}
	for _, mk := range []string{".first_run_done_mtproto", ".ipv6_warned"} {
		if _, err := os.Stat(filepath.Join(data, mk)); err != nil {
			t.Errorf("нет маркера %s", mk)
		}
	}
	c := readTgwsConf(data)
	if got, want := tgwsLink(c), "tg://proxy?server=127.0.0.1&port=1443&secret=dd0123456789abcdef0123456789abcdef"; got != want {
		t.Errorf("ссылка %q, ожидалось %q", got, want)
	}

	// свои настройки без force не перезаписываются
	_ = os.WriteFile(filepath.Join(src, "config.json"), []byte(`{"secret":"ffffffffffffffffffffffffffffffff"}`), 0644)
	if err := tgwsPrepareIn(data, src, false); err != nil {
		t.Fatal(err)
	}
	if s := readTgwsConf(data).Secret; s != "0123456789abcdef0123456789abcdef" {
		t.Errorf("без force secret заменён на %s", s)
	}
	// при переносе отдельного экземпляра (force) — берутся его
	if err := tgwsPrepareIn(data, src, true); err != nil {
		t.Fatal(err)
	}
	if s := readTgwsConf(data).Secret; s != "ffffffffffffffffffffffffffffffff" {
		t.Errorf("с force secret = %s", s)
	}
}

func TestTgwsPrepareFresh(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, tgwsDataName)
	if err := tgwsPrepareIn(data, filepath.Join(dir, "нет такой папки"), false); err != nil {
		t.Fatal(err)
	}
	c := readTgwsConf(data)
	if len(c.Secret) != 32 || strings.Trim(c.Secret, "0123456789abcdef") != "" {
		t.Errorf("secret %q — ожидалось 32 hex-символа", c.Secret)
	}
	if c.Host != "127.0.0.1" || c.Port != 1443 {
		t.Errorf("адрес по умолчанию %s:%d", c.Host, c.Port)
	}
	if readJSON(t, filepath.Join(data, "config.json"))["check_updates"] != false {
		t.Error("check_updates не выключен")
	}
}

func TestTgwsPrepareKeepsBrokenConfig(t *testing.T) {
	data := t.TempDir()
	broken := []byte(`{"secret": "abc",`)
	_ = os.WriteFile(filepath.Join(data, "config.json"), broken, 0644)
	if err := tgwsPrepareIn(data, t.TempDir(), false); err == nil {
		t.Error("ожидалась ошибка на испорченном config.json")
	}
	if b, _ := os.ReadFile(filepath.Join(data, "config.json")); string(b) != string(broken) {
		t.Error("испорченный config.json перезаписан")
	}
}

func TestTgwsLinkHost(t *testing.T) {
	if l := tgwsLink(tgwsConf{Host: "0.0.0.0", Port: 1443, Secret: "aa"}); l != "tg://proxy?server=127.0.0.1&port=1443&secret=ddaa" {
		t.Error(l)
	}
	if l := tgwsLink(tgwsConf{Host: "127.0.0.1", Port: 1443}); l != "" {
		t.Error("без secret ссылки быть не должно:", l)
	}
}

func TestProcHelpers(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("только Windows")
	}
	exe, _ := os.Executable()
	var me *procEntry
	for _, p := range listProcs() {
		if p.PID == uint32(os.Getpid()) {
			p := p
			me = &p
		}
	}
	if me == nil {
		t.Fatal("listProcs не нашёл текущий процесс")
	}
	if !strings.EqualFold(me.Name, filepath.Base(exe)) || me.PPID == 0 {
		t.Errorf("процесс %+v, exe %s", *me, exe)
	}
	if p := procPath(me.PID); !strings.EqualFold(p, exe) {
		t.Errorf("procPath = %q, ожидалось %q", p, exe)
	}
	if mutexExists(`Local\NetSwitch-test-no-such-mutex`) {
		t.Error("несуществующий мьютекс найден")
	}
}

// Скачивает настоящий релиз во временную папку тестового exe (сеть, ~22 МБ). NETSWITCH_LIVE_DL=1 go test -run LiveTgwsDownload -v
func TestLiveTgwsDownload(t *testing.T) {
	if os.Getenv("NETSWITCH_LIVE_DL") == "" {
		t.Skip("NETSWITCH_LIVE_DL не задан")
	}
	t.Setenv("APPDATA", t.TempDir()) // не трогать настройки настоящего TG WS Proxy
	loadConfig()
	defer os.RemoveAll(tgwsDir())
	if err := tgwsDownload(); err != nil {
		t.Fatal(err)
	}
	refreshTgwsStatus()
	s := getTgwsStatus()
	t.Logf("%s; версия %s, последняя %s", s.DownloadMsg, s.LocalVersion, s.LatestVersion)
	fi, err := os.Stat(tgwsExe())
	if err != nil || fi.Size() < 5<<20 {
		t.Fatalf("exe не установлен: %v", err)
	}
	if !s.Installed || !s.UpToDate || s.Running || len(s.Secret) != 32 || s.Link == "" {
		t.Errorf("состояние после установки: %+v", s)
	}
	if _, err := os.Stat(tgwsExe() + ".download"); err == nil {
		t.Error("остался временный файл")
	}
}

// Только чтение: что NetSwitch видит на этом компьютере. NETSWITCH_LIVE=1 go test -run Live -v
func TestLiveTgwsDetect(t *testing.T) {
	if os.Getenv("NETSWITCH_LIVE") == "" {
		t.Skip("NETSWITCH_LIVE не задан")
	}
	ours, ext := tgwsProcs()
	t.Logf("наши: %v", ours)
	for _, p := range ext {
		t.Logf("отдельный: pid %d (родитель %d) %s — %s", p.PID, p.PPID, p.Name, procPath(p.PID))
	}
	t.Logf("мьютекс %s: %v", tgwsMutex, mutexExists(tgwsMutex))
}
