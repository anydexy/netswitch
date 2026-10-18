//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
)

// zapretSupported — winws и драйвер WinDivert есть только под Windows.
const zapretSupported = true

func platformInit()  {}
func platformStart() {}

// appDir — папка программы: настройки, журнал, zapret и TG WS Proxy лежат рядом с exe.
func appDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

// dataDir — служебные файлы: instance.json и профиль окна Edge.
func dataDir() string {
	d := os.Getenv("LOCALAPPDATA")
	if d == "" {
		d = os.TempDir()
	}
	d = filepath.Join(d, "NetSwitch")
	_ = os.MkdirAll(d, 0755)
	return d
}

// fixOwner, fixOwnerTree — под Windows файлы и так принадлежат пользователю.
func fixOwner(path string)     {}
func fixOwnerTree(path string) {}

// openWindow открывает интерфейс отдельным окном Edge (режим приложения), иначе — в браузере.
func openWindow(url string) {
	w, h := windowSize()
	for _, base := range []string{os.Getenv("ProgramFiles(x86)"), os.Getenv("ProgramFiles"), os.Getenv("LOCALAPPDATA")} {
		if base == "" {
			continue
		}
		edge := filepath.Join(base, "Microsoft", "Edge", "Application", "msedge.exe")
		if _, err := os.Stat(edge); err == nil {
			c := exec.Command(edge, "--app="+url, fmt.Sprintf("--window-size=%d,%d", w, h),
				"--user-data-dir="+filepath.Join(dataDir(), "ui-profile"), "--no-first-run", "--disable-features=Translate")
			if c.Start() == nil {
				return
			}
		}
	}
	openURL(url)
}

// setClipboard кладёт текст (ASCII) в буфер обмена Windows — из окна браузера это может быть запрещено.
func setClipboard(s string) error {
	c := exec.Command("clip")
	hideCmd(c)
	c.Stdin = strings.NewReader(s)
	return c.Run()
}

func warpCLI() string {
	for _, base := range []string{os.Getenv("ProgramFiles"), `C:\Program Files`, os.Getenv("ProgramFiles(x86)")} {
		if base == "" {
			continue
		}
		p := filepath.Join(base, "Cloudflare", "Cloudflare WARP", "warp-cli.exe")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// --- автозапуск через Планировщик (с правами администратора, без окна UAC) ---

const taskName = "NetSwitch"

func autostartEnabled() bool {
	_, err := run(8*time.Second, "schtasks", "/Query", "/TN", taskName)
	return err == nil
}

func setAutostart(on bool) error {
	if !on {
		_, _ = run(10*time.Second, "schtasks", "/Delete", "/F", "/TN", taskName)
		return nil
	}
	exe, _ := os.Executable()
	user := os.Getenv("USERDOMAIN") + `\` + os.Getenv("USERNAME")
	xml := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>NetSwitch — DNS / WARP / zapret</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>` + xmlEsc(user) + `</UserId><Delay>PT10S</Delay></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>` + xmlEsc(user) + `</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>` + xmlEsc(exe) + `</Command><Arguments>--tray</Arguments><WorkingDirectory>` + xmlEsc(filepath.Dir(exe)) + `</WorkingDirectory></Exec></Actions>
</Task>`
	u := utf16.Encode([]rune(xml))
	b := make([]byte, 2+len(u)*2)
	b[0], b[1] = 0xFF, 0xFE
	for i, v := range u {
		b[2+i*2], b[3+i*2] = byte(v), byte(v>>8)
	}
	tmp := filepath.Join(os.TempDir(), "netswitch_task.xml")
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	defer os.Remove(tmp)
	out, err := run(15*time.Second, "schtasks", "/Create", "/F", "/TN", taskName, "/XML", tmp)
	if err != nil {
		return fmt.Errorf("schtasks: %s", strings.TrimSpace(out))
	}
	return nil
}
