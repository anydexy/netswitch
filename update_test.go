package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewerVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.4.1", "1.4.0", true},
		{"1.10.0", "1.9.9", true},
		{"1.4.0", "1.4.0", false},
		{"1.4", "1.4.0", false},
		{"1.4.0.1", "1.4", true},
		{"v2.0.0", "1.99.99", true},
		{"1.3.9", "1.4.0", false},
		{"1.5.0-beta", "1.4.9", true},
	}
	for _, c := range cases {
		if got := newerVersion(c.a, c.b); got != c.want {
			t.Errorf("newerVersion(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestReleaseNotes(t *testing.T) {
	body := "## Что нового\r\n\r\n**Версия для macOS.** Скачайте `NetSwitch-mac.zip`.\r\n- DNS\r\n\r\n## Установка\r\n\r\nРаспакуйте"
	want := "Версия для macOS. Скачайте NetSwitch-mac.zip.\n- DNS"
	if got := releaseNotes(body); got != want {
		t.Errorf("releaseNotes = %q", got)
	}
	if got := releaseNotes("## Исправлено\n\nЛожное «Нет интернета».\n## Обновление\nтекст"); got != "Ложное «Нет интернета»." {
		t.Errorf("releaseNotes (Исправлено) = %q", got)
	}
}

func TestReplaceFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "NetSwitch.exe")
	if err := os.WriteFile(p, []byte("old"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := replaceFile(p, []byte("new"), 0755); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "new" {
		t.Errorf("после замены: %q", b)
	}
	for _, s := range []string{".new", ".old"} {
		if _, err := os.Stat(p + s); err == nil {
			t.Errorf("остался %s", s)
		}
	}
}
