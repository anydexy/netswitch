package main

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"
)

// run запускает программу без окна и возвращает вывод.
func run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	hideCmd(c)
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	err := c.Run()
	return out.String(), err
}

// ps выполняет PowerShell-скрипт, вывод в UTF-8.
func ps(timeout time.Duration, script string) (string, error) {
	full := "$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.Encoding]::UTF8;" + script
	return run(timeout, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", full)
}

// psQuote — строка в одинарных кавычках для PowerShell.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// escapeArg — экранирование аргумента командной строки Windows (как syscall.EscapeArg).
func escapeArg(s string) string {
	if s == "" {
		return `""`
	}
	need := false
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '"' {
			need = true
			break
		}
	}
	if !need {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			slashes++
		case '"':
			b.WriteString(strings.Repeat(`\`, slashes*2+1))
			b.WriteByte('"')
			slashes = 0
			continue
		default:
			if slashes > 0 {
				b.WriteString(strings.Repeat(`\`, slashes))
			}
			slashes = 0
			b.WriteByte(c)
			continue
		}
	}
	b.WriteString(strings.Repeat(`\`, slashes*2))
	b.WriteByte('"')
	return b.String()
}
