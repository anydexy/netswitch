//go:build darwin

package main

import (
	"archive/zip"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const updateAsset = "NetSwitch-mac.zip"

// updateApply заменяет файлы внутри NetSwitch.app файлами из архива, сохраняя владельца программы.
func updateApply(z *zip.Reader) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		exe = p
	}
	if strings.Contains(exe, "/AppTranslocation/") {
		return errors.New("macOS запустила NetSwitch из временной копии — перенесите NetSwitch.app в «Программы» и запустите снова")
	}
	macos := filepath.Dir(exe)
	bundle := filepath.Dir(filepath.Dir(macos))
	if filepath.Base(macos) != "MacOS" || !strings.HasSuffix(bundle, ".app") {
		return errors.New("NetSwitch запущен не из NetSwitch.app")
	}
	var st syscall.Stat_t
	if err := syscall.Stat(bundle, &st); err != nil {
		return err
	}
	const prefix = "NetSwitch.app/"
	var files []*zip.File
	hasExe := false
	for _, f := range z.File {
		i := strings.Index(f.Name, prefix)
		if i < 0 {
			continue
		}
		rel := f.Name[i+len(prefix):]
		if rel == "" || strings.HasSuffix(rel, "/") || strings.Contains(rel, "..") {
			continue
		}
		if rel == "Contents/MacOS/NetSwitch" {
			hasExe = true
		}
		files = append(files, f)
	}
	if !hasExe {
		return errors.New("в архиве нет NetSwitch.app")
	}
	for _, f := range files {
		rel := f.Name[strings.Index(f.Name, prefix)+len(prefix):]
		dst := filepath.Join(bundle, filepath.FromSlash(rel))
		b, err := zipFile(f)
		if err != nil {
			return err
		}
		mode := f.Mode().Perm()
		if mode == 0 {
			mode = 0644
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return err
		}
		if err := replaceFile(dst, b, mode); err != nil {
			return err
		}
		_ = os.Lchown(dst, int(st.Uid), int(st.Gid))
	}
	_, _ = run(5*time.Second, "/usr/bin/touch", bundle) // Finder покажет новую версию
	return nil
}

// releaseInstance отдаёт блокировку единственного экземпляра.
func releaseInstance() {
	if instanceLock != nil {
		_ = syscall.Flock(int(instanceLock.Fd()), syscall.LOCK_UN)
		instanceLock.Close()
		instanceLock = nil
	}
}

// detachCmd — своя группа процессов: если NetSwitch запущен launchd (автозапуск), тот при выходе
// прежнего процесса завершает всю его группу, и новая версия не должна в неё попасть.
func detachCmd(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
