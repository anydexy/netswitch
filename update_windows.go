//go:build windows

package main

import (
	"archive/zip"
	"errors"
	"os"
	"os/exec"
	"path"
	"strings"
)

const updateAsset = "NetSwitch-windows.zip"

// updateApply ставит NetSwitch.exe из архива на место работающего.
func updateApply(z *zip.Reader) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	for _, f := range z.File {
		if !strings.EqualFold(path.Base(f.Name), "NetSwitch.exe") {
			continue
		}
		b, err := zipFile(f)
		if err != nil {
			return err
		}
		if len(b) < 1<<20 || string(b[:2]) != "MZ" {
			return errors.New("в архиве повреждённый NetSwitch.exe")
		}
		return replaceFile(exe, b, 0755)
	}
	return errors.New("в архиве нет NetSwitch.exe")
}

func detachCmd(c *exec.Cmd) {}
