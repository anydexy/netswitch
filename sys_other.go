//go:build !windows && !darwin

package main

// Заглушки для сборки/тестов не под Windows и не под macOS.

import (
	"archive/zip"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

const (
	zapretSupported = false
	tgwsAsset       = ""
	updateAsset     = ""
	awgTunName      = "netswitch0"
)

var errUnsupported = errors.New("не поддерживается в этой системе")

func hideCmd(c *exec.Cmd)                           {}
func isAdmin() bool                                 { return true }
func relaunchAsAdmin() error                        { return errUnsupported }
func alreadyRunning() bool                          { return false }
func claimInstance() bool                           { return true }
func trayRemove()                                   {}
func openURL(u string)                              { println("open", u) }
func openWindow(u string)                           { openURL(u) }
func serviceState(name string) int                  { return 0 }
func icmpPing(ip string, t int) (int, error)        { return 0, errors.New("нет ICMP") }
func runTray(onOpen func(), menu func() []trayItem) {}
func trayUpdate(color uint32, tip string)           {}
func trayBalloon(title, text string)                {}
func mutexExists(name string) bool                  { return false }
func listProcs() []procEntry                        { return nil }
func procPath(pid uint32) string                    { return "" }
func killPID(pid uint32)                            {}

func postToProcWindows(pids map[uint32]bool, prefix, suffix string, msg uint32) int { return 0 }

func platformInit()            {}
func platformStart()           {}
func appDir() string           { return dataDir() }
func dataDir() string          { return filepath.Join(os.TempDir(), "NetSwitch") }
func fixOwner(path string)     {}
func fixOwnerTree(path string) {}
func setClipboard(s string) error {
	return errUnsupported
}
func warpCLI() string                                { return "" }
func autostartEnabled() bool                         { return false }
func setAutostart(on bool) error                     { return errUnsupported }
func listAdapters() ([]Adapter, error)               { return nil, errUnsupported }
func setSystemDNS(v4, v6 []string, doh string) error { return errUnsupported }
func resetSystemDNS() error                          { return errUnsupported }
func setDNSBypass(domains, servers []string) error   { return errUnsupported }

func tgwsExe() string              { return "" }
func tgwsDataDir() string          { return filepath.Join(tgwsDir(), tgwsDataName) }
func tgwsStdDir() string           { return "" }
func tgwsCommand() *exec.Cmd       { return exec.Command("false") }
func tgwsRemoveForeignAutostart()  {}
func tgwsInstall(tmp string) error { return errUnsupported }

func zapretRepo() string                       { return "" }
func zapretLocalVersion() string               { return "" }
func zapretStrategies() []string               { return nil }
func winwsRunning() bool                       { return false }
func killWinws()                               {}
func zapretStartProcess(strategy string) error { return errUnsupported }
func zapretServiceInstall(strategy string) error {
	return errUnsupported
}
func zapretServiceRemove(withDriver bool) {}
func zapretServiceStrategy() string       { return "" }
func zapretDownload() error               { return errUnsupported }
func zapretPauseForTest() func()          { return func() {} }
func zapretTestRun(strategy string) (func() *http.Client, error) {
	return nil, errUnsupported
}
func zapretTestKill() {}

func updateApply(z *zip.Reader) error { return errUnsupported }
func releaseInstance()                {}
func detachCmd(c *exec.Cmd)           {}

func awgPrepare() error { return errUnsupported }
func awgRoutesUp(tdev tun.Device, name string, c awgConf, ep netip.AddrPort) (func(), error) {
	return nil, errUnsupported
}
