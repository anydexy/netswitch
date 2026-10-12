//go:build windows

package main

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	iphlpapi = syscall.NewLazyDLL("iphlpapi.dll")

	procCreateMutexW = kernel32.NewProc("CreateMutexW")
	procOpenMutexW   = kernel32.NewProc("OpenMutexW")
	procCloseHandle  = kernel32.NewProc("CloseHandle")

	procIsUserAnAdmin = shell32.NewProc("IsUserAnAdmin")
	procShellExecuteW = shell32.NewProc("ShellExecuteW")

	procOpenSCManagerW     = advapi32.NewProc("OpenSCManagerW")
	procOpenServiceW       = advapi32.NewProc("OpenServiceW")
	procQueryServiceStatus = advapi32.NewProc("QueryServiceStatus")
	procCloseServiceHandle = advapi32.NewProc("CloseServiceHandle")
	procIcmpCreateFile     = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpSendEcho       = iphlpapi.NewProc("IcmpSendEcho")
	procIcmpCloseHandle    = iphlpapi.NewProc("IcmpCloseHandle")
)

const createNoWindow = 0x08000000

func hideCmd(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}

func isAdmin() bool {
	r, _, _ := procIsUserAnAdmin.Call()
	return r != 0
}

func u16(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }

func shellExecute(verb, file, args string) error {
	r, _, _ := procShellExecuteW.Call(0, uintptr(unsafe.Pointer(u16(verb))), uintptr(unsafe.Pointer(u16(file))),
		uintptr(unsafe.Pointer(u16(args))), 0, 1)
	if r <= 32 {
		return errors.New("ShellExecute failed")
	}
	return nil
}

// relaunchAsAdmin перезапускает программу с правами администратора (окно UAC).
func relaunchAsAdmin() error {
	exe, _ := os.Executable()
	args := make([]string, 0, len(os.Args)-1)
	for _, a := range os.Args[1:] {
		args = append(args, escapeArg(a))
	}
	return shellExecute("runas", exe, strings.Join(args, " "))
}

const mutexName = "Local\\NetSwitch-single-instance"

// alreadyRunning — запущен ли уже экземпляр программы (только проверка, мьютекс не создаётся).
func alreadyRunning() bool {
	h, _, err := procOpenMutexW.Call(0x00100000, 0, uintptr(unsafe.Pointer(u16(mutexName)))) // SYNCHRONIZE
	if h != 0 {
		procCloseHandle.Call(h)
		return true
	}
	if errno, ok := err.(syscall.Errno); ok && errno == 5 { // ERROR_ACCESS_DENIED — существует, создан администратором
		return true
	}
	return false
}

// claimInstance — занять мьютекс; false, если кто-то успел раньше.
func claimInstance() bool {
	h, _, err := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(u16(mutexName))))
	if h == 0 {
		return false
	}
	if errno, ok := err.(syscall.Errno); ok && errno == 183 {
		return false
	}
	return true
}

func openURL(u string) {
	_ = shellExecute("open", u, "")
}

// serviceState: 0 — не установлена, 1 — остановлена, 2 — запускается, 3 — останавливается, 4 — работает.
func serviceState(name string) int {
	scm, _, _ := procOpenSCManagerW.Call(0, 0, 1) // SC_MANAGER_CONNECT
	if scm == 0 {
		return 0
	}
	defer procCloseServiceHandle.Call(scm)
	h, _, _ := procOpenServiceW.Call(scm, uintptr(unsafe.Pointer(u16(name))), 4) // SERVICE_QUERY_STATUS
	if h == 0 {
		return 0
	}
	defer procCloseServiceHandle.Call(h)
	var st [7]uint32
	r, _, _ := procQueryServiceStatus.Call(h, uintptr(unsafe.Pointer(&st[0])))
	if r == 0 {
		return 0
	}
	return int(st[1])
}

// icmpPing — ICMP-пинг через IcmpSendEcho (работает без raw-сокетов). Возвращает мс.
func icmpPing(ip string, timeoutMs int) (int, error) {
	p := net.ParseIP(ip).To4()
	if p == nil {
		return 0, errors.New("не IPv4")
	}
	addr := uint32(p[0]) | uint32(p[1])<<8 | uint32(p[2])<<16 | uint32(p[3])<<24
	h, _, _ := procIcmpCreateFile.Call()
	if h == 0 || h == ^uintptr(0) {
		return 0, errors.New("IcmpCreateFile")
	}
	defer procIcmpCloseHandle.Call(h)
	data := []byte("NetSwitch-ping-NetSwitch-ping-32")
	reply := make([]byte, 256+len(data))
	r, _, _ := procIcmpSendEcho.Call(h, uintptr(addr), uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0,
		uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeoutMs))
	if r == 0 {
		return 0, errors.New("нет ответа")
	}
	status := binary.LittleEndian.Uint32(reply[4:8])
	rtt := binary.LittleEndian.Uint32(reply[8:12])
	if status != 0 {
		return 0, errors.New("нет ответа")
	}
	if rtt == 0 {
		rtt = 1
	}
	return int(rtt), nil
}
