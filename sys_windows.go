//go:build windows

package main

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	iphlpapi = syscall.NewLazyDLL("iphlpapi.dll")

	procCreateMutexW               = kernel32.NewProc("CreateMutexW")
	procOpenMutexW                 = kernel32.NewProc("OpenMutexW")
	procCloseHandle                = kernel32.NewProc("CloseHandle")
	procQueryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")

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

var (
	procEnumWindows              = user32.NewProc("EnumWindows")
	procGetClassNameW            = user32.NewProc("GetClassNameW")
	procGetWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
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
func alreadyRunning() bool { return mutexExists(mutexName) }

// mutexExists — существует ли именованный мьютекс (то есть запущена ли программа, которая его держит).
func mutexExists(name string) bool {
	h, _, err := procOpenMutexW.Call(0x00100000, 0, uintptr(unsafe.Pointer(u16(name)))) // SYNCHRONIZE
	if h != 0 {
		procCloseHandle.Call(h)
		return true
	}
	if errno, ok := err.(syscall.Errno); ok && errno == 5 { // ERROR_ACCESS_DENIED — существует, создан администратором
		return true
	}
	return false
}

// listProcs — все процессы системы (снимок Toolhelp).
func listProcs() []procEntry {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer syscall.CloseHandle(snap)
	var pe syscall.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var r []procEntry
	for err = syscall.Process32First(snap, &pe); err == nil; err = syscall.Process32Next(snap, &pe) {
		r = append(r, procEntry{PID: pe.ProcessID, PPID: pe.ParentProcessID, Name: syscall.UTF16ToString(pe.ExeFile[:])})
	}
	return r
}

// procPath — полный путь к exe процесса ("" — нет доступа или процесса).
func procPath(pid uint32) string {
	h, err := syscall.OpenProcess(0x1000, false, pid) // PROCESS_QUERY_LIMITED_INFORMATION
	if err != nil {
		return ""
	}
	defer syscall.CloseHandle(h)
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	if r, _, _ := procQueryFullProcessImageNameW.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n))); r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:n])
}

func killPID(pid uint32) {
	h, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return
	}
	_ = syscall.TerminateProcess(h, 1)
	syscall.CloseHandle(h)
}

var (
	enumMu sync.Mutex
	enumFn func(hwnd uintptr) bool
	enumCb = syscall.NewCallback(func(hwnd, _ uintptr) uintptr {
		if enumFn(hwnd) {
			return 1
		}
		return 0
	})
)

// postToProcWindows отправляет msg окнам верхнего уровня процессов pids, у которых класс окна
// начинается с prefix и заканчивается suffix. Возвращает число окон.
func postToProcWindows(pids map[uint32]bool, prefix, suffix string, msg uint32) int {
	enumMu.Lock()
	defer enumMu.Unlock()
	n := 0
	buf := make([]uint16, 256)
	enumFn = func(hwnd uintptr) bool {
		var pid uint32
		procGetWindowThreadProcessId.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		if !pids[pid] {
			return true
		}
		l, _, _ := procGetClassNameW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		cls := syscall.UTF16ToString(buf[:l])
		if strings.HasPrefix(cls, prefix) && strings.HasSuffix(cls, suffix) {
			procPostMessageW.Call(hwnd, uintptr(msg), 0, 0)
			n++
		}
		return true
	}
	procEnumWindows.Call(enumCb, 0)
	return n
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
