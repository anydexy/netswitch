//go:build windows

package main

import (
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

var (
	user32 = syscall.NewLazyDLL("user32.dll")

	procRegisterClassExW    = user32.NewProc("RegisterClassExW")
	procCreateWindowExW     = user32.NewProc("CreateWindowExW")
	procDefWindowProcW      = user32.NewProc("DefWindowProcW")
	procGetMessageW         = user32.NewProc("GetMessageW")
	procTranslateMessage    = user32.NewProc("TranslateMessage")
	procDispatchMessageW    = user32.NewProc("DispatchMessageW")
	procCreatePopupMenu     = user32.NewProc("CreatePopupMenu")
	procAppendMenuW         = user32.NewProc("AppendMenuW")
	procTrackPopupMenu      = user32.NewProc("TrackPopupMenu")
	procDestroyMenu         = user32.NewProc("DestroyMenu")
	procGetCursorPos        = user32.NewProc("GetCursorPos")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procPostMessageW        = user32.NewProc("PostMessageW")
	procCreateIcon          = user32.NewProc("CreateIcon")
	procDestroyIcon         = user32.NewProc("DestroyIcon")
	procRegisterWindowMsgW  = user32.NewProc("RegisterWindowMessageW")
	procShellNotifyIconW    = shell32.NewProc("Shell_NotifyIconW")
	procGetModuleHandleW    = kernel32.NewProc("GetModuleHandleW")
)

type wndClassEx struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

type notifyIconData struct {
	cbSize           uint32
	hWnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         [16]byte
	hBalloonIcon     uintptr
}

type winMsg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      [2]int32
	private uint32
}

const (
	wmApp       = 0x8000
	wmTray      = wmApp + 1
	wmTrayCmd   = wmApp + 2
	nimAdd      = 0
	nimModify   = 1
	nimDelete   = 2
	nifMessage  = 1
	nifIcon     = 2
	nifTip      = 4
	nifInfo     = 0x10
	mfString    = 0
	mfSeparator = 0x800
)

var (
	trayMu      sync.Mutex
	trayNid     notifyIconData
	trayReady   bool
	trayIcon    uintptr
	trayCbs     [4]func()
	taskbarMsg  uintptr
	trayPending struct {
		color uint32
		tip   string
		info  [2]string
		has   bool
	}
)

func setUTF16(dst []uint16, s string) {
	u, _ := syscall.UTF16FromString(s)
	if len(u) > len(dst) {
		u = u[:len(dst)]
		u[len(u)-1] = 0
	}
	for i := range dst {
		dst[i] = 0
	}
	copy(dst, u)
}

// makeIcon рисует круглую иконку 32x32 заданного цвета (0xRRGGBB) с белым "щитом"-точкой.
func makeIcon(color uint32) uintptr {
	const n = 32
	xor := make([]byte, n*n*4)
	and := make([]byte, n*n/8)
	r, g, b := byte(color>>16), byte(color>>8), byte(color)
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			dx, dy := float64(x)-15.5, float64(y)-15.5
			d := dx*dx + dy*dy
			i := (y*n + x) * 4
			if d <= 15.5*15.5 {
				cr, cg, cb := r, g, b
				if d <= 5.5*5.5 {
					cr, cg, cb = 255, 255, 255
				} else if d >= 14*14 {
					cr, cg, cb = byte(int(r)*7/10), byte(int(g)*7/10), byte(int(b)*7/10)
				}
				xor[i], xor[i+1], xor[i+2], xor[i+3] = cb, cg, cr, 255
			}
		}
	}
	h, _, _ := procCreateIcon.Call(0, n, n, 1, 32, uintptr(unsafe.Pointer(&and[0])), uintptr(unsafe.Pointer(&xor[0])))
	return h
}

func trayWndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch {
	case msg == wmTray:
		switch lParam & 0xFFFF {
		case 0x202, 0x203: // WM_LBUTTONUP, WM_LBUTTONDBLCLK
			if trayCbs[0] != nil {
				go trayCbs[0]()
			}
		case 0x205: // WM_RBUTTONUP
			showTrayMenu(hwnd)
		}
		return 0
	case taskbarMsg != 0 && msg == taskbarMsg: // проводник перезапустился — вернуть иконку
		trayMu.Lock()
		procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&trayNid)))
		trayMu.Unlock()
		return 0
	case msg == wmTrayCmd:
		trayMu.Lock()
		if trayPending.has {
			p := trayPending
			trayPending.has = false
			if trayIcon != 0 {
				procDestroyIcon.Call(trayIcon)
			}
			trayIcon = makeIcon(p.color)
			trayNid.hIcon = trayIcon
			trayNid.uFlags = nifMessage | nifIcon | nifTip
			setUTF16(trayNid.szTip[:], p.tip)
			if p.info[0] != "" {
				trayNid.uFlags |= nifInfo
				setUTF16(trayNid.szInfoTitle[:], p.info[0])
				setUTF16(trayNid.szInfo[:], p.info[1])
			}
			procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&trayNid)))
			trayPending.info = [2]string{}
		}
		trayMu.Unlock()
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return r
}

func showTrayMenu(hwnd uintptr) {
	m, _, _ := procCreatePopupMenu.Call()
	items := []string{"Открыть NetSwitch", "Подключить самый быстрый", "Отключить (DNS провайдера)", "", "Выход"}
	ids := []uintptr{1, 2, 3, 0, 4}
	for i, s := range items {
		if s == "" {
			procAppendMenuW.Call(m, mfSeparator, 0, 0)
			continue
		}
		procAppendMenuW.Call(m, mfString, ids[i], uintptr(unsafe.Pointer(u16(s))))
	}
	var pt [2]int32
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt[0])))
	procSetForegroundWindow.Call(hwnd)
	cmd, _, _ := procTrackPopupMenu.Call(m, 0x100|0x2|0x20, uintptr(pt[0]), uintptr(pt[1]), 0, hwnd, 0) // RETURNCMD|RIGHTBUTTON|BOTTOMALIGN
	procDestroyMenu.Call(m)
	if cmd >= 1 && cmd <= 4 && trayCbs[cmd-1] != nil {
		go trayCbs[cmd-1]()
	}
}

var trayHwnd uintptr

// runTray запускает иконку в трее (блокирует — вызывать в отдельной горутине).
func runTray(onOpen, onFastest, onOff, onExit func()) {
	runtime.LockOSThread()
	trayCbs = [4]func(){onOpen, onFastest, onOff, onExit}
	hinst, _, _ := procGetModuleHandleW.Call(0)
	cls := u16("NetSwitchTray")
	wc := wndClassEx{lpfnWndProc: syscall.NewCallback(trayWndProc), hInstance: hinst, lpszClassName: cls}
	wc.cbSize = uint32(unsafe.Sizeof(wc))
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	hwnd, _, _ := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(u16("NetSwitch"))),
		0, 0, 0, 0, 0, 0, 0, hinst, 0)
	if hwnd == 0 {
		return
	}
	taskbarMsg, _, _ = procRegisterWindowMsgW.Call(uintptr(unsafe.Pointer(u16("TaskbarCreated"))))

	trayMu.Lock()
	trayHwnd = hwnd
	trayIcon = makeIcon(0x8e8e93)
	trayNid.cbSize = uint32(unsafe.Sizeof(trayNid))
	trayNid.hWnd = hwnd
	trayNid.uID = 1
	trayNid.uFlags = nifMessage | nifIcon | nifTip
	trayNid.uCallbackMessage = wmTray
	trayNid.hIcon = trayIcon
	setUTF16(trayNid.szTip[:], "NetSwitch")
	procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&trayNid)))
	trayReady = true
	pending := trayPending.has
	trayMu.Unlock()
	if pending {
		procPostMessageW.Call(hwnd, wmTrayCmd, 0, 0)
	}

	var m winMsg
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func trayRemove() {
	trayMu.Lock()
	defer trayMu.Unlock()
	if trayReady {
		procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&trayNid)))
		trayReady = false
	}
}

func trayUpdate(color uint32, tip string) {
	trayMu.Lock()
	trayPending.color, trayPending.tip, trayPending.has = color, tip, true
	h := trayHwnd
	trayMu.Unlock()
	if h != 0 {
		procPostMessageW.Call(h, wmTrayCmd, 0, 0)
	}
}

func trayBalloon(title, text string) {
	trayMu.Lock()
	trayPending.info = [2]string{title, text}
	if !trayPending.has {
		trayPending.has = true
		trayPending.color = lastTrayColor
		trayPending.tip = lastTrayTip
	}
	h := trayHwnd
	trayMu.Unlock()
	if h != 0 {
		procPostMessageW.Call(h, wmTrayCmd, 0, 0)
	}
}
