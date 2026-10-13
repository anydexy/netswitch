//go:build !windows

package main

// Заглушки для сборки/тестов не под Windows.

import (
	"errors"
	"os/exec"
)

func hideCmd(c *exec.Cmd)                             {}
func isAdmin() bool                                   { return true }
func relaunchAsAdmin() error                          { return errors.New("not windows") }
func alreadyRunning() bool                            { return false }
func claimInstance() bool                             { return true }
func trayRemove()                                     {}
func openURL(u string)                                { println("open", u) }
func serviceState(name string) int                    { return 0 }
func icmpPing(ip string, t int) (int, error)          { return 0, errors.New("нет ICMP") }
func runTray(onOpen, onFastest, onOff, onExit func()) {}
func trayUpdate(color uint32, tip string)             {}
func trayBalloon(title, text string)                  {}
func mutexExists(name string) bool                    { return false }
func listProcs() []procEntry                          { return nil }
func procPath(pid uint32) string                      { return "" }
func killPID(pid uint32)                              {}

func postToProcWindows(pids map[uint32]bool, prefix, suffix string, msg uint32) int { return 0 }
