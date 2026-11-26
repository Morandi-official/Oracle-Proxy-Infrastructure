// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"
)

// Only the attested SYSTEM child uses this DLL. Its parent pins both images and
// holds a non-replaceable bundle lease throughout the entire child lifetime.
var adapterBindingLibrary struct {
	once          sync.Once
	park, restore uintptr
}

func loadAdapterBindingLibrary() {
	if runtime.GOARCH != "amd64" {
		return
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	var session uint32
	if err != nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) ||
		windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session) != nil || session != 0 {
		return
	}
	files, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil || !filepath.IsAbs(files) {
		return
	}
	root := filepath.Join(files, "OracleProxy")
	image, err := os.Executable()
	if err != nil || !strings.EqualFold(filepath.Clean(image), filepath.Join(root, "Proxy.Core.exe")) {
		return
	}
	// A fully qualified path and System32-only dependency search exclude the
	// working directory, PATH, and user settings from privileged resolution.
	module, err := windows.LoadLibraryEx(filepath.Join(root, "Proxy.Guard.dll"), 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return
	}
	park, errPark := windows.GetProcAddress(module, "OpParkIpBindings")
	restore, errRestore := windows.GetProcAddress(module, "OpRestoreIpBindings")
	if errPark != nil || errRestore != nil || park == 0 || restore == 0 {
		_ = windows.FreeLibrary(module)
		return
	}
	// Keep the module alive, including its owner-scoped recovery state, until
	// process exit. Failure to resolve either operation disables both.
	adapterBindingLibrary.park, adapterBindingLibrary.restore = park, restore
}

func parkAdapterBindings(luid uint64) error {
	adapterBindingLibrary.once.Do(loadAdapterBindingLibrary)
	if luid == 0 || adapterBindingLibrary.park == 0 {
		return errors.New("PARK_BINDINGS_LOAD_FAILED")
	}
	status, _, _ := syscall.SyscallN(adapterBindingLibrary.park, uintptr(luid))
	if status != 0 {
		return errors.New("PARK_BINDINGS_DISABLE_FAILED")
	}
	return nil
}

func restoreAdapterBindings(luid uint64) error {
	adapterBindingLibrary.once.Do(loadAdapterBindingLibrary)
	if luid == 0 || adapterBindingLibrary.restore == 0 {
		return errors.New("PARK_BINDINGS_LOAD_FAILED")
	}
	status, _, _ := syscall.SyscallN(adapterBindingLibrary.restore, uintptr(luid))
	if status != 0 {
		return errors.New("PARK_BINDINGS_RESTORE_FAILED")
	}
	return nil
}
