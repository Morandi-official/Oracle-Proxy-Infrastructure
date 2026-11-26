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
	return bindingRestoreResult(status)
}

// Every value returned here is safe to report across the recovery pipe. The
// result identifies the failing Windows check without recording device or user data.
type bindingRestoreFailure string

func (code bindingRestoreFailure) Error() string { return string(code) }

func bindingRestoreResult(status uintptr) error {
	switch syscall.Errno(status) {
	case windows.ERROR_SUCCESS:
		return nil
	case windows.ERROR_ACCESS_DENIED:
		return bindingRestoreFailure("PARK_RESTORE_ACCESS_DENIED")
	case windows.ERROR_BUSY:
		return bindingRestoreFailure("PARK_RESTORE_LOCK_BUSY")
	case windows.ERROR_SUCCESS_REBOOT_REQUIRED:
		return bindingRestoreFailure("PARK_RESTORE_REBOOT_REQUIRED")
	case windows.ERROR_INVALID_OWNER:
		return bindingRestoreFailure("PARK_RESTORE_OWNER")
	case windows.ERROR_NOT_FOUND:
		return bindingRestoreFailure("PARK_RESTORE_IDENTITY")
	case windows.ERROR_DEVICE_NOT_CONNECTED:
		return bindingRestoreFailure("PARK_RESTORE_PNP")
	case windows.ERROR_REVISION_MISMATCH:
		return bindingRestoreFailure("PARK_RESTORE_DRIFT")
	case windows.ERROR_NO_MATCH:
		return bindingRestoreFailure("PARK_RESTORE_READBACK")
	case windows.ERROR_INVALID_DATA:
		return bindingRestoreFailure("PARK_RESTORE_JOURNAL_INVALID")
	case windows.ERROR_INVALID_STATE:
		return bindingRestoreFailure("PARK_RESTORE_INVALID_STATE")
	default:
		return bindingRestoreFailure("PARK_BINDINGS_RESTORE_FAILED")
	}
}
