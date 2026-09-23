//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	modkernel32       = syscall.NewLazyDLL("kernel32.dll")
	procMoveFileExW   = modkernel32.NewProc("MoveFileExW")
)

const moveFileReplaceExisting = 0x00000001

func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}

	tmpName := tmp.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temporary file: %w", err)
	}

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary file: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}

	src, err := syscall.UTF16PtrFromString(tmpName)
	if err != nil {
		return fmt.Errorf("temporary filename: %w", err)
	}

	dst, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("destination filename: %w", err)
	}

	r, _, callErr := procMoveFileExW.Call(
		uintptr(unsafe.Pointer(src)),
		uintptr(unsafe.Pointer(dst)),
		moveFileReplaceExisting,
	)

	if r == 0 {
		return fmt.Errorf("replace database: %w", callErr)
	}

	keep = true
	return nil
}
