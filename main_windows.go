package main

import "golang.org/x/sys/windows"

func openLibrary(name string) (uintptr, error) {
	// Use [syscall.LoadLibrary] here to avoid external dependencies (#270).
	// For actual use cases, [golang.org/x/sys/windows.NewLazySystemDLL] is recommended.
	//handle, err := syscall.LoadLibrary(name)
	lazyDLL := windows.NewLazyDLL(name)
	if err := lazyDLL.Load(); err != nil {
		return 0x00, err
	}
	return lazyDLL.Handle(), nil
}