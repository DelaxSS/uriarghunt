//go:build windows

package argv

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SplitCommandLine parses a Windows command line using shell32.dll!CommandLineToArgvW.
func SplitCommandLine(cmdLine string) ([]string, error) {
	// CommandLineToArgvW returns the current executable path on an empty string.
	if strings.TrimSpace(cmdLine) == "" {
		return nil, nil
	}

	cmdUTF16, err := windows.UTF16PtrFromString(cmdLine)
	if err != nil {
		return nil, fmt.Errorf("utf16 encode command line: %w", err)
	}

	var argc int32
	argvPtr, err := windows.CommandLineToArgv(cmdUTF16, &argc)
	if err != nil {
		return nil, fmt.Errorf("CommandLineToArgvW: %w", err)
	}
	// CommandLineToArgvW allocates one LocalAlloc block that must be freed with LocalFree.
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(argvPtr)))

	if argc <= 0 {
		return nil, nil
	}

	// Slice by actual argc rather than indexing Go's fixed *[8192] signature (go.dev/issue/63236).
	ptrs := unsafe.Slice((**uint16)(unsafe.Pointer(argvPtr)), int(argc))
	args := make([]string, int(argc))
	for i, p := range ptrs {
		args[i] = windows.UTF16PtrToString(p)
	}
	return args, nil
}
