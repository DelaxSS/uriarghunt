//go:build windows

package fingerprint

import (
	"os"
	"path/filepath"
	"strings"

	winreg "golang.org/x/sys/windows/registry"

	"uriarghunt/internal/registry"
)

const appPathsKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\`

// lookupAppPaths resolves bare executable names registered under Windows App Paths
// (HKCU then HKLM), matching ShellExecute's search order.
func lookupAppPaths(name string) (string, bool) {
	candidates := []string{name}
	if filepath.Ext(name) == "" {
		candidates = append(candidates, name+".exe")
	}

	lookup := registry.SystemEnvLookup()
	for _, root := range []winreg.Key{winreg.CURRENT_USER, winreg.LOCAL_MACHINE} {
		for _, cand := range candidates {
			k, err := winreg.OpenKey(root, appPathsKey+cand, winreg.QUERY_VALUE)
			if err != nil {
				continue
			}
			val, _, valErr := k.GetStringValue("")
			k.Close()
			if valErr != nil || strings.TrimSpace(val) == "" {
				continue
			}

			expanded, _ := registry.ExpandEnv(strings.Trim(strings.TrimSpace(val), `"`), lookup)
			cleaned := filepath.Clean(expanded)
			if st, err := os.Stat(cleaned); err == nil && !st.IsDir() {
				return cleaned, true
			}
		}
	}
	return "", false
}
