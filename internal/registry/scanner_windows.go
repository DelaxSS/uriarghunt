//go:build windows

package registry

import (
	"errors"
	"fmt"
	"strings"

	winreg "golang.org/x/sys/windows/registry"
)

const classesSubkey = `Software\Classes`

// ScanAll enumerates URL Protocol handlers under HKCU and HKLM without requiring
// administrator privileges, including partial HKCU shell\open\command overrides.
func ScanAll() ([]Handler, error) {
	lookup := SystemEnvLookup()

	hkcu, err := scanHive(winreg.CURRENT_USER, HiveHKCU, lookup)
	if err != nil {
		return nil, fmt.Errorf("scan HKCU: %w", err)
	}

	hklm, err := scanHive(winreg.LOCAL_MACHINE, HiveHKLM, lookup)
	if err != nil {
		return nil, fmt.Errorf("scan HKLM: %w", err)
	}

	// HKCR merges subkeys across hives: HKCU can override shell\open\command
	// for an HKLM scheme without duplicating the "URL Protocol" marker.
	hkcuSeen := make(map[string]struct{}, len(hkcu))
	for _, h := range hkcu {
		hkcuSeen[strings.ToLower(h.Scheme)] = struct{}{}
	}
	for _, h := range hklm {
		if _, exists := hkcuSeen[strings.ToLower(h.Scheme)]; exists {
			continue
		}
		if override, ok := readPartialHKCUOverride(h, lookup); ok {
			hkcu = append(hkcu, override)
		}
	}

	return MergeHandlers(hkcu, hklm), nil
}

func scanHive(root winreg.Key, hiveName string, lookup func(string) (string, bool)) ([]Handler, error) {
	classesKey, err := winreg.OpenKey(root, classesSubkey, winreg.ENUMERATE_SUB_KEYS|winreg.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, winreg.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer classesKey.Close()

	names, err := classesKey.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("enumerate %s\\%s: %w", hiveName, classesSubkey, err)
	}

	var handlers []Handler
	for _, name := range names {
		if name == "" || strings.HasPrefix(name, ".") {
			continue
		}
		if h, ok := inspectSchemeKey(classesKey, hiveName, name, lookup); ok {
			handlers = append(handlers, h)
		}
	}
	return handlers, nil
}

func inspectSchemeKey(classesKey winreg.Key, hiveName, scheme string, lookup func(string) (string, bool)) (Handler, bool) {
	sub, err := winreg.OpenKey(classesKey, scheme, winreg.QUERY_VALUE)
	if err != nil {
		return Handler{}, false
	}
	defer sub.Close()

	// "URL Protocol" is normally an empty REG_SZ; check presence rather than value.
	_, _, err = sub.GetValue("URL Protocol", nil)
	if err != nil && !errors.Is(err, winreg.ErrShortBuffer) {
		return Handler{}, false
	}

	desc, _, _ := sub.GetStringValue("")
	rawCmd, expandedCmd, isExpandSZ, envExpanded, delegateExec := readOpenCommand(sub, lookup)

	return Handler{
		Scheme:          scheme,
		Hive:            hiveName,
		RegistryPath:    fmt.Sprintf(`%s\%s\%s`, hiveName, classesSubkey, scheme),
		Description:     desc,
		RawCommand:      rawCmd,
		Command:         expandedCmd,
		IsExpandSZ:      isExpandSZ,
		EnvExpanded:     envExpanded,
		DelegateExecute: delegateExec,
		Analysis:        AnalyzeTemplate(expandedCmd),
	}, true
}

func readPartialHKCUOverride(hklmHandler Handler, lookup func(string) (string, bool)) (Handler, bool) {
	path := fmt.Sprintf(`%s\%s`, classesSubkey, hklmHandler.Scheme)
	sub, err := winreg.OpenKey(winreg.CURRENT_USER, path, winreg.QUERY_VALUE)
	if err != nil {
		return Handler{}, false
	}
	defer sub.Close()

	rawCmd, expandedCmd, isExpandSZ, envExpanded, delegateExec := readOpenCommand(sub, lookup)
	if rawCmd == "" && delegateExec == "" {
		return Handler{}, false
	}

	desc, _, _ := sub.GetStringValue("")
	if desc == "" {
		desc = hklmHandler.Description
	}

	return Handler{
		Scheme:            hklmHandler.Scheme,
		Hive:              HiveHKCU,
		RegistryPath:      fmt.Sprintf(`%s\%s`, HiveHKCU, path),
		Description:       desc,
		RawCommand:        rawCmd,
		Command:           expandedCmd,
		IsExpandSZ:        isExpandSZ,
		EnvExpanded:       envExpanded,
		DelegateExecute:   delegateExec,
		PartialHKCUShadow: true,
		Analysis:          AnalyzeTemplate(expandedCmd),
	}, true
}

func readOpenCommand(schemeKey winreg.Key, lookup func(string) (string, bool)) (rawCmd, expandedCmd string, isExpandSZ, envExpanded bool, delegateExec string) {
	cmdKey, err := winreg.OpenKey(schemeKey, `shell\open\command`, winreg.QUERY_VALUE)
	if err != nil {
		return "", "", false, false, ""
	}
	defer cmdKey.Close()

	val, valType, err := cmdKey.GetStringValue("")
	if err == nil {
		rawCmd = val
		isExpandSZ = (valType == winreg.EXPAND_SZ)
		expandedCmd, envExpanded = ExpandEnv(val, lookup)
	}

	if del, _, delErr := cmdKey.GetStringValue("DelegateExecute"); delErr == nil {
		delegateExec = del
	}

	return rawCmd, expandedCmd, isExpandSZ, envExpanded, delegateExec
}
