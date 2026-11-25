package fingerprint

import (
	"debug/pe"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"uriarghunt/internal/fuses"
)

// RuntimeKind classifies the target executable runtime.
type RuntimeKind string

const (
	RuntimeElectron RuntimeKind = "electron"
	RuntimeCEF      RuntimeKind = "cef"
	RuntimeChromium RuntimeKind = "chromium"
	RuntimeNode     RuntimeKind = "node"
	RuntimeShell    RuntimeKind = "shell"
	RuntimeJava     RuntimeKind = "java"
	RuntimeLOLBin   RuntimeKind = "lolbin"
	RuntimeNative   RuntimeKind = "native"
	RuntimeDangling RuntimeKind = "dangling"
	RuntimeUnknown  RuntimeKind = "unknown"
)

// Info describes the resolved target binary, PE metadata, Electron fuses, and runtime class.
type Info struct {
	RawExecutable   string      `json:"raw_executable,omitempty"`
	ResolvedPath    string      `json:"resolved_path,omitempty"`
	Exists          bool        `json:"exists"`
	Dangling        bool        `json:"dangling"`
	ValidPE         bool        `json:"valid_pe"`
	Architecture    string      `json:"architecture,omitempty"`
	Subsystem       string      `json:"subsystem,omitempty"`
	Runtime         RuntimeKind `json:"runtime"`
	HighRiskRuntime bool        `json:"high_risk_runtime"`
	Fuses           *fuses.Info `json:"fuses,omitempty"`
	Evidence        []string    `json:"evidence,omitempty"`
	PEError         string      `json:"pe_error,omitempty"`
}

// IsCmdShell reports whether the existing target runs through cmd.exe
// (either cmd.exe directly or a .bat/.cmd script), where unquoted `&` acts as a command separator.
func (info Info) IsCmdShell() bool {
	if !info.Exists || info.Dangling {
		return false
	}
	base := strings.ToLower(filepath.Base(info.ResolvedPath))
	if base == "cmd.exe" {
		return true
	}
	ext := strings.ToLower(filepath.Ext(base))
	return ext == ".bat" || ext == ".cmd"
}

var (
	shellInterpreters = map[string]struct{}{
		"cmd.exe":        {},
		"powershell.exe": {},
		"pwsh.exe":       {},
		"wscript.exe":    {},
		"cscript.exe":    {},
		"mshta.exe":      {},
	}

	javaRunners = map[string]struct{}{
		"java.exe":        {},
		"javaw.exe":       {},
		"jp2launcher.exe": {},
	}

	windowsLOLBins = map[string]struct{}{
		"rundll32.exe": {},
		"msdt.exe":     {},
		"regsvr32.exe": {},
		"msiexec.exe":  {},
	}
)

// Inspect resolves rawExe, validates its PE header via debug/pe, classifies its runtime,
// and decodes Electron Fuses v1 when the target is an Electron binary.
func Inspect(rawExe string) Info {
	trimmed := strings.TrimSpace(strings.Trim(rawExe, `"`))
	if trimmed == "" {
		return Info{Runtime: RuntimeUnknown}
	}

	info := Info{
		RawExecutable: trimmed,
		Runtime:       RuntimeUnknown,
	}

	resolved, ok := resolveExecutable(trimmed)
	if !ok {
		info.Dangling = true
		info.Runtime = RuntimeDangling
		info.Evidence = []string{"target binary missing on disk"}
		return info
	}

	info.ResolvedPath = resolved
	info.Exists = true

	importedDLLs := inspectPE(resolved, &info)
	info.Runtime, info.HighRiskRuntime, info.Evidence = classifyRuntime(resolved, importedDLLs)

	if info.Runtime == RuntimeElectron && info.ValidPE {
		fi := fuses.InspectFile(resolved)
		info.Fuses = &fi
	}

	return info
}

func resolveExecutable(raw string) (string, bool) {
	// Bare executable names (e.g. "cmd.exe", "msedge.exe") must resolve via App Paths
	// or PATH rather than os.Stat in CWD to prevent working-directory hijacking.
	if !strings.ContainsAny(raw, `\/:`) {
		if found, ok := lookupAppPaths(raw); ok {
			return found, true
		}
		if found, err := exec.LookPath(raw); err == nil {
			return filepath.Clean(found), true
		}
		return "", false
	}

	cleaned := filepath.Clean(raw)
	if st, err := os.Stat(cleaned); err == nil && !st.IsDir() {
		return cleaned, true
	}

	if filepath.Ext(cleaned) == "" {
		withExe := cleaned + ".exe"
		if st, err := os.Stat(withExe); err == nil && !st.IsDir() {
			return withExe, true
		}
	}

	return "", false
}

func inspectPE(path string, info *Info) []string {
	f, err := pe.Open(path)
	if err != nil {
		info.PEError = err.Error()
		return nil
	}
	defer f.Close()

	info.ValidPE = true
	info.Architecture = machineToArch(f.FileHeader.Machine)

	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		info.Subsystem = subsystemToName(oh.Subsystem)
	case *pe.OptionalHeader32:
		info.Subsystem = subsystemToName(oh.Subsystem)
	}

	libs, err := f.ImportedLibraries()
	if err != nil {
		return nil
	}
	return libs
}

func classifyRuntime(resolvedPath string, importedDLLs []string) (RuntimeKind, bool, []string) {
	base := strings.ToLower(filepath.Base(resolvedPath))
	ext := strings.ToLower(filepath.Ext(base))
	dir := filepath.Dir(resolvedPath)

	// Script handlers verified to exist on disk.
	switch ext {
	case ".bat", ".cmd":
		return RuntimeShell, true, []string{"script=" + ext, "cmd.exe metacharacters (&, |, %VAR%)"}
	case ".ps1", ".vbs":
		return RuntimeShell, true, []string{"script=" + ext}
	}

	if _, ok := shellInterpreters[base]; ok {
		ev := []string{"executable=" + base}
		if base == "cmd.exe" {
			ev = append(ev, "cmd.exe metacharacters (&, |, %VAR%)")
		}
		return RuntimeShell, true, ev
	}
	if _, ok := javaRunners[base]; ok {
		return RuntimeJava, true, []string{"executable=" + base}
	}
	if _, ok := windowsLOLBins[base]; ok {
		return RuntimeLOLBin, true, []string{"executable=" + base}
	}
	if base == "node.exe" {
		return RuntimeNode, true, []string{"executable=node.exe"}
	}

	scanDirs := []struct {
		path   string
		prefix string
	}{
		{path: dir, prefix: ""},
	}
	// Skip child-directory scanning in shared roots (System32, Program Files, AppData\Local\Programs)
	// so unrelated sibling apps or components do not cause false runtime matches.
	if !isSharedDir(dir) {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				name := e.Name()
				scanDirs = append(scanDirs, struct {
					path   string
					prefix string
				}{
					path:   filepath.Join(dir, name),
					prefix: name + string(filepath.Separator),
				})
			}
		}
	}

	var (
		electronHits []string
		cefHits      []string
		chromiumHits []string
		nodeHits     []string
	)

	electronRelPaths := []string{
		filepath.Join("resources", "app.asar"),
		filepath.Join("resources", "electron.asar"),
		filepath.Join("resources", "default_app.asar"),
		filepath.Join("resources", "app", "package.json"),
		"electron.asar",
	}
	chromiumFiles := []string{
		"chrome_100_percent.pak",
		"icudtl.dat",
		"v8_context_snapshot.bin",
		"chrome.dll",
		"msedge.dll",
		"opera.dll",
		"chrome_elf.dll",
	}

	for _, sd := range scanDirs {
		for _, rel := range electronRelPaths {
			if pathExists(filepath.Join(sd.path, rel)) {
				electronHits = appendUnique(electronHits, sd.prefix+rel)
			}
		}
		if pathExists(filepath.Join(sd.path, "libcef.dll")) {
			cefHits = appendUnique(cefHits, sd.prefix+"libcef.dll")
		}
		if pathExists(filepath.Join(sd.path, "node.dll")) {
			nodeHits = appendUnique(nodeHits, sd.prefix+"node.dll")
		}
		for _, f := range chromiumFiles {
			if pathExists(filepath.Join(sd.path, f)) {
				chromiumHits = appendUnique(chromiumHits, sd.prefix+f)
			}
		}
	}

	for _, dll := range importedDLLs {
		switch strings.ToLower(dll) {
		case "libcef.dll":
			cefHits = appendUnique(cefHits, "import:libcef.dll")
		case "node.dll":
			nodeHits = appendUnique(nodeHits, "import:node.dll")
		case "jvm.dll":
			return RuntimeJava, true, []string{"import:jvm.dll"}
		}
	}

	switch {
	case len(electronHits) > 0:
		return RuntimeElectron, true, append(electronHits, chromiumHits...)
	case len(cefHits) > 0:
		return RuntimeCEF, true, append(cefHits, chromiumHits...)
	case len(nodeHits) > 0:
		return RuntimeNode, true, nodeHits
	case len(chromiumHits) >= 2 || hasBrowserCoreDLL(chromiumHits):
		return RuntimeChromium, true, chromiumHits
	default:
		return RuntimeNative, false, nil
	}
}

func isSharedDir(dir string) bool {
	clean := strings.ToLower(filepath.Clean(dir))
	localAppData := os.Getenv("LOCALAPPDATA")
	roots := []string{
		os.Getenv("SystemRoot"),
		filepath.Join(os.Getenv("SystemRoot"), "System32"),
		filepath.Join(os.Getenv("SystemRoot"), "SysWOW64"),
		os.Getenv("ProgramFiles"),
		os.Getenv("ProgramFiles(x86)"),
		localAppData,
		os.Getenv("APPDATA"),
		os.Getenv("USERPROFILE"),
	}
	if localAppData != "" {
		roots = append(roots, filepath.Join(localAppData, "Programs"))
	}

	for _, root := range roots {
		if root != "" && clean == strings.ToLower(filepath.Clean(root)) {
			return true
		}
	}

	// Match drive-root X:\windows directly so nested paths like D:\proj\build\windows
	// are not misclassified as shared system directories.
	if len(clean) == 10 && clean[1:] == `:\windows` {
		return true
	}

	for _, suffix := range []string{
		`\windows\system32`,
		`\windows\syswow64`,
		`\appdata\local`,
		`\appdata\local\programs`,
		`\appdata\roaming`,
	} {
		if strings.HasSuffix(clean, suffix) {
			return true
		}
	}
	return false
}

func hasBrowserCoreDLL(hits []string) bool {
	for _, h := range hits {
		switch strings.ToLower(filepath.Base(h)) {
		case "chrome.dll", "msedge.dll", "opera.dll", "chrome_elf.dll":
			return true
		}
	}
	return false
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func appendUnique(list []string, item string) []string {
	for _, x := range list {
		if x == item {
			return list
		}
	}
	return append(list, item)
}

func machineToArch(m uint16) string {
	switch m {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x64"
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	case pe.IMAGE_FILE_MACHINE_ARM:
		return "arm"
	default:
		return "unknown"
	}
}

func subsystemToName(s uint16) string {
	switch s {
	case pe.IMAGE_SUBSYSTEM_WINDOWS_GUI:
		return "GUI"
	case pe.IMAGE_SUBSYSTEM_WINDOWS_CUI:
		return "Console"
	default:
		return "Other"
	}
}
