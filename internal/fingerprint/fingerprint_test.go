package fingerprint

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInspect_DanglingBinary(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.exe")
	info := Inspect(missing)

	if info.Exists || !info.Dangling || info.Runtime != RuntimeDangling || info.HighRiskRuntime {
		t.Fatalf("unexpected dangling result: %+v", info)
	}
}

func TestInspect_ScriptHandlers(t *testing.T) {
	dir := t.TempDir()

	// Missing script must remain dangling, not RuntimeShell.
	missingBat := filepath.Join(dir, "missing.bat")
	if info := Inspect(missingBat); !info.Dangling || info.Runtime != RuntimeDangling || info.HighRiskRuntime {
		t.Fatalf("missing .bat should be dangling: %+v", info)
	}

	cases := []struct {
		file      string
		wantCmd   bool
		wantEvSub string
	}{
		{"handler.bat", true, "metacharacters"},
		{"handler.cmd", true, "metacharacters"},
		{"handler.ps1", false, "script=.ps1"},
		{"handler.vbs", false, "script=.vbs"},
	}

	for _, tc := range cases {
		p := filepath.Join(dir, tc.file)
		mustWriteFile(t, p, "@echo off\n")
		info := Inspect(p)
		if !info.Exists || info.Dangling || info.Runtime != RuntimeShell || !info.HighRiskRuntime {
			t.Errorf("%s: got %+v, want existing RuntimeShell + HighRiskRuntime", tc.file, info)
		}
		if info.IsCmdShell() != tc.wantCmd {
			t.Errorf("%s: IsCmdShell() = %v, want %v", tc.file, info.IsCmdShell(), tc.wantCmd)
		}
		if !strings.Contains(strings.Join(info.Evidence, " "), tc.wantEvSub) {
			t.Errorf("%s: evidence %v missing %q", tc.file, info.Evidence, tc.wantEvSub)
		}
	}
}

func TestInspect_ElectronDirectory(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "MyElectronApp.exe")
	mustWriteFile(t, exe, "stub")
	mustWriteFile(t, filepath.Join(dir, "resources", "app.asar"), "asar")
	mustWriteFile(t, filepath.Join(dir, "icudtl.dat"), "icu")
	mustWriteFile(t, filepath.Join(dir, "chrome_100_percent.pak"), "pak")

	info := Inspect(exe)
	if !info.Exists || info.Dangling || info.ValidPE {
		t.Fatalf("unexpected file metadata: %+v", info)
	}
	if info.Runtime != RuntimeElectron || !info.HighRiskRuntime {
		t.Errorf("got (%s, highRisk=%v), want (electron, true)", info.Runtime, info.HighRiskRuntime)
	}
}

func TestInspect_CEFDirectory(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "Launcher.exe")
	mustWriteFile(t, exe, "stub")
	mustWriteFile(t, filepath.Join(dir, "libcef.dll"), "cef")
	mustWriteFile(t, filepath.Join(dir, "icudtl.dat"), "icu")

	info := Inspect(exe)
	if info.Runtime != RuntimeCEF || !info.HighRiskRuntime {
		t.Errorf("got (%s, highRisk=%v), want (cef, true)", info.Runtime, info.HighRiskRuntime)
	}
}

func TestInspect_VersionedSubdirLayouts(t *testing.T) {
	vsDir := t.TempDir()
	vsExe := filepath.Join(vsDir, "Code.exe")
	mustWriteFile(t, vsExe, "stub")
	mustWriteFile(t, filepath.Join(vsDir, "2c33b50b16", "resources", "app", "package.json"), "{}")
	mustWriteFile(t, filepath.Join(vsDir, "2c33b50b16", "icudtl.dat"), "icu")

	if info := Inspect(vsExe); info.Runtime != RuntimeElectron || !info.HighRiskRuntime {
		t.Errorf("versioned VS Code layout: got %+v", info)
	}

	chDir := t.TempDir()
	chExe := filepath.Join(chDir, "chrome.exe")
	mustWriteFile(t, chExe, "stub")
	mustWriteFile(t, filepath.Join(chDir, "131.0.6778.85", "chrome.dll"), "dll")
	mustWriteFile(t, filepath.Join(chDir, "131.0.6778.85", "icudtl.dat"), "icu")

	if info := Inspect(chExe); info.Runtime != RuntimeChromium || !info.HighRiskRuntime {
		t.Errorf("versioned Chrome layout: got %+v", info)
	}
}

func TestInspect_SharedDirSkipsSubdirScan(t *testing.T) {
	sys32 := filepath.Join(t.TempDir(), "Windows", "System32")
	ctrlExe := filepath.Join(sys32, "control.exe")
	mustWriteFile(t, ctrlExe, "stub")
	mustWriteFile(t, filepath.Join(sys32, "Component", "msedge.dll"), "dll")
	mustWriteFile(t, filepath.Join(sys32, "Component", "icudtl.dat"), "icu")

	if info := Inspect(ctrlExe); info.Runtime != RuntimeNative || info.HighRiskRuntime {
		t.Errorf("System32 subdir scan false positive: %+v", info)
	}

	programs := filepath.Join(t.TempDir(), "AppData", "Local", "Programs")
	toolExe := filepath.Join(programs, "standalone.exe")
	mustWriteFile(t, toolExe, "stub")
	mustWriteFile(t, filepath.Join(programs, "SomeElectronApp", "resources", "app.asar"), "asar")

	if info := Inspect(toolExe); info.Runtime != RuntimeNative || info.HighRiskRuntime {
		t.Errorf("AppData\\Local\\Programs subdir scan false positive: %+v", info)
	}

	// A nested project path ending in \windows (e.g. D:\proj\build\windows) must NOT
	// be treated as C:\Windows; its 1-level versioned Electron subdir must still be scanned.
	buildWin := filepath.Join(t.TempDir(), "proj", "build", "windows")
	appExe := filepath.Join(buildWin, "MyApp.exe")
	mustWriteFile(t, appExe, "stub")
	mustWriteFile(t, filepath.Join(buildWin, "1.0.0", "resources", "app.asar"), "asar")

	if info := Inspect(appExe); info.Runtime != RuntimeElectron || !info.HighRiskRuntime {
		t.Errorf("nested \\build\\windows dir should still scan versioned subdir: %+v", info)
	}
}

func TestInspect_BareNameIgnoresCWD(t *testing.T) {
	// A stray dummy file in the current working directory must not be resolved for a bare name.
	tmp := t.TempDir()
	mustWriteFile(t, filepath.Join(tmp, "uriarghunt-cwd-decoy.exe"), "decoy")

	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(orig) }()

	info := Inspect("uriarghunt-cwd-decoy.exe")
	if info.Exists || !info.Dangling {
		t.Errorf("bare executable resolved from CWD instead of App Paths/PATH: %+v", info)
	}
}

func TestInspect_ShellJavaAndLOLBin(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		exe    string
		want   RuntimeKind
		wantHR bool
	}{
		{"powershell.exe", RuntimeShell, true},
		{"cmd.exe", RuntimeShell, true},
		{"javaw.exe", RuntimeJava, true},
		{"rundll32.exe", RuntimeLOLBin, true},
		{"plain.exe", RuntimeNative, false},
	}

	for _, tc := range cases {
		p := filepath.Join(dir, tc.exe)
		mustWriteFile(t, p, "stub")
		info := Inspect(p)
		if info.Runtime != tc.want || info.HighRiskRuntime != tc.wantHR {
			t.Errorf("%s: got (%s, %v), want (%s, %v)",
				tc.exe, info.Runtime, info.HighRiskRuntime, tc.want, tc.wantHR)
		}
	}
}

func TestInspect_RealWindowsPE(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows only")
	}

	info := Inspect("cmd.exe")
	if !info.Exists || !info.ValidPE || !info.IsCmdShell() {
		t.Fatalf("cmd.exe should be a valid PE cmd shell: %+v", info)
	}
	if info.Architecture != "x64" && info.Architecture != "x86" && info.Architecture != "arm64" {
		t.Errorf("unexpected arch %q", info.Architecture)
	}
	if info.Runtime != RuntimeShell || !info.HighRiskRuntime {
		t.Errorf("unexpected runtime for cmd.exe: %+v", info)
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}
