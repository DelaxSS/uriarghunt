package fingerprint

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInspect_DanglingBinary(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.exe")
	info := Inspect(missing)

	if info.Exists || !info.Dangling || info.Runtime != RuntimeDangling || info.HighRiskRuntime {
		t.Fatalf("unexpected dangling result: %+v", info)
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
	info := Inspect("cmd.exe")
	if !info.Exists || !info.ValidPE {
		t.Fatalf("cmd.exe should be a valid PE: %+v", info)
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
