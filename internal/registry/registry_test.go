//go:build windows

package registry

import (
	"strings"
	"testing"
)

func TestAnalyzeTemplate(t *testing.T) {
	tests := []struct {
		name                   string
		cmd                    string
		wantPlaceholder        string
		wantQuoted             bool
		wantDirectlyQuoted     bool
		wantExe                string
		wantUnquotedSpaces     bool
	}{
		{
			name:               "quoted exe and quoted %1",
			cmd:                `"C:\Program Files\VS Code\Code.exe" --open-url "%1"`,
			wantPlaceholder:    "%1",
			wantQuoted:         true,
			wantDirectlyQuoted: true,
			wantExe:            `C:\Program Files\VS Code\Code.exe`,
			wantUnquotedSpaces: false,
		},
		{
			name:               "unquoted exe with spaces and unquoted %1",
			cmd:                `C:\Program Files\My App\client.exe %1`,
			wantPlaceholder:    "%1",
			wantQuoted:         false,
			wantDirectlyQuoted: false,
			wantExe:            `C:\Program Files\My App\client.exe`,
			wantUnquotedSpaces: true,
		},
		{
			name:               "unquoted exe without spaces and %l",
			cmd:                `C:\Windows\System32\rundll32.exe url.dll,FileProtocolHandler %l`,
			wantPlaceholder:    "%l",
			wantQuoted:         false,
			wantDirectlyQuoted: false,
			wantExe:            `C:\Windows\System32\rundll32.exe`,
			wantUnquotedSpaces: false,
		},
		{
			name:               "flag-attached quoted %1",
			cmd:                `"C:\App\app.exe" --url="%1"`,
			wantPlaceholder:    "%1",
			wantQuoted:         true,
			wantDirectlyQuoted: true,
			wantExe:            `C:\App\app.exe`,
			wantUnquotedSpaces: false,
		},
		{
			name:               "bare cmd /c with script arg does not merge .bat into exe",
			cmd:                `cmd /c C:\tools\run.bat %1`,
			wantPlaceholder:    "%1",
			wantQuoted:         false,
			wantDirectlyQuoted: false,
			wantExe:            `cmd`,
			wantUnquotedSpaces: false,
		},
		{
			name:               "bare powershell -File with .ps1 arg does not merge .ps1 into exe",
			cmd:                `powershell -File C:\x.ps1 %1`,
			wantPlaceholder:    "%1",
			wantQuoted:         false,
			wantDirectlyQuoted: false,
			wantExe:            `powershell`,
			wantUnquotedSpaces: false,
		},
		{
			name:               "cmd /c outer-quoted command leaves %1 not directly quoted",
			cmd:                `cmd.exe /c "start x.exe %1"`,
			wantPlaceholder:    "%1",
			wantQuoted:         true,
			wantDirectlyQuoted: false,
			wantExe:            `cmd.exe`,
			wantUnquotedSpaces: false,
		},
		{
			name:               "cmd /c outer-quoted batch command leaves %1 not directly quoted",
			cmd:                `cmd /c "C:\a.bat %1"`,
			wantPlaceholder:    "%1",
			wantQuoted:         true,
			wantDirectlyQuoted: false,
			wantExe:            `cmd`,
			wantUnquotedSpaces: false,
		},
		{
			name:               "no placeholder",
			cmd:                `"C:\App\launcher.exe" --start`,
			wantPlaceholder:    "",
			wantQuoted:         false,
			wantDirectlyQuoted: false,
			wantExe:            `C:\App\launcher.exe`,
			wantUnquotedSpaces: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := AnalyzeTemplate(tc.cmd)
			if got.Placeholder != tc.wantPlaceholder {
				t.Errorf("Placeholder = %q, want %q", got.Placeholder, tc.wantPlaceholder)
			}
			if got.PlaceholderQuoted != tc.wantQuoted {
				t.Errorf("PlaceholderQuoted = %v, want %v", got.PlaceholderQuoted, tc.wantQuoted)
			}
			if got.PlaceholderDirectlyQuoted != tc.wantDirectlyQuoted {
				t.Errorf("PlaceholderDirectlyQuoted = %v, want %v", got.PlaceholderDirectlyQuoted, tc.wantDirectlyQuoted)
			}
			if got.ExecutableRaw != tc.wantExe {
				t.Errorf("ExecutableRaw = %q, want %q", got.ExecutableRaw, tc.wantExe)
			}
			if got.UnquotedExeSpaces != tc.wantUnquotedSpaces {
				t.Errorf("UnquotedExeSpaces = %v, want %v", got.UnquotedExeSpaces, tc.wantUnquotedSpaces)
			}
		})
	}
}

func TestExpandEnv(t *testing.T) {
	mockEnv := map[string]string{
		"localappdata":      `C:\Users\dev\AppData\Local`,
		"programfiles":      `C:\Program Files`,
		"programfiles(x86)": `C:\Program Files (x86)`,
	}
	lookup := func(name string) (string, bool) {
		v, ok := mockEnv[strings.ToLower(name)]
		return v, ok
	}

	tests := []struct {
		name        string
		raw         string
		want        string
		wantChanged bool
	}{
		{
			name:        "expands LocalAppData and preserves %1",
			raw:         `"%LocalAppData%\Programs\App\app.exe" "%1"`,
			want:        `"C:\Users\dev\AppData\Local\Programs\App\app.exe" "%1"`,
			wantChanged: true,
		},
		{
			name:        "preserves repeated %1 placeholders",
			raw:         `"%ProgramFiles%\App\app.exe" --first "%1" --second "%1"`,
			want:        `"C:\Program Files\App\app.exe" --first "%1" --second "%1"`,
			wantChanged: true,
		},
		{
			name:        "does not mispair %1 with trailing ProgramFiles(x86)",
			raw:         `wrapper.exe %1 "%ProgramFiles(x86)%\Tool\tool.exe"`,
			want:        `wrapper.exe %1 "C:\Program Files (x86)\Tool\tool.exe"`,
			wantChanged: true,
		},
		{
			name:        "handles LOCALAPPDATA alongside %l",
			raw:         `"%LOCALAPPDATA%\Tool\tool.exe" %l`,
			want:        `"C:\Users\dev\AppData\Local\Tool\tool.exe" %l`,
			wantChanged: true,
		},
		{
			name:        "no env vars",
			raw:         `"C:\App\app.exe" -- "%1"`,
			want:        `"C:\App\app.exe" -- "%1"`,
			wantChanged: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := ExpandEnv(tc.raw, lookup)
			if got != tc.want || changed != tc.wantChanged {
				t.Errorf("ExpandEnv(%q) = (%q, %v), want (%q, %v)",
					tc.raw, got, changed, tc.want, tc.wantChanged)
			}
		})
	}
}

func TestMergeHandlers_HKCUShadowsHKLM(t *testing.T) {
	hklm := []Handler{
		{Scheme: "vscode", Hive: HiveHKLM, Command: `"C:\Program Files\Code\Code.exe" -- "%1"`},
		{Scheme: "mailto", Hive: HiveHKLM, Command: `"C:\Mail\mail.exe" "%1"`},
	}
	hkcu := []Handler{
		{Scheme: "VSCode", Hive: HiveHKCU, Command: `"C:\Users\dev\Code.exe" "%1"`},
		{Scheme: "discord", Hive: HiveHKCU, Command: `"C:\Users\dev\Discord.exe" "%1"`},
	}

	got := MergeHandlers(hkcu, hklm)
	if len(got) != 3 {
		t.Fatalf("len(got) = %d, want 3", len(got))
	}

	if got[0].Scheme != "discord" || got[1].Scheme != "mailto" || got[2].Scheme != "VSCode" {
		t.Fatalf("unexpected order: %q, %q, %q", got[0].Scheme, got[1].Scheme, got[2].Scheme)
	}

	vsc := got[2]
	if vsc.Hive != HiveHKCU || !vsc.ShadowsHKLM {
		t.Errorf("expected HKCU shadow for VSCode, got hive=%s shadows=%v", vsc.Hive, vsc.ShadowsHKLM)
	}
	if vsc.ShadowedHKLMCommand != `"C:\Program Files\Code\Code.exe" -- "%1"` {
		t.Errorf("ShadowedHKLMCommand = %q", vsc.ShadowedHKLMCommand)
	}
}

func TestScanAllLive(t *testing.T) {
	handlers, err := ScanAll()
	if err != nil {
		t.Fatalf("ScanAll() error: %v", err)
	}
	if len(handlers) == 0 {
		t.Fatal("expected at least one registered URI scheme on Windows")
	}
	for _, h := range handlers {
		if h.Scheme == "" {
			t.Error("returned handler with empty scheme")
		}
		if h.Hive != HiveHKCU && h.Hive != HiveHKLM {
			t.Errorf("%s: invalid hive %q", h.Scheme, h.Hive)
		}
	}
}
