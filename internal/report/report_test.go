//go:build windows

package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"uriarghunt/internal/argv"
	"uriarghunt/internal/browser"
	"uriarghunt/internal/fingerprint"
	"uriarghunt/internal/fuses"
	"uriarghunt/internal/registry"
)

func TestClassifyBuiltin(t *testing.T) {
	cases := []struct {
		scheme      string
		wantBuiltin bool
	}{
		{"http", true},
		{"HTTPS", true},
		{"mailto", true},
		{"ms-settings", true},
		{"ms-msdt", true},
		{"telnet", true},
		{"rlogin", true},
		{"tn3270", true},
		{"odopen", true},
		{"google-chrome", true},
		{"Explorer.AssocProtocol.search-ms", true},
		{"vscode", false},
		{"spotify", false},
		{"openvpn-connect", false},
		{"jnlp", false},
		{"com.epicgames.launcher", false},
	}

	for _, tc := range cases {
		if got, _ := ClassifyBuiltin(tc.scheme); got != tc.wantBuiltin {
			t.Errorf("ClassifyBuiltin(%q) = %v, want %v", tc.scheme, got, tc.wantBuiltin)
		}
	}
}

func TestEvaluateFinding_Tiers(t *testing.T) {
	eval := func(scheme, cmd string, fp fingerprint.Info) Finding {
		h := registry.Handler{
			Scheme:   scheme,
			Hive:     registry.HiveHKCU,
			Command:  cmd,
			Analysis: registry.AnalyzeTemplate(cmd),
		}
		p := argv.ProbeTemplate(scheme, cmd)
		br := browser.Evaluate(p, browser.TargetContext{
			IsCmdShell:                fp.IsCmdShell(),
			PlaceholderDirectlyQuoted: h.Analysis.PlaceholderDirectlyQuoted,
		})
		return EvaluateFinding(h, p, fp, br)
	}

	if f := eval("deadapp", `"C:\Missing\app.exe" "%1"`, fingerprint.Info{
		Dangling: true,
		Runtime:  fingerprint.RuntimeDangling,
	}); f.Tier != TierInfo {
		t.Errorf("dangling binary: got %v, want TierInfo", f.Tier)
	}

	if f := eval("vscode", `"C:\Code\Code.exe" --open-url -- "%1"`, fingerprint.Info{
		Exists:          true,
		Runtime:         fingerprint.RuntimeElectron,
		HighRiskRuntime: true,
	}); f.Tier != TierInfo {
		t.Errorf("'--' guarded electron: got %v, want TierInfo", f.Tier)
	}

	if f := eval("docker-desktop", `"C:\Docker\Docker Desktop.exe" "%1"`, fingerprint.Info{
		Exists:  true,
		Runtime: fingerprint.RuntimeNative,
	}); f.Tier != Tier1 {
		t.Errorf("native split: got %v, want Tier1", f.Tier)
	}

	// Plain "%1" Electron/CEF without "--" is blocked by Chromium %22/%20/%5C encoding,
	// so it must land in Tier 2 (with missing-- noted), not inflated to Tier 3.
	fOVPN := eval("openvpn-connect", `"C:\OVPN\OpenVPNConnect.exe" "%1"`, fingerprint.Info{
		Exists:          true,
		Runtime:         fingerprint.RuntimeElectron,
		HighRiskRuntime: true,
		Fuses: &fuses.Info{
			Found:                true,
			RunAsNode:            fuses.StateDisabled,
			EnableNodeCliInspect: fuses.StateDisabled,
			InspectHardened:      true,
		},
	})
	if fOVPN.Tier != Tier2 {
		t.Errorf("browser-blocked Electron missing '--': got %v, want Tier2", fOVPN.Tier)
	}
	joinedReasons := strings.Join(fOVPN.Reasons, "; ")
	if !strings.Contains(joinedReasons, "missing--") || !strings.Contains(joinedReasons, "fuses:hardened") {
		t.Errorf("expected missing-- and fuses:hardened in reasons: %q", joinedReasons)
	}

	// Local ShellExecute trailing backslash before '--' on Electron is Tier 2 (blocked in Chromium %5C).
	if f := eval("trailapp", `"C:\Trail\app.exe" "%1" --extra`, fingerprint.Info{
		Exists:          true,
		Runtime:         fingerprint.RuntimeElectron,
		HighRiskRuntime: true,
	}); f.Tier != Tier2 || f.Browser.Reachability != browser.ReachabilityLocalBackslash {
		t.Errorf("pre-'--' local backslash break: got tier=%v reach=%v", f.Tier, f.Browser.Reachability)
	}

	// Local trailing backslash after '--' is positional corruption only -> Tier 1.
	if f := eval("postdd", `"C:\Post\app.exe" -- "%1" "--foo"`, fingerprint.Info{
		Exists:          true,
		Runtime:         fingerprint.RuntimeElectron,
		HighRiskRuntime: true,
	}); f.Tier != Tier1 || f.Browser.Reachability != browser.ReachabilityLocalBackslashDD {
		t.Errorf("post-'--' local backslash break: got tier=%v reach=%v", f.Tier, f.Browser.Reachability)
	}

	// Unquoted .bat / cmd.exe handler receives raw '&' through Chromium -> genuine Tier 3.
	if f := eval("badbatch", `C:\Tools\handler.bat %1`, fingerprint.Info{
		Exists:          true,
		ResolvedPath:    `C:\Tools\handler.bat`,
		Runtime:         fingerprint.RuntimeShell,
		HighRiskRuntime: true,
	}); f.Tier != Tier3 || f.Browser.Reachability != browser.ReachabilityBrowserCmdAmp {
		t.Errorf("unquoted .bat handler: got tier=%v reach=%v, want Tier3 + browser-cmd-amp",
			f.Tier, f.Browser.Reachability)
	}

	// Outer-quoted `cmd.exe /c "start x.exe %1"` leaves %1 unquoted after /c strips outer quotes -> Tier 3.
	if f := eval("outercmd", `cmd.exe /c "start x.exe %1"`, fingerprint.Info{
		Exists:          true,
		ResolvedPath:    `C:\Windows\System32\cmd.exe`,
		Runtime:         fingerprint.RuntimeShell,
		HighRiskRuntime: true,
	}); f.Tier != Tier3 || f.Browser.Reachability != browser.ReachabilityBrowserCmdAmp {
		t.Errorf("outer-quoted cmd /c handler: got tier=%v reach=%v, want Tier3 + browser-cmd-amp",
			f.Tier, f.Browser.Reachability)
	}

	// Existing binary with unquoted spaces in exe path must be at least Tier 1.
	if f := eval("unqstatic", `C:\Program Files\My App\app.exe --launch`, fingerprint.Info{
		Exists:  true,
		Runtime: fingerprint.RuntimeNative,
	}); f.Tier != Tier1 {
		t.Errorf("unquoted exe with spaces (no placeholder): got %v, want Tier1", f.Tier)
	}

	if f := eval("unqdd", `C:\Program Files\My App\app.exe -- "%1"`, fingerprint.Info{
		Exists:          true,
		Runtime:         fingerprint.RuntimeElectron,
		HighRiskRuntime: true,
	}); f.Tier != Tier1 {
		t.Errorf("unquoted exe with spaces (with '--'): got %v, want Tier1", f.Tier)
	}
}

func TestBuildReport_FilterSortAndJSON(t *testing.T) {
	findings := []Finding{
		{Scheme: "http", Tier: Tier2, TierLabel: "TIER 2", Builtin: true, Handler: registry.Handler{Command: `"msedge.exe" "%1"`, Hive: registry.HiveHKLM}},
		{Scheme: "z-native", Tier: Tier1, TierLabel: "TIER 1", Builtin: false, Handler: registry.Handler{Command: `"z.exe" "%1"`, Hive: registry.HiveHKCU}},
		{Scheme: "a-batch", Tier: Tier3, TierLabel: "TIER 3", Builtin: false, Handler: registry.Handler{Command: `C:\t\run.bat %1`, Hive: registry.HiveHKCU}},
		{Scheme: "b-cef", Tier: Tier2, TierLabel: "TIER 2", Builtin: false, Handler: registry.Handler{Command: `"b.exe" --uri="%1"`, Hive: registry.HiveHKCU}},
	}

	rep := BuildReport(findings, FilterOptions{MinTier: Tier2, IncludeBuiltin: false})
	if len(rep.Findings) != 2 {
		t.Fatalf("len(Findings) = %d, want 2", len(rep.Findings))
	}
	if rep.Findings[0].Scheme != "a-batch" || rep.Findings[1].Scheme != "b-cef" {
		t.Errorf("order = [%s, %s], want [a-batch, b-cef]", rep.Findings[0].Scheme, rep.Findings[1].Scheme)
	}
	if rep.Summary.HiddenBuiltinCount != 1 {
		t.Errorf("HiddenBuiltinCount = %d, want 1", rep.Summary.HiddenBuiltinCount)
	}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, rep); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}
	var decoded ScanReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}
	if decoded.Version != Version || len(decoded.Findings) != 2 {
		t.Errorf("decoded mismatch: version=%q len=%d", decoded.Version, len(decoded.Findings))
	}
}

func TestFormatFlagLabel(t *testing.T) {
	tests := []struct {
		name string
		rep  argv.ProbeReport
		br   browser.Assessment
		want string
	}{
		{
			name: "browser cmd ampersand",
			br:   browser.Assessment{ShellAmpersandSurvive: true},
			want: "CMD&!",
		},
		{
			name: "local backslash break before --",
			br:   browser.Assessment{Local: browser.LocalResult{BackslashBreak: true}},
			want: "BSLASH",
		},
		{
			name: "local backslash break after --",
			br:   browser.Assessment{Local: browser.LocalResult{BackslashBreak: true, BackslashAfterDD: true}},
			want: "bslash--",
		},
		{
			name: "unmitigated flag",
			rep:  argv.ProbeReport{AnySplit: true, AnyUnmitigatedFlag: true},
			want: "YES",
		},
		{
			name: "flag after --",
			rep:  argv.ProbeReport{AnySplit: true, AnyMitigatedFlag: true},
			want: "after--",
		},
		{
			name: "split without standalone flag",
			rep:  argv.ProbeReport{AnySplit: true},
			want: "split-only",
		},
		{
			name: "no split",
			want: "no",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := FormatFlagLabel(tc.rep, tc.br); got != tc.want {
				t.Errorf("FormatFlagLabel() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWriteInspect_ShowsFusesAndLocalBackslash(t *testing.T) {
	f := Finding{
		Scheme:    "demo",
		Tier:      Tier2,
		TierLabel: "TIER 2",
		Probe:     argv.ProbeReport{HasDoubleDash: false},
		Fingerprint: fingerprint.Info{
			Runtime: fingerprint.RuntimeElectron,
			Fuses: &fuses.Info{
				Found:                true,
				RunAsNode:            fuses.StateDisabled,
				EnableNodeCliInspect: fuses.StateDisabled,
				EnableNodeOptionsEnv: fuses.StateEnabled,
				OnlyLoadAppFromAsar:  fuses.StateDisabled,
				InspectHardened:      true,
				RawWire:              "00100001",
			},
		},
		Browser: browser.Assessment{
			Reachability: browser.ReachabilityLocalBackslash,
			Local: browser.LocalResult{
				BackslashBreak: true,
				BackslashURI:   `demo://host/probe\`,
				BackslashDelta: -1,
				BackslashArgv:  []string{"app.exe", `demo://host/probe" --tail`},
			},
		},
	}

	var buf bytes.Buffer
	WriteInspect(&buf, f)
	out := buf.String()

	for _, want := range []string{
		"[Electron Fuses v1]",
		`wire="00100001", hardened=true`,
		"[local ShellExecute | before --]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("WriteInspect missing %q:\n%s", want, out)
		}
	}
}
