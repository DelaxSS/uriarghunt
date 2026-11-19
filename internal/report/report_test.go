//go:build windows

package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"uriarghunt/internal/argv"
	"uriarghunt/internal/browser"
	"uriarghunt/internal/fingerprint"
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
		br := browser.Evaluate(p)
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

	if f := eval("spotify", `"C:\Spotify\Spotify.exe" --uri="%1"`, fingerprint.Info{
		Exists:          true,
		Runtime:         fingerprint.RuntimeCEF,
		HighRiskRuntime: true,
	}); f.Tier != Tier2 {
		t.Errorf("CEF local-only: got %v, want Tier2", f.Tier)
	}

	if f := eval("openvpn-connect", `"C:\OVPN\OpenVPNConnect.exe" "%1"`, fingerprint.Info{
		Exists:          true,
		Runtime:         fingerprint.RuntimeElectron,
		HighRiskRuntime: true,
	}); f.Tier != Tier3 {
		t.Errorf("Electron missing '--': got %v, want Tier3", f.Tier)
	}

	if f := eval("trailapp", `"C:\Trail\app.exe" "%1" --extra`, fingerprint.Info{
		Exists:          true,
		Runtime:         fingerprint.RuntimeElectron,
		HighRiskRuntime: true,
	}); f.Tier != Tier3 || f.Browser.Reachability != browser.ReachabilityBrowserSplit {
		t.Errorf("pre-'--' backslash break: got tier=%v reach=%v", f.Tier, f.Browser.Reachability)
	}

	if f := eval("postdd", `"C:\Post\app.exe" -- "%1" "--foo"`, fingerprint.Info{
		Exists:          true,
		Runtime:         fingerprint.RuntimeElectron,
		HighRiskRuntime: true,
	}); f.Tier != Tier1 || f.Browser.Reachability != browser.ReachabilityBrowserPosSplit {
		t.Errorf("post-'--' backslash break: got tier=%v reach=%v", f.Tier, f.Browser.Reachability)
	}

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
		{Scheme: "http", Tier: Tier3, TierLabel: "TIER 3", Builtin: true, Handler: registry.Handler{Command: `"msedge.exe" "%1"`, Hive: registry.HiveHKLM}},
		{Scheme: "z-native", Tier: Tier1, TierLabel: "TIER 1", Builtin: false, Handler: registry.Handler{Command: `"z.exe" "%1"`, Hive: registry.HiveHKCU}},
		{Scheme: "a-electron", Tier: Tier3, TierLabel: "TIER 3", Builtin: false, Handler: registry.Handler{Command: `"a.exe" "%1"`, Hive: registry.HiveHKCU}},
		{Scheme: "b-cef", Tier: Tier2, TierLabel: "TIER 2", Builtin: false, Handler: registry.Handler{Command: `"b.exe" --uri="%1"`, Hive: registry.HiveHKCU}},
	}

	rep := BuildReport(findings, FilterOptions{MinTier: Tier2, IncludeBuiltin: false})
	if len(rep.Findings) != 2 {
		t.Fatalf("len(Findings) = %d, want 2", len(rep.Findings))
	}
	if rep.Findings[0].Scheme != "a-electron" || rep.Findings[1].Scheme != "b-cef" {
		t.Errorf("order = [%s, %s], want [a-electron, b-cef]", rep.Findings[0].Scheme, rep.Findings[1].Scheme)
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
			name: "backslash break before --",
			br:   browser.Assessment{BackslashBreak: true},
			want: "BSLASH!",
		},
		{
			name: "backslash break after --",
			br:   browser.Assessment{BackslashBreak: true, BackslashAfterDD: true},
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

func TestWriteInspect_DynamicBackslashProfile(t *testing.T) {
	f := Finding{
		Scheme:    "ffonly",
		Tier:      Tier3,
		TierLabel: "TIER 3",
		Browser: browser.Assessment{
			Reachability:   browser.ReachabilityBrowserSplit,
			BackslashBreak: true,
			ChromeEdge130: browser.ChannelResult{
				Profile:        browser.ProfileChromeEdge130,
				BackslashBreak: false,
			},
			FirefoxCurrent: browser.ChannelResult{
				Profile:        browser.ProfileFirefoxCurrent,
				BackslashBreak: true,
				BackslashURI:   `ffonly://probe\`,
				BackslashDelta: -1,
				BackslashArgv:  []string{"app.exe", `ffonly://probe" --tail`},
			},
		},
	}

	var buf bytes.Buffer
	WriteInspect(&buf, f)

	if !bytes.Contains(buf.Bytes(), []byte("[firefox-current | before --]")) {
		t.Errorf("missing dynamic Firefox profile line:\n%s", buf.String())
	}
	if bytes.Contains(buf.Bytes(), []byte("[chrome-edge-130+")) {
		t.Errorf("unexpected Chrome/Edge profile line:\n%s", buf.String())
	}
}
