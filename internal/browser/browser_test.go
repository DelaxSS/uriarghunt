//go:build windows

package browser

import (
	"testing"

	"uriarghunt/internal/argv"
	"uriarghunt/internal/registry"
)

func TestEscapeURI_EmpiricalBrowserRules(t *testing.T) {
	raw := `demo://host/a" \<>` + "`" + `|^a%Zb?x=1&y=2`

	wantChromium := `demo://host/a%22%20%5C%3C%3E%60%7C%5Ea%25Zb?x=1&y=2`
	if got := EscapeURI(raw, ProfileChromium); got != wantChromium {
		t.Errorf("EscapeURI(Chromium):\ngot:  %q\nwant: %q", got, wantChromium)
	}

	// Firefox 160.0.1 encodes space/"/\/</>/`/|/^ identically, but leaves % raw.
	wantFirefox := `demo://host/a%22%20%5C%3C%3E%60%7C%5Ea%Zb?x=1&y=2`
	if got := EscapeURI(raw, ProfileFirefox); got != wantFirefox {
		t.Errorf("EscapeURI(Firefox):\ngot:  %q\nwant: %q", got, wantFirefox)
	}
}

func TestEvaluate_StandardQuotedIsLocalOnly(t *testing.T) {
	probe := argv.ProbeTemplate("demo", `"C:\Demo\demo.exe" "%1"`)
	a := Evaluate(probe, TargetContext{PlaceholderDirectlyQuoted: true})

	if !a.Local.RawSplitWorks || !a.BrowserBlocked || a.BrowserSplitSurvives || a.Local.BackslashBreak {
		t.Fatalf("unexpected assessment: %+v", a)
	}
	if a.Firefox.Profile != ProfileFirefox || !a.Firefox.Verified {
		t.Errorf("expected verified firefox-160 profile, got %+v", a.Firefox)
	}
	if a.Reachability != ReachabilityLocalOnly {
		t.Errorf("Reachability = %q, want %q", a.Reachability, ReachabilityLocalOnly)
	}
}

func TestEvaluate_TrailingBackslashIsLocalNotBrowserSplit(t *testing.T) {
	// Both Chromium 157+ and Firefox 160.0.1 encode \ -> %5C, so trailing backslash breaks
	// local ShellExecute but does not survive browser escaping.
	probe := argv.ProbeTemplate("demo", `"C:\App\app.exe" "%1" --mode safe`)
	a := Evaluate(probe, TargetContext{PlaceholderDirectlyQuoted: true})

	if a.Chromium.BackslashBreak || a.Firefox.BackslashBreak || a.BrowserSplitSurvives {
		t.Fatalf("Chromium and Firefox %%5C encoding should block backslash break: %+v", a)
	}
	if !a.Local.BackslashBreak || a.Local.BackslashAfterDD {
		t.Fatalf("expected pre-'--' local ShellExecute backslash break: %+v", a.Local)
	}
	if a.Reachability != ReachabilityLocalBackslash {
		t.Errorf("Reachability = %q, want %q", a.Reachability, ReachabilityLocalBackslash)
	}
}

func TestEvaluate_TrailingBackslashAfterDoubleDash(t *testing.T) {
	probe := argv.ProbeTemplate("demo", `"C:\App\app.exe" -- "%1" "--foo"`)
	a := Evaluate(probe, TargetContext{PlaceholderDirectlyQuoted: true})

	if !a.Local.BackslashBreak || !a.Local.BackslashAfterDD {
		t.Fatalf("expected post-'--' local backslash break: %+v", a.Local)
	}
	if a.Reachability != ReachabilityLocalBackslashDD {
		t.Errorf("Reachability = %q, want %q", a.Reachability, ReachabilityLocalBackslashDD)
	}
}

func TestEvaluate_UnquotedCmdShellAmpersandSurvivesBrowsers(t *testing.T) {
	cases := []struct {
		name     string
		template string
	}{
		{
			name:     "bare unquoted .bat",
			template: `C:\Tools\handler.bat %1`,
		},
		{
			name:     "cmd.exe /c outer-quoted start command",
			template: `cmd.exe /c "start x.exe %1"`,
		},
		{
			name:     "cmd /c outer-quoted batch command",
			template: `cmd /c "C:\a.bat %1"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			analysis := registry.AnalyzeTemplate(tc.template)
			probe := argv.ProbeTemplate("batchapp", tc.template)
			a := Evaluate(probe, TargetContext{
				IsCmdShell:                true,
				PlaceholderDirectlyQuoted: analysis.PlaceholderDirectlyQuoted,
			})

			if !a.ShellAmpersandSurvive || !a.Chromium.AmpersandRaw {
				t.Fatalf("expected raw '&' to survive Chromium on %q: %+v", tc.template, a)
			}
			if a.Reachability != ReachabilityBrowserCmdAmp {
				t.Errorf("Reachability = %q, want %q", a.Reachability, ReachabilityBrowserCmdAmp)
			}
		})
	}
}

func TestEvaluate_DirectlyQuotedCmdShellBlocksAmpersandSeparator(t *testing.T) {
	analysis := registry.AnalyzeTemplate(`C:\Tools\handler.bat "%1"`)
	probe := argv.ProbeTemplate("batchapp", `C:\Tools\handler.bat "%1"`)
	a := Evaluate(probe, TargetContext{
		IsCmdShell:                true,
		PlaceholderDirectlyQuoted: analysis.PlaceholderDirectlyQuoted,
	})

	if a.ShellAmpersandSurvive {
		t.Fatalf("directly quoted \"%%1\" should not flag unquoted '&' separator: %+v", a)
	}
	if a.Reachability != ReachabilityLocalOnly {
		t.Errorf("Reachability = %q, want %q", a.Reachability, ReachabilityLocalOnly)
	}
}

func TestEvaluate_MitigatedWithDoubleDash(t *testing.T) {
	probe := argv.ProbeTemplate("vscode", `"C:\Code\Code.exe" --open-url -- "%1"`)
	a := Evaluate(probe, TargetContext{PlaceholderDirectlyQuoted: true})

	if a.Local.RawSplitWorks || a.Reachability != ReachabilityMitigated {
		t.Errorf("unexpected mitigated assessment: %+v", a)
	}
}
