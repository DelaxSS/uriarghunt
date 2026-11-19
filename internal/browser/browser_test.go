//go:build windows

package browser

import (
	"strings"
	"testing"

	"uriarghunt/internal/argv"
)

func TestEscapeURI(t *testing.T) {
	raw := `demo://a" --uriarghunt-canary "b`
	want := `demo://a%22%20--uriarghunt-canary%20%22b`

	if got := EscapeURI(raw, ProfileChromeEdge130); got != want {
		t.Errorf("ChromeEdge130: got %q, want %q", got, want)
	}
	if got := EscapeURI(raw, ProfileFirefoxCurrent); got != want {
		t.Errorf("FirefoxCurrent: got %q, want %q", got, want)
	}
	if got := EscapeURI(`demo://--uriarghunt-canary`, ProfileChromeEdge130); !strings.Contains(got, argv.CanaryFlag) {
		t.Errorf("dash flag altered: %q", got)
	}
	if got := EscapeURI(`demo://probe\`, ProfileChromeEdge130); got != `demo://probe\` {
		t.Errorf("trailing backslash altered: %q", got)
	}
}

func TestEvaluate_QuotedWithoutDoubleDash(t *testing.T) {
	probe := argv.ProbeTemplate("demo", `"C:\Demo\demo.exe" "%1"`)
	a := Evaluate(probe)

	if !a.LocalSplit || !a.BrowserBlocked || a.BackslashBreak || !a.DashSurvives {
		t.Fatalf("unexpected assessment: %+v", a)
	}
	if a.Reachability != ReachabilityLocalSplitDashCand {
		t.Errorf("Reachability = %q, want %q", a.Reachability, ReachabilityLocalSplitDashCand)
	}
}

func TestEvaluate_TrailingBackslashBeforeDoubleDash(t *testing.T) {
	cases := []struct {
		name     string
		template string
		wantSign int
	}{
		{
			name:     "merges following flags",
			template: `"C:\App\app.exe" "%1" --mode safe`,
			wantSign: -1,
		},
		{
			name:     "splits following quoted argument",
			template: `"C:\App\app.exe" "%1" "second arg here"`,
			wantSign: +1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := Evaluate(argv.ProbeTemplate("demo", tc.template))

			if !a.BackslashBreak || a.BackslashAfterDD {
				t.Fatalf("expected pre-'--' BackslashBreak: %+v", a)
			}
			if a.Reachability != ReachabilityBrowserSplit {
				t.Errorf("Reachability = %q, want %q", a.Reachability, ReachabilityBrowserSplit)
			}
			delta := a.ChromeEdge130.BackslashDelta
			if (tc.wantSign < 0 && delta >= 0) || (tc.wantSign > 0 && delta <= 0) {
				t.Errorf("delta = %d (want sign %d), argv=%#v", delta, tc.wantSign, a.ChromeEdge130.BackslashArgv)
			}
		})
	}
}

func TestEvaluate_TrailingBackslashAfterDoubleDash(t *testing.T) {
	a := Evaluate(argv.ProbeTemplate("demo", `"C:\App\app.exe" -- "%1" "--foo"`))

	if !a.BackslashBreak || !a.BackslashAfterDD {
		t.Fatalf("expected post-'--' BackslashBreak: %+v", a)
	}
	if a.Reachability != ReachabilityBrowserPosSplit {
		t.Errorf("Reachability = %q, want %q", a.Reachability, ReachabilityBrowserPosSplit)
	}
}

func TestEvaluate_MitigatedWithDoubleDash(t *testing.T) {
	a := Evaluate(argv.ProbeTemplate("vscode", `"C:\Code\Code.exe" --open-url -- "%1"`))

	if a.LocalSplit || a.DashSurvives || a.Reachability != ReachabilityMitigated {
		t.Errorf("unexpected mitigated assessment: %+v", a)
	}
}

func TestEvaluate_AttachedFlagIsLocalOnly(t *testing.T) {
	a := Evaluate(argv.ProbeTemplate("flagapp", `"C:\App\app.exe" --url="%1"`))

	if !a.LocalSplit || a.DashSurvives || a.Reachability != ReachabilityLocalOnly {
		t.Errorf("unexpected attached-flag assessment: %+v", a)
	}
}

func TestEvaluate_UnquotedPlaceholderBlockedByBrowsers(t *testing.T) {
	a := Evaluate(argv.ProbeTemplate("epic", `"C:\Epic\Launcher.exe" %1`))

	if !a.LocalSplit || a.ChromeEdge130.SplitSurvives || a.FirefoxCurrent.SplitSurvives {
		t.Errorf("expected browser percent-encoding to block space split: %+v", a)
	}
	if a.Reachability != ReachabilityLocalSplitDashCand {
		t.Errorf("Reachability = %q, want %q", a.Reachability, ReachabilityLocalSplitDashCand)
	}
}
