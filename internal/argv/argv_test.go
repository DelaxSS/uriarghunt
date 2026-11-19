//go:build windows

package argv

import (
	"reflect"
	"testing"
)

func TestSplitCommandLine_Win32Rules(t *testing.T) {
	tests := []struct {
		name    string
		cmdLine string
		want    []string
	}{
		{
			name:    "empty",
			cmdLine: "",
			want:    nil,
		},
		{
			name:    "whitespace only",
			cmdLine: "   \t  ",
			want:    nil,
		},
		{
			name:    "quoted path with spaces",
			cmdLine: `"C:\Program Files\App\app.exe" "vscode://open"`,
			want:    []string{`C:\Program Files\App\app.exe`, `vscode://open`},
		},
		{
			name:    "escaped quote",
			cmdLine: `app.exe "a\"b" c`,
			want:    []string{`app.exe`, `a"b`, `c`},
		},
		{
			name:    "double backslash before closing quote",
			cmdLine: `app.exe "C:\dir\\" next`,
			want:    []string{`app.exe`, `C:\dir\`, `next`},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SplitCommandLine(tc.cmdLine)
			if err != nil {
				t.Fatalf("SplitCommandLine error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("SplitCommandLine(%q) = %#v, want %#v", tc.cmdLine, got, tc.want)
			}
		})
	}
}

func TestSplitCommandLine_NulByteRejected(t *testing.T) {
	if _, err := SplitCommandLine("app.exe \x00 bad"); err == nil {
		t.Fatal("expected error on NUL byte")
	}
}

func TestProbeTemplate_QuotedWithoutDoubleDash(t *testing.T) {
	rep := ProbeTemplate("demo", `"C:\Program Files\Demo\demo.exe" "%1"`)

	if !rep.HasPlaceholder || rep.Placeholder != "%1" {
		t.Fatalf("placeholder = %q (ok=%v), want %%1", rep.Placeholder, rep.HasPlaceholder)
	}
	if rep.BaselineArgc != 2 {
		t.Fatalf("BaselineArgc = %d (%#v), want 2", rep.BaselineArgc, rep.BaselineArgv)
	}
	if rep.HasDoubleDash {
		t.Error("HasDoubleDash = true, want false")
	}
	if !rep.AnySplit || !rep.AnyUnmitigatedFlag || rep.AnyMitigatedFlag {
		t.Errorf("unexpected flags: %+v", rep)
	}
	if !rep.MissingDoubleDash {
		t.Error("MissingDoubleDash = false, want true")
	}

	scA := rep.Scenarios[0]
	if !scA.SplitDetected || scA.ArgcDelta != 2 || !scA.StandaloneFlag || !scA.BeforeDoubleDash {
		t.Errorf("quote_split mismatch: %+v", scA)
	}
	scB := rep.Scenarios[1]
	if scB.SplitDetected || scB.StandaloneFlag {
		t.Errorf("space_split should not split quoted placeholder: %+v", scB)
	}
	scC := rep.Scenarios[2]
	if !scC.MissingDoubleDash || scC.AttachedToFlag {
		t.Errorf("dash_flag mismatch: %+v", scC)
	}
}

func TestProbeTemplate_UnquotedPlaceholder(t *testing.T) {
	rep := ProbeTemplate("demo", `"C:\Demo\demo.exe" %1`)

	if !rep.AnySplit || !rep.AnyUnmitigatedFlag {
		t.Fatalf("expected unquoted space split: %+v", rep)
	}
	// On unquoted %1, quote_split's two quotes pair up and merge into one argument.
	if rep.Scenarios[0].SplitDetected {
		t.Errorf("quote_split unexpectedly split unquoted %%1: %#v", rep.Scenarios[0].Argv)
	}
	scB := rep.Scenarios[1]
	if !scB.SplitDetected || scB.ArgcDelta != 1 || !scB.StandaloneFlag || !scB.BeforeDoubleDash {
		t.Errorf("space_split mismatch: %+v", scB)
	}
}

func TestProbeTemplate_QuotedWithDoubleDash(t *testing.T) {
	rep := ProbeTemplate("safe", `"C:\Safe\safe.exe" -- "%1"`)

	if !rep.HasDoubleDash || !rep.AnySplit || rep.AnyUnmitigatedFlag || !rep.AnyMitigatedFlag {
		t.Errorf("unexpected report: %+v", rep)
	}
	if rep.MissingDoubleDash || rep.Scenarios[2].MissingDoubleDash {
		t.Error("expected MissingDoubleDash=false when '--' is present")
	}
	if !rep.Scenarios[0].StandaloneFlag || rep.Scenarios[0].BeforeDoubleDash {
		t.Errorf("expected flag after '--': %+v", rep.Scenarios[0])
	}
}

func TestProbeTemplate_SplitOnlyWithoutStandaloneFlag(t *testing.T) {
	rep := ProbeTemplate("edge", `"C:\Edge\edge.exe" %1=foo`)

	if !rep.AnySplit {
		t.Fatal("expected space_split to increase argc")
	}
	if rep.AnyUnmitigatedFlag || rep.AnyMitigatedFlag {
		t.Errorf("expected no standalone canary flag, got unmit=%v mit=%v",
			rep.AnyUnmitigatedFlag, rep.AnyMitigatedFlag)
	}
}

func TestProbeTemplate_AttachedToFlag(t *testing.T) {
	rep := ProbeTemplate("flagapp", `"C:\App\app.exe" --url="%1"`)

	if !rep.AttachedToFlag {
		t.Error("AttachedToFlag = false, want true")
	}
	if !rep.AnySplit || !rep.AnyUnmitigatedFlag {
		t.Errorf("expected quote_split breakout from --url=\"%%1\": %+v", rep)
	}
	scC := rep.Scenarios[2]
	if !scC.AttachedToFlag || scC.MissingDoubleDash {
		t.Errorf("dash_flag mismatch: %+v", scC)
	}
}

func TestProbeTemplate_NoPlaceholder(t *testing.T) {
	rep := ProbeTemplate("static", `"C:\Static\app.exe" --launch`)
	if rep.HasPlaceholder || rep.BaselineArgc != 2 || rep.AnySplit || len(rep.Scenarios) != 0 {
		t.Errorf("unexpected report for static command: %+v", rep)
	}
}

func TestProbeTemplate_PercentLPlaceholder(t *testing.T) {
	rep := ProbeTemplate("legacy", `C:\Windows\System32\rundll32.exe url.dll,FileProtocolHandler %l`)
	if rep.Placeholder != "%l" || !rep.AnySplit || !rep.AnyUnmitigatedFlag {
		t.Errorf("expected %%l unquoted split: %+v", rep)
	}
}
