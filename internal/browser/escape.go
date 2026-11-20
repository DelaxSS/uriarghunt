package browser

import (
	"fmt"
	"strings"

	"uriarghunt/internal/argv"
)

// Profile identifies a browser non-special URI escaping model.
type Profile string

const (
	// ProfileChromium reflects live Windows 11 measurements on Chrome 157,
	// Edge 157, and Opera GX 139.
	ProfileChromium Profile = "chromium-157"

	// ProfileFirefox models standard non-special escaping (not empirically verified on this host).
	ProfileFirefox Profile = "firefox-modeled"
)

// Reachability classifies how a handler's command template behaves across browsers
// and local Windows ShellExecute triggers.
type Reachability string

const (
	ReachabilityNone             Reachability = "none"
	ReachabilityMitigated        Reachability = "mitigated"
	ReachabilityLocalOnly        Reachability = "local-only"
	ReachabilityLocalBackslash   Reachability = "local-backslash"
	ReachabilityLocalBackslashDD Reachability = "local-backslash--"
	ReachabilityBrowserSplit     Reachability = "browser-split"
	ReachabilityBrowserCmdAmp    Reachability = "browser-cmd-amp"
)

// TargetContext supplies handler properties needed for browser-to-shell checks.
// PlaceholderDirectlyQuoted must be true only when the placeholder itself is directly
// wrapped in quotes (`"%1"`), not merely enclosed inside an outer `cmd /c "..."` string.
type TargetContext struct {
	IsCmdShell                bool
	PlaceholderDirectlyQuoted bool
}

// ChannelResult records CommandLineToArgvW outcomes after applying one browser profile.
type ChannelResult struct {
	Profile          Profile `json:"profile"`
	Verified         bool    `json:"verified"`
	QuoteURI         string  `json:"quote_uri,omitempty"`
	SpaceURI         string  `json:"space_uri,omitempty"`
	BackslashURI     string  `json:"backslash_uri,omitempty"`
	AmpersandURI     string  `json:"ampersand_uri,omitempty"`
	SplitSurvives    bool    `json:"split_survives"`
	UnmitigatedSplit bool    `json:"unmitigated_split"`
	BackslashBreak   bool    `json:"backslash_break"`
	AmpersandRaw     bool    `json:"ampersand_raw"`
}

// LocalResult records empirically verified raw Windows ShellExecute behavior
// (no percent-encoding applied before CommandLineToArgvW).
type LocalResult struct {
	RawSplitWorks    bool     `json:"raw_split_works"`
	BackslashURI     string   `json:"backslash_uri,omitempty"`
	BackslashArgv    []string `json:"backslash_argv,omitempty"`
	BackslashDelta   int      `json:"backslash_delta,omitempty"`
	BackslashBreak   bool     `json:"backslash_break"`
	BackslashAfterDD bool     `json:"backslash_after_dd,omitempty"`
}

// Assessment combines empirical Chromium escaping, modeled Firefox escaping,
// and local Windows ShellExecute behavior.
type Assessment struct {
	Reachability          Reachability  `json:"reachability"`
	Chromium              ChannelResult `json:"chromium"`
	Firefox               ChannelResult `json:"firefox"`
	Local                 LocalResult   `json:"local"`
	BrowserSplitSurvives  bool          `json:"browser_split_survives"`
	BrowserBlocked        bool          `json:"browser_blocked"`
	ShellAmpersandSurvive bool          `json:"shell_ampersand_survives"`
	Summary               string        `json:"summary"`
}

// EscapeURI percent-encodes characters in non-special schemes per Chrome 157 / Edge 157 / Opera GX 139
// measurements: space, ", \, <, >, `, |, ^, and % are encoded; & passes raw.
// Note: Chromium browsers reject links containing ", space, or \ in the authority/host component.
func EscapeURI(rawURI string, _ Profile) string {
	colon := strings.IndexByte(rawURI, ':')
	if colon == -1 {
		return escapeRemainder(rawURI)
	}
	return rawURI[:colon+1] + escapeRemainder(rawURI[colon+1:])
}

func escapeRemainder(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 16)

	for i := 0; i < len(s); i++ {
		switch ch := s[i]; ch {
		case '%':
			b.WriteString("%25")
		case ' ':
			b.WriteString("%20")
		case '"':
			b.WriteString("%22")
		case '\\':
			b.WriteString("%5C")
		case '<':
			b.WriteString("%3C")
		case '>':
			b.WriteString("%3E")
		case '`':
			b.WriteString("%60")
		case '|':
			b.WriteString("%7C")
		case '^':
			b.WriteString("%5E")
		default:
			b.WriteByte(ch)
		}
	}
	return b.String()
}

// Evaluate tests probe's template against browser-escaped URIs and raw local ShellExecute,
// using real Win32 CommandLineToArgvW for split and trailing-backslash verification.
func Evaluate(probe argv.ProbeReport, ctx TargetContext) Assessment {
	if !probe.HasPlaceholder {
		return Assessment{
			Reachability: ReachabilityNone,
			Summary:      "no URI placeholder in command template",
		}
	}

	ch := evaluateChannel(probe, ProfileChromium, true)
	ff := evaluateChannel(probe, ProfileFirefox, false)
	loc := evaluateLocal(probe)

	browserSplit := ch.SplitSurvives || ff.SplitSurvives
	ampSurvives := ctx.IsCmdShell && !ctx.PlaceholderDirectlyQuoted && (ch.AmpersandRaw || ff.AmpersandRaw)

	a := Assessment{
		Chromium:              ch,
		Firefox:               ff,
		Local:                 loc,
		BrowserSplitSurvives:  browserSplit,
		BrowserBlocked:        (probe.AnySplit || loc.BackslashBreak) && !browserSplit && !ampSurvives,
		ShellAmpersandSurvive: ampSurvives,
	}

	switch {
	case ampSurvives:
		a.Reachability = ReachabilityBrowserCmdAmp
		a.Summary = "unquoted cmd.exe/.bat/.cmd handler receives raw '&' through Chromium browsers (command separator)"
	case browserSplit:
		a.Reachability = ReachabilityBrowserSplit
		a.Summary = "CommandLineToArgvW split survives browser percent-encoding"
	case loc.BackslashBreak && !loc.BackslashAfterDD:
		a.Reachability = ReachabilityLocalBackslash
		a.Summary = "local ShellExecute trailing '\\' breaks '\"%1\"' closing quote before '--'; blocked in Chromium (%5C)"
	case loc.BackslashBreak && loc.BackslashAfterDD:
		a.Reachability = ReachabilityLocalBackslashDD
		a.Summary = "local ShellExecute trailing '\\' corrupts positional args after '--'; blocked in Chromium (%5C)"
	case probe.AnyMitigatedFlag && !probe.AnyUnmitigatedFlag:
		a.Reachability = ReachabilityMitigated
		a.Summary = "browser encoding blocks split; local raw split lands after '--'"
	case loc.RawSplitWorks:
		a.Reachability = ReachabilityLocalOnly
		a.Summary = "local ShellExecute split confirmed; blocked in Chrome 157/Edge 157/Opera GX 139 (%20/%22/%5C)"
	default:
		a.Reachability = ReachabilityNone
		a.Summary = "no argument split detected"
	}

	return a
}

func evaluateChannel(probe argv.ProbeReport, profile Profile, verified bool) ChannelResult {
	res := ChannelResult{
		Profile:  profile,
		Verified: verified,
	}

	for _, sc := range probe.Scenarios {
		if sc.ID == argv.ScenarioDashFlag {
			continue
		}
		escaped := EscapeURI(sc.TestURI, profile)
		switch sc.ID {
		case argv.ScenarioQuoteSplit:
			res.QuoteURI = escaped
		case argv.ScenarioSpaceSplit:
			res.SpaceURI = escaped
		}

		cmd := argv.SubstituteURI(probe.Template, probe.Placeholder, escaped)
		args, err := argv.SplitCommandLine(cmd)
		if err != nil {
			continue
		}
		if len(args) > probe.BaselineArgc {
			res.SplitSurvives = true
			if hasUnmitigatedCanary(args) {
				res.UnmitigatedSplit = true
			}
		}
	}

	// Trailing backslash test after browser escaping (Chromium encodes \ -> %5C).
	rawBS := fmt.Sprintf(`%s://host/probe\`, probe.Scheme)
	escapedBS := EscapeURI(rawBS, profile)
	res.BackslashURI = escapedBS
	if bsArgs, err := argv.SplitCommandLine(argv.SubstituteURI(probe.Template, probe.Placeholder, escapedBS)); err == nil {
		if len(bsArgs) != probe.BaselineArgc {
			res.BackslashBreak = true
			res.SplitSurvives = true
		}
	}

	// Raw '&' test for cmd.exe / .bat / .cmd handlers.
	rawAmp := fmt.Sprintf(`%s://host/path?a=1&b=2`, probe.Scheme)
	escapedAmp := EscapeURI(rawAmp, profile)
	res.AmpersandURI = escapedAmp
	res.AmpersandRaw = strings.Contains(escapedAmp, "&")

	return res
}

func evaluateLocal(probe argv.ProbeReport) LocalResult {
	res := LocalResult{
		RawSplitWorks: probe.AnyUnmitigatedFlag || (probe.AnySplit && !probe.AnyMitigatedFlag),
	}

	rawBS := fmt.Sprintf(`%s://host/probe\`, probe.Scheme)
	res.BackslashURI = rawBS
	if bsArgs, err := argv.SplitCommandLine(argv.SubstituteURI(probe.Template, probe.Placeholder, rawBS)); err == nil {
		res.BackslashArgv = bsArgs
		res.BackslashDelta = len(bsArgs) - probe.BaselineArgc
		if len(bsArgs) != probe.BaselineArgc {
			res.BackslashBreak = true
			res.BackslashAfterDD = probe.HasDoubleDash
		}
	}

	return res
}

func hasUnmitigatedCanary(args []string) bool {
	doubleDashIdx := -1
	for i := 1; i < len(args); i++ {
		if doubleDashIdx == -1 && args[i] == "--" {
			doubleDashIdx = i
		}
		if args[i] == argv.CanaryFlag {
			return doubleDashIdx == -1 || i < doubleDashIdx
		}
	}
	return false
}
