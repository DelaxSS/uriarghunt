package browser

import (
	"fmt"
	"strings"

	"uriarghunt/internal/argv"
)

// Profile identifies a browser non-special URI escaping profile.
type Profile string

const (
	// ProfileChromeEdge130 models Chromium 130+ StandardCompliantNonSpecialSchemeURLParsing.
	ProfileChromeEdge130  Profile = "chrome-edge-130+"
	ProfileFirefoxCurrent Profile = "firefox-current"
)

// Reachability summarizes how a command template behaves under browser escaping.
type Reachability string

const (
	ReachabilityNone               Reachability = "none"
	ReachabilityMitigated          Reachability = "mitigated"
	ReachabilityLocalOnly          Reachability = "local-only"
	ReachabilityLocalSplitDashCand Reachability = "local-split+dash-cand"
	ReachabilityBrowserPosSplit    Reachability = "browser-pos-split"
	ReachabilityBrowserSplit       Reachability = "browser-split"
)

// ChannelResult records CommandLineToArgvW outcomes after applying one browser profile.
type ChannelResult struct {
	Profile          Profile  `json:"profile"`
	QuoteURI         string   `json:"quote_uri,omitempty"`
	SpaceURI         string   `json:"space_uri,omitempty"`
	DashURI          string   `json:"dash_uri,omitempty"`
	BackslashURI     string   `json:"backslash_uri,omitempty"`
	BackslashArgv    []string `json:"backslash_argv,omitempty"`
	BackslashDelta   int      `json:"backslash_delta,omitempty"`
	BackslashBreak   bool     `json:"backslash_break"`
	BackslashAfterDD bool     `json:"backslash_after_dd,omitempty"`
	SplitSurvives    bool     `json:"split_survives"`
	UnmitigatedSplit bool     `json:"unmitigated_split"`
	DashPreserved    bool     `json:"dash_preserved"`
}

// Assessment combines browser-escaped parsing results with local raw split results.
type Assessment struct {
	Reachability     Reachability  `json:"reachability"`
	ChromeEdge130    ChannelResult `json:"chrome_edge_130"`
	FirefoxCurrent   ChannelResult `json:"firefox_current"`
	LocalSplit       bool          `json:"local_split"`
	BrowserBlocked   bool          `json:"browser_blocked"`
	BackslashBreak   bool          `json:"backslash_break"`
	BackslashAfterDD bool          `json:"backslash_after_dd,omitempty"`
	DashSurvives     bool          `json:"dash_survives"`
	Summary          string        `json:"summary"`
}

// EscapeURI applies percent-encoding rules for non-special schemes while preserving
// the scheme prefix, hyphens, and literal backslashes.
func EscapeURI(rawURI string, profile Profile) string {
	colon := strings.IndexByte(rawURI, ':')
	if colon == -1 {
		return escapeRemainder(rawURI, profile)
	}
	return rawURI[:colon+1] + escapeRemainder(rawURI[colon+1:], profile)
}

func escapeRemainder(s string, profile Profile) string {
	var b strings.Builder
	b.Grow(len(s) + 16)

	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch ch {
		case ' ':
			b.WriteString("%20")
		case '"':
			b.WriteString("%22")
		case '<':
			b.WriteString("%3C")
		case '>':
			b.WriteString("%3E")
		case '`':
			if profile == ProfileChromeEdge130 {
				b.WriteString("%60")
			} else {
				b.WriteByte(ch)
			}
		default:
			b.WriteByte(ch)
		}
	}
	return b.String()
}

// Evaluate tests probe's template through Chrome/Edge 130+ and Firefox escaping,
// then re-parses the resulting command lines with real CommandLineToArgvW.
func Evaluate(probe argv.ProbeReport) Assessment {
	if !probe.HasPlaceholder {
		return Assessment{
			Reachability: ReachabilityNone,
			Summary:      "no URI placeholder in command template",
		}
	}

	ce := evaluateChannel(probe, ProfileChromeEdge130)
	ff := evaluateChannel(probe, ProfileFirefoxCurrent)

	backslashBreak := ce.BackslashBreak || ff.BackslashBreak
	backslashAfterDD := backslashBreak && probe.HasDoubleDash

	a := Assessment{
		ChromeEdge130:    ce,
		FirefoxCurrent:   ff,
		BackslashBreak:   backslashBreak,
		BackslashAfterDD: backslashAfterDD,
		LocalSplit:       probe.AnyUnmitigatedFlag || (probe.AnySplit && !probe.AnyMitigatedFlag),
	}

	browserSurvives := ce.SplitSurvives || ff.SplitSurvives
	a.BrowserBlocked = probe.AnySplit && !browserSurvives
	a.DashSurvives = probe.MissingDoubleDash && (ce.DashPreserved || ff.DashPreserved)

	switch {
	case backslashBreak && !backslashAfterDD:
		a.Reachability = ReachabilityBrowserSplit
		a.Summary = "trailing '\\' escapes the closing quote of \"%1\" before '--' and alters subsequent argv boundaries"
	case backslashBreak && backslashAfterDD:
		a.Reachability = ReachabilityBrowserPosSplit
		a.Summary = "trailing '\\' breaks positional argument boundaries after '--' (no pre-'--' flag injection)"
	case browserSurvives:
		a.Reachability = ReachabilityBrowserSplit
		a.Summary = "CommandLineToArgvW split survives browser percent-encoding"
	case probe.AnyMitigatedFlag && !probe.AnyUnmitigatedFlag:
		a.Reachability = ReachabilityMitigated
		a.Summary = "browser encoding blocks split; local raw split lands after '--'"
	case a.LocalSplit && a.DashSurvives:
		a.Reachability = ReachabilityLocalSplitDashCand
		a.Summary = "raw quote/space split is local-only (browsers encode %22/%20); missing '--' leaves a dash-arg candidate"
	case a.LocalSplit:
		a.Reachability = ReachabilityLocalOnly
		a.Summary = "split requires raw local trigger; Chrome/Edge 130+ and Firefox block it via %22/%20 encoding"
	case a.DashSurvives:
		a.Reachability = ReachabilityLocalSplitDashCand
		a.Summary = "no argv split; missing '--' allows unencoded dash payload through browsers"
	default:
		a.Reachability = ReachabilityNone
		a.Summary = "no argument split or missing '--' exposure"
	}

	return a
}

func evaluateChannel(probe argv.ProbeReport, profile Profile) ChannelResult {
	res := ChannelResult{Profile: profile}

	for _, sc := range probe.Scenarios {
		escaped := EscapeURI(sc.TestURI, profile)
		switch sc.ID {
		case argv.ScenarioQuoteSplit:
			res.QuoteURI = escaped
		case argv.ScenarioSpaceSplit:
			res.SpaceURI = escaped
		case argv.ScenarioDashFlag:
			res.DashURI = escaped
			res.DashPreserved = strings.Contains(escaped, argv.CanaryFlag)
			continue
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

	// Non-special schemes keep a trailing backslash raw, which triggers Win32 `\"`
	// quote-escaping when additional arguments follow `"%1"` in the template.
	rawBS := fmt.Sprintf(`%s://probe\`, probe.Scheme)
	escapedBS := EscapeURI(rawBS, profile)
	res.BackslashURI = escapedBS

	bsCmd := argv.SubstituteURI(probe.Template, probe.Placeholder, escapedBS)
	if bsArgs, err := argv.SplitCommandLine(bsCmd); err == nil {
		res.BackslashArgv = bsArgs
		res.BackslashDelta = len(bsArgs) - probe.BaselineArgc
		if len(bsArgs) != probe.BaselineArgc {
			res.BackslashBreak = true
			res.BackslashAfterDD = probe.HasDoubleDash
			res.SplitSurvives = true
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
