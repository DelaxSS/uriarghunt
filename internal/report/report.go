package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"uriarghunt/internal/argv"
	"uriarghunt/internal/browser"
	"uriarghunt/internal/fingerprint"
	"uriarghunt/internal/registry"
)

const Version = "0.1.0"

// Tier ranks findings by deterministic evidence strength.
type Tier int

const (
	TierInfo Tier = 0
	Tier1    Tier = 1
	Tier2    Tier = 2
	Tier3    Tier = 3
)

func (t Tier) String() string {
	switch t {
	case Tier3:
		return "TIER 3"
	case Tier2:
		return "TIER 2"
	case Tier1:
		return "TIER 1"
	default:
		return "INFO"
	}
}

// Finding aggregates registry, argv, fingerprint, and browser evaluation for one scheme.
type Finding struct {
	Scheme          string             `json:"scheme"`
	Tier            Tier               `json:"tier"`
	TierLabel       string             `json:"tier_label"`
	Builtin         bool               `json:"builtin"`
	BuiltinCategory string             `json:"builtin_category,omitempty"`
	Reasons         []string           `json:"reasons,omitempty"`
	Handler         registry.Handler   `json:"handler"`
	Probe           argv.ProbeReport   `json:"probe"`
	Fingerprint     fingerprint.Info   `json:"fingerprint"`
	Browser         browser.Assessment `json:"browser"`
}

// FilterOptions controls which findings appear in the rendered report.
type FilterOptions struct {
	MinTier        Tier `json:"min_tier"`
	IncludeBuiltin bool `json:"include_builtin"`
	OnlySplits     bool `json:"only_splits"`
	ShowAllEmpty   bool `json:"show_all_empty"`
}

// Summary contains aggregate counts across all scanned schemes and visible findings.
type Summary struct {
	TotalSchemes       int `json:"total_schemes"`
	WithCommand        int `json:"with_command"`
	HKCUCount          int `json:"hkcu_count"`
	HKLMCount          int `json:"hklm_count"`
	ShadowCount        int `json:"shadow_count"`
	DoubleDashCount    int `json:"double_dash_count"`
	UnquotedExeCount   int `json:"unquoted_exe_count"`
	DanglingCount      int `json:"dangling_count"`
	BuiltinWithCommand int `json:"builtin_with_command"`
	ThirdPartyCommand  int `json:"third_party_with_command"`
	HiddenBuiltinCount int `json:"hidden_builtin_count"`
	ShownCount         int `json:"shown_count"`
	Tier3Count         int `json:"tier3_count"`
	Tier2Count         int `json:"tier2_count"`
	Tier1Count         int `json:"tier1_count"`
	InfoCount          int `json:"info_count"`
	ThirdPartyTier3    int `json:"third_party_tier3"`
	ThirdPartyTier2    int `json:"third_party_tier2"`
	ThirdPartyTier1    int `json:"third_party_tier1"`
}

// ScanReport is the top-level output structure for terminal and JSON reports.
type ScanReport struct {
	Version     string        `json:"version"`
	GeneratedAt string        `json:"generated_at"`
	Options     FilterOptions `json:"options"`
	Summary     Summary       `json:"summary"`
	Findings    []Finding     `json:"findings"`
}

// EvaluateFinding assigns a Tier (0-3) and concise rationale from all four analysis layers.
func EvaluateFinding(h registry.Handler, p argv.ProbeReport, fp fingerprint.Info, br browser.Assessment) Finding {
	isBuiltin, builtinCat := ClassifyBuiltin(h.Scheme)

	f := Finding{
		Scheme:          h.Scheme,
		Builtin:         isBuiltin,
		BuiltinCategory: builtinCat,
		Handler:         h,
		Probe:           p,
		Fingerprint:     fp,
		Browser:         br,
	}

	var reasons []string
	if h.ShadowsHKLM {
		reasons = append(reasons, "HKCU shadows HKLM")
	}
	if h.Analysis.UnquotedExeSpaces {
		reasons = append(reasons, "unquoted executable path with spaces")
	}

	if h.Command == "" {
		if h.DelegateExecute != "" {
			reasons = append(reasons, "handled via DelegateExecute")
		} else {
			reasons = append(reasons, "empty shell\\open\\command")
		}
		f.Tier = TierInfo
		f.TierLabel = f.Tier.String()
		f.Reasons = reasons
		return f
	}

	if fp.Dangling {
		reasons = append(reasons, "target binary missing on disk (dangling)")
		f.Tier = TierInfo
		f.TierLabel = f.Tier.String()
		f.Reasons = reasons
		return f
	}

	preDDBackslashBreak := br.BackslashBreak && !br.BackslashAfterDD
	postDDBackslashBreak := br.BackslashBreak && br.BackslashAfterDD
	hasUnmitigatedSplit := p.AnyUnmitigatedFlag ||
		(p.AnySplit && !p.AnyMitigatedFlag) ||
		preDDBackslashBreak

	if !hasUnmitigatedSplit {
		if postDDBackslashBreak {
			reasons = append(reasons, "trailing backslash corrupts positional args after '--'")
			f.Tier = Tier1
			f.TierLabel = f.Tier.String()
			f.Reasons = reasons
			return f
		}
		if h.Analysis.UnquotedExeSpaces {
			if p.AnyMitigatedFlag {
				reasons = append(reasons, "URI arg guarded by '--', but unquoted exe path remains Tier 1")
			}
			f.Tier = Tier1
			f.TierLabel = f.Tier.String()
			f.Reasons = reasons
			return f
		}

		if p.AnyMitigatedFlag {
			reasons = append(reasons, "guarded by '--' terminator")
		} else {
			reasons = append(reasons, "no CommandLineToArgvW split detected")
		}
		f.Tier = TierInfo
		f.TierLabel = f.Tier.String()
		f.Reasons = reasons
		return f
	}

	tier := Tier1
	if preDDBackslashBreak {
		reasons = append(reasons, "trailing backslash breaks closing quote before '--'")
	} else if p.AnyUnmitigatedFlag {
		reasons = append(reasons, "CommandLineToArgvW splits standalone flag before '--'")
	} else {
		reasons = append(reasons, "CommandLineToArgvW increases argc")
	}

	if fp.HighRiskRuntime {
		tier = Tier2
		reasons = append(reasons, fmt.Sprintf("high-risk runtime (%s)", fp.Runtime))
	}

	if tier == Tier2 && (br.Reachability == browser.ReachabilityBrowserSplit || br.Reachability == browser.ReachabilityLocalSplitDashCand) {
		tier = Tier3
		if br.Reachability == browser.ReachabilityBrowserSplit {
			reasons = append(reasons, "browser-surviving argv boundary break before '--'")
		} else {
			reasons = append(reasons, "missing '--' dash candidate (verify app-side argv/ASAR handling)")
		}
	}

	f.Tier = tier
	f.TierLabel = tier.String()
	f.Reasons = reasons
	return f
}

// BuildReport filters, summarizes, and sorts findings by descending Tier,
// placing third-party handlers ahead of built-in schemes.
func BuildReport(all []Finding, opts FilterOptions) ScanReport {
	var sum Summary
	sum.TotalSchemes = len(all)

	filtered := make([]Finding, 0, len(all))
	for _, f := range all {
		if f.Handler.Hive == registry.HiveHKCU {
			sum.HKCUCount++
		} else {
			sum.HKLMCount++
		}
		if f.Handler.ShadowsHKLM {
			sum.ShadowCount++
		}
		if f.Handler.Analysis.UnquotedExeSpaces {
			sum.UnquotedExeCount++
		}
		if f.Probe.HasDoubleDash {
			sum.DoubleDashCount++
		}

		if f.Handler.Command != "" {
			sum.WithCommand++
			if f.Fingerprint.Dangling {
				sum.DanglingCount++
			}
			if f.Builtin {
				sum.BuiltinWithCommand++
			} else {
				sum.ThirdPartyCommand++
			}

			switch f.Tier {
			case Tier3:
				sum.Tier3Count++
				if !f.Builtin {
					sum.ThirdPartyTier3++
				}
			case Tier2:
				sum.Tier2Count++
				if !f.Builtin {
					sum.ThirdPartyTier2++
				}
			case Tier1:
				sum.Tier1Count++
				if !f.Builtin {
					sum.ThirdPartyTier1++
				}
			default:
				sum.InfoCount++
			}
		}

		if !opts.ShowAllEmpty && f.Handler.Command == "" {
			continue
		}
		if !opts.IncludeBuiltin && f.Builtin {
			sum.HiddenBuiltinCount++
			continue
		}
		if opts.OnlySplits && !f.Probe.AnySplit && !f.Browser.BackslashBreak {
			continue
		}
		if f.Tier < opts.MinTier {
			continue
		}

		filtered = append(filtered, f)
	}

	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Tier != filtered[j].Tier {
			return filtered[i].Tier > filtered[j].Tier
		}
		if filtered[i].Builtin != filtered[j].Builtin {
			return !filtered[i].Builtin
		}
		return strings.ToLower(filtered[i].Scheme) < strings.ToLower(filtered[j].Scheme)
	})

	sum.ShownCount = len(filtered)

	return ScanReport{
		Version:     Version,
		GeneratedAt: time.Now().Format(time.RFC3339),
		Options:     opts,
		Summary:     sum,
		Findings:    filtered,
	}
}

// WriteTable renders ScanReport as an aligned terminal table.
func WriteTable(w io.Writer, rep ScanReport) {
	s := rep.Summary
	fmt.Fprintf(w, "uriarghunt v%s — Windows URI Protocol Handler Audit\n", rep.Version)
	fmt.Fprintf(w, "Schemes : %d total (HKCU=%d, HKLM=%d, shadows=%d) | %d with command (3rd-party=%d, builtin=%d, --=%d, dangling=%d)\n",
		s.TotalSchemes, s.HKCUCount, s.HKLMCount, s.ShadowCount,
		s.WithCommand, s.ThirdPartyCommand, s.BuiltinWithCommand, s.DoubleDashCount, s.DanglingCount)
	fmt.Fprintf(w, "3rdParty: TIER 3=%d  TIER 2=%d  TIER 1=%d\n",
		s.ThirdPartyTier3, s.ThirdPartyTier2, s.ThirdPartyTier1)
	if !rep.Options.IncludeBuiltin && s.HiddenBuiltinCount > 0 {
		fmt.Fprintf(w, "Filter  : hiding %d builtin OS/browser schemes (use --include-builtin), min-tier=%d\n\n",
			s.HiddenBuiltinCount, rep.Options.MinTier)
	} else {
		fmt.Fprintf(w, "Filter  : include-builtin=%v, min-tier=%d, shown=%d\n\n",
			rep.Options.IncludeBuiltin, rep.Options.MinTier, s.ShownCount)
	}

	if len(rep.Findings) == 0 {
		fmt.Fprintln(w, "No findings matched the active filters.")
		return
	}

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "TIER\tSCHEME\tSCOPE\tHIVE\tPLACEHOLDER\tSPLIT(A/B)\tFLAG\tRUNTIME\tREACHABILITY\tTARGET_EXE")
	fmt.Fprintln(tw, "------\t------\t-----\t----\t-----------\t----------\t----\t-------\t------------\t----------")

	for _, f := range rep.Findings {
		scope := "3rd-party"
		if f.Builtin {
			scope = "builtin"
		}

		hive := f.Handler.Hive
		if f.Handler.ShadowsHKLM {
			hive += "*"
		}

		ph := "-"
		if f.Handler.Analysis.HasPlaceholder {
			if f.Handler.Analysis.PlaceholderQuoted {
				ph = `"` + f.Handler.Analysis.Placeholder + `"`
			} else {
				ph = f.Handler.Analysis.Placeholder + " (UNQ)"
			}
		} else if f.Handler.DelegateExecute != "" {
			ph = "(Delegate)"
		}

		exeName := "-"
		if f.Handler.Analysis.ExecutableRaw != "" {
			exeName = filepath.Base(f.Handler.Analysis.ExecutableRaw)
		}

		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			f.TierLabel,
			f.Scheme,
			scope,
			hive,
			ph,
			FormatSplitPair(f.Probe),
			FormatFlagLabel(f.Probe, f.Browser),
			string(f.Fingerprint.Runtime),
			string(f.Browser.Reachability),
			exeName,
		)
	}
	_ = tw.Flush()

	fmt.Fprintln(w, "\nNotes: HIVE* = HKCU shadows HKLM. TIER 3 indicates a high-priority candidate; verify app-side argv handling manually.")
	fmt.Fprintln(w, "Run `uriarghunt inspect <scheme>` for full argv breakdown or `uriarghunt scan --json` for JSON output.")
}

// WriteJSON encodes ScanReport as indented JSON.
func WriteJSON(w io.Writer, rep ScanReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(rep)
}

// WriteInspect prints the detailed four-layer breakdown for a single URI scheme.
func WriteInspect(w io.Writer, f Finding) {
	h := f.Handler
	p := f.Probe
	fp := f.Fingerprint
	br := f.Browser

	scope := "3rd-party"
	if f.Builtin {
		scope = "builtin (" + f.BuiltinCategory + ")"
	}

	fmt.Fprintf(w, "Scheme          : %s://\n", f.Scheme)
	fmt.Fprintf(w, "Tier            : %s (%s)\n", f.TierLabel, scope)
	if len(f.Reasons) > 0 {
		fmt.Fprintf(w, "Reasons         : %s\n", strings.Join(f.Reasons, "; "))
	}
	fmt.Fprintf(w, "Registry Path   : %s\n", h.RegistryPath)
	if h.Description != "" {
		fmt.Fprintf(w, "Description     : %s\n", h.Description)
	}
	if h.ShadowsHKLM {
		fmt.Fprintf(w, "Shadows HKLM    : true (partial=%v)\n", h.PartialHKCUShadow)
		fmt.Fprintf(w, "Shadowed HKLM   : %s\n", h.ShadowedHKLMCommand)
	}
	if h.DelegateExecute != "" {
		fmt.Fprintf(w, "DelegateExecute : %s\n", h.DelegateExecute)
	}
	fmt.Fprintf(w, "Raw Command     : %s\n", h.RawCommand)
	if h.EnvExpanded && h.Command != h.RawCommand {
		fmt.Fprintf(w, "Expanded Command: %s (REG_EXPAND_SZ=%v)\n", h.Command, h.IsExpandSZ)
	}
	fmt.Fprintf(w, "Template        : placeholder=%q quoted=%v double_dash=%v attached_to_flag=%v unquoted_exe_spaces=%v\n",
		h.Analysis.Placeholder,
		h.Analysis.PlaceholderQuoted,
		h.Analysis.HasDoubleDash,
		p.AttachedToFlag,
		h.Analysis.UnquotedExeSpaces,
	)

	fmt.Fprintln(w, "\n[Fingerprint]")
	fmt.Fprintf(w, "Resolved Path   : %s (exists=%v, dangling=%v)\n", fp.ResolvedPath, fp.Exists, fp.Dangling)
	fmt.Fprintf(w, "PE Header       : valid=%v arch=%s subsystem=%s\n", fp.ValidPE, fp.Architecture, fp.Subsystem)
	fmt.Fprintf(w, "Runtime         : %s (high_risk=%v)\n", fp.Runtime, fp.HighRiskRuntime)
	if len(fp.Evidence) > 0 {
		fmt.Fprintf(w, "Evidence        : %s\n", strings.Join(fp.Evidence, ", "))
	}

	fmt.Fprintln(w, "\n[Browser Escape]")
	fmt.Fprintf(w, "Reachability    : %s\n", br.Reachability)
	fmt.Fprintf(w, "Chrome/Edge 130+: split_survives=%v backslash_break=%v dash_preserved=%v\n",
		br.ChromeEdge130.SplitSurvives, br.ChromeEdge130.BackslashBreak, br.ChromeEdge130.DashPreserved)
	fmt.Fprintf(w, "Firefox Current : split_survives=%v backslash_break=%v dash_preserved=%v\n",
		br.FirefoxCurrent.SplitSurvives, br.FirefoxCurrent.BackslashBreak, br.FirefoxCurrent.DashPreserved)
	if br.BackslashBreak {
		for _, ch := range []browser.ChannelResult{br.ChromeEdge130, br.FirefoxCurrent} {
			if !ch.BackslashBreak {
				continue
			}
			pos := "before --"
			if ch.BackslashAfterDD {
				pos = "after -- positional"
			}
			fmt.Fprintf(w, "Backslash Proof : [%s | %s] %s (delta=%+d) -> %#v\n",
				ch.Profile, pos, ch.BackslashURI, ch.BackslashDelta, ch.BackslashArgv)
		}
	}
	fmt.Fprintf(w, "Summary         : %s\n", br.Summary)

	fmt.Fprintf(w, "\n[CommandLineToArgvW] Baseline argc=%d\n", p.BaselineArgc)
	for i, a := range p.BaselineArgv {
		fmt.Fprintf(w, "  argv[%d] = %q\n", i, a)
	}

	for _, sc := range p.Scenarios {
		fmt.Fprintf(w, "\n[%s] %s\n", sc.ID, sc.Name)
		fmt.Fprintf(w, "  URI    : %s\n", sc.TestURI)
		fmt.Fprintf(w, "  Result : argc=%d (delta=%+d) split=%v standalone_flag=%v before_double_dash=%v\n",
			sc.Argc, sc.ArgcDelta, sc.SplitDetected, sc.StandaloneFlag, sc.BeforeDoubleDash)
		if sc.Note != "" {
			fmt.Fprintf(w, "  Note   : %s\n", sc.Note)
		}
		for i, a := range sc.Argv {
			marker := ""
			if i == sc.FlagIndex {
				marker = "  <-- canary"
			}
			fmt.Fprintf(w, "  argv[%d] = %q%s\n", i, a, marker)
		}
	}
}

// FormatFlagLabel returns a short status tag for the table FLAG column.
func FormatFlagLabel(p argv.ProbeReport, br browser.Assessment) string {
	switch {
	case br.BackslashBreak && !br.BackslashAfterDD:
		return "BSLASH!"
	case br.BackslashBreak && br.BackslashAfterDD:
		return "bslash--"
	case p.AnyUnmitigatedFlag:
		return "YES"
	case p.AnyMitigatedFlag:
		return "after--"
	case p.AnySplit:
		return "split-only"
	default:
		return "no"
	}
}

// FormatSplitPair formats quote_split and space_split argc deltas as "A/B".
func FormatSplitPair(p argv.ProbeReport) string {
	if len(p.Scenarios) < 2 {
		return "-"
	}
	a := "-"
	if p.Scenarios[0].SplitDetected {
		a = fmt.Sprintf("+%d", p.Scenarios[0].ArgcDelta)
	}
	b := "-"
	if p.Scenarios[1].SplitDetected {
		b = fmt.Sprintf("+%d", p.Scenarios[1].ArgcDelta)
	}
	return a + "/" + b
}
