package argv

import (
	"fmt"
	"strings"

	"uriarghunt/internal/registry"
)

const (
	CanaryFlag    = "--uriarghunt-canary"
	BaselineToken = "uriarghunt-baseline"
)

type ScenarioID string

const (
	ScenarioQuoteSplit ScenarioID = "quote_split"
	ScenarioSpaceSplit ScenarioID = "space_split"
	ScenarioDashFlag   ScenarioID = "dash_flag"
)

// ScenarioResult holds the CommandLineToArgvW output for one harmless probe URI.
type ScenarioResult struct {
	ID                ScenarioID `json:"id"`
	Name              string     `json:"name"`
	TestURI           string     `json:"test_uri"`
	ExpandedCommand   string     `json:"expanded_command"`
	Argv              []string   `json:"argv"`
	Argc              int        `json:"argc"`
	ArgcDelta         int        `json:"argc_delta"`
	SplitDetected     bool       `json:"split_detected"`
	StandaloneFlag    bool       `json:"standalone_flag"`
	FlagIndex         int        `json:"flag_index"`
	BeforeDoubleDash  bool       `json:"before_double_dash"`
	AttachedToFlag    bool       `json:"attached_to_flag,omitempty"`
	MissingDoubleDash bool       `json:"missing_double_dash,omitempty"`
	Note              string     `json:"note,omitempty"`
	Error             string     `json:"error,omitempty"`
}

// ProbeReport summarizes baseline parsing and canary split results for a template.
type ProbeReport struct {
	Scheme             string           `json:"scheme"`
	Template           string           `json:"template"`
	Placeholder        string           `json:"placeholder,omitempty"`
	HasPlaceholder     bool             `json:"has_placeholder"`
	HasDoubleDash      bool             `json:"has_double_dash"`
	AttachedToFlag     bool             `json:"attached_to_flag"`
	BaselineURI        string           `json:"baseline_uri,omitempty"`
	BaselineCommand    string           `json:"baseline_command,omitempty"`
	BaselineArgv       []string         `json:"baseline_argv,omitempty"`
	BaselineArgc       int              `json:"baseline_argc"`
	Scenarios          []ScenarioResult `json:"scenarios,omitempty"`
	AnySplit           bool             `json:"any_split"`
	AnyUnmitigatedFlag bool             `json:"any_unmitigated_flag"`
	AnyMitigatedFlag   bool             `json:"any_mitigated_flag"`
	MissingDoubleDash  bool             `json:"missing_double_dash"`
	Error              string           `json:"error,omitempty"`
}

// SubstituteURI replaces all occurrences of placeholder in template with uri.
func SubstituteURI(template, placeholder, uri string) string {
	if placeholder == "" {
		return template
	}
	return strings.ReplaceAll(template, placeholder, uri)
}

// ProbeTemplate evaluates a command template against a baseline URI and three
// harmless canary probes using real Win32 CommandLineToArgvW parsing.
func ProbeTemplate(scheme, template string) ProbeReport {
	report := ProbeReport{
		Scheme:   scheme,
		Template: template,
	}

	if strings.TrimSpace(template) == "" {
		return report
	}

	placeholder, _, ok := registry.FindPlaceholder(template)
	report.Placeholder = placeholder
	report.HasPlaceholder = ok

	if !ok {
		baseArgv, err := SplitCommandLine(template)
		if err != nil {
			report.Error = err.Error()
			return report
		}
		report.BaselineCommand = template
		report.BaselineArgv = baseArgv
		report.BaselineArgc = len(baseArgv)
		return report
	}

	baselineURI := fmt.Sprintf("%s://%s", scheme, BaselineToken)
	baselineCmd := SubstituteURI(template, placeholder, baselineURI)
	baseArgv, err := SplitCommandLine(baselineCmd)
	if err != nil {
		report.Error = err.Error()
		return report
	}

	report.BaselineURI = baselineURI
	report.BaselineCommand = baselineCmd
	report.BaselineArgv = baseArgv
	report.BaselineArgc = len(baseArgv)
	report.HasDoubleDash = hasDoubleDashBeforeToken(baseArgv, BaselineToken)
	report.AttachedToFlag = isTokenAttachedToFlag(baseArgv, BaselineToken, baselineURI)

	scenarios := []struct {
		id   ScenarioID
		name string
		uri  string
	}{
		{
			id:   ScenarioQuoteSplit,
			name: "quote/space split",
			uri:  fmt.Sprintf(`%s://a" %s "b`, scheme, CanaryFlag),
		},
		{
			id:   ScenarioSpaceSplit,
			name: "unquoted space split",
			uri:  fmt.Sprintf(`%s://a %s`, scheme, CanaryFlag),
		},
		{
			id:   ScenarioDashFlag,
			name: "dash placement check",
			uri:  fmt.Sprintf(`%s://%s`, scheme, CanaryFlag),
		},
	}

	for _, sc := range scenarios {
		expanded := SubstituteURI(template, placeholder, sc.uri)
		res := ScenarioResult{
			ID:              sc.id,
			Name:            sc.name,
			TestURI:         sc.uri,
			ExpandedCommand: expanded,
			FlagIndex:       -1,
		}

		args, splitErr := SplitCommandLine(expanded)
		if splitErr != nil {
			res.Error = splitErr.Error()
			report.Scenarios = append(report.Scenarios, res)
			continue
		}

		res.Argv = args
		res.Argc = len(args)
		res.ArgcDelta = res.Argc - report.BaselineArgc
		res.SplitDetected = res.Argc > report.BaselineArgc

		doubleDashIdx := -1
		for i := 1; i < len(args); i++ {
			if doubleDashIdx == -1 && args[i] == "--" {
				doubleDashIdx = i
			}
			if args[i] == CanaryFlag && res.FlagIndex == -1 {
				res.StandaloneFlag = true
				res.FlagIndex = i
			}
		}

		if res.StandaloneFlag {
			res.BeforeDoubleDash = doubleDashIdx == -1 || res.FlagIndex < doubleDashIdx
		}

		if sc.id == ScenarioDashFlag {
			res.AttachedToFlag = report.AttachedToFlag
			switch {
			case report.AttachedToFlag:
				res.Note = "placeholder is attached to an existing flag (e.g. --url=%1)"
			case !report.HasDoubleDash:
				res.MissingDoubleDash = true
				report.MissingDoubleDash = true
				res.Note = "positional URI argument is not preceded by '--'"
			default:
				res.Note = "URI argument is positioned after '--'"
			}
		}

		if res.SplitDetected {
			report.AnySplit = true
		}
		if res.StandaloneFlag {
			if res.BeforeDoubleDash {
				report.AnyUnmitigatedFlag = true
			} else {
				report.AnyMitigatedFlag = true
			}
		}

		report.Scenarios = append(report.Scenarios, res)
	}

	return report
}

func hasDoubleDashBeforeToken(args []string, token string) bool {
	for i := 1; i < len(args); i++ {
		if strings.Contains(args[i], token) {
			return false
		}
		if args[i] == "--" {
			return true
		}
	}
	return false
}

func isTokenAttachedToFlag(args []string, token, fullURI string) bool {
	for i := 1; i < len(args); i++ {
		if !strings.Contains(args[i], token) {
			continue
		}
		return args[i] != fullURI && (strings.HasPrefix(args[i], "-") || strings.HasPrefix(args[i], "/"))
	}
	return false
}
