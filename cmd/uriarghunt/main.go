package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"uriarghunt/internal/argv"
	"uriarghunt/internal/browser"
	"uriarghunt/internal/fingerprint"
	"uriarghunt/internal/registry"
	"uriarghunt/internal/report"
)

func main() {
	if len(os.Args) == 1 {
		parseAndRunScan(nil)
		return
	}

	sub := os.Args[1]
	switch {
	case sub == "inspect":
		parseAndRunInspect(os.Args[2:])
	case sub == "scan":
		parseAndRunScan(os.Args[2:])
	case sub == "version" || sub == "--version" || sub == "-v":
		fmt.Printf("uriarghunt v%s\n", report.Version)
	case sub == "help" || sub == "-h" || sub == "--help":
		printUsage(os.Stdout)
	case strings.HasPrefix(sub, "-"):
		parseAndRunScan(os.Args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n\n", sub)
		printUsage(os.Stderr)
		os.Exit(2)
	}
}

func printUsage(w *os.File) {
	fmt.Fprintf(w, "uriarghunt v%s — Windows URI protocol handler auditor\n\n", report.Version)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  uriarghunt [scan] [--min-tier 0..3] [--include-builtin] [--only-splits] [--all] [--json]")
	fmt.Fprintln(w, "  uriarghunt inspect [--json] <scheme>")
	fmt.Fprintln(w, "  uriarghunt version")
}

func parseTier(n int) (report.Tier, error) {
	if n < int(report.TierInfo) || n > int(report.Tier3) {
		return report.TierInfo, fmt.Errorf("invalid --min-tier value %d: must be 0, 1, 2, or 3", n)
	}
	return report.Tier(n), nil
}

func parseAndRunScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	minTierInt := fs.Int("min-tier", 0, "minimum tier to display (0=INFO, 1=TIER 1, 2=TIER 2, 3=TIER 3)")
	includeBuiltin := fs.Bool("include-builtin", false, "include built-in Windows OS and browser schemes")
	onlySplits := fs.Bool("only-splits", false, "show only handlers with detected argument splits")
	showAll := fs.Bool("all", false, "include handlers without a shell\\open\\command template")
	asJSON := fs.Bool("json", false, "output report as JSON")
	_ = fs.Parse(args)

	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unexpected arguments: %s\n\n", strings.Join(fs.Args(), " "))
		printUsage(os.Stderr)
		os.Exit(2)
	}

	minTier, err := parseTier(*minTierInt)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	findings, err := scanAllFindings()
	if err != nil {
		fmt.Fprintf(os.Stderr, "registry scan failed: %v\n", err)
		os.Exit(1)
	}

	rep := report.BuildReport(findings, report.FilterOptions{
		MinTier:        minTier,
		IncludeBuiltin: *includeBuiltin,
		OnlySplits:     *onlySplits,
		ShowAllEmpty:   *showAll,
	})

	if *asJSON {
		if err := report.WriteJSON(os.Stdout, rep); err != nil {
			fmt.Fprintf(os.Stderr, "encode json: %v\n", err)
			os.Exit(1)
		}
		return
	}

	report.WriteTable(os.Stdout, rep)
}

func parseAndRunInspect(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output finding as JSON")
	_ = fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: uriarghunt inspect [--json] <scheme>")
		os.Exit(2)
	}
	target := fs.Arg(0)

	findings, err := scanAllFindings()
	if err != nil {
		fmt.Fprintf(os.Stderr, "registry scan failed: %v\n", err)
		os.Exit(1)
	}

	var found *report.Finding
	for i := range findings {
		if strings.EqualFold(findings[i].Scheme, target) {
			found = &findings[i]
			break
		}
	}

	if found == nil {
		fmt.Fprintf(os.Stderr, "scheme not found: %q\n", target)
		os.Exit(1)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(found); err != nil {
			fmt.Fprintf(os.Stderr, "encode json: %v\n", err)
			os.Exit(1)
		}
		return
	}

	report.WriteInspect(os.Stdout, *found)
}

func scanAllFindings() ([]report.Finding, error) {
	handlers, err := registry.ScanAll()
	if err != nil {
		return nil, err
	}

	findings := make([]report.Finding, 0, len(handlers))
	for _, h := range handlers {
		p := argv.ProbeTemplate(h.Scheme, h.Command)
		fp := fingerprint.Inspect(h.Analysis.ExecutableRaw)
		br := browser.Evaluate(p)
		findings = append(findings, report.EvaluateFinding(h, p, fp, br))
	}
	return findings, nil
}
