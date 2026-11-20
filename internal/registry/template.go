package registry

import (
	"os"
	"strings"
	"unicode"
)

// TemplateAnalysis holds static properties extracted from a shell\open\command string.
type TemplateAnalysis struct {
	Placeholder               string `json:"placeholder,omitempty"`
	HasPlaceholder            bool   `json:"has_placeholder"`
	PlaceholderQuoted         bool   `json:"placeholder_quoted"`
	PlaceholderDirectlyQuoted bool   `json:"placeholder_directly_quoted"`
	ExecutableRaw             string `json:"executable_raw,omitempty"`
	UnquotedExeSpaces         bool   `json:"unquoted_exe_spaces"`
}

var (
	executableExtensions = []string{".exe", ".com", ".bat", ".cmd", ".vbs", ".ps1", ".msc"}

	bareCommands = map[string]struct{}{
		"cmd":        {},
		"powershell": {},
		"pwsh":       {},
		"wscript":    {},
		"cscript":    {},
		"mshta":      {},
		"rundll32":   {},
		"java":       {},
		"javaw":      {},
		"node":       {},
		"explorer":   {},
		"msiexec":    {},
		"regsvr32":   {},
		"msdt":       {},
		"control":    {},
	}
)

// AnalyzeTemplate inspects a command template for URI placeholders, quoting,
// and unquoted executable paths containing spaces.
func AnalyzeTemplate(command string) TemplateAnalysis {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return TemplateAnalysis{}
	}

	var res TemplateAnalysis
	res.ExecutableRaw, res.UnquotedExeSpaces = extractExecutable(trimmed)

	placeholder, idx, ok := FindPlaceholder(trimmed)
	res.Placeholder = placeholder
	res.HasPlaceholder = ok

	if ok {
		res.PlaceholderQuoted = isInsideQuotes(trimmed, idx)
		res.PlaceholderDirectlyQuoted = isDirectlyQuoted(trimmed, idx, len(placeholder))
	}

	return res
}

// FindPlaceholder returns the earliest ShellExecute URI placeholder (%1, %l, %L, %*).
func FindPlaceholder(template string) (token string, index int, ok bool) {
	candidates := []string{"%1", "%l", "%L", "%*"}
	bestIdx := -1
	bestTok := ""

	for _, c := range candidates {
		if idx := strings.Index(template, c); idx != -1 {
			if bestIdx == -1 || idx < bestIdx {
				bestIdx = idx
				bestTok = c
			}
		}
	}

	if bestIdx == -1 {
		return "", -1, false
	}
	return bestTok, bestIdx, true
}

// ExpandEnv expands defined %VAR% references while leaving URI placeholders intact.
// Unlike Win32 ExpandEnvironmentStringsW, it handles %VAR% inside REG_SZ values
// and avoids mispairing `%1` with a later `%ProgramFiles%`.
func ExpandEnv(raw string, lookup func(string) (string, bool)) (expanded string, changed bool) {
	if !strings.ContainsRune(raw, '%') {
		return raw, false
	}

	var b strings.Builder
	b.Grow(len(raw))

	for i := 0; i < len(raw); {
		if raw[i] != '%' {
			b.WriteByte(raw[i])
			i++
			continue
		}

		relEnd := strings.IndexByte(raw[i+1:], '%')
		if relEnd > 0 {
			end := i + 1 + relEnd
			name := raw[i+1 : end]
			if !strings.ContainsAny(name, "\"\\/\r\n\t") {
				if val, ok := lookup(name); ok {
					b.WriteString(val)
					changed = true
					i = end + 1
					continue
				}
			}
		}

		b.WriteByte('%')
		i++
	}

	if !changed {
		return raw, false
	}
	return b.String(), true
}

// SystemEnvLookup returns a case-insensitive lookup over the current process environment.
func SystemEnvLookup() func(string) (string, bool) {
	env := os.Environ()
	m := make(map[string]string, len(env))
	for _, entry := range env {
		if k, v, ok := strings.Cut(entry, "="); ok && k != "" {
			m[strings.ToLower(k)] = v
		}
	}
	return func(name string) (string, bool) {
		val, ok := m[strings.ToLower(name)]
		return val, ok
	}
}

func isInsideQuotes(s string, pos int) bool {
	inQuotes := false
	for i := 0; i < pos && i < len(s); i++ {
		if s[i] == '"' {
			inQuotes = !inQuotes
		}
	}
	return inQuotes
}

// isDirectlyQuoted distinguishes a directly-quoted placeholder (e.g. `"%1"`, `--url="%1"`)
// from one merely sitting inside an outer shell wrapper (e.g. `cmd /c "start x.exe %1"`),
// where cmd.exe strips the outer quotes before executing the inner command.
func isDirectlyQuoted(s string, idx, phLen int) bool {
	if !isInsideQuotes(s, idx) {
		return false
	}
	openIdx := strings.LastIndexByte(s[:idx], '"')
	if openIdx == -1 {
		return false
	}
	after := idx + phLen
	relClose := strings.IndexByte(s[after:], '"')
	if relClose == -1 {
		return false
	}

	beforePh := s[openIdx+1 : idx]
	afterPh := s[after : after+relClose]
	if strings.ContainsFunc(beforePh, unicode.IsSpace) || strings.ContainsFunc(afterPh, unicode.IsSpace) {
		return false
	}
	return true
}

func extractExecutable(trimmed string) (exe string, unquotedSpaces bool) {
	if strings.HasPrefix(trimmed, `"`) {
		rest := trimmed[1:]
		if end := strings.IndexByte(rest, '"'); end != -1 {
			return rest[:end], false
		}
		return rest, false
	}

	first, rest := splitFirstToken(trimmed)
	if first == "" {
		return "", false
	}

	// If the next token is a CLI flag (/c, -File, --flag), or the first token is
	// a bare command without path separators, do not merge later script arguments.
	if rest != "" && (strings.HasPrefix(rest, "/") || strings.HasPrefix(rest, "-")) {
		return first, false
	}
	if !strings.ContainsAny(first, `\/:`) {
		if _, known := bareCommands[strings.ToLower(first)]; known {
			return first, false
		}
	}

	lower := strings.ToLower(trimmed)
	bestEnd := -1
	for _, ext := range executableExtensions {
		searchFrom := 0
		for {
			rel := strings.Index(lower[searchFrom:], ext)
			if rel == -1 {
				break
			}
			end := searchFrom + rel + len(ext)
			if end == len(trimmed) || unicode.IsSpace(rune(trimmed[end])) || trimmed[end] == '"' {
				candidate := trimmed[:end]
				if isValidUnquotedExeCandidate(candidate) {
					if bestEnd == -1 || end < bestEnd {
						bestEnd = end
					}
				}
				break
			}
			searchFrom = end
		}
	}

	if bestEnd != -1 {
		candidate := trimmed[:bestEnd]
		return candidate, strings.ContainsFunc(candidate, unicode.IsSpace)
	}

	return first, false
}

func splitFirstToken(s string) (first, rest string) {
	idx := strings.IndexFunc(s, unicode.IsSpace)
	if idx == -1 {
		return s, ""
	}
	return s[:idx], strings.TrimSpace(s[idx:])
}

func isValidUnquotedExeCandidate(candidate string) bool {
	if strings.ContainsAny(candidate, `"`) {
		return false
	}
	// Reject candidates that cross into a CLI flag or a separate drive-qualified argument.
	fields := strings.Fields(candidate)
	for i := 1; i < len(fields); i++ {
		f := fields[i]
		if strings.HasPrefix(f, "/") || strings.HasPrefix(f, "-") {
			return false
		}
		if len(f) >= 2 && f[1] == ':' {
			return false
		}
	}
	return true
}
