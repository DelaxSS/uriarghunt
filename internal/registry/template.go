package registry

import (
	"os"
	"strings"
	"unicode"
)

// TemplateAnalysis holds static properties extracted from a shell\open\command string.
type TemplateAnalysis struct {
	Placeholder       string `json:"placeholder,omitempty"`
	HasPlaceholder    bool   `json:"has_placeholder"`
	PlaceholderQuoted bool   `json:"placeholder_quoted"`
	HasDoubleDash     bool   `json:"has_double_dash"`
	ExecutableRaw     string `json:"executable_raw,omitempty"`
	UnquotedExeSpaces bool   `json:"unquoted_exe_spaces"`
}

var executableExtensions = []string{".exe", ".com", ".bat", ".cmd", ".vbs", ".ps1", ".msc"}

// AnalyzeTemplate inspects a command template for URI placeholders, quoting,
// `--` flag termination, and unquoted executable paths containing spaces.
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
		res.HasDoubleDash = hasDoubleDashBefore(trimmed[:idx])
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

func hasDoubleDashBefore(prefix string) bool {
	inQuotes := false
	var tok strings.Builder
	tokens := make([]string, 0, 8)

	for i := 0; i < len(prefix); i++ {
		ch := prefix[i]
		if ch == '"' {
			inQuotes = !inQuotes
			continue
		}
		if !inQuotes && unicode.IsSpace(rune(ch)) {
			if tok.Len() > 0 {
				tokens = append(tokens, tok.String())
				tok.Reset()
			}
			continue
		}
		tok.WriteByte(ch)
	}
	if tok.Len() > 0 {
		tokens = append(tokens, tok.String())
	}

	for i := 1; i < len(tokens); i++ {
		if tokens[i] == "--" {
			return true
		}
	}
	return false
}

func extractExecutable(trimmed string) (exe string, unquotedSpaces bool) {
	if strings.HasPrefix(trimmed, `"`) {
		rest := trimmed[1:]
		if end := strings.IndexByte(rest, '"'); end != -1 {
			return rest[:end], false
		}
		return rest, false
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
				if !strings.ContainsAny(candidate, `"`) {
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

	fields := strings.Fields(trimmed)
	if len(fields) > 0 {
		return fields[0], false
	}
	return "", false
}
