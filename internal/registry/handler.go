package registry

import (
	"sort"
	"strings"
)

const (
	HiveHKCU = "HKCU"
	HiveHKLM = "HKLM"
)

// Handler represents a URI protocol handler discovered in the Windows Registry.
type Handler struct {
	Scheme              string           `json:"scheme"`
	Hive                string           `json:"hive"`
	RegistryPath        string           `json:"registry_path"`
	Description         string           `json:"description,omitempty"`
	RawCommand          string           `json:"raw_command"`
	Command             string           `json:"command"`
	IsExpandSZ          bool             `json:"is_expand_sz,omitempty"`
	EnvExpanded         bool             `json:"env_expanded,omitempty"`
	DelegateExecute     string           `json:"delegate_execute,omitempty"`
	ShadowsHKLM         bool             `json:"shadows_hklm,omitempty"`
	PartialHKCUShadow   bool             `json:"partial_hkcu_shadow,omitempty"`
	ShadowedHKLMCommand string           `json:"shadowed_hklm_command,omitempty"`
	Analysis            TemplateAnalysis `json:"analysis"`
}

// MergeHandlers combines HKCU and HKLM registrations using HKCR precedence
// (HKCU overrides HKLM case-insensitively) and returns them sorted by scheme.
func MergeHandlers(hkcu, hklm []Handler) []Handler {
	merged := make(map[string]Handler, len(hkcu)+len(hklm))

	for _, h := range hklm {
		merged[strings.ToLower(h.Scheme)] = h
	}

	for _, h := range hkcu {
		key := strings.ToLower(h.Scheme)
		if existing, exists := merged[key]; exists {
			h.ShadowsHKLM = true
			h.ShadowedHKLMCommand = existing.Command
		}
		merged[key] = h
	}

	out := make([]Handler, 0, len(merged))
	for _, h := range merged {
		out = append(out, h)
	}

	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Scheme) < strings.ToLower(out[j].Scheme)
	})
	return out
}
