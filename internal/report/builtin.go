package report

import "strings"

var (
	builtinBrowserSchemes = map[string]struct{}{
		"http":           {},
		"https":          {},
		"ftp":            {},
		"google-chrome":  {},
		"microsoft-edge": {},
		"edge":           {},
		"opera gxstable": {},
		"opera":          {},
		"firefoxurl":     {},
		"ie.http":        {},
		"ie.https":       {},
	}

	builtinOSSchemes = map[string]struct{}{
		"mailto":                      {},
		"news":                        {},
		"nntp":                        {},
		"snews":                       {},
		"ldap":                        {},
		"mms":                         {},
		"rlogin":                      {},
		"telnet":                      {},
		"tn3270":                      {},
		"search":                      {},
		"search-ms":                   {},
		"dlna-playsingle":             {},
		"wdmam":                       {},
		"odopen":                      {},
		"grvopen":                     {},
		"msonedrivesyncserviceclient": {},
	}

	builtinPrefixes = []string{
		"ms-",
		"explorer.assoc",
		"wmp11.assoc",
		"microsoft.",
		"windows.",
		"ie.",
		"firefoxurl-",
		"opera ",
	}
)

// ClassifyBuiltin reports whether scheme belongs to built-in Windows OS or browser handlers.
func ClassifyBuiltin(scheme string) (isBuiltin bool, category string) {
	lower := strings.ToLower(strings.TrimSpace(scheme))
	if lower == "" {
		return false, ""
	}

	if _, ok := builtinBrowserSchemes[lower]; ok {
		return true, "browser"
	}
	if _, ok := builtinOSSchemes[lower]; ok {
		return true, "windows-builtin"
	}
	for _, prefix := range builtinPrefixes {
		if strings.HasPrefix(lower, prefix) {
			if prefix == "firefoxurl-" || prefix == "opera " || prefix == "ie." {
				return true, "browser"
			}
			return true, "windows-builtin"
		}
	}
	return false, ""
}
