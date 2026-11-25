//go:build !windows

package fingerprint

func lookupAppPaths(string) (string, bool) {
	return "", false
}
