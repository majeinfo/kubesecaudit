package cis

import "strings"

func buildMapFromOptions(options []string) map[string]string {
	opts := make(map[string]string, 50)

	for _, option := range options {
		parts := strings.Split(option, "=")
		if len(parts[0]) > 2 {
			parts[0] = parts[0][2:]
		}
		if len(parts) < 2 {
			opts[parts[0]] = ""
		} else {
			opts[parts[0]] = parts[1]
		}
	}

	return opts
}

func findPrefixName(string_list []string, name string) (string, bool) {
	for _, s := range string_list {
		if strings.HasPrefix(s, name) {
			return s, true
		}
	}

	return "", false
}

func findName(strings []string, name string) bool {
	for _, s := range strings {
		if s == name {
			return true
		}
	}

	return false
}

func getOptionValue(option string) string {
	parts := strings.Split(option, "=")
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}
