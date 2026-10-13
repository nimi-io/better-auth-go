package captcha

import (
	"regexp"
	"strings"
	"sync"
)

// wildcardRegexp ports utils/wildcard.ts wildcardMatch(pattern) with its default
// separator (true): "/" separates segments, "*" and "?" stay within one segment and "**"
// spans any number of segments.
func wildcardRegexp(pattern string) *regexp.Regexp {
	wildcardMu.Lock()
	defer wildcardMu.Unlock()
	if re, ok := wildcardCache[pattern]; ok {
		return re
	}
	re := regexp.MustCompile("^" + transform(pattern) + "$")
	wildcardCache[pattern] = re
	return re
}

var (
	wildcardMu    sync.Mutex
	wildcardCache = map[string]*regexp.Regexp{}
)

func escapeChar(c string) string {
	if strings.ContainsAny(c, `-^$+.()|[]{}*?\`) {
		return `\` + c
	}
	return c
}

func transform(pattern string) string {
	const (
		separatorMatcher = `[/\\]`
		wildcard         = `[^/\\]`
	)
	required := separatorMatcher + "+?"
	optional := separatorMatcher + "*?"
	segments := strings.Split(pattern, "/")
	var result strings.Builder
	for s, segment := range segments {
		if segment == "" && s > 0 {
			continue
		}
		next := ""
		if s+1 < len(segments) {
			next = segments[s+1]
		}
		current := ""
		switch {
		case s == len(segments)-1:
			current = optional
		case next != "**":
			current = required
		}
		if segment == "**" {
			if current != "" {
				if s != 0 {
					result.WriteString(current)
				}
				result.WriteString("(?:" + wildcard + "*?" + current + ")*?")
			}
			continue
		}
		chars := []rune(segment)
		for c := 0; c < len(chars); c++ {
			ch := string(chars[c])
			switch ch {
			case `\`:
				if c < len(chars)-1 {
					result.WriteString(escapeChar(string(chars[c+1])))
					c++
				}
			case "?":
				result.WriteString(wildcard)
			case "*":
				result.WriteString(wildcard + "*?")
			default:
				result.WriteString(escapeChar(ch))
			}
		}
		result.WriteString(current)
	}
	return result.String()
}
