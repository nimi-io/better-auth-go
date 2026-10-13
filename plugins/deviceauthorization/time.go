package deviceauthorization

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Port of packages/better-auth/src/utils/time.ts (ms).

const (
	msSec   = 1000.0
	msMin   = msSec * 60
	msHour  = msMin * 60
	msDay   = msHour * 24
	msWeek  = msDay * 7
	msMonth = msDay * 30
	msYear  = msDay * 365.25
)

var timeStringRe = regexp.MustCompile(`(?i)^(\+|\-)? ?(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|months?|mo|years?|yrs?|y)(?: (ago|from now))?$`)

// ParseTimeString converts a time string such as "30m", "5s", "1 hour" or "2 days ago"
// into milliseconds (ms upstream).
func ParseTimeString(value string) (float64, error) {
	m := timeStringRe.FindStringSubmatch(value)
	if m == nil || (m[4] != "" && m[1] != "") {
		return 0, fmt.Errorf(`Invalid time string format: "%s". Use formats like "7d", "30m", "1 hour", etc.`, value)
	}
	n, _ := strconv.ParseFloat(m[2], 64)
	var unit float64
	switch strings.ToLower(m[3]) {
	case "years", "year", "yrs", "yr", "y":
		unit = msYear
	case "months", "month", "mo":
		unit = msMonth
	case "weeks", "week", "w":
		unit = msWeek
	case "days", "day", "d":
		unit = msDay
	case "hours", "hour", "hrs", "hr", "h":
		unit = msHour
	case "minutes", "minute", "mins", "min", "m":
		unit = msMin
	default:
		unit = msSec
	}
	result := n * unit
	if m[1] == "-" || m[4] == "ago" {
		return -result, nil
	}
	return result, nil
}

func msDuration(ms float64) time.Duration { return time.Duration(ms * float64(time.Millisecond)) }
