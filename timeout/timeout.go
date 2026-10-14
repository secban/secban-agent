package timeout

import (
	"time"
)

func IsValid(timeout string) bool {
	d, parseError := time.ParseDuration(timeout)
	if parseError != nil {
		return false
	}
	// Only positive durations are considered valid.
	return d > time.Duration(0)
}
