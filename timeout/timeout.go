package timeout

import (
	"time"
)

const noTimeout = 0

func IsValid(timeout string) bool {
	d, parseError := time.ParseDuration(timeout)
	if parseError != nil {
		return false
	}
	// Only positive durations are considered valid.
	return d > time.Duration(noTimeout)
}

func ToSeconds(timeout string) (int, error) {
	d, parseError := time.ParseDuration(timeout)
	if parseError != nil {
		return noTimeout, parseError
	}

	return int(d.Seconds()), nil
}
