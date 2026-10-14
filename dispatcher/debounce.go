package dispatcher

import (
	"sync"
	"time"
)

const (
	debounceWindow    = 2 * time.Second
	maxTrackerEntries = 500
)

type debounceTracker struct {
	lock sync.Mutex
	last map[string]time.Time
}

func newDebounceTracker() *debounceTracker {
	return &debounceTracker{
		last: make(map[string]time.Time),
	}
}

func (tracker *debounceTracker) ShouldAct(ip string) bool {
	tracker.lock.Lock()
	defer tracker.lock.Unlock()

	now := time.Now()

	if len(tracker.last) > maxTrackerEntries {
		for key, timestamp := range tracker.last {
			if now.Sub(timestamp) > debounceWindow {
				delete(tracker.last, key)
			}
		}
	}

	lastTime, exists := tracker.last[ip]
	if exists && now.Sub(lastTime) < debounceWindow {
		return false
	}

	tracker.last[ip] = now

	return true
}
