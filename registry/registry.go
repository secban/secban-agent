package registry

import (
	"sync"
	"time"

	"gitlab.com/thequietbot/secban/secban-agent/entry"
	"gitlab.com/thequietbot/secban/secban-agent/offender"
)

const (
	janitorInterval    = 100 * time.Millisecond
	maxOffenderEntries = 20
)

type Registry struct {
	offenders   map[string]offender.Offender
	lock        *sync.Mutex
	ttl         time.Duration
	maxEntries  int
	stopJanitor chan struct{}
}

func New(ttl time.Duration, maxEntries int) *Registry {
	newRegistry := &Registry{
		offenders:   make(map[string]offender.Offender),
		lock:        &sync.Mutex{},
		ttl:         ttl,
		maxEntries:  maxEntries,
		stopJanitor: make(chan struct{}),
	}

	if ttl > 0 {
		go newRegistry.startJanitor()
	}

	return newRegistry
}

func (r *Registry) Add(
	ip string,
	rule string,
	message string,
) offender.Offender {
	r.lock.Lock()
	defer r.lock.Unlock()

	foundOffender, exists := r.offenders[ip]
	if !exists {
		if r.maxEntries > 0 && len(r.offenders) >= r.maxEntries {
			r.evictOldestLocked()
		}

		foundOffender = offender.Offender{
			IP:        ip,
			Timestamp: time.Now(),
			Entries:   []entry.Entry{},
			Count:     0,
		}
	}

	foundOffender.Count++
	foundOffender.Timestamp = time.Now()

	newEntry := entry.Entry{
		Timestamp: foundOffender.Timestamp,
		Message:   message,
	}

	foundOffender.Entries = append([]entry.Entry{newEntry}, foundOffender.Entries...)

	if len(foundOffender.Entries) > maxOffenderEntries {
		foundOffender.Entries = foundOffender.Entries[:maxOffenderEntries]
	}

	r.offenders[ip] = foundOffender

	return foundOffender
}

func (r *Registry) Get(ip string) (offender.Offender, bool) {
	r.lock.Lock()
	defer r.lock.Unlock()

	offender, exists := r.offenders[ip]

	return offender, exists
}

func (r *Registry) PruneExpired() int {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.ttl <= 0 {
		return 0
	}

	pruned := 0
	now := time.Now()

	for ip, o := range r.offenders {
		if now.Sub(o.Timestamp) > r.ttl {
			delete(r.offenders, ip)

			pruned++
		}
	}

	return pruned
}

func (r *Registry) Close() {
	select {
	case <-r.stopJanitor:
		return
	default:
		close(r.stopJanitor)
	}
}

func (r *Registry) Count() int {
	r.lock.Lock()
	defer r.lock.Unlock()

	return len(r.offenders)
}

func (r *Registry) evictOldestLocked() {
	now := time.Now()

	if r.ttl > 0 {
		for ip, o := range r.offenders {
			if now.Sub(o.Timestamp) > r.ttl {
				delete(r.offenders, ip)
			}
		}

		if len(r.offenders) < r.maxEntries {
			return
		}
	}

	var oldestIP string

	var oldestTime time.Time

	first := true

	for ip, o := range r.offenders {
		if first || o.Timestamp.Before(oldestTime) {
			oldestIP = ip
			oldestTime = o.Timestamp
			first = false
		}
	}

	if oldestIP != "" {
		delete(r.offenders, oldestIP)
	}
}

func (r *Registry) startJanitor() {
	ticker := time.NewTicker(janitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopJanitor:
			return
		case <-ticker.C:
			r.PruneExpired()
		}
	}
}
