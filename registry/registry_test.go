package registry_test

import (
	"strconv"
	"testing"
	"time"

	"gitlab.com/thequietbot/secban/secban-agent/registry"
)

func TestRegistryCapacityEviction(t *testing.T) {
	t.Parallel()

	reg := registry.New(1*time.Hour, 3)
	defer reg.Close()

	reg.Add("192.168.1.1", "bad", "msg1")
	time.Sleep(10 * time.Millisecond)
	reg.Add("192.168.1.2", "bad", "msg2")
	time.Sleep(10 * time.Millisecond)
	reg.Add("192.168.1.3", "bad", "msg3")

	if reg.Count() != 3 {
		t.Fatalf("expected count 3, got %d", reg.Count())
	}

	time.Sleep(10 * time.Millisecond)
	reg.Add("192.168.1.4", "bad", "msg4")

	if reg.Count() != 3 {
		t.Fatalf("expected count 3 after eviction, got %d", reg.Count())
	}

	_, existsOldest := reg.Get("192.168.1.1")
	if existsOldest {
		t.Fatal("expected oldest IP 192.168.1.1 to be evicted, but still exists")
	}

	_, existsNew := reg.Get("192.168.1.4")
	if !existsNew {
		t.Fatal("expected newest IP 192.168.1.4 to exist")
	}
}

func TestRegistryTTLExpiration(t *testing.T) {
	t.Parallel()

	ttl := 50 * time.Millisecond

	reg := registry.New(ttl, 100)
	defer reg.Close()

	reg.Add("10.0.0.1", "bad", "msg1")

	if reg.Count() != 1 {
		t.Fatalf("expected 1 entry, got %d", reg.Count())
	}

	time.Sleep(150 * time.Millisecond)

	if reg.Count() != 0 {
		t.Fatalf("expected 0 entries after TTL expiration, got %d", reg.Count())
	}
}

func TestRegistryMultipleEntriesPerOffender(t *testing.T) {
	t.Parallel()

	reg := registry.New(10*time.Minute, 10)
	defer reg.Close()

	for i := 1; i <= 5; i++ {
		offender := reg.Add("10.0.0.2", "bad", "msg "+strconv.Itoa(i))
		if offender.Count != i {
			t.Fatalf("expected count %d, got %d", i, offender.Count)
		}
	}
}

func TestRegistryOffenderEntriesCapped(t *testing.T) {
	t.Parallel()

	reg := registry.New(10*time.Minute, 10)
	defer reg.Close()

	for count := 1; count <= 30; count++ {
		offender := reg.Add("10.0.0.3", "bad", "msg "+strconv.Itoa(count))
		if count == 30 {
			if offender.Count != 30 {
				t.Fatalf("expected count 30, got %d", offender.Count)
			}

			if len(offender.Entries) != 20 {
				t.Fatalf("expected entries capped at 20, got %d", len(offender.Entries))
			}

			// Newest entry must be at index 0 (reverse chronological order)
			if offender.Entries[0].Message != "msg 30" {
				t.Fatalf("expected newest entry at index 0, got %q", offender.Entries[0].Message)
			}

			// Oldest retained entry must be at index 19
			if offender.Entries[19].Message != "msg 11" {
				t.Fatalf("expected oldest entry at index 19, got %q", offender.Entries[19].Message)
			}
		}
	}
}
