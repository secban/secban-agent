//go:build functional

package ipset_test

import (
	"context"
	"os"
	"testing"
	"time"

	"gitlab.com/secban/secban-agent/ban/ipset"
)

const (
	timeoutDuration = 10 * time.Second
	banDuration     = "1m"
	testIPv4        = "192.0.2.100"
	testIPv6        = "2001:db8::100"
)

func TestFunctionalIpsetLifecycle(t *testing.T) { //nolint:paralleltest // Global firewall manipulation cannot run in parallel.
	if os.Geteuid() != 0 {
		t.Skip("root privileges required for ipset/iptables functional tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)
	defer cancel()

	mgr := ipset.New()

	// Clean up any stale state first.
	_ = mgr.Exit(ctx)

	initErr := mgr.Init(ctx)
	if initErr != nil {
		t.Fatalf("Init failed: %v", initErr)
	}

	defer func() {
		cleanupErr := mgr.Exit(ctx)
		if cleanupErr != nil {
			t.Errorf("cleanup Exit failed: %v", cleanupErr)
		}
	}()

	// Re-init should be idempotent and not fail or duplicate rules.
	reinitErr := mgr.Init(ctx)
	if reinitErr != nil {
		t.Fatalf("second Init failed: %v", reinitErr)
	}

	block4Err := mgr.Block(ctx, testIPv4, banDuration)
	if block4Err != nil {
		t.Fatalf("Block IPv4 failed: %v", block4Err)
	}

	block6Err := mgr.Block(ctx, testIPv6, banDuration)
	if block6Err != nil {
		t.Fatalf("Block IPv6 failed: %v", block6Err)
	}

	flushErr := mgr.Flush(ctx)
	if flushErr != nil {
		t.Fatalf("Flush failed: %v", flushErr)
	}

	exitErr := mgr.Exit(ctx)
	if exitErr != nil {
		t.Fatalf("Exit failed: %v", exitErr)
	}
}
