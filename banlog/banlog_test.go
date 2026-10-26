package banlog_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"gitlab.com/secban/secban-agent/banlog"
	"gitlab.com/secban/secban-agent/db"
	"gitlab.com/secban/secban-agent/offender"
)

func TestBanlogCountSinceAndGetSince(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "agent.sqlite")

	initErr := db.Init(ctx, dbPath)
	if initErr != nil {
		t.Fatalf("db.Init failed: %v", initErr)
	}
	defer func() {
		_ = db.Close()
	}()

	timeStart := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	timeFirst := timeStart.Add(2 * time.Minute)
	timeSecond := timeStart.Add(4 * time.Minute)

	banlog.Log(ctx, "rule-a", offender.Offender{
		IP:        "1.1.1.1",
		Timestamp: timeFirst,
		BanCount:  1,
	})
	banlog.Log(ctx, "rule-b", offender.Offender{
		IP:        "2.2.2.2",
		Timestamp: timeSecond,
		BanCount:  2,
	})

	countAll, countAllErr := banlog.CountSince(ctx, timeStart)
	if countAllErr != nil {
		t.Fatalf("CountSince t0 failed: %v", countAllErr)
	}

	if countAll != 2 {
		t.Fatalf("expected 2 bans, got %d", countAll)
	}

	countPartial, countPartialErr := banlog.CountSince(ctx, timeFirst)
	if countPartialErr != nil {
		t.Fatalf("CountSince t1 failed: %v", countPartialErr)
	}

	if countPartial != 1 {
		t.Fatalf("expected 1 ban, got %d", countPartial)
	}

	entries, getErr := banlog.GetSince(ctx, timeFirst)
	if getErr != nil {
		t.Fatalf("GetSince failed: %v", getErr)
	}

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	if entries[0].IP != "2.2.2.2" {
		t.Fatalf("expected IP 2.2.2.2, got %q", entries[0].IP)
	}

	if entries[0].BanCount != 2 {
		t.Fatalf("expected BanCount 2, got %d", entries[0].BanCount)
	}
}
