package dispatcher_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	dispatcher "gitlab.com/secban/secban-agent/dispatcher"
	"gitlab.com/secban/secban-agent/ip"
)

type fakeBanActor struct {
	blocked []string
	inited  bool
	exited  bool
}

func (f *fakeBanActor) Block(_ context.Context, ip string, timeout string) error {
	f.blocked = append(f.blocked, ip+":"+timeout)
	return nil
}

func (f *fakeBanActor) Init(_ context.Context) error {
	f.inited = true
	return nil
}

func (f *fakeBanActor) Exit(_ context.Context) error {
	f.exited = true
	return nil
}

func (f *fakeBanActor) Flush(_ context.Context) error {
	return nil
}

func TestMain(m *testing.M) {
	tempDir, tempDirErr := os.MkdirTemp("", "dispatcher-test-*")
	if tempDirErr != nil {
		panic(tempDirErr)
	}

	allowlistPath := filepath.Join(tempDir, "allowlist")

	writeErr := os.WriteFile(allowlistPath, []byte("192.0.2.99\n"), 0o600)
	if writeErr != nil {
		panic(writeErr)
	}

	ipErr := ip.Init(allowlistPath, true, true)
	if ipErr != nil {
		panic(ipErr)
	}

	exitCode := m.Run()
	_ = os.RemoveAll(tempDir)

	os.Exit(exitCode)
}

func TestDispatcherReportTriggersBlockAtThreshold(t *testing.T) {
	t.Parallel()

	actor := &fakeBanActor{}

	dispatcherInstance, newErr := dispatcher.New([]dispatcher.RuleConfig{{
		Name:       "bad",
		Count:      2,
		Timeout:    "30m",
		TTL:        "1h",
		MaxEntries: 10,
	}}, actor, false)
	if newErr != nil {
		t.Fatalf("new dispatcher: %v", newErr)
	}

	allowed, reportErr := dispatcherInstance.Report(context.Background(), "192.0.2.10", "bad", "first")
	if reportErr != nil {
		t.Fatalf("first report: %v", reportErr)
	}

	if allowed {
		t.Fatal("expected allowed to be false")
	}

	if len(actor.blocked) != 0 {
		t.Fatalf("block should not trigger before threshold; got %v", actor.blocked)
	}

	allowed, reportErr = dispatcherInstance.Report(context.Background(), "192.0.2.10", "bad", "second")
	if reportErr != nil {
		t.Fatalf("second report: %v", reportErr)
	}

	if allowed {
		t.Fatal("expected allowed to be false")
	}

	if len(actor.blocked) != 1 {
		t.Fatalf(
			"expected one block after threshold, got %d: %v",
			len(actor.blocked),
			actor.blocked,
		)
	}

	if got := actor.blocked[0]; got != "192.0.2.10:30m" {
		t.Fatalf("unexpected block call: %q", got)
	}
}

func TestDispatcherGetReturnsRecordedOffender(t *testing.T) {
	t.Parallel()

	actor := &fakeBanActor{}

	dispatcherInstance, newErr := dispatcher.New([]dispatcher.RuleConfig{{
		Name:       "bad",
		Count:      1,
		Timeout:    "5m",
		TTL:        "10m",
		MaxEntries: 10,
	}}, actor, false)
	if newErr != nil {
		t.Fatalf("new dispatcher: %v", newErr)
	}

	allowed, reportErr := dispatcherInstance.Report(context.Background(), "192.0.2.11", "bad", "alert")
	if reportErr != nil {
		t.Fatalf("report: %v", reportErr)
	}

	if allowed {
		t.Fatal("expected allowed to be false")
	}

	offender, getErr := dispatcherInstance.Get(context.Background(), "192.0.2.11")
	if getErr != nil {
		t.Fatalf("get offender: %v", getErr)
	}

	if offender.IP != "192.0.2.11" {
		t.Fatalf("wrong offender IP: got %q", offender.IP)
	}

	if offender.Count != 1 {
		t.Fatalf("count mismatch: got %d want 1", offender.Count)
	}
}

func TestDispatcherRejectsUnknownRule(t *testing.T) {
	t.Parallel()

	actor := &fakeBanActor{}

	dispatcherInstance, newErr := dispatcher.New([]dispatcher.RuleConfig{{
		Name:       "bad",
		Count:      1,
		Timeout:    "5m",
		TTL:        "10m",
		MaxEntries: 10,
	}}, actor, false)
	if newErr != nil {
		t.Fatalf("new dispatcher: %v", newErr)
	}

	_, reportErr := dispatcherInstance.Report(context.Background(), "192.0.2.12", "unknown", "alert")
	if reportErr == nil {
		t.Fatal("expected unknown-rule error, got nil")
	}
}

func TestDispatcherInitAndExit(t *testing.T) {
	t.Parallel()

	actor := &fakeBanActor{}

	dispatcherInstance, newErr := dispatcher.New([]dispatcher.RuleConfig{{
		Name:       "bad",
		Count:      1,
		Timeout:    "5m",
		TTL:        "10m",
		MaxEntries: 10,
	}}, actor, false)
	if newErr != nil {
		t.Fatalf("new dispatcher: %v", newErr)
	}

	initErr := dispatcherInstance.Init(context.Background())
	if initErr != nil {
		t.Fatalf("init: %v", initErr)
	}

	if !actor.inited {
		t.Fatal("expected Init to call ban actor")
	}

	exitErr := dispatcherInstance.Exit(context.Background())
	if exitErr != nil {
		t.Fatalf("exit: %v", exitErr)
	}

	if !actor.exited {
		t.Fatal("expected Exit to call ban actor")
	}
}

func TestDispatcherRunsAllActions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	markerOne := filepath.Join(dir, "first.log")
	markerTwo := filepath.Join(dir, "second.log")

	firstScript := filepath.Join(dir, "first.sh")
	secondScript := filepath.Join(dir, "second.sh")

	firstScriptBody := "#!/bin/sh\nprintf '%s' \"$1\" > \"" + markerOne + "\"\n"
	secondScriptBody := "#!/bin/sh\nprintf '%s' \"$1\" > \"" + markerTwo + "\"\n"

	writeErr := os.WriteFile(firstScript, []byte(firstScriptBody), 0o700)
	if writeErr != nil {
		t.Fatalf("write first script: %v", writeErr)
	}

	writeErr = os.WriteFile(secondScript, []byte(secondScriptBody), 0o700)
	if writeErr != nil {
		t.Fatalf("write second script: %v", writeErr)
	}

	actor := &fakeBanActor{}

	dispatcherInstance, newErr := dispatcher.New([]dispatcher.RuleConfig{{
		Name:       "bad",
		Count:      1,
		Timeout:    "5m",
		TTL:        "10m",
		MaxEntries: 10,
		Actions:    []string{firstScript, secondScript},
	}}, actor, false)
	if newErr != nil {
		t.Fatalf("new dispatcher: %v", newErr)
	}

	allowed, reportErr := dispatcherInstance.Report(context.Background(), "192.0.2.20", "bad", "alert")
	if reportErr != nil {
		t.Fatalf("report: %v", reportErr)
	}

	if allowed {
		t.Fatal("expected allowed to be false")
	}

	time.Sleep(200 * time.Millisecond)

	_, statErr := os.Stat(markerOne)
	if statErr != nil {
		t.Fatalf("first action did not run: %v", statErr)
	}

	_, statErr = os.Stat(markerTwo)
	if statErr != nil {
		t.Fatalf("second action did not run: %v", statErr)
	}
}

func TestDispatcherDebouncesActionsWhileRebanning(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	marker := filepath.Join(dir, "action.log")
	script := filepath.Join(dir, "count.sh")

	writeErr := os.WriteFile(script, []byte("#!/bin/sh\nprintf 'hit\n' >> \""+marker+"\"\n"), 0o700)
	if writeErr != nil {
		t.Fatalf("write script: %v", writeErr)
	}

	actor := &fakeBanActor{}

	dispatcherInstance, newErr := dispatcher.New([]dispatcher.RuleConfig{{
		Name:    "bad",
		Count:   1,
		Timeout: "5m",
		TTL:     "10m",
		Actions: []string{script},
	}}, actor, false)
	if newErr != nil {
		t.Fatalf("new dispatcher: %v", newErr)
	}

	report := func(msg string) {
		allowed, reportErr := dispatcherInstance.Report(context.Background(), "192.0.2.30", "bad", msg)
		if reportErr != nil {
			t.Fatalf("report: %v", reportErr)
		}

		if allowed {
			t.Fatal("expected allowed to be false")
		}
	}

	// First report triggers ban + action
	report("hit-1")
	time.Sleep(100 * time.Millisecond)

	// Second report within debounce window: re-bans immediately, but does NOT re-run action
	report("hit-2")
	time.Sleep(100 * time.Millisecond)

	if len(actor.blocked) != 2 {
		t.Fatalf("expected 2 block calls, got %d", len(actor.blocked))
	}

	data, readErr := os.ReadFile(marker)
	if readErr != nil {
		t.Fatalf("read marker: %v", readErr)
	}

	if string(data) != "hit\n" {
		t.Fatalf(
			"expected action to run exactly once inside debounce window, got: %q",
			string(data),
		)
	}
}

func TestDispatcherReportAllowedIP(t *testing.T) {
	t.Parallel()

	actor := &fakeBanActor{}

	dispatcherInstance, newErr := dispatcher.New([]dispatcher.RuleConfig{{
		Name:       "bad",
		Count:      1,
		Timeout:    "5m",
		TTL:        "10m",
		MaxEntries: 10,
	}}, actor, false)
	if newErr != nil {
		t.Fatalf("new dispatcher: %v", newErr)
	}

	// 192.0.2.99 is allowlisted in TestMain
	allowed, reportErr := dispatcherInstance.Report(context.Background(), "192.0.2.99", "bad", "alert")
	if reportErr != nil {
		t.Fatalf("report allowed ip: %v", reportErr)
	}

	if !allowed {
		t.Fatal("expected allowed to be true for allowlisted IP")
	}

	if len(actor.blocked) != 0 {
		t.Fatalf("allowed IP should not trigger block, got: %v", actor.blocked)
	}

	_, getErr := dispatcherInstance.Get(context.Background(), "192.0.2.99")
	if getErr == nil {
		t.Fatal("expected error getting offender for allowed IP, got nil")
	}

	// Loopback address is also allowed via allowLoopback=true
	allowed, reportErr = dispatcherInstance.Report(context.Background(), "127.0.0.1", "bad", "alert")
	if reportErr != nil {
		t.Fatalf("report loopback ip: %v", reportErr)
	}

	if !allowed {
		t.Fatal("expected allowed to be true for loopback IP")
	}
}

func TestDispatcherActAllowedIP(t *testing.T) {
	t.Parallel()

	actor := &fakeBanActor{}

	dispatcherInstance, newErr := dispatcher.New([]dispatcher.RuleConfig{{
		Name:       "bad",
		Count:      1,
		Timeout:    "5m",
		TTL:        "10m",
		MaxEntries: 10,
	}}, actor, false)
	if newErr != nil {
		t.Fatalf("new dispatcher: %v", newErr)
	}

	allowed, actErr := dispatcherInstance.Act(context.Background(), "192.0.2.99", "bad", "manual ban")
	if actErr != nil {
		t.Fatalf("act allowed ip: %v", actErr)
	}

	if !allowed {
		t.Fatal("expected allowed to be true for allowlisted IP")
	}

	if len(actor.blocked) != 0 {
		t.Fatalf("allowed IP should not trigger block, got: %v", actor.blocked)
	}
}

func TestDispatcherReportAndActInvalidIP(t *testing.T) {
	t.Parallel()

	actor := &fakeBanActor{}

	dispatcherInstance, newErr := dispatcher.New([]dispatcher.RuleConfig{{
		Name:       "bad",
		Count:      1,
		Timeout:    "5m",
		TTL:        "10m",
		MaxEntries: 10,
	}}, actor, false)
	if newErr != nil {
		t.Fatalf("new dispatcher: %v", newErr)
	}

	allowed, reportErr := dispatcherInstance.Report(context.Background(), "invalid-ip", "bad", "alert")
	if reportErr == nil {
		t.Fatal("expected error for invalid IP in report, got nil")
	}

	if allowed {
		t.Fatal("expected allowed to be false for invalid IP")
	}

	allowed, actErr := dispatcherInstance.Act(context.Background(), "invalid-ip", "bad", "manual ban")
	if actErr == nil {
		t.Fatal("expected error for invalid IP in act, got nil")
	}

	if allowed {
		t.Fatal("expected allowed to be false for invalid IP")
	}
}

func TestPackageLevelReportAndBan(t *testing.T) { //nolint: paralleltest
	actor := &fakeBanActor{}

	initErr := dispatcher.Init(context.Background(), []dispatcher.RuleConfig{{
		Name:       "bad",
		Count:      1,
		Timeout:    "5m",
		TTL:        "10m",
		MaxEntries: 10,
	}}, actor, false)
	if initErr != nil {
		t.Fatalf("dispatcher.Init: %v", initErr)
	}

	defer func() {
		_ = dispatcher.Exit(context.Background())
	}()

	// Allowlisted IP returns allowed=true without banning
	allowed, reportErr := dispatcher.Report(context.Background(), "192.0.2.99", "bad", "alert")
	if reportErr != nil {
		t.Fatalf("dispatcher.Report allowed: %v", reportErr)
	}

	if !allowed {
		t.Fatal("expected allowed to be true")
	}

	allowed, banErr := dispatcher.Ban(context.Background(), "192.0.2.99", "bad", "manual")
	if banErr != nil {
		t.Fatalf("dispatcher.Ban allowed: %v", banErr)
	}

	if !allowed {
		t.Fatal("expected allowed to be true")
	}

	if len(actor.blocked) != 0 {
		t.Fatalf("expected 0 blocks for allowed IP, got: %v", actor.blocked)
	}

	// Non-allowed IP returns allowed=false and bans
	allowed, reportErr = dispatcher.Report(context.Background(), "192.0.2.50", "bad", "alert")
	if reportErr != nil {
		t.Fatalf("dispatcher.Report non-allowed: %v", reportErr)
	}

	if allowed {
		t.Fatal("expected allowed to be false")
	}

	if len(actor.blocked) != 1 {
		t.Fatalf("expected 1 block for non-allowed IP, got: %d", len(actor.blocked))
	}
}
