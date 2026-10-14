package dispatcher_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	dispatcher "gitlab.com/thequietbot/secban/secban-agent/dispatcher"
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

func TestDispatcherReportTriggersBlockAtThreshold(t *testing.T) {
	t.Parallel()

	actor := &fakeBanActor{}

	dispatcherInstance, err := dispatcher.New([]dispatcher.RuleConfig{{
		Name:       "bad",
		Count:      2,
		Timeout:    "30m",
		TTL:        "1h",
		MaxEntries: 10,
	}}, actor, false)
	if err != nil {
		t.Fatalf("new dispatcher: %v", err)
	}

	err = dispatcherInstance.Report(context.Background(), "192.0.2.10", "bad", "first")
	if err != nil {
		t.Fatalf("first report: %v", err)
	}

	if len(actor.blocked) != 0 {
		t.Fatalf("block should not trigger before threshold; got %v", actor.blocked)
	}

	err = dispatcherInstance.Report(context.Background(), "192.0.2.10", "bad", "second")
	if err != nil {
		t.Fatalf("second report: %v", err)
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

	dispatcherInstance, err := dispatcher.New([]dispatcher.RuleConfig{{
		Name:       "bad",
		Count:      1,
		Timeout:    "5m",
		TTL:        "10m",
		MaxEntries: 10,
	}}, actor, false)
	if err != nil {
		t.Fatalf("new dispatcher: %v", err)
	}

	err = dispatcherInstance.Report(context.Background(), "192.0.2.11", "bad", "alert")
	if err != nil {
		t.Fatalf("report: %v", err)
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

	dispatcherInstance, err := dispatcher.New([]dispatcher.RuleConfig{{
		Name:       "bad",
		Count:      1,
		Timeout:    "5m",
		TTL:        "10m",
		MaxEntries: 10,
	}}, actor, false)
	if err != nil {
		t.Fatalf("new dispatcher: %v", err)
	}

	err = dispatcherInstance.Report(context.Background(), "192.0.2.12", "unknown", "alert")
	if err == nil {
		t.Fatal("expected unknown-rule error, got nil")
	}
}

func TestDispatcherInitAndExit(t *testing.T) {
	t.Parallel()

	actor := &fakeBanActor{}

	dispatcherInstance, err := dispatcher.New([]dispatcher.RuleConfig{{
		Name:       "bad",
		Count:      1,
		Timeout:    "5m",
		TTL:        "10m",
		MaxEntries: 10,
	}}, actor, false)
	if err != nil {
		t.Fatalf("new dispatcher: %v", err)
	}

	err = dispatcherInstance.Init(context.Background())
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	if !actor.inited {
		t.Fatal("expected Init to call ban actor")
	}

	err = dispatcherInstance.Exit(context.Background())
	if err != nil {
		t.Fatalf("exit: %v", err)
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

	dispatcherInstance, err := dispatcher.New([]dispatcher.RuleConfig{{
		Name:       "bad",
		Count:      1,
		Timeout:    "5m",
		TTL:        "10m",
		MaxEntries: 10,
		Actions:    []string{firstScript, secondScript},
	}}, actor, false)
	if err != nil {
		t.Fatalf("new dispatcher: %v", err)
	}

	err = dispatcherInstance.Report(context.Background(), "192.0.2.20", "bad", "alert")
	if err != nil {
		t.Fatalf("report: %v", err)
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
	scriptBody := "#!/bin/sh\nprintf 'hit\n' >> \"" + marker + "\"\n"

	writeErr := os.WriteFile(script, []byte(scriptBody), 0o700)
	if writeErr != nil {
		t.Fatalf("write script: %v", writeErr)
	}

	actor := &fakeBanActor{}

	dispatcherInstance, err := dispatcher.New([]dispatcher.RuleConfig{{
		Name:       "bad",
		Count:      1,
		Timeout:    "5m",
		TTL:        "10m",
		MaxEntries: 10,
		Actions:    []string{script},
	}}, actor, false)
	if err != nil {
		t.Fatalf("new dispatcher: %v", err)
	}

	// First report triggers ban + action
	err = dispatcherInstance.Report(context.Background(), "192.0.2.30", "bad", "hit-1")
	if err != nil {
		t.Fatalf("first report: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Second report within debounce window: re-bans immediately, but does NOT re-run action
	err = dispatcherInstance.Report(context.Background(), "192.0.2.30", "bad", "hit-2")
	if err != nil {
		t.Fatalf("second report: %v", err)
	}

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
