package action_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gitlab.com/secban/secban-agent/action"
	"gitlab.com/secban/secban-agent/offender"
)

func TestExecuteCustomActionRunsAllConfiguredActions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	markerOne := filepath.Join(dir, "first.log")
	markerTwo := filepath.Join(dir, "second.log")

	firstScript := filepath.Join(dir, "first.sh")
	secondScript := filepath.Join(dir, "second.sh")

	writeErr := os.WriteFile(
		firstScript,
		[]byte("#!/bin/sh\nprintf '%s' \"$1\" > \""+markerOne+"\"\n"),
		0o700,
	)
	if writeErr != nil {
		t.Fatalf("write first script: %v", writeErr)
	}

	writeErr = os.WriteFile(
		secondScript,
		[]byte("#!/bin/sh\nprintf '%s' \"$1\" > \""+markerTwo+"\"\n"),
		0o700,
	)
	if writeErr != nil {
		t.Fatalf("write second script: %v", writeErr)
	}

	args := action.ActionArgs{
		IP:      "192.0.2.100",
		Rule:    "bad",
		Actions: []string{firstScript, secondScript},
		Offender: offender.Offender{
			IP:      "192.0.2.100",
			Entries: nil,
			Count:   1,
		},
	}

	action.ExecuteCustomAction(context.Background(), args)

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

func TestExecuteCustomActionCancelsWhenPastTimeout(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	marker := filepath.Join(dir, "timed.out")
	scriptPath := filepath.Join(dir, "timeout.sh")

	writeErr := os.WriteFile(
		scriptPath,
		[]byte("#!/bin/sh\nsleep 30\nprintf '%s' 'done' > \""+marker+"\"\n"),
		0o700,
	)
	if writeErr != nil {
		t.Fatalf("write timeout script: %v", writeErr)
	}

	args := action.ActionArgs{
		IP:      "192.0.2.101",
		Rule:    "bad",
		Actions: []string{scriptPath},
		Offender: offender.Offender{
			IP:      "192.0.2.101",
			Entries: nil,
			Count:   1,
		},
	}

	action.ExecuteCustomAction(context.Background(), args)

	time.Sleep(25 * time.Second)

	_, statErr := os.Stat(marker)
	if statErr == nil {
		t.Fatal("expected timed-out action to be cancelled before completion")
	}

	if !os.IsNotExist(statErr) {
		t.Fatalf("unexpected marker stat error: %v", statErr)
	}
}
