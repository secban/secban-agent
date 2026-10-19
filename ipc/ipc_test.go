package ipc_test

import (
	"encoding/json"
	"testing"
	"time"

	"gitlab.com/secban/secban-agent/entry"
	"gitlab.com/secban/secban-agent/ipc"
	"gitlab.com/secban/secban-agent/offender"
)

func TestParseMessageRoundTrip(t *testing.T) {
	t.Parallel()

	now := time.Now()
	msg := ipc.Message{
		IP:   "192.17.1.111",
		Rule: "bad",
		Offender: offender.Offender{
			IP:        "192.17.1.111",
			Timestamp: now,
			Entries: []entry.Entry{{
				Timestamp: now,
				Message:   "badbotia",
			}},
			Count: 1,
		},
	}

	payload, marshalErr := json.Marshal(msg)
	if marshalErr != nil {
		t.Fatalf("marshal message: %v", marshalErr)
	}

	parsed, parseErr := ipc.ParseMessage(payload)
	if parseErr != nil {
		t.Fatalf("parse message: %v", parseErr)
	}

	assertParsedMessageMatches(t, msg, parsed)
}

func assertParsedMessageMatches(t *testing.T, expected, actual ipc.Message) {
	t.Helper()

	if actual.IP != expected.IP {
		t.Fatalf("IP mismatch: got %q want %q", actual.IP, expected.IP)
	}

	if actual.Rule != expected.Rule {
		t.Fatalf("rule mismatch: got %q want %q", actual.Rule, expected.Rule)
	}

	if actual.Offender.IP != expected.Offender.IP {
		t.Fatalf("offender IP mismatch: got %q want %q", actual.Offender.IP, expected.Offender.IP)
	}

	if !actual.Offender.Timestamp.Equal(expected.Offender.Timestamp) {
		t.Fatalf(
			"offender timestamp mismatch: got %v want %v",
			actual.Offender.Timestamp,
			expected.Offender.Timestamp,
		)
	}

	if actual.Offender.Count != expected.Offender.Count {
		t.Fatalf(
			"offender count mismatch: got %d want %d",
			actual.Offender.Count,
			expected.Offender.Count,
		)
	}

	if len(actual.Offender.Entries) != len(expected.Offender.Entries) {
		t.Fatalf(
			"offender entries mismatch: got %d want %d",
			len(actual.Offender.Entries),
			len(expected.Offender.Entries),
		)
	}

	if !actual.Offender.Entries[0].Timestamp.Equal(expected.Offender.Entries[0].Timestamp) {
		t.Fatalf(
			"entry timestamp mismatch: got %v want %v",
			actual.Offender.Entries[0].Timestamp,
			expected.Offender.Entries[0].Timestamp,
		)
	}

	if actual.Offender.Entries[0].Message != expected.Offender.Entries[0].Message {
		t.Fatalf(
			"entry message mismatch: got %q want %q",
			actual.Offender.Entries[0].Message,
			expected.Offender.Entries[0].Message,
		)
	}
}
