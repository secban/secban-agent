package timeout_test

import (
	"testing"

	"gitlab.com/thequietbot/secban/secban-agent/timeout"
)

func TestIsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  bool
	}{
		{input: "30s", want: true},
		{input: "1m", want: true},
		{input: "2h", want: true},
		{input: "7d", want: false},
		{input: "0s", want: false},
		{input: "", want: false},
		{input: "30", want: false},
		{input: "s", want: false},
		{input: "10x", want: false},
		{input: "-5s", want: false},
	}

	for _, tt := range tests {
		got := timeout.IsValid(tt.input)
		if got != tt.want {
			t.Errorf("IsValid(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
