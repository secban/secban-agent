package ip_test

import (
	"os"
	"path/filepath"
	"testing"

	"gitlab.com/secban/secban-agent/ip"
)

func TestAddrType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{input: "127.0.0.1", want: "ip", wantErr: false},
		{input: "192.168.1.1", want: "ip", wantErr: false},
		{input: "::1", want: "ip6", wantErr: false},
		{input: "2001:db8::1", want: "ip6", wantErr: false},
		{input: "invalid", want: "", wantErr: true},
		{input: "", want: "", wantErr: true},
	}

	for _, tt := range tests {
		got, addrErr := ip.AddrType(tt.input)
		if tt.wantErr {
			if addrErr == nil {
				t.Fatalf("AddrType(%q) expected error, got nil", tt.input)
			}

			continue
		}

		if addrErr != nil {
			t.Fatalf("AddrType(%q) unexpected error: %v", tt.input, addrErr)
		}

		if got != tt.want {
			t.Fatalf("AddrType(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestAllowlist(t *testing.T) { //nolint: paralleltest
	allowlistContent := `
# Loopback and local network
127.0.0.1
::1
10.0.0.0/8
2001:db8::/32

# Specific host in another subnet
192.168.1.50
`

	dir := t.TempDir()
	filePath := filepath.Join(dir, "allowlist")

	writeErr := os.WriteFile(filePath, []byte(allowlistContent), 0o600)
	if writeErr != nil {
		t.Fatalf("failed to write allowlist file: %v", writeErr)
	}

	initErr := ip.Init(filePath, false, false)
	if initErr != nil {
		t.Fatalf("ip.Init unexpected error: %v", initErr)
	}

	tests := []struct {
		ip   string
		want bool
	}{
		{ip: "127.0.0.1", want: true},
		{ip: "::1", want: true},
		{ip: "10.1.2.3", want: true},
		{ip: "10.254.254.254", want: true},
		{ip: "2001:db8::1", want: true},
		{ip: "2001:db8:ffff::1", want: true},
		{ip: "192.168.1.50", want: true},
		{ip: "192.168.1.51", want: false},
		{ip: "11.0.0.1", want: false},
		{ip: "2001:db9::1", want: false},
		{ip: "not-an-ip", want: false},
		{ip: "", want: false},
	}

	for _, tt := range tests {
		got := ip.IsAllowed(tt.ip)
		if got != tt.want {
			t.Errorf("ip.IsAllowed(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}

	ipObj, newErr := ip.New(filePath, false, true)
	if newErr != nil {
		t.Fatalf("ip.New unexpected error: %v", newErr)
	}

	for _, tt := range tests {
		got := ipObj.IsAllowed(tt.ip)
		if got != tt.want {
			t.Errorf("ipObj.IsAllowed(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}
