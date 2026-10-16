package ip

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

const (
	IP4 = "ip"
	IP6 = "ip6"
)

type IP struct {
	allowedSingleIPs map[netip.Addr]bool
	allowedPrefixes  []netip.Prefix
	lock             sync.RWMutex
	allowLocal       bool
	allowLoopback    bool
}

var ipManager *IP //nolint:gochecknoglobals

func New(allowlistPath string, allowLocal bool, allowLoopback bool) (*IP, error) {
	var prefixes []netip.Prefix

	singleIPs := make(map[netip.Addr]bool)

	var scanErr error
	if allowlistPath != "" {
		prefixes, singleIPs, scanErr = scanAllowlist(allowlistPath)
		if scanErr != nil {
			return nil, scanErr
		}
	}

	return &IP{
		allowedPrefixes:  prefixes,
		allowedSingleIPs: singleIPs,
		allowLocal:       allowLocal,
		allowLoopback:    allowLoopback,
	}, nil
}

func Init(allowlistPath string, allowLocal bool, allowLoopback bool) error {
	manager, newErr := New(allowlistPath, allowLocal, allowLoopback)
	if newErr != nil {
		return newErr
	}

	ipManager = manager

	return nil
}

func (ip *IP) IsAllowed(raw string) bool {
	addr, parseErr := netip.ParseAddr(raw)
	if parseErr != nil {
		return false
	}

	if ip.isAllowedFromConfig(addr) {
		return true
	}

	if ip.isAllowedFromAllowList(addr) {
		return true
	}

	return false
}

func (ip *IP) isAllowedFromConfig(addr netip.Addr) bool {
	if ip.allowLoopback && addr.IsLoopback() {
		return true
	}

	if ip.allowLocal &&
		(addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast()) {
		return true
	}

	return false
}

func (ip *IP) isAllowedFromAllowList(addr netip.Addr) bool {
	ip.lock.RLock()
	defer ip.lock.RUnlock()

	if ip.allowedSingleIPs[addr] {
		return true
	}

	for _, prefix := range ip.allowedPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}

func IsValid(raw string) bool {
	_, parseErr := netip.ParseAddr(raw)
	return parseErr == nil
}

func IsAllowed(raw string) bool {
	if ipManager == nil {
		log.Error().
			Err(errors.New("ipManager is not initialized")).
			Msg("IP manager not initialized")
		// Returning true as a safe default when IP manager is not initialized.
		// This leaves all IPs effectively allowed, but prevents users locking themselves out.
		// Should never be reached in normal operation.
		return true
	}

	return ipManager.IsAllowed(raw)
}

func AddrType(raw string) (string, error) {
	addr, parseErr := netip.ParseAddr(raw)
	if parseErr != nil {
		return "", parseErr
	}

	if addr.Is4() {
		return IP4, nil
	}

	if addr.Is6() {
		return IP6, nil
	}

	return "", errors.New("unknown address type")
}

func scanAllowlist(allowlistPath string) ([]netip.Prefix, map[netip.Addr]bool, error) {
	file, openErr := os.Open(allowlistPath)
	if openErr != nil {
		return nil, nil, fmt.Errorf("failed to open allowlist file: %w", openErr)
	}
	defer file.Close()

	var prefixes []netip.Prefix

	singleIPs := make(map[netip.Addr]bool)

	scanner := bufio.NewScanner(file)

	lineNum := 0
	for scanner.Scan() {
		lineNum++

		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "/") {
			prefix, parsePrefixErr := netip.ParsePrefix(line)
			if parsePrefixErr != nil {
				return nil, nil, fmt.Errorf(
					"invalid cidr at line %d (%q): %w",
					lineNum,
					line,
					parsePrefixErr,
				)
			}

			prefixes = append(prefixes, prefix)
		} else {
			addr, parseAddrErr := netip.ParseAddr(line)
			if parseAddrErr != nil {
				return nil, nil, fmt.Errorf(
					"invalid ip at line %d (%q): %w",
					lineNum,
					line,
					parseAddrErr,
				)
			}

			singleIPs[addr] = true
		}
	}

	scanErr := scanner.Err()
	if scanErr != nil {
		return nil, nil, fmt.Errorf("error reading allowlist file: %w", scanErr)
	}

	return prefixes, singleIPs, nil
}
