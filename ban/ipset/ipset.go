package ipset

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"sync"

	"github.com/rs/zerolog"
	"gitlab.com/secban/secban-agent/ban"
	"gitlab.com/secban/secban-agent/ip"
	"gitlab.com/secban/secban-agent/timeout"
)

const (
	set      = "secban"
	ipsetCmd = "/usr/sbin/ipset"
	iptable4 = "/usr/sbin/iptables"
	iptable6 = "/usr/sbin/ip6tables"
)

type Command struct {
	Set string
	Cmd string
}

type Manager struct {
	set          string
	ipsetCmd     string
	addressTypes []string
	lock         sync.Mutex
}

var _ ban.Actor = (*Manager)(nil)

func New() *Manager {
	return &Manager{
		set:          set,
		ipsetCmd:     ipsetCmd,
		addressTypes: []string{ip.IP4, ip.IP6},
	}
}

func (m *Manager) Block(ctx context.Context, address string, duration string) error {
	return m.ban(ctx, address, duration)
}

func (m *Manager) Init(ctx context.Context) error {
	for _, addrType := range m.addressTypes {
		setErr := m.createSet(ctx, addrType)
		if setErr != nil {
			return setErr
		}

		linkErr := m.linkSet(ctx, addrType)
		if linkErr != nil {
			return linkErr
		}
	}

	return nil
}

func (m *Manager) Exit(ctx context.Context) error {
	for _, addrType := range m.addressTypes {
		destroyErr := m.destroySet(ctx, addrType)
		if destroyErr != nil {
			return destroyErr
		}
	}

	return nil
}

func (m *Manager) Flush(ctx context.Context) error {
	for _, addrType := range m.addressTypes {
		flushErr := m.flushSet(ctx, addrType)
		if flushErr != nil {
			return flushErr
		}
	}

	return nil
}

func (m *Manager) execCommand(ctx context.Context, args ...string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	// #nosec G204 // We control the arguments and context.
	execCmd := exec.CommandContext(ctx, m.ipsetCmd, args...)

	if zerolog.GlobalLevel() == zerolog.DebugLevel {
		execCmd.Stdout = os.Stdout
		execCmd.Stderr = os.Stderr
	}

	runErr := execCmd.Run()
	if runErr != nil {
		return runErr
	}

	return nil
}

func (m *Manager) createSet(ctx context.Context, addrType string) error {
	family := "inet"
	if addrType == ip.IP6 {
		family = "inet6"
	}

	args := []string{
		"create",
		"-exist",
		m.set + addrType,
		"hash:ip",
		"family",
		family,
		"timeout",
		"60",
	}

	return m.execCommand(ctx, args...)
}

func (m *Manager) linkSet(ctx context.Context, addrType string) error {
	iptableCmd := iptable4
	if addrType == ip.IP6 {
		iptableCmd = iptable6
	}

	// #nosec G204 // We control the arguments and context.
	// #nosec G204 // We control the arguments and context.
	iptableCommand := exec.CommandContext(ctx, iptableCmd, "-I", "INPUT", "-m", "set", "--match-set", m.set+addrType, "src", "-j", "DROP")
	if zerolog.GlobalLevel() == zerolog.DebugLevel {
		iptableCommand.Stdout = os.Stdout
		iptableCommand.Stderr = os.Stderr
	}

	runErr := iptableCommand.Run()
	if runErr != nil {
		return runErr
	}

	return nil
}

func (m *Manager) destroySet(ctx context.Context, addrType string) error {
	return m.execCommand(ctx, "destroy", m.set+addrType)
}

func (m *Manager) flushSet(ctx context.Context, addrType string) error {
	return m.execCommand(ctx, "flush", m.set+addrType)
}

func (m *Manager) ban(ctx context.Context, address string, duration string) error {
	addrType, addrTypeErr := ip.AddrType(address)
	if addrTypeErr != nil {
		return addrTypeErr
	}

	setName := m.set + addrType

	if !timeout.IsValid(duration) {
		return errors.New("invalid timeout format")
	}

	seconds, secondsErr := timeout.ToSeconds(duration)
	if secondsErr != nil {
		return secondsErr
	}

	args := []string{
		"add",
		"-exist",
		setName,
		address,
		"timeout",
		strconv.Itoa(seconds),
	}

	return m.execCommand(ctx, args...)
}
