package ipset

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"gitlab.com/secban/secban-agent/ban"
	"gitlab.com/secban/secban-agent/ip"
	"gitlab.com/secban/secban-agent/timeout"
)

const (
	ipSetName           = "secban"
	ipsetCmd            = "/usr/sbin/ipset"
	iptablesChain       = "INPUT"
	iptable4            = "/usr/sbin/iptables"
	iptable6            = "/usr/sbin/ip6tables"
	iptablesRuleMissing = 1
	existFlag           = "-exist"
)

type Command struct {
	Set string
	Cmd string
}

type Manager struct {
	set          string
	chain        string
	ipsetCmd     string
	addressTypes []string
	lock         sync.Mutex
}

var _ ban.Actor = (*Manager)(nil)

func New() *Manager {
	return &Manager{
		set:          ipSetName,
		chain:        iptablesChain,
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
		unlinkErr := m.unlinkSet(ctx, addrType)
		if unlinkErr != nil {
			return unlinkErr
		}

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

	var stderrBuf bytes.Buffer

	if zerolog.GlobalLevel() == zerolog.DebugLevel {
		execCmd.Stdout = os.Stdout
		execCmd.Stderr = io.MultiWriter(os.Stderr, &stderrBuf)
	} else {
		execCmd.Stderr = &stderrBuf
	}

	runErr := execCmd.Run()
	if runErr != nil {
		stderrStr := strings.TrimSpace(stderrBuf.String())
		if stderrStr != "" {
			return fmt.Errorf("%w: %s", runErr, stderrStr)
		}

		return runErr
	}

	return nil
}

func (m *Manager) execIPCommand(ctx context.Context, addrType string, args ...string) error {
	iptableCmd := iptable4
	if addrType == ip.IP6 {
		iptableCmd = iptable6
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	// #nosec G204 // We control the arguments and context.
	execCmd := exec.CommandContext(ctx, iptableCmd, args...)

	var stderrBuf bytes.Buffer

	if zerolog.GlobalLevel() == zerolog.DebugLevel {
		execCmd.Stdout = os.Stdout
		execCmd.Stderr = io.MultiWriter(os.Stderr, &stderrBuf)
	} else {
		execCmd.Stderr = &stderrBuf
	}

	runErr := execCmd.Run()
	if runErr != nil {
		stderrStr := strings.TrimSpace(stderrBuf.String())
		if stderrStr != "" {
			return fmt.Errorf("%w: %s", runErr, stderrStr)
		}

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
		existFlag,
		m.set + addrType,
		"hash:ip",
		"family",
		family,
		"timeout",
		"60",
	}

	return m.execCommand(ctx, args...)
}

func (m *Manager) getlinkArgs(addrType string) []string {
	return []string{m.chain, "-m", "set", "--match-set", m.set + addrType, "src", "-j", "DROP"}
}

func (m *Manager) setInChain(ctx context.Context, addrType string) (bool, error) {
	checkArgs := append([]string{"-C"}, m.getlinkArgs(addrType)...)

	checkErr := m.execIPCommand(ctx, addrType, checkArgs...)
	if checkErr == nil {
		return true, nil
	}

	var exitErr *exec.ExitError
	if errors.As(checkErr, &exitErr) && exitErr.ExitCode() == iptablesRuleMissing {
		return false, nil
	}

	if strings.Contains(checkErr.Error(), "doesn't exist") {
		return false, nil
	}

	return false, checkErr
}

func (m *Manager) linkSet(ctx context.Context, addrType string) error {
	exists, existsErr := m.setInChain(ctx, addrType)
	if existsErr != nil {
		return existsErr
	}

	if exists {
		return nil
	}

	insertArgs := append([]string{"-I"}, m.getlinkArgs(addrType)...)

	insertErr := m.execIPCommand(ctx, addrType, insertArgs...)
	if insertErr != nil {
		return insertErr
	}

	return nil
}

func (m *Manager) unlinkSet(ctx context.Context, addrType string) error {
	exists, existsErr := m.setInChain(ctx, addrType)
	if existsErr != nil {
		return existsErr
	}

	if !exists {
		return nil
	}

	delArgs := append([]string{"-D"}, m.getlinkArgs(addrType)...)

	return m.execIPCommand(ctx, addrType, delArgs...)
}

func (m *Manager) destroySet(ctx context.Context, addrType string) error {
	return m.execCommand(ctx, "destroy", existFlag, m.set+addrType)
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
		existFlag,
		setName,
		address,
		"timeout",
		strconv.Itoa(seconds),
	}

	return m.execCommand(ctx, args...)
}
