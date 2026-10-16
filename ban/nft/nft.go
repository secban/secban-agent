package nft

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"gitlab.com/secban/secban-agent/ban"
	"gitlab.com/secban/secban-agent/ip"
	"gitlab.com/secban/secban-agent/timeout"
)

const (
	table  = "secban"
	chain  = "bounce"
	set    = "offenders"
	nftCmd = "/usr/sbin/nft"
)

type Command struct {
	Table string
	Chain string
	Set   string
	Cmd   string
}

type Manager struct {
	table        string
	chain        string
	set          string
	nftCmd       string
	addressTypes []string
	lock         sync.Mutex
}

var _ ban.Actor = (*Manager)(nil)

func New() *Manager {
	return &Manager{
		table:        table,
		chain:        chain,
		set:          set,
		nftCmd:       nftCmd,
		addressTypes: []string{ip.IP4, ip.IP6},
	}
}

func (m *Manager) Block(ctx context.Context, address string, banDuration string) error {
	return m.ban(ctx, address, banDuration)
}

func (m *Manager) Init(ctx context.Context) error {
	return m.Flush(ctx)
}

func (m *Manager) Exit(ctx context.Context) error {
	return m.cleanupTables(ctx)
}

func (m *Manager) Flush(ctx context.Context) error {
	cleanupErr := m.cleanupTables(ctx)
	if cleanupErr != nil {
		return cleanupErr
	}

	return m.initTables(ctx)
}

func (m *Manager) execCommand(ctx context.Context, args ...string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	// #nosec G204 // We control the arguments and context.
	execCmd := exec.CommandContext(ctx, m.nftCmd, args...)

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

func (m *Manager) cleanupTables(ctx context.Context) error {
	for _, addrType := range m.addressTypes {
		args := []string{
			"destroy",
			"table",
			addrType,
			m.table,
		}

		runErr := m.execCommand(ctx, args...)
		if runErr != nil {
			return runErr
		}
	}

	return nil
}

func (m *Manager) initTables(ctx context.Context) error {
	for _, addrType := range m.addressTypes {
		tableErr := m.createTable(ctx, addrType)
		if tableErr != nil {
			return tableErr
		}

		chainErr := m.createChain(ctx, addrType)
		if chainErr != nil {
			return chainErr
		}

		setErr := m.createSet(ctx, addrType)
		if setErr != nil {
			return setErr
		}

		ruleErr := m.createRule(ctx, addrType)
		if ruleErr != nil {
			return ruleErr
		}
	}

	return nil
}

func (m *Manager) createTable(ctx context.Context, addrType string) error {
	args := []string{
		"add",
		"table",
		addrType,
		m.table,
	}

	return m.execCommand(ctx, args...)
}

func (m *Manager) createChain(ctx context.Context, addrType string) error {
	args := []string{
		"add",
		"chain",
		addrType,
		m.table,
		m.chain,
		"{ type filter hook input priority -10 ; }",
	}

	return m.execCommand(ctx, args...)
}

func (m *Manager) createSet(ctx context.Context, addrType string) error {
	iptype := "ipv4_addr"
	if addrType == ip.IP6 {
		iptype = "ipv6_addr"
	}

	args := []string{
		"add",
		"set",
		addrType,
		m.table,
		m.set,
		"{ type " + iptype + " ; flags timeout ; }",
	}

	return m.execCommand(ctx, args...)
}

func (m *Manager) createRule(ctx context.Context, addrType string) error {
	args := []string{
		"add",
		"rule",
		addrType,
		m.table,
		m.chain,
		addrType,
		"saddr",
		"@" + m.set,
		"drop",
	}

	return m.execCommand(ctx, args...)
}

func (m *Manager) ban(ctx context.Context, address string, banDuration string) error {
	addrType, addrTypeErr := ip.AddrType(address)
	if addrTypeErr != nil {
		return addrTypeErr
	}

	if !timeout.IsValid(banDuration) {
		return errors.New("invalid timeout format")
	}

	args := []string{
		"add",
		"element",
		addrType,
		m.table,
		m.set,
		"{ " + address + " timeout " + banDuration + " }",
	}

	return m.execCommand(ctx, args...)
}
