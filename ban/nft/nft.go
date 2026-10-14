package nft

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"

	"gitlab.com/thequietbot/secban/secban-agent/ban"
	"gitlab.com/thequietbot/secban/secban-agent/ip"
	"gitlab.com/thequietbot/secban/secban-agent/timeout"
)

const (
	table  = "secban"
	chain  = "bounce"
	set    = "offenders"
	nftCmd = "/usr/sbin/nft"
)

type NftCommand struct {
	Table string
	Chain string
	Set   string
	Cmd   string
}

type NftManager struct {
	lock         sync.Mutex
	table        string
	chain        string
	set          string
	nftCmd       string
	addressTypes []string
}

var _ ban.Actor = (*NftManager)(nil)

func New() *NftManager {
	return &NftManager{
		table:        table,
		chain:        chain,
		set:          set,
		nftCmd:       nftCmd,
		addressTypes: []string{"ip", "ip6"},
	}
}

func (n *NftManager) Block(ctx context.Context, ip string, timeout string) error {
	return n.ban(ctx, ip, timeout)
}

func (n *NftManager) Init(ctx context.Context) error {
	return n.Flush(ctx)
}

func (n *NftManager) Exit(ctx context.Context) error {
	return n.cleanupTables(ctx)
}

func (n *NftManager) Flush(ctx context.Context) error {
	cleanupErr := n.cleanupTables(ctx)
	if cleanupErr != nil {
		return cleanupErr
	}

	return n.initTables(ctx)
}

func (n *NftManager) execCommand(ctx context.Context, args ...string) error {
	n.lock.Lock()
	defer n.lock.Unlock()

	//#nosec G204 // We control the arguments and context.
	execCmd := exec.CommandContext(ctx, n.nftCmd, args...)

	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	runErr := execCmd.Run()
	if runErr != nil {
		return runErr
	}

	return nil
}

func (n *NftManager) cleanupTables(ctx context.Context) error {
	for _, addrType := range n.addressTypes {
		args := []string{
			"destroy",
			"table",
			addrType,
			n.table,
		}

		runErr := n.execCommand(ctx, args...)
		if runErr != nil {
			return runErr
		}
	}

	return nil
}

func (n *NftManager) initTables(ctx context.Context) error {
	for _, addrType := range n.addressTypes {
		tableErr := n.createTable(ctx, addrType)
		if tableErr != nil {
			return tableErr
		}

		chainErr := n.createChain(ctx, addrType)
		if chainErr != nil {
			return chainErr
		}

		setErr := n.createSet(ctx, addrType)
		if setErr != nil {
			return setErr
		}

		ruleErr := n.createRule(ctx, addrType)
		if ruleErr != nil {
			return ruleErr
		}
	}

	return nil
}

func (n *NftManager) createTable(ctx context.Context, addrType string) error {
	args := []string{
		"add",
		"table",
		addrType,
		n.table,
	}

	return n.execCommand(ctx, args...)
}

func (n *NftManager) createChain(ctx context.Context, addrType string) error {
	args := []string{
		"add",
		"chain",
		addrType,
		n.table,
		n.chain,
		"{ type filter hook input priority -10 ; }",
	}

	return n.execCommand(ctx, args...)
}

func (n *NftManager) createSet(ctx context.Context, addrType string) error {
	iptype := "ipv4_addr"
	if addrType == "ip6" {
		iptype = "ipv6_addr"
	}

	args := []string{
		"add",
		"set",
		addrType,
		n.table,
		n.set,
		"{ type " + iptype + " ; flags timeout ; }",
	}

	return n.execCommand(ctx, args...)
}

func (n *NftManager) createRule(ctx context.Context, addrType string) error {
	args := []string{
		"add",
		"rule",
		addrType,
		n.table,
		n.chain,
		addrType,
		"saddr",
		"@" + n.set,
		"drop",
	}

	return n.execCommand(ctx, args...)
}

func (n *NftManager) ban(ctx context.Context, address string, duration string) error {
	addrType, addrTypeErr := ip.AddrType(address)
	if addrTypeErr != nil {
		return addrTypeErr
	}

	if !timeout.IsValid(duration) {
		return errors.New("invalid timeout format")
	}

	args := []string{
		"add",
		"element",
		addrType,
		n.table,
		n.set,
		"{ " + address + " timeout " + duration + " }",
	}

	return n.execCommand(ctx, args...)
}
