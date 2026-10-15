package dispatcher

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/rs/zerolog/log"
	"gitlab.com/secban/secban-agent/action"
	"gitlab.com/secban/secban-agent/ban"
	"gitlab.com/secban/secban-agent/banlog"
	"gitlab.com/secban/secban-agent/ip"
	"gitlab.com/secban/secban-agent/ipc"
	"gitlab.com/secban/secban-agent/offender"
	"gitlab.com/secban/secban-agent/registry"
)

var dispatcher *Dispatcher //nolint: gochecknoglobals

type Entry struct {
	registry *registry.Registry
	debounce *debounceTracker
	count    int
	timeout  string
	actions  []string
	sockets  []string
}

type Dispatcher struct {
	withBanLog bool
	banActor   ban.Actor
	matches    map[string]Entry
}

type RuleConfig struct {
	Name       string
	Count      int
	Timeout    string
	TTL        string
	MaxEntries int
	Actions    []string
	Sockets    []string
}

func Init(ctx context.Context, rules []RuleConfig, banActor ban.Actor, withBanLog bool) error {
	var newErr error

	dispatcher, newErr = New(rules, banActor, withBanLog)
	if newErr != nil {
		return newErr
	}

	initErr := dispatcher.Init(ctx)
	if initErr != nil {
		return initErr
	}

	return nil
}

func Exit(ctx context.Context) error {
	if dispatcher == nil {
		return errors.New("dispatcher not initialized")
	}

	return dispatcher.Exit(ctx)
}

func New(rules []RuleConfig, banActor ban.Actor, withBanLog bool) (*Dispatcher, error) {
	newDispatcher := &Dispatcher{
		withBanLog: withBanLog,
		banActor:   banActor,
		matches:    make(map[string]Entry),
	}

	for _, rule := range rules {
		ttl, parseErr := time.ParseDuration(rule.TTL)
		if parseErr != nil {
			return nil, parseErr
		}

		newDispatcher.matches[rule.Name] = Entry{
			registry: registry.New(ttl, rule.MaxEntries),
			debounce: newDebounceTracker(),
			count:    rule.Count,
			timeout:  rule.Timeout,
			actions:  rule.Actions,
			sockets:  rule.Sockets,
		}
	}

	return newDispatcher, nil
}

func (d *Dispatcher) Report(ctx context.Context, address string, rule string, message string) (bool, error) {
	if !ip.IsValid(address) {
		return false, errors.New("invalid IP address " + address)
	}

	if ip.IsAllowed(address) {
		return true, nil
	}

	entry, exists := d.matches[rule]
	if !exists {
		return false, errors.New("no match found for rule " + rule)
	}

	message = d.sanitizeMessage(message)

	offender := entry.registry.Add(address, rule, message)

	log.Debug().
		Str("ip", address).
		Str("rule", rule).
		Int("count", offender.Count).
		Int("threshold", entry.count).
		Msg("offender reported")

	if offender.Count >= entry.count {
		return d.Act(ctx, address, rule, message)
	}

	return false, nil
}

func (d *Dispatcher) Get(ctx context.Context, address string) (*offender.Offender, error) {
	if !ip.IsValid(address) {
		return nil, errors.New("invalid IP address " + address)
	}

	for _, entry := range d.matches {
		offender, exists := entry.registry.Get(address)
		if exists && offender.Count > 0 {
			return &offender, nil
		}
	}

	return nil, errors.New("no offender found for IP " + address)
}

func (d *Dispatcher) Act(ctx context.Context, address string, rule string, message string) (bool, error) {
	if !ip.IsValid(address) {
		return false, errors.New("invalid IP address " + address)
	}

	if ip.IsAllowed(address) {
		return true, nil
	}

	entry, exists := d.matches[rule]
	if !exists {
		return false, errors.New("no match found for rule " + rule)
	}

	message = d.sanitizeMessage(message)

	offender, found := entry.registry.Get(address)
	if !found {
		offender = entry.registry.Add(address, rule, message)
	}

	log.Info().
		Str("ip", address).
		Str("rule", rule).
		Str("timeout", entry.timeout).
		Int("count", offender.Count).
		Msg("triggering ban action")

	banErr := d.banActor.Block(ctx, address, entry.timeout)
	if banErr != nil {
		return false, banErr
	}

	if !entry.debounce.ShouldAct(address) {
		return false, nil
	}

	d.triggerActions(ctx, entry, address, rule, offender)

	return false, nil
}

func (d *Dispatcher) Init(ctx context.Context) error {
	if d.banActor == nil {
		return errors.New("ban actor not initialized")
	}

	initErr := d.banActor.Init(ctx)
	if initErr != nil {
		return initErr
	}

	return nil
}

func (d *Dispatcher) Exit(ctx context.Context) error {
	if d.banActor == nil {
		return errors.New("ban actor not initialized")
	}

	return d.banActor.Exit(ctx)
}

func (d *Dispatcher) triggerActions(
	ctx context.Context,
	entry Entry,
	address string,
	rule string,
	offender offender.Offender,
) {
	// Silently log the ban in the background with a new context.
	if d.withBanLog {
		logCtx := context.WithoutCancel(ctx)
		go banlog.Log(logCtx, rule, offender)
	}

	// Execute custom actions if defined.
	if len(entry.actions) > 0 {
		actionCtx := context.WithoutCancel(ctx)
		go action.ExecuteCustomAction(actionCtx, action.ActionArgs{
			IP:       address,
			Rule:     rule,
			Offender: offender,
			Actions:  entry.actions,
		})
	}

	// Send IPC messages.
	if len(entry.sockets) > 0 {
		ipcCtx := context.WithoutCancel(ctx)
		go ipc.Message(ipcCtx, ipc.IPCArgs{
			IP:       address,
			Rule:     rule,
			Offender: offender,
			Sockets:  entry.sockets,
		})
	}
}

func (d *Dispatcher) sanitizeMessage(message string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}

		return -1
	}, message)
}

func Report(ctx context.Context, address string, rule string, message string) (bool, error) {
	if dispatcher == nil {
		return false, errors.New("dispatcher not initialized")
	}

	return dispatcher.Report(ctx, address, rule, message)
}

func Ban(ctx context.Context, address string, rule string, message string) (bool, error) {
	if dispatcher == nil {
		return false, errors.New("dispatcher not initialized")
	}

	return dispatcher.Act(ctx, address, rule, message)
}

func Get(ctx context.Context, address string) (*offender.Offender, error) {
	if dispatcher == nil {
		return nil, errors.New("dispatcher not initialized")
	}

	return dispatcher.Get(ctx, address)
}
