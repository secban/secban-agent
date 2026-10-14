package dispatcher

import (
	"context"
	"errors"
	"time"

	"github.com/rs/zerolog/log"
	"gitlab.com/thequietbot/secban/secban-agent/action"
	"gitlab.com/thequietbot/secban/secban-agent/ban"
	"gitlab.com/thequietbot/secban/secban-agent/banlog"
	"gitlab.com/thequietbot/secban/secban-agent/ip"
	"gitlab.com/thequietbot/secban/secban-agent/ipc"
	"gitlab.com/thequietbot/secban/secban-agent/offender"
	"gitlab.com/thequietbot/secban/secban-agent/registry"
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

func (d *Dispatcher) Report(ctx context.Context, ip string, rule string, message string) error {
	entry, exists := d.matches[rule]
	if !exists {
		return errors.New("no match found for rule " + rule)
	}

	offender := entry.registry.Add(ip, rule, message)

	log.Debug().
		Str("ip", ip).
		Str("rule", rule).
		Int("count", offender.Count).
		Int("threshold", entry.count).
		Msg("offender reported")

	if offender.Count >= entry.count {
		return d.Act(ctx, ip, rule, message)
	}

	return nil
}

func (d *Dispatcher) Get(ctx context.Context, ip string) (*offender.Offender, error) {
	for _, entry := range d.matches {
		offender, exists := entry.registry.Get(ip)
		if exists && offender.Count > 0 {
			return &offender, nil
		}
	}

	return nil, errors.New("no offender found for IP " + ip)
}

func (d *Dispatcher) Act(ctx context.Context, ip string, rule string, message string) error {
	entry, exists := d.matches[rule]
	if !exists {
		return errors.New("no match found for rule " + rule)
	}

	offender, found := entry.registry.Get(ip)
	if !found {
		offender = entry.registry.Add(ip, rule, message)
	}

	log.Info().
		Str("ip", ip).
		Str("rule", rule).
		Str("timeout", entry.timeout).
		Int("count", offender.Count).
		Msg("triggering ban action")

	banErr := d.banActor.Block(ctx, ip, entry.timeout)
	if banErr != nil {
		return banErr
	}

	if !entry.debounce.ShouldAct(ip) {
		return nil
	}

	// Silently log the ban in the background with a new context.
	if d.withBanLog {
		logCtx := context.WithoutCancel(ctx)
		go banlog.Log(logCtx, rule, offender)
	}

	// Execute custom actions if defined.
	if len(entry.actions) > 0 {
		actionCtx := context.WithoutCancel(ctx)
		go action.ExecuteCustomAction(actionCtx, action.ActionArgs{
			IP:       ip,
			Rule:     rule,
			Offender: offender,
			Actions:  entry.actions,
		})
	}

	// Send IPC messages.
	if len(entry.sockets) > 0 {
		ipcCtx := context.WithoutCancel(ctx)
		go ipc.Message(ipcCtx, ipc.IPCArgs{
			IP:       ip,
			Rule:     rule,
			Offender: offender,
			Sockets:  entry.sockets,
		})
	}

	return banErr
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

func Report(ctx context.Context, address string, rule string, message string) error {
	if dispatcher == nil {
		return errors.New("dispatcher not initialized")
	}

	if !ip.IsValid(address) {
		return errors.New("invalid IP address " + address)
	}

	return dispatcher.Report(ctx, address, rule, message)
}

func Ban(ctx context.Context, address string, rule string, message string) error {
	if dispatcher == nil {
		return errors.New("dispatcher not initialized")
	}

	if !ip.IsValid(address) {
		return errors.New("invalid IP address " + address)
	}

	return dispatcher.Act(ctx, address, rule, message)
}

func Get(ctx context.Context, address string) (*offender.Offender, error) {
	if dispatcher == nil {
		return nil, errors.New("dispatcher not initialized")
	}

	if !ip.IsValid(address) {
		return nil, errors.New("invalid IP address " + address)
	}

	return dispatcher.Get(ctx, address)
}
