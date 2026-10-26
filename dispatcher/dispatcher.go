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

var dispatcher *Dispatcher //nolint:gochecknoglobals

var ErrNotInitialized = errors.New("dispatcher not initialized")

type Entry struct {
	registry *registry.Registry
	debounce *debounceTracker
	timeouts []string
	actions  []string
	sockets  []string
	count    int
}

type Dispatcher struct {
	banActor   ban.Actor
	matches    map[string]Entry
	withBanLog bool
}

type RuleConfig struct {
	Name       string
	TTL        string
	Timeouts   []string
	Actions    []string
	Sockets    []string
	Count      int
	MaxEntries int
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
		return ErrNotInitialized
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
			timeouts: rule.Timeouts,
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

	o := entry.registry.Add(address, rule, message)

	log.Debug().
		Str("ip", address).
		Str("rule", rule).
		Int("report_count", o.ReportCount).
		Int("threshold", entry.count).
		Msg("offender reported")

	if o.ReportCount >= entry.count {
		return d.Act(ctx, address, rule, message)
	}

	return false, nil
}

func (d *Dispatcher) Get(_ context.Context, address string) (*offender.Offender, error) {
	if !ip.IsValid(address) {
		return nil, errors.New("invalid IP address " + address)
	}

	for _, entry := range d.matches {
		o, exists := entry.registry.Get(address)
		if exists && o.ReportCount > 0 {
			return &o, nil
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

	o, found := entry.registry.Get(address)
	if !found {
		o = entry.registry.Add(address, rule, message)
	}

	timeoutValue := pickTimeout(entry.timeouts, o.BanCount)
	o = entry.registry.IncrementBan(address)

	log.Info().
		Str("ip", address).
		Str("rule", rule).
		Str("timeout", timeoutValue).
		Int("report_count", o.ReportCount).
		Int("ban_count", o.BanCount).
		Msg("triggering ban action")

	banErr := d.banActor.Block(ctx, address, timeoutValue)
	if banErr != nil {
		return false, banErr
	}

	if !entry.debounce.ShouldAct(address) {
		return false, nil
	}

	d.triggerActions(ctx, entry, address, rule, o)

	return false, nil
}

func pickTimeout(timeouts []string, banCount int) string {
	if len(timeouts) == 0 {
		return ""
	}

	if banCount < 0 {
		return timeouts[0]
	}

	if banCount >= len(timeouts) {
		return timeouts[len(timeouts)-1]
	}

	return timeouts[banCount]
}

func (d *Dispatcher) Init(ctx context.Context) error {
	if d.banActor == nil {
		return ErrNotInitialized
	}

	initErr := d.banActor.Init(ctx)
	if initErr != nil {
		return initErr
	}

	return nil
}

func (d *Dispatcher) Exit(ctx context.Context) error {
	if d.banActor == nil {
		return ErrNotInitialized
	}

	return d.banActor.Exit(ctx)
}

func (d *Dispatcher) triggerActions(
	ctx context.Context,
	entry Entry,
	address string,
	rule string,
	o offender.Offender,
) {
	// Silently log the ban in the background with a new context.
	if d.withBanLog {
		logCtx := context.WithoutCancel(ctx)
		go banlog.Log(logCtx, rule, o)
	}

	// Execute custom actions if defined.
	if len(entry.actions) > 0 {
		actionCtx := context.WithoutCancel(ctx)
		go action.ExecuteCustomAction(actionCtx, action.Args{
			IP:       address,
			Rule:     rule,
			Offender: o,
			Actions:  entry.actions,
		})
	}

	// Send IPC messages.
	if len(entry.sockets) > 0 {
		ipcCtx := context.WithoutCancel(ctx)
		go ipc.Send(ipcCtx, ipc.Args{
			IP:       address,
			Rule:     rule,
			Offender: o,
			Sockets:  entry.sockets,
		})
	}
}

func (*Dispatcher) sanitizeMessage(message string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}

		return -1
	}, message)
}

func Report(ctx context.Context, address string, rule string, message string) (bool, error) {
	if dispatcher == nil {
		return false, ErrNotInitialized
	}

	return dispatcher.Report(ctx, address, rule, message)
}

func Ban(ctx context.Context, address string, rule string, message string) (bool, error) {
	if dispatcher == nil {
		return false, ErrNotInitialized
	}

	return dispatcher.Act(ctx, address, rule, message)
}

func Get(ctx context.Context, address string) (*offender.Offender, error) {
	if dispatcher == nil {
		return nil, ErrNotInitialized
	}

	return dispatcher.Get(ctx, address)
}
