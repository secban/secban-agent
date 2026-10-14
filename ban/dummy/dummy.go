package dummy

import (
	"context"

	"github.com/rs/zerolog/log"
	"gitlab.com/thequietbot/secban/secban-agent/ban"
)

type DummyManager struct{}

var _ ban.Actor = (*DummyManager)(nil)

func New() *DummyManager {
	return &DummyManager{}
}

func (n *DummyManager) Block(ctx context.Context, ip string, timeout string) error {
	log.Info().Str("ip", ip).Str("timeout", timeout).Msg("Blocking IP with dummy manager")
	return nil
}

func (n *DummyManager) Init(ctx context.Context) error {
	log.Info().Msg("Initializing dummy manager")
	return nil
}

func (n *DummyManager) Exit(ctx context.Context) error {
	log.Info().Msg("Exiting dummy manager")
	return nil
}

func (n *DummyManager) Flush(ctx context.Context) error {
	log.Info().Msg("Flushing dummy manager")
	return nil
}
