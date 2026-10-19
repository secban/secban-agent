package dummy

import (
	"context"

	"github.com/rs/zerolog/log"
	"gitlab.com/secban/secban-agent/ban"
)

type Manager struct{}

var _ ban.Actor = (*Manager)(nil)

func New() *Manager {
	return &Manager{}
}

func (*Manager) Block(_ context.Context, ip string, timeout string) error {
	log.Info().Str("ip", ip).Str("timeout", timeout).Msg("Blocking IP with dummy manager")
	return nil
}

func (*Manager) Init(_ context.Context) error {
	log.Info().Msg("Initializing dummy manager")
	return nil
}

func (*Manager) Exit(_ context.Context) error {
	log.Info().Msg("Exiting dummy manager")
	return nil
}

func (*Manager) Flush(_ context.Context) error {
	log.Info().Msg("Flushing dummy manager")
	return nil
}
