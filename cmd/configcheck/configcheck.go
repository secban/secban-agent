package main

import (
	"flag"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gitlab.com/secban/secban-agent/ban/dummy"
	"gitlab.com/secban/secban-agent/config"
	"gitlab.com/secban/secban-agent/dispatcher"
	"gitlab.com/secban/secban-agent/ip"
)

func main() {
	var configDir string

	flag.StringVar(&configDir, "config", "/etc/secban", "path to config directory")
	flag.Parse()

	conf, err := config.LoadConfig(configDir)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to parse config")
	}

	zerolog.SetGlobalLevel(conf.LogLevel)

	banLogEnabled := conf.Database != ""

	_, dispatcherErr := dispatcher.New(conf.Rules, dummy.New(), banLogEnabled)
	if dispatcherErr != nil {
		log.Fatal().Err(dispatcherErr).Msg("failed to create dispatcher")
	}

	_, ipErr := ip.New(conf.AllowList, conf.AllowLocal, conf.AllowLoopback)
	if ipErr != nil {
		log.Fatal().Err(ipErr).Msg("allowlist check failed")
	}

	log.Info().
		Str("log_level", conf.LogLevel.String()).
		Str("ban_method", conf.BanMethod).
		Str("allow_list", conf.AllowList).
		Int("rules", len(conf.Rules)).
		Msg("config check successful")
}
