package main

import (
	"context"
	"flag"
	"os"
	"path"
	"time"

	"github.com/rs/zerolog/log"
	"gitlab.com/thequietbot/secban/secban-agent/banlog"
	"gitlab.com/thequietbot/secban/secban-agent/db"
	"gopkg.in/yaml.v2"
)

const configFile = "agent.yaml"

type Config struct {
	Database string `yaml:"database"`
}

func main() {
	ctx := context.Background()

	var configDir string

	flag.StringVar(&configDir, "config", "/etc/secban", "path to config directory")
	flag.Parse()

	config, parseErr := parseConfig(configDir)
	if parseErr != nil {
		log.Fatal().Err(parseErr).Msg("Failed to parse config")
	}

	initErr := db.Init(ctx, config.Database)
	if initErr != nil {
		panic(initErr)
	}

	entries, err := banlog.GetAllFrom(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get recent ban entries")
	}

	for _, entry := range entries {
		log.Info().
			Str("ip", entry.IP).
			Time("ban", entry.Ban).
			Str("events", entry.Events).
			Msg("Recent ban entry")
	}
}

func parseConfig(configDir string) (*Config, error) {
	mainConfigPath := path.Join(configDir, configFile)

	var parsed Config

	configData, readErr := os.ReadFile(mainConfigPath)
	if readErr != nil {
		return nil, readErr
	}

	decodeErr := yaml.Unmarshal(configData, &parsed)
	if decodeErr != nil {
		return nil, decodeErr
	}

	return &parsed, nil
}
