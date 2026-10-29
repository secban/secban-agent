package config

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"

	"github.com/rs/zerolog"
	"gitlab.com/secban/secban-agent/ban"
	"gitlab.com/secban/secban-agent/configloader"
	"gitlab.com/secban/secban-agent/db"
	"gitlab.com/secban/secban-agent/dispatcher"
	"gitlab.com/secban/secban-agent/ip"
	"gitlab.com/secban/secban-agent/timeout"
)

const (
	fileName = "agent.yaml"
	rulesDir = "rules.d"
)

type Rule struct {
	BanDuration []string `koanf:"ban_duration"`
	RegistryTTL string   `koanf:"registry_ttl"`
	Actions     []string `koanf:"actions"`
	Sockets     []string `koanf:"sockets"`
	Count       int      `koanf:"count"`
	MaxEntries  int      `koanf:"max_entries"`
}

type RulesDefault struct {
	BanDuration []string `koanf:"ban_duration"`
	RegistryTTL string   `koanf:"registry_ttl"`
	Actions     []string `koanf:"actions"`
	Sockets     []string `koanf:"sockets"`
	Count       int      `koanf:"count"`
	MaxEntries  int      `koanf:"max_entries"`
}

type ParsedConfig struct {
	Rules         map[string]Rule `koanf:"rules"`
	LogLevel      string          `koanf:"log_level"`
	AllowList     string          `koanf:"allow_list"`
	ListenTCP     string          `koanf:"listen_tcp"`
	ListenUnix    string          `koanf:"listen_unix"`
	Profiler      string          `koanf:"profiler"`
	BanMethod     string          `koanf:"ban_method"`
	Database      string          `koanf:"database"`
	RulesDefault  RulesDefault    `koanf:"rules_default"`
	AllowLocal    bool            `koanf:"allow_local"`
	AllowLoopback bool            `koanf:"allow_loopback"`
}

type Config struct {
	AllowList     string
	ListenTCP     string
	ListenUnix    string
	Profiler      string
	BanMethod     string
	Database      string
	Rules         []dispatcher.RuleConfig
	LogLevel      zerolog.Level
	AllowLocal    bool
	AllowLoopback bool
}

func LoadConfig(configDir string) (Config, error) {
	mainConfigPath := path.Join(configDir, fileName)
	rulesPath := path.Join(configDir, rulesDir)

	parsed, parseErr := configloader.ParseConfig(DefaultParsedConfig(), mainConfigPath, []string{rulesPath})
	if parseErr != nil {
		return Config{}, parseErr
	}

	transformed, transformErr := transformConfig(parsed)
	if transformErr != nil {
		return Config{}, transformErr
	}

	return transformed, nil
}

func transformConfig(parsed ParsedConfig) (Config, error) {
	config := Config{
		AllowLocal:    parsed.AllowLocal,
		AllowLoopback: parsed.AllowLoopback,
	}

	if parsed.ListenTCP == "" && parsed.ListenUnix == "" {
		return Config{}, errors.New("at least one of listen_tcp or listen_unix must be specified")
	}

	config.ListenUnix = parsed.ListenUnix
	config.ListenTCP = parsed.ListenTCP
	config.Profiler = parsed.Profiler

	logLevel, logLevelErr := configloader.TransformLogLevel(parsed.LogLevel)
	if logLevelErr != nil {
		return Config{}, logLevelErr
	}

	config.LogLevel = logLevel

	banMethod, banMethodErr := transformBanMethod(parsed.BanMethod)
	if banMethodErr != nil {
		return Config{}, banMethodErr
	}

	config.BanMethod = banMethod

	allowList, allowListErr := transformAllowList(parsed.AllowList)
	if allowListErr != nil {
		return Config{}, allowListErr
	}

	config.AllowList = allowList

	database, databaseErr := transformDatabase(parsed.Database)
	if databaseErr != nil {
		return Config{}, databaseErr
	}

	config.Database = database

	rules, transformErr := transformRules(parsed.Rules, parsed.RulesDefault)
	if transformErr != nil {
		return Config{}, transformErr
	}

	config.Rules = rules

	return config, nil
}

func transformBanMethod(banMethod string) (string, error) {
	if !slices.Contains(ban.Methods(), banMethod) {
		return "", fmt.Errorf("invalid ban method %q", banMethod)
	}

	return banMethod, nil
}

func transformDatabase(databasePath string) (string, error) {
	if databasePath == "" {
		return "", errors.New("database path must be specified")
	}
	// Defer to the database manager for validation.
	loadedDB, loadErr := db.New(context.Background(), databasePath)
	if loadErr != nil {
		return "", loadErr
	}

	schemaErr := db.CreateSchema(context.Background(), loadedDB)
	if schemaErr != nil {
		return "", schemaErr
	}

	closeErr := loadedDB.Close()
	if closeErr != nil {
		return "", closeErr
	}

	return databasePath, nil
}

func transformAllowList(allowList string) (string, error) {
	if allowList == "" {
		return "", nil
	}
	// Defer to the ip manager.
	_, err := ip.New(allowList, false, false)
	if err != nil {
		return "", err
	}

	return allowList, nil
}

func transformRules(
	rules map[string]Rule,
	rulesDefaultConfig RulesDefault,
) ([]dispatcher.RuleConfig, error) {
	transformed := make([]dispatcher.RuleConfig, 0, len(rules))

	for name, rule := range rules {
		transformedRule, err := transformRule(name, rule, rulesDefaultConfig)
		if err != nil {
			return nil, err
		}

		transformed = append(transformed, transformedRule)
	}

	return transformed, nil
}

func transformRule(
	name string,
	rule Rule,
	rulesDefaultConfig RulesDefault,
) (dispatcher.RuleConfig, error) {
	count, countErr := resolveCount(rule.Count, rulesDefaultConfig.Count)
	if countErr != nil {
		return dispatcher.RuleConfig{}, fmt.Errorf("rule %s: %w", name, countErr)
	}

	banDurations, timeoutErr := resolveDurations(rule.BanDuration, rulesDefaultConfig.BanDuration)
	if timeoutErr != nil {
		return dispatcher.RuleConfig{}, fmt.Errorf(
			"rule %s: invalid ban duration: %w",
			name,
			timeoutErr,
		)
	}

	ttl, ttlErr := resolveDuration(rule.RegistryTTL, rulesDefaultConfig.RegistryTTL)
	if ttlErr != nil {
		return dispatcher.RuleConfig{}, fmt.Errorf(
			"rule %s: invalid registry ttl: %w",
			name,
			ttlErr,
		)
	}

	maxEntries, maxEntriesErr := resolveMaxEntries(rule.MaxEntries, rulesDefaultConfig.MaxEntries)
	if maxEntriesErr != nil {
		return dispatcher.RuleConfig{}, fmt.Errorf("rule %s: %w", name, maxEntriesErr)
	}

	return dispatcher.RuleConfig{
		Name:       name,
		Count:      count,
		Timeouts:   banDurations,
		TTL:        ttl,
		MaxEntries: maxEntries,
		Actions:    resolveActions(rule.Actions, rulesDefaultConfig.Actions),
		Sockets:    resolveSockets(rule.Sockets, rulesDefaultConfig.Sockets),
	}, nil
}

func resolveMaxEntries(maxEntries int, defaultMaxEntries int) (int, error) {
	if maxEntries == 0 {
		maxEntries = defaultMaxEntries
	}

	if maxEntries <= 0 {
		return 0, fmt.Errorf("invalid max entries %d", maxEntries)
	}

	return maxEntries, nil
}

func resolveCount(count int, defaultCount int) (int, error) {
	if count == 0 {
		count = defaultCount
	}

	if count <= 0 {
		return 0, fmt.Errorf("invalid count %d", count)
	}

	return count, nil
}

func resolveActions(actions []string, defaultActions []string) []string {
	if len(actions) > 0 {
		return actions
	}

	return defaultActions
}

func resolveSockets(sockets []string, defaultSockets []string) []string {
	if len(sockets) == 0 {
		sockets = defaultSockets
	}

	return sockets
}

func resolveDuration(duration string, defaultDuration string) (string, error) {
	if duration == "" {
		duration = defaultDuration
	}

	if !timeout.IsValid(duration) {
		return "", fmt.Errorf("invalid duration %q", duration)
	}

	return duration, nil
}

func resolveDurations(durations []string, defaultDurations []string) ([]string, error) {
	if len(durations) == 0 {
		durations = defaultDurations
	}

	if len(durations) == 0 {
		return nil, errors.New("ban duration must be specified")
	}

	for _, d := range durations {
		if !timeout.IsValid(d) {
			return nil, fmt.Errorf("invalid duration %q", d)
		}
	}

	return durations, nil
}
