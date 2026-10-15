package config

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gitlab.com/thequietbot/secban/secban-agent/ban"
	"gitlab.com/thequietbot/secban/secban-agent/db"
	"gitlab.com/thequietbot/secban/secban-agent/dispatcher"
	"gitlab.com/thequietbot/secban/secban-agent/ip"
	"gitlab.com/thequietbot/secban/secban-agent/timeout"
	"gopkg.in/yaml.v2"
)

const (
	fileName     = "agent.yaml"
	rulesDir     = "rules.d"
	maxFilePerms = fs.FileMode(0o644)
)

type Rule struct {
	Count       int      `yaml:"count"`
	BanDuration string   `yaml:"ban_duration"`
	RegistryTTL string   `yaml:"registry_ttl"`
	MaxEntries  int      `yaml:"max_entries"`
	Actions     []string `yaml:"actions"`
	Sockets     []string `yaml:"sockets"`
}

type RulesDefault struct {
	Count       int      `yaml:"count"`
	BanDuration string   `yaml:"ban_duration"`
	RegistryTTL string   `yaml:"registry_ttl"`
	MaxEntries  int      `yaml:"max_entries"`
	Actions     []string `yaml:"actions"`
	Sockets     []string `yaml:"sockets"`
}

type ParsedConfig struct {
	LogLevel      string       `yaml:"log_level"`
	AllowList     string       `yaml:"allow_list"`
	AllowLocal    bool         `yaml:"allow_local"`
	AllowLoopback bool         `yaml:"allow_loopback"`
	RulesDefault  RulesDefault `yaml:"rules_default"`
	ListenTCP     string       `yaml:"listen_tcp"`
	ListenUnix    string       `yaml:"listen_unix"`
	BanMethod     string       `yaml:"ban_method"`
	Database      string       `yaml:"database"`
}

type Config struct {
	Rules         []dispatcher.RuleConfig
	LogLevel      zerolog.Level
	AllowList     string
	AllowLocal    bool
	AllowLoopback bool
	ListenTCP     string
	ListenUnix    string
	BanMethod     string
	Database      string
}

func LoadConfig(configDir string) (*Config, error) {
	parsed, parseErr := parseConfig(configDir)
	if parseErr != nil {
		return nil, parseErr
	}

	config := Config{
		AllowLocal:    parsed.AllowLocal,
		AllowLoopback: parsed.AllowLoopback,
	}

	if parsed.ListenTCP == "" && parsed.ListenUnix == "" {
		return nil, errors.New("at least one of listen_tcp or listen_unix must be specified")
	}

	config.ListenUnix = parsed.ListenUnix
	config.ListenTCP = parsed.ListenTCP

	logLevel, logLevelErr := parseLogLevel(parsed.LogLevel)
	if logLevelErr != nil {
		return nil, logLevelErr
	}

	config.LogLevel = logLevel

	banMethod, banMethodErr := parseBanMethod(parsed.BanMethod)
	if banMethodErr != nil {
		return nil, banMethodErr
	}

	config.BanMethod = banMethod

	allowList, allowListErr := parseAllowList(parsed.AllowList)
	if allowListErr != nil {
		return nil, allowListErr
	}

	config.AllowList = allowList

	database, databaseErr := parseDatabase(parsed.Database)
	if databaseErr != nil {
		return nil, databaseErr
	}

	config.Database = database

	rules, loadRulesErr := loadRules(configDir, parsed.RulesDefault)
	if loadRulesErr != nil {
		return nil, loadRulesErr
	}

	config.Rules = rules

	return &config, nil
}

func parseConfig(configDir string) (*ParsedConfig, error) {
	mainConfigPath := path.Join(configDir, fileName)

	checkYAMLPermissions(mainConfigPath)

	var parsed ParsedConfig

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

func checkYAMLPermissions(filePath string) {
	fileInfo, statErr := os.Stat(filePath)
	if statErr != nil {
		log.Fatal().
			Str("file", filePath).
			Err(statErr).
			Msg("failed to stat yaml configuration file")
	}

	mode := fileInfo.Mode().Perm()
	if mode > maxFilePerms || mode&^maxFilePerms != 0 {
		log.Fatal().
			Str("file", filePath).
			Str("permissions", fmt.Sprintf("%#o", mode)).
			Str("max_expected", fmt.Sprintf("%#o", maxFilePerms)).
			Msg("invalid permissions for yaml configuration file: expected 0644 or lower")
	}
}

func parseLogLevel(logLevel string) (zerolog.Level, error) {
	if logLevel == "" {
		logLevel = "info"
	}

	parsedLevel, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		return zerolog.Disabled, err
	}

	return parsedLevel, nil
}

func parseBanMethod(banMethod string) (string, error) {
	if !slices.Contains(ban.Methods(), banMethod) {
		return "", fmt.Errorf("invalid ban method %q", banMethod)
	}

	return banMethod, nil
}

func parseDatabase(databasePath string) (string, error) {
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

func parseAllowList(allowList string) (string, error) {
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

func loadRules(configDir string, rulesDefault RulesDefault) ([]dispatcher.RuleConfig, error) {
	rulesMap, loadRulesErr := parseRules(configDir)
	if loadRulesErr != nil {
		return nil, loadRulesErr
	}

	transformedRules, transformRulesErr := transformRules(
		rulesMap,
		rulesDefault,
	)
	if transformRulesErr != nil {
		return nil, transformRulesErr
	}

	return transformedRules, nil
}

func parseRules(configDir string) (map[string]Rule, error) {
	dirRules, readDirErr := readYAMLDir[Rule](filepath.Join(configDir, rulesDir))
	if readDirErr != nil {
		return nil, readDirErr
	}

	return dirRules, nil
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

	timeout, timeoutErr := resolveDuration(rule.BanDuration, rulesDefaultConfig.BanDuration)
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
		Timeout:    timeout,
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

func readYAMLDir[T any](dirPath string) (map[string]T, error) {
	result := make(map[string]T)

	entries, readDirErr := os.ReadDir(dirPath)
	if readDirErr != nil {
		if os.IsNotExist(readDirErr) {
			return result, nil
		}

		return nil, readDirErr
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}

		filePath := filepath.Join(dirPath, name)

		checkYAMLPermissions(filePath)

		data, readFileErr := os.ReadFile(filePath)
		if readFileErr != nil {
			return nil, readFileErr
		}

		var items map[string]T

		unmarshalErr := yaml.Unmarshal(data, &items)
		if unmarshalErr != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", filePath, unmarshalErr)
		}

		maps.Copy(result, items)
	}

	return result, nil
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
