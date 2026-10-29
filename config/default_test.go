package config_test

import (
	"path/filepath"
	"reflect"
	"testing"

	"gitlab.com/secban/secban-agent/config"
	"gitlab.com/secban/secban-agent/configloader"
)

func TestDefaultConfigDrift(t *testing.T) {
	t.Parallel()

	defaultCfg, emptyLoadErr := configloader.ParseConfig(
		config.DefaultParsedConfig(),
		"",
		nil,
	)
	if emptyLoadErr != nil {
		t.Fatalf("load default config: %v", emptyLoadErr)
	}

	mainConfigPath := filepath.Join("default", "agent.yaml")
	rulesDirPath := filepath.Join("default", "rules.d")

	fileCfg, fileLoadErr := configloader.ParseConfig(
		config.ParsedConfig{},
		mainConfigPath,
		[]string{rulesDirPath},
	)
	if fileLoadErr != nil {
		t.Fatalf("load config from default folder: %v", fileLoadErr)
	}

	if !reflect.DeepEqual(defaultCfg, fileCfg) {
		t.Fatalf("configuration drift detected between code defaults and config/default folder:\ncode: %#v\nfile: %#v", defaultCfg, fileCfg)
	}
}
