package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"gitlab.com/secban/secban-agent/config"
)

func TestLoadConfigAcceptsActionsSlice(t *testing.T) {
	t.Parallel()

	dir := createConfigDir(t, `
allow_local: true
allow_loopback: true
ban_method: dummy
log_level: debug
rules_default:
  actions:
    - /tmp/default.sh
  ban_duration: 5m
  count: 1
  max_entries: 10
  registry_ttl: 10m
`)

	writeRuleFile(t, dir, "bad.yaml", `
bad:
  actions:
    - /tmp/first.sh
    - /tmp/second.sh
  ban_duration: 5m
  count: 1
  max_entries: 10
  registry_ttl: 10m
`)

	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	assertRuleActions(t, cfg, []string{"/tmp/first.sh", "/tmp/second.sh"})
}

func TestLoadConfigAcceptsStrictPermissions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	databasePath := filepath.Join(dir, "agent.sqlite")
	listenUnix := filepath.Join(dir, "agent.sock")

	agentConfig := "database: " + databasePath + "\nlisten_unix: " + listenUnix + "\nban_method: dummy\nrules_default:\n  count: 1\n  ban_duration: 5m\n  registry_ttl: 10m\n  max_entries: 10\n"

	writeErr := os.WriteFile(filepath.Join(dir, "agent.yaml"), []byte(agentConfig), 0o600)
	if writeErr != nil {
		t.Fatalf("write agent config: %v", writeErr)
	}

	writeErr = os.MkdirAll(filepath.Join(dir, "rules.d"), 0o755)
	if writeErr != nil {
		t.Fatalf("create rules dir: %v", writeErr)
	}

	ruleConfig := "ssh:\n  count: 2\n  ban_duration: 10m\n  registry_ttl: 10m\n  max_entries: 10\n"

	writeErr = os.WriteFile(filepath.Join(dir, "rules.d", "ssh.yaml"), []byte(ruleConfig), 0o600)
	if writeErr != nil {
		t.Fatalf("write rule config: %v", writeErr)
	}

	cfg, loadErr := config.LoadConfig(dir)
	if loadErr != nil {
		t.Fatalf("load config with 0600 perms: %v", loadErr)
	}

	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}
}

func createConfigDir(t *testing.T, agentYAML string) string {
	t.Helper()

	dir := t.TempDir()
	databasePath := filepath.Join(dir, "agent.sqlite")
	listenUnix := filepath.Join(dir, "agent.sock")

	agentConfig := "database: " + databasePath + "\nlisten_unix: " + listenUnix + "\n" + agentYAML

	writeErr := os.WriteFile(filepath.Join(dir, "agent.yaml"), []byte(agentConfig), 0o644)
	if writeErr != nil {
		t.Fatalf("write agent config: %v", writeErr)
	}

	writeErr = os.MkdirAll(filepath.Join(dir, "rules.d"), 0o755)
	if writeErr != nil {
		t.Fatalf("create rules dir: %v", writeErr)
	}

	return dir
}

func writeRuleFile(t *testing.T, dir string, name string, ruleYAML string) {
	t.Helper()

	writeErr := os.WriteFile(filepath.Join(dir, "rules.d", name), []byte(ruleYAML), 0o644)
	if writeErr != nil {
		t.Fatalf("write rule config: %v", writeErr)
	}
}

func assertRuleActions(t *testing.T, cfg *config.Config, want []string) {
	t.Helper()

	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}

	if len(cfg.Rules[0].Actions) != len(want) {
		t.Fatalf("expected %d actions, got %d", len(want), len(cfg.Rules[0].Actions))
	}

	for index, action := range want {
		if cfg.Rules[0].Actions[index] != action {
			t.Fatalf("unexpected actions: %#v", cfg.Rules[0].Actions)
		}
	}
}
