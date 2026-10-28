package configloader_test

import (
	"os"
	"path/filepath"
	"testing"

	"gitlab.com/secban/secban-agent/configloader"
)

type DummyChild struct {
	Value int `koanf:"value"`
}

type DummyConfig struct {
	Children map[string]DummyChild `koanf:"items"`
	Name     string                `koanf:"name"`
	Port     int                   `koanf:"port"`
	Count    int                   `koanf:"count"`
	Enabled  bool                  `koanf:"enabled"`
}

func TestParseConfigWithDefaultOnly(t *testing.T) {
	t.Parallel()

	def := DummyConfig{
		Name: "default-name",
		Port: 8080,
	}

	res, err := configloader.ParseConfig(def, "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Name != "default-name" || res.Port != 8080 {
		t.Fatalf("expected default values, got name=%q port=%d", res.Name, res.Port)
	}
}

func TestParseConfigFileAndDirMerge(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mainFile := filepath.Join(dir, "main.yaml")
	mainContent := `
name: overridden-name
port: 9090
`

	writeErr := os.WriteFile(mainFile, []byte(mainContent), 0o600)
	if writeErr != nil {
		t.Fatalf("write main: %v", writeErr)
	}

	subDir := filepath.Join(dir, "items.d")

	mkdirErr := os.MkdirAll(subDir, 0o755)
	if mkdirErr != nil {
		t.Fatalf("mkdir items.d: %v", mkdirErr)
	}

	itemFile := filepath.Join(subDir, "one.yaml")
	itemContent := `
first:
  value: 42
`

	writeErr = os.WriteFile(itemFile, []byte(itemContent), 0o600)
	if writeErr != nil {
		t.Fatalf("write item: %v", writeErr)
	}

	def := DummyConfig{
		Name: "default-name",
		Port: 8080,
	}

	res, parseErr := configloader.ParseConfig(def, mainFile, []string{subDir})
	if parseErr != nil {
		t.Fatalf("unexpected error: %v", parseErr)
	}

	if res.Name != "overridden-name" {
		t.Errorf("expected name overridden-name, got %q", res.Name)
	}

	if res.Port != 9090 {
		t.Errorf("expected port 9090, got %d", res.Port)
	}

	if len(res.Children) != 1 || res.Children["first"].Value != 42 {
		t.Errorf("expected children first with value 42, got %v", res.Children)
	}
}

func TestParseConfigRejectsInsecurePermissions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mainFile := filepath.Join(dir, "insecure.yaml")

	writeErr := os.WriteFile(mainFile, []byte("name: test\n"), 0o600)
	if writeErr != nil {
		t.Fatalf("write file: %v", writeErr)
	}

	chmodErr := os.Chmod(mainFile, 0o666)
	if chmodErr != nil {
		t.Fatalf("chmod file: %v", chmodErr)
	}

	def := DummyConfig{}

	_, parseErr := configloader.ParseConfig(def, mainFile, nil)
	if parseErr == nil {
		t.Fatal("expected error for insecure file permissions, got nil")
	}
}

func TestParseConfigIntegerDefaultAndZeroOverride(t *testing.T) {
	t.Parallel()

	def := DummyConfig{
		Count: 3,
	}

	dir := t.TempDir()

	// 1. Not provided in file: default value 3 must stick.
	fileWithoutCount := filepath.Join(dir, "no_count.yaml")

	writeErr := os.WriteFile(fileWithoutCount, []byte("name: test\n"), 0o600)
	if writeErr != nil {
		t.Fatalf("write file: %v", writeErr)
	}

	resWithoutCount, errWithoutCount := configloader.ParseConfig(def, fileWithoutCount, nil)
	if errWithoutCount != nil {
		t.Fatalf("unexpected error: %v", errWithoutCount)
	}

	if resWithoutCount.Count != 3 {
		t.Fatalf("expected count=3 when not provided, got %d", resWithoutCount.Count)
	}

	// 2. Explicitly set to 0 in file: count must be 0.
	fileWithZero := filepath.Join(dir, "zero_count.yaml")

	writeErr = os.WriteFile(fileWithZero, []byte("count: 0\n"), 0o600)
	if writeErr != nil {
		t.Fatalf("write file: %v", writeErr)
	}

	resWithZero, errWithZero := configloader.ParseConfig(def, fileWithZero, nil)
	if errWithZero != nil {
		t.Fatalf("unexpected error: %v", errWithZero)
	}

	if resWithZero.Count != 0 {
		t.Fatalf("expected count=0 when set to 0, got %d", resWithZero.Count)
	}
}

func TestParseConfigBoolDefaultAndFalseOverride(t *testing.T) {
	t.Parallel()

	def := DummyConfig{
		Enabled: true,
	}

	dir := t.TempDir()

	// 1. Not provided in file: default true must stick.
	fileWithoutBool := filepath.Join(dir, "no_bool.yaml")

	writeErr := os.WriteFile(fileWithoutBool, []byte("name: test\n"), 0o600)
	if writeErr != nil {
		t.Fatalf("write file: %v", writeErr)
	}

	resWithoutBool, errWithoutBool := configloader.ParseConfig(def, fileWithoutBool, nil)
	if errWithoutBool != nil {
		t.Fatalf("unexpected error: %v", errWithoutBool)
	}

	if !resWithoutBool.Enabled {
		t.Fatalf("expected enabled=true when not provided, got %v", resWithoutBool.Enabled)
	}

	// 2. Explicitly set to false in file: enabled must be false.
	fileWithFalse := filepath.Join(dir, "false_bool.yaml")

	writeErr = os.WriteFile(fileWithFalse, []byte("enabled: false\n"), 0o600)
	if writeErr != nil {
		t.Fatalf("write file: %v", writeErr)
	}

	resWithFalse, errWithFalse := configloader.ParseConfig(def, fileWithFalse, nil)
	if errWithFalse != nil {
		t.Fatalf("unexpected error: %v", errWithFalse)
	}

	if resWithFalse.Enabled {
		t.Fatalf("expected enabled=false when set to false, got %v", resWithFalse.Enabled)
	}
}
