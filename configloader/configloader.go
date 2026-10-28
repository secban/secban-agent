package configloader

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"
	"github.com/rs/zerolog/log"
)

const (
	maxConfigFilePerms = fs.FileMode(0o644)
)

var (
	ErrFileStat = errors.New("failed to stat yaml configuration file")
	ErrFilePerm = errors.New("invalid permissions for yaml configuration file: expected 0644 or lower")
)

// ParseConfig loads and merges configuration using koanf.
// It loads defaultConfig, overlays filePath (if non-empty and exists),
// and overlays all YAML files in scanDirs (if non-empty).
// Directory files are merged under a key derived from each dir (e.g., "rules.d" -> "rules").
func ParseConfig[T any](defaultConfig T, filePath string, scanDirs []string) (T, error) { //nolint:ireturn // Generic config unmarshaling returns caller's type.
	var result T

	instance := koanf.New(".")

	loadDefaultErr := instance.Load(structs.Provider(defaultConfig, "koanf"), nil)
	if loadDefaultErr != nil {
		return result, loadDefaultErr
	}

	if filePath != "" {
		loadFileErr := loadConfigFile(instance, filePath)
		if loadFileErr != nil {
			return result, loadFileErr
		}
	}

	for _, scanDir := range scanDirs {
		if scanDir == "" {
			continue
		}

		loadDirErr := loadConfigDir(instance, scanDir)
		if loadDirErr != nil {
			return result, loadDirErr
		}
	}

	unmarshalErr := instance.UnmarshalWithConf("", &result, koanf.UnmarshalConf{Tag: "koanf"})
	if unmarshalErr != nil {
		return result, unmarshalErr
	}

	return result, nil
}

func loadConfigFile(instance *koanf.Koanf, filePath string) error {
	checkErr := CheckYAMLPermissions(filePath)
	if checkErr != nil {
		return checkErr
	}

	loadErr := instance.Load(file.Provider(filePath), yaml.Parser())
	if loadErr != nil {
		return loadErr
	}

	return nil
}

func loadConfigDir(instance *koanf.Koanf, dirPath string) error {
	entries, readDirErr := os.ReadDir(dirPath)
	if readDirErr != nil {
		if os.IsNotExist(readDirErr) {
			return nil
		}

		return readDirErr
	}

	subKey := deriveSubKey(dirPath)

	for _, entry := range entries {
		if !isYAMLFile(entry) {
			continue
		}

		entryPath := filepath.Join(dirPath, entry.Name())

		loadErr := loadAndMergeDirEntry(instance, entryPath, subKey)
		if loadErr != nil {
			return loadErr
		}
	}

	return nil
}

func isYAMLFile(entry os.DirEntry) bool {
	if entry.IsDir() {
		return false
	}

	name := entry.Name()

	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}

func loadAndMergeDirEntry(instance *koanf.Koanf, entryPath string, subKey string) error {
	checkErr := CheckYAMLPermissions(entryPath)
	if checkErr != nil {
		return checkErr
	}

	subInstance := koanf.New(".")

	loadErr := subInstance.Load(file.Provider(entryPath), yaml.Parser())
	if loadErr != nil {
		return fmt.Errorf("failed to parse %s: %w", entryPath, loadErr)
	}

	mergeErr := instance.MergeAt(subInstance, subKey)
	if mergeErr != nil {
		return fmt.Errorf("failed to merge %s into %s: %w", entryPath, subKey, mergeErr)
	}

	return nil
}

func deriveSubKey(dirPath string) string {
	base := filepath.Base(dirPath)
	clean := strings.TrimSuffix(base, ".d")

	return clean
}

func CheckYAMLPermissions(filePath string) error {
	fileInfo, statErr := os.Stat(filePath)
	if statErr != nil {
		log.Error().
			Str("file", filePath).
			Err(statErr).
			Msg("failed to stat yaml configuration file")

		return fmt.Errorf("%w: %s", ErrFileStat, filePath)
	}

	mode := fileInfo.Mode().Perm()
	if mode > maxConfigFilePerms || mode&^maxConfigFilePerms != 0 {
		log.Error().
			Str("file", filePath).
			Str("permissions", fmt.Sprintf("%#o", mode)).
			Str("max_expected", fmt.Sprintf("%#o", maxConfigFilePerms)).
			Msg("invalid permissions for yaml configuration file: expected 0644 or lower")

		return fmt.Errorf("%w: %s", ErrFilePerm, filePath)
	}

	return nil
}
