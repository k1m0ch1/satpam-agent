package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

type AgentConfig struct {
	ServerURL string `yaml:"server_url"`
	AgentID   string `yaml:"agent_id"`
	OS        string `yaml:"os"`
	Arch      string `yaml:"arch"`
	Interval  string `yaml:"interval"`
	Workers   int    `yaml:"workers"`
}

func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	return filepath.Join(home, ".satpam-agent"), nil
}

func Path() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

// IsFirstRun returns true when ~/.satpam-agent/config.yaml does not exist.
func IsFirstRun() bool {
	p, err := Path()
	if err != nil {
		return true
	}
	_, err = os.Stat(p)
	return os.IsNotExist(err)
}

func Load() (*AgentConfig, error) {
	p, err := Path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg AgentConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

func Save(cfg *AgentConfig) error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	p := filepath.Join(dir, "config.yaml")
	return os.WriteFile(p, data, 0o600)
}

func DetectedOS() string   { return runtime.GOOS }
func DetectedArch() string { return runtime.GOARCH }
