package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

const (
	DefaultTimeout = 20 * time.Second
)

type Config struct {
	Token       string        `json:"token"`
	DaemonAddr  string        `json:"daemon_addr"`
	DaemonToken string        `json:"daemon_token"`
	StatePath   string        `json:"state_path"`
	Timeout     time.Duration `json:"timeout"`
}

func Default() Config {
	return Config{
		Timeout: DefaultTimeout,
	}
}

func DefaultConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		home, herr := os.UserHomeDir()
		if herr != nil || home == "" {
			return "./discli.json"
		}
		return filepath.Join(home, ".config", "discli", "config.json")
	}
	return filepath.Join(dir, "discli", "config.json")
}

func DefaultDaemonAddr() string {
	return "127.0.0.1:54889"
}

func DefaultStatePath() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		home, herr := os.UserHomeDir()
		if herr != nil || home == "" {
			return "./discli-state.json"
		}
		return filepath.Join(home, ".config", "discli", "state.json")
	}
	return filepath.Join(dir, "discli", "state.json")
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	return cfg, nil
}

func Save(path string, cfg Config) error {
	if path == "" {
		return errors.New("config path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func ApplyEnv(cfg *Config) {
	if cfg == nil {
		return
	}
	if v := os.Getenv("DISCLI_TOKEN"); v != "" {
		cfg.Token = v
	}
	if v := os.Getenv("DISCLI_DAEMON_ADDR"); v != "" {
		cfg.DaemonAddr = v
	}
	if v := os.Getenv("DISCLI_DAEMON_TOKEN"); v != "" {
		cfg.DaemonToken = v
	}
	if v := os.Getenv("DISCLI_STATE_PATH"); v != "" {
		cfg.StatePath = v
	}
	if v := os.Getenv("DISCLI_TIMEOUT"); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil {
			cfg.Timeout = parsed
		}
	}
}

func ApplyDefaults(cfg *Config) {
	if cfg == nil {
		return
	}
	if cfg.DaemonAddr == "" {
		cfg.DaemonAddr = DefaultDaemonAddr()
	}
	if cfg.StatePath == "" {
		cfg.StatePath = DefaultStatePath()
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
}
