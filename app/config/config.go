package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	DatabaseURL string `json:"database_url"`
	ServerPort  int    `json:"server_port"`
	LogLevel    string `json:"log_level"`
}

func LoadConfig(filename string) (*Config, error) {
	configFile, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer configFile.Close()

	var config Config
	decoder := json.NewDecoder(configFile)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode config file: %w", err)
	}

	return &config, nil
}

func GetConfigPath() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "config.json"
	}
	return filepath.Join(configDir, "myapp", "config.json")
}
