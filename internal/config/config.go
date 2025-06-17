package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Env              string
	LogLevel         string
	LogPath          string
	MilterPort       string
	ApiPort          string
	DatabaseURL      string
	MaxDBConnections int
	RedisURL         string
	RedisTimeout     time.Duration
	HTTPTimeout      time.Duration
}

func LoadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("error reading config file: %s", err)
	}

	// Load environment variables
	viper.AutomaticEnv()

	cfg := &Config{
		Env:              viper.GetString("env"),
		LogLevel:         viper.GetString("log.level"),
		LogPath:          viper.GetString("log.path"),
		MilterPort:       viper.GetString("milter.port"),
		ApiPort:          viper.GetString("api.port"),
		DatabaseURL:      viper.GetString("database.url"),
		MaxDBConnections: viper.GetInt("database.max_connections"),
		RedisURL:         viper.GetString("redis.url"),
		RedisTimeout:     viper.GetDuration("redis.timeout"),
		HTTPTimeout:      viper.GetDuration("http.timeout"),
	}

	return cfg, nil
}
