package config

import (
	"gopkg.in/yaml.v3"
	"io/ioutil"
)

// Config represents application configuration loaded from YAML.
type Config struct {
	API struct {
		Addr string `yaml:"addr"`
	} `yaml:"api"`
	Milter struct {
		Addr string `yaml:"addr"`
	} `yaml:"milter"`
	Logging struct {
		Level string `yaml:"level"`
	} `yaml:"logging"`
}

// Load reads the given YAML file into a Config.
func Load(path string) (*Config, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
