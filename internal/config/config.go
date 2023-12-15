package config

import "github.com/kelseyhightower/envconfig"

// Config holds the project configuration
type Config struct {
	ApiPort string `envconfig:"port" default:"3009"`
	KeyDIR  string `envconfig:"keydir" default:"./keys"`
}

// Load loads the configuration from the environment
func Load() (*Config, error) {
	conf := &Config{}
	if err := envconfig.Process("VERIFIER_BACKEND", conf); err != nil {
		return nil, err
	}
	return conf, nil
}
