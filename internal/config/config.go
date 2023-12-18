package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const CallbackURL string = "/callback"

// Config holds the project configuration
type Config struct {
	Host                 string `envconfig:"host" default:"http://localhost"`
	ApiPort              string `envconfig:"port" default:"3009"`
	KeyDIR               string `envconfig:"keydir" default:"./keys"`
	MumbaiSenderDID      string `envconfig:"mumbai_sender_did" default:"0x2C1DdDc4C8b6BdAaE831eF04bF4FfDfA575d8bA7"`
	MainSenderDID        string `envconfig:"main_sender_did" default:"0x2C1DdDc4C8b6BdAaE831eF04bF4FfDfA575d8bA7"`
	IPFSURL              string `envconfig:"ipfs_url" default:"https://gateway.pinata.cloud"`
	ResolverSettingsPath string `envconfig:"resolver_settings_path" default:"./resolvers_settings.yaml"`
	ResolverSettings     ResolverSettings
}

// ResolverSettings holds the resolver settings
type ResolverSettings map[string]map[string]struct {
	ContractAddress string `yaml:"contractAddress"`
	NetworkURL      string `yaml:"networkURL"`
}

// Load loads the configuration from the environment
func Load() (*Config, error) {
	conf := &Config{}
	if err := envconfig.Process("VERIFIER_BACKEND", conf); err != nil {
		return nil, err
	}
	rs, err := parseResolversSettings(conf.ResolverSettingsPath)
	if err != nil {
		log.Error("failed to parse resolvers settings")
		return nil, err
	}
	conf.ResolverSettings = rs
	return conf, nil
}

func parseResolversSettings(resolverSettingsPath string) (ResolverSettings, error) {
	f, err := os.Open(filepath.Clean(resolverSettingsPath))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Println("failed to close setting file:", err)
		}
	}()

	settings := ResolverSettings{}
	if err := yaml.NewDecoder(f).Decode(&settings); err != nil {
		return nil, fmt.Errorf("invalid yaml file: %v", settings)
	}
	return settings, nil
}
