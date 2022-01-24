package oidcclient

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/go-playground/validator"
	"gopkg.in/yaml.v2"
)

type OIDCClientConfig struct {
	ClientID     string `yaml:"client_id"  validate:"required"`
	ClientSecret string `yaml:"client_secret" validate:"required"`
	AuthMethod   string `yaml:"auth_method"  validate:"required,oneof=client_secret_basic client_secret_post"`

	Scopes []string `yaml:"scopes"  validate:"required"`

	AcrValues string `yaml:"acr_values"`

	Issuer string `yaml:"issuer"  validate:"required"`

	TokenEndpoint     string `yaml:"token_endpoint"  `
	AuthorizeEndpoint string `yaml:"authorize_endpoint"  `
	UserinfoEndpoint  string `yaml:"userinfo_endpoint" `
	JwksEndpoint      string `yaml:"jwks_endpoint"`

	TokenSigningAlg []string `yaml:"token_signing_alg" validate:"required"`

	AMRWhitelist []string `yaml:"amr_list"`

	RedirectUri string

	// NOTE: default is false
	SkipTLSVerification bool `yaml:"skip_tls_verification"`

	// Listen Address
	ListenAddress string
	// Listen Port
	ListenPort int
}

// ValidateConfig validate config
func ValidateConfig(config *OIDCClientConfig) bool {

	validate := validator.New()
	errs := validate.Struct(config)

	if errs == nil {
		return true
	}

	for _, e := range errs.(validator.ValidationErrors) {
		fmt.Println(e)
	}

	return false

}

// ParseConfig Parse config file
func ParseConfig(configFile string) (*OIDCClientConfig, error) {

	file, err := os.Open(configFile)
	if err != nil {
		return nil, err
	}

	defer file.Close()
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	config := OIDCClientConfig{}

	err = yaml.Unmarshal([]byte(data), &config)
	if err != nil {
		return nil, err
	}

	// override properties with env variable if declared
	parseEnv(&config)

	// return Parse config struct
	return &config, nil

}

// parseEnv Parse config file
func parseEnv(config *OIDCClientConfig) {

	clientID := os.Getenv("OIDC_CLIENT_ID")
	clientSecret := os.Getenv("OIDC_CLIENT_SECRET")

	if clientID != "" {
		config.ClientID = clientID
	}

	if clientSecret != "" {
		config.ClientSecret = clientSecret
	}

}
