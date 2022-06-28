package oidcclient

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/go-playground/validator"
	"gopkg.in/yaml.v3"

	"github.com/vdbulcke/oidc-client-demo/oidc-client/internal"
)

type OIDCClientConfig struct {
	ClientID     string `yaml:"client_id"  validate:"required"`
	ClientSecret string `yaml:"client_secret" `
	AuthMethod   string `yaml:"auth_method"  validate:"required,oneof=client_secret_basic client_secret_post"`

	UsePKCE             bool   `yaml:"use_pkce"`
	PKCEChallengeMethod string `yaml:"pkce_challenge_method"`
	PKCECodeLength      int

	AccessTokenJwt  bool `yaml:"access_token_jwt"`
	RefreshTokenJwt bool `yaml:"refresh_token_jwt"`

	Scopes []string `yaml:"scopes"  validate:"required"`

	AcrValues string `yaml:"acr_values"`

	Issuer string `yaml:"issuer"  validate:"required"`

	TokenEndpoint      string `yaml:"token_endpoint"  `
	AuthorizeEndpoint  string `yaml:"authorize_endpoint"  `
	JwksEndpoint       string `yaml:"jwks_endpoint"`
	IntrospectEndpoint string `yaml:"introspect_endpoint"`

	TokenSigningAlg []string `yaml:"token_signing_alg" validate:"required"`

	AMRWhitelist []string `yaml:"amr_list"`
	ACRWhitelist []string `yaml:"acr_list"`

	RedirectUri string

	// NOTE: default is false
	SkipTLSVerification bool `yaml:"skip_tls_verification"`

	// NOTE: default is false
	SkipUserinfo bool `yaml:"skip_userinfo_call"`

	// Listen Address
	ListenAddress string
	// Listen Port
	ListenPort int
}

// ValidateConfig validate config
func ValidateConfig(config *OIDCClientConfig) bool {

	validate := validator.New()
	errs := validate.Struct(config)

	if config.PKCEChallengeMethod != "" {
		if config.PKCEChallengeMethod != internal.PKCEMethodPlain && config.PKCEChallengeMethod != internal.PKCEMethodS256 {
			fmt.Println("Invalid 'pkce_challenge_method' must be one of 'S256' or 'plain'")
			return false
		}
	}

	if !config.UsePKCE && config.ClientSecret == "" {
		fmt.Println("Error 'client_secret' not set")
		return false
	}

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

	// Set Default PKCE Method if not set
	if config.PKCEChallengeMethod == "" {
		config.PKCEChallengeMethod = internal.PKCEMethodS256
	}

	// set default PKCE Code length
	config.PKCECodeLength = 50

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

	if clientSecret != "" && !config.UsePKCE {
		config.ClientSecret = clientSecret
	}

}
