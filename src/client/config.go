package oidcclient

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/creasty/defaults"
	"github.com/go-playground/validator"
	"gopkg.in/yaml.v3"

	"github.com/vdbulcke/oauthx"
	client_http "github.com/vdbulcke/oidc-client-demo/src/client/http"
)

type OIDCClientConfig struct {
	ClientID     string `yaml:"client_id"  validate:"required"`
	ClientSecret string `yaml:"client_secret" `
	AuthMethod   string `yaml:"auth_method"  validate:"required,oneof=none client_secret_basic client_secret_post private_key_jwt tls_client_auth"`

	ClientIDParamForTokenEndpoint bool `yaml:"always_set_client_id_for_token_endpoint" default:"false"`

	UsePKCE             bool   `yaml:"use_pkce"`
	PKCEChallengeMethod string `yaml:"pkce_challenge_method"`
	PKCECodeLength      int
	FakePKCEVerifier    bool

	AccessTokenJwt  bool `yaml:"access_token_jwt"`
	RefreshTokenJwt bool `yaml:"refresh_token_jwt"`

	Scopes   []string `yaml:"scopes"  validate:"required"`
	Audience []string `yaml:"audiences"`

	AcrValues string `yaml:"acr_values"`

	Issuer string `yaml:"issuer"  validate:"required"`

	Claims      string `yaml:"oidc_claims_param"`
	ParseClaims *oauthx.OpenIdRequestedClaimsParam

	AuthorizationDetailsInput string `yaml:"authorization_details"`
	AuthorizationDetails      oauthx.AuthorizationDetails

	TokenEndpoint                string `yaml:"token_endpoint"  `
	AuthorizeEndpoint            string `yaml:"authorize_endpoint"  `
	UserinfoEndpoint             string `yaml:"userinfo_endpoint"  `
	JwksEndpoint                 string `yaml:"jwks_endpoint"`
	IntrospectEndpoint           string `yaml:"introspect_endpoint"`
	PAREndpoint                  string `yaml:"par_endpoint"`
	EndSessionEndpoint           string `yaml:"endsession_endpoint"`
	RevocationEndpoint           string `yaml:"revocation_endpoint"`
	AlternativeWellKnownEndpoint string `yaml:"alternative_wellknown_endpoint"`
	InsecureWellKnownEndpoint    bool   `yaml:"insecure_wellknown_endpoint"`

	UsePAR                            bool              `yaml:"use_par"`
	PARIntrospectEndpointWellKnownKey string            `yaml:"par_endpoint_wellknown_key"`
	PARAdditionalParameter            map[string]string `yaml:"par_additional_parameters"`
	AuthorizeAdditionalParameter      map[string]string `yaml:"authorize_additional_parameters"`

	TokenSigningAlg    []string `yaml:"token_signing_alg" validate:"required"`
	TokenEncryptionAlg []string `yaml:"token_encryption_alg" validate:"dive,oneof=ECDH-ES RSA-OAEP RSA-OAEP-256 ECDH-ES+A128KW ECDH-ES+A192KW ECDH-ES+A256KW"`

	AllowNonCompliantAmr bool     `yaml:"allow_non_compliant_amr" default:"false"`
	AMRWhitelist         []string `yaml:"amr_list"`
	ACRWhitelist         []string `yaml:"acr_list"`

	RedirectUri string `yaml:"override_redirect_uri"`

	UseRequestParameter             bool                   `yaml:"use_request_parameter" default:"false"`
	StrictOIDCAndRCF6749Param       bool                   `yaml:"strict_oidc_rcf6749_param" default:"false"`
	LegacyRequestJwtHeaderType      bool                   `yaml:"legacy_request_jwt_header_type" default:"false"`
	JwtProfileTokenDuration         time.Duration          `yaml:"jwt_profile_token_duration" default:"5m"`
	JwtProfileAudiance              string                 `yaml:"jwt_profile_token_audiance" `
	JwtProfilePARAudiance           string                 `yaml:"jwt_profile_par_endpoint_audiance" `
	JwtProfileTokenAudiance         string                 `yaml:"jwt_profile_token_endpoint_audiance" `
	JwtProfileRevocationAudiance    string                 `yaml:"jwt_profile_revocation_endpoint_audiance" `
	JwtProfileIntrospectionAudiance string                 `yaml:"jwt_profile_introspection_endpoint_audiance" `
	JwtProfileEndpointAsAudiance    bool                   `yaml:"jwt_profile_endpoint_audiance" default:"false"`
	JwtRequestTokenDuration         time.Duration          `yaml:"jwt_request_token_duration" default:"5m"`
	JwtRequestAudiance              string                 `yaml:"jwt_request_token_audiance" `
	JwtRequestAdditionalParameter   map[string]interface{} `yaml:"jwt_request_token_additional_parameters"`
	JwtSigningAlg                   string                 `yaml:"jwt_signing_alg" default:"RS256" validate:"required,oneof=ES256 ES384 ES512 RS256 RS384 RS512"`

	HttpClientConfig *client_http.HttpClientConfig `yaml:"http_client_config"  `
	// Mock
	MockState        string
	MockNonce        string
	MockCodeVerifier string

	// keep server running during authorizaiton code flow
	//
	KeepRunning bool

	// Output
	OutputEnabled       bool
	OutputDir           string
	AccessTokenRespFile string
	IDTokenFile         string
	AccessTokenFile     string
	RefreshTokenFile    string
	UserinfoFile        string
	IntrospectFile      string

	// NOTE: default is false
	SkipTLSVerification bool `yaml:"skip_tls_verification"`

	// NOTE: default is false
	SkipUserinfo bool `yaml:"skip_userinfo_call"`

	// Listen Address
	ListenAddress string
	// Listen Port
	ListenPort int
}

func (c *OIDCClientConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// source: https://stackoverflow.com/questions/56049589/what-is-the-way-to-set-default-values-on-keys-in-lists-when-unmarshalling-yaml-i
	// set default
	err := defaults.Set(c)
	if err != nil {
		return err
	}

	type plain OIDCClientConfig

	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}

	return nil
}

// ValidateConfig validate config
func ValidateConfig(config *OIDCClientConfig) bool {

	validate := validator.New()
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("yaml"), ",", 2)[0]

		if name == "-" {
			return ""
		}

		return name
	})

	errs := validate.Struct(config)

	if config.PKCEChallengeMethod != "" {
		if config.PKCEChallengeMethod != "plain" && config.PKCEChallengeMethod != "S256" {
			fmt.Println("Invalid 'pkce_challenge_method' must be one of 'S256' or 'plain'")
			return false
		}
	}

	// if !config.UsePKCE && config.ClientSecret == "" {
	// 	fmt.Println("Error 'client_secret' not set")
	// 	return false
	// }

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
	data, err := io.ReadAll(file)
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
		config.PKCEChallengeMethod = "S256"
	}

	if config.Claims != "" {

		var claims oauthx.OpenIdRequestedClaimsParam
		err = json.Unmarshal([]byte(config.Claims), &claims)
		if err != nil {
			return nil, fmt.Errorf("oidc claims: parse error %w", err)
		}

		config.ParseClaims = &claims

	}

	if config.AuthorizationDetailsInput != "" {
		var authDetails oauthx.AuthorizationDetails
		err = json.Unmarshal([]byte(config.AuthorizationDetailsInput), &authDetails)
		if err != nil {
			return nil, fmt.Errorf("rfc9396 authotization_details: parse error %w", err)
		}

		config.AuthorizationDetails = authDetails

	}

	// set default PKCE Code length
	config.PKCECodeLength = 50

	// Handle default
	if config.HttpClientConfig == nil {
		config.HttpClientConfig = client_http.NewDefaultHttpClientCfg()
	}
	config.HttpClientConfig.InsecureSkipVerify = config.SkipTLSVerification

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
