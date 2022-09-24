package discovery

// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata

type OIDCWellKnownOpenidConfiguration struct {
	Issuer                string `json:"issuer"  validate:"required"`
	AuthorizationEndpoint string `json:"authorization_endpoint"  validate:"required"`
	TokenEndpoint         string `json:"token_endpoint"  validate:"required"`
	JwksUri               string `json:"jwks_uri"  validate:"required"`

	// Optional
	UserinfoEndpoint       string   `json:"userinfo_endpoint"  `
	RegistrationEndpoint   string   `json:"registration_endpoint"  `
	ScopesSupported        []string `json:"scopes_supported"  `
	ResponseTypesSupported []string `json:"response_types_supported"  `
	ResponseModeSupported  []string `json:"response_modes_supported"  `
	GrantTypesSupported    []string `json:"grant_types_supported"  `
	AcrValuesSupported     []string `json:"acr_values_supported"  `
	SubjectTypesSupported  []string `json:"subject_types_supported"  `

	IDTokenSigningAlgValuesSupported    []string `json:"id_token_signing_alg_values_supported"  `
	IDTokenEncryptionAlgValuesSupported []string `json:"id_token_encryption_alg_values_supported"  `
	IDTokenEncryptionEncValuesSupported []string `json:"id_token_encryption_enc_values_supported"  `

	UserinfoSigningAlgValuesSupported    []string `json:"userinfo_signing_alg_values_supported"  `
	UserinfoEncryptionAlgValuesSupported []string `json:"userinfo_encryption_alg_values_supported"  `
	UserinfoEncryptionEncValuesSupported []string `json:"userinfo_encryption_enc_values_supported"  `

	RequestObjectSigningAlgValuesSupported    []string `json:"request_object_signing_alg_values_supported"  `
	RequestObjectEncryptionAlgValuesSupported []string `json:"request_object_encryption_alg_values_supported"  `
	RequestObjectEncryptionEncValuesSupported []string `json:"request_object_encryption_enc_values_supported"  `

	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"  `
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"  `

	DisplayValuesSupported []string `json:"display_values_supported"  `
	ClaimTypesSupported    []string `json:"claim_types_supported"  `
	ClaimsSupported        []string `json:"claims_supported"  `
	ClaimsLocalesSupported []string `json:"claims_locales_supported"  `
	UILocalesSupported     []string `json:"ui_locales_supported"  `

	ClaimsParameterSupported      bool `json:"claims_parameter_supported"  `
	RequestParameterSupported     bool `json:"request_parameter_supported"  `
	RequestURIParameterSupported  bool `json:"request_uri_parameter_supported"  `
	RequireRequestUriRegistration bool `json:"require_request_uri_registration"  `

	OpPolicyUri          string `json:"op_policy_uri"  `
	OpTosUri             string `json:"op_tos_uri"  `
	ServiceDocumentation string `json:"service_documentation" `

	WellKnownRaw map[string]interface{}
}
