package oidcclient

// // newProvider
// func (c *OIDCClient) NewProvider(ctx context.Context) *oidc.Provider {
// 	return &oidc.Provider{
// 		issuer:       c.config.Issuer,
// 		authURL:      c.config.AuthorizeEndpoint,
// 		tokenURL:     c.config.TokenEndpoint,
// 		userInfoURL:  c.config.UserinfoEndpoint,
// 		algorithms:   c.config.TokenSigningAlg,
// 		remoteKeySet: oidc.NewRemoteKeySet(ctx, c.config.JwksEndpoint),
// 	}
// }
