# Home

`oidc-client` is a CLI tool for testing OIDC integration. See CLI docs [here](https://github.com/vdbulcke/oidc-client-demo/blob/main/doc/oidc-client.md) 

## Features

* OIDC Authorization Code flow 
* Provider Discovery (`./well-known/openid-configuration`)
* Token Signature validation (from jwk provider endpoint)
* Client Auth Method (`client_secret_basic`, `client_secret_post`)
* PKCE: Proof Key for Code Exchange [rfc7636](https://datatracker.ietf.org/doc/html/rfc7636)
* Refresh Token Flow
* Userinfo 
* Token Introspection 
* (optional) Pushed Authorization Request ([rfc9126](https://datatracker.ietf.org/doc/html/rfc9126))
* (optional) Acr Values
* (optional) Amr Whitelist

