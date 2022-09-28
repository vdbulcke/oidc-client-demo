# oidc-client-demo

`oidc-client` is a CLI tool for testing OIDC integration. See CLI docs [here](https://github.com/vdbulcke/oidc-client-demo/blob/main/doc/oidc-client.md).


## Documentation

The complete documentation is hosted [here](https://vdbulcke.github.io/oidc-client-demo/)

## Features

* OIDC Authorization Code flow 
* Provider Discovery: Based on Issuer (`./well-known/openid-configuration`) or via an alternative endpoint
* Token Signature validation (from jwk provider endpoint)
* Client Auth Method (`client_secret_basic`, `client_secret_post`)
* PKCE: Proof Key for Code Exchange [rfc7636](https://datatracker.ietf.org/doc/html/rfc7636)
* Refresh Token Flow
* Userinfo 
* Token Introspection 
* (optional) Pushed Authorization Request ([rfc9126](https://datatracker.ietf.org/doc/html/rfc9126))
* (optional) Acr Values
* (optional) Amr Whitelist
