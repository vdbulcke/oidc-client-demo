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
* (optional) Support JWT Access and Refresh Token decoding
* (optional) Outputs response, decoded JWT as json (see [oidc opa policies](https://github.com/vdbulcke/oidc-client-policies))
* (optional) Additional authorization parameters: [claims](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter), `ui_locales`, etc.
* (optional) Signed JWT `request` parameters (#47)
* (optional) `private_key_jwt` (`client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer`) Auth Method (#46)


## Install 

See [Install Documenation](https://vdbulcke.github.io/oidc-client-demo/install/).

### Validate Signature With Cosign

Make sure you have `cosign` installed locally (see [Cosign Install](https://docs.sigstore.dev/cosign/installation/)).


Then you can use the `./verify_signature.sh` in this repo: 

```bash
./verify_signature.sh PATH_TO_DOWNLOADED_ARCHIVE TAG_VERSION
```
for example
```bash
$ ./verify_signature.sh ~/Downloads/oidc-client-demo_0.15.0_Linux_x86_64.tar.gz v0.15.0

Checking Signature for version: v0.15.0
Verified OK

```