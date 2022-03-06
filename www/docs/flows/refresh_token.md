# Refresh Token

## tl;dr

1. Use a previously obtained Refresh Token with the client configuration `config.yaml`:
```
oidc-client refresh-token --config config.yaml  --refresh-token [Refresh Token]
```
1. The client will automatically exchange the Refresh Token for a new Access Token Response, ID Token and fetch the Userinfo
```
[INFO]  oidc-client: Access Token Response:
  Response=
  | {
  |     "access_token": "",
  |     "refresh_token": "",
  |     "scope": "openid profile ",
  |     "id_token": "",
  |     "token_type": "Bearer",
  |     "nonce": "-",
  |     "expires_in_human_readable": ""
  | }
  
[INFO]  oidc-client: IDToken Claims:
  IDTokenClaims=
  | {
  | }
  
[INFO]  oidc-client: Userinfo Claims:
  UserInfoClaims=
  | {
  | }
  
[INFO]  oidc-client: Stopping server

```

## How it works?

The CLI client will parse the config file (`--config`) and fetch the Issuer `.well-known/openid-configuration`. The client will then exchange the Refresh Token (--refresh-token`) for a new Token Response, including a new Access Token, Refresh Token, and ID Token. 

Unless `--skip-id-token-verification` is set, the client will 

1. validate the ID Token Signature against the Authorization Server `jwk_uri`
1. if `amr_list` is configured, validate that _at least one_ of the `amr` from the ID Token is present in the `amr_list`

Unless `--skip-userinfo` is set, the client will use the Access Token obtain to fetch user profile information from the `userinfo` endpoint.

## CLI Usage

```
oidc-client help  refresh-token
```
```                                    
Renew tokens with Refresh Token

Usage:
  oidc-client refresh-token [flags]

Flags:
  -c, --config string                oidc client config file
  -h, --help                         help for refresh-token
      --refresh-token string         Refresh Token
      --skip-id-token-verification   Skip validation of id_token after renewing tokens

Global Flags:
  -d, --debug           debug mode enabled
      --no-color        disable color output
      --skip-userinfo   Skip fetching Userinfo

```