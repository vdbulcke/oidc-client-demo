# Token Introspection

!!! warning
  For the `introspect` subcommand the `introspect_endpoint:` is mandatory.

  See [configuration](/oidc-client-demo/config/) for more details.

## tl;dr

1. Use a previously obtained Refresh Token or Access Token with the client configuration `config.yaml`:
```
oidc-client introspect --config config.yaml --token [Token]
```
1. The client will Introspect the Token and display the response from the server
```
[INFO]  oidc-client: Introspect Response:
  Response=
  | {
  |     "active": true,
  |     "scope": "openid profile",
  |     "client_id": "some_client_id",
  |     "username": "alice",
  |     "token_type": "Bearer",
  |     "exp": 1644084182,
  |     "sub": "alice",
  |     "iss": "https://oauth.example.com/oauth2",
  |     "expiry": "2022-02-05T19:03:02+01:00",
  |     "issued_at": "0001-01-01T00:00:00Z",
  |     "not_before": "0001-01-01T00:00:00Z"
  | }
  
[INFO]  oidc-client: Introspect Raw:
  raw=
  | {
  |     "active": true
  | }


```

## How it works?

The CLI client sends the token introspection request to the Authorization Server, based on the config (`config.yaml`). 

It will parse the JSON response according to the [rfc7662](https://datatracker.ietf.org/doc/html/rfc7662#section-2.2) and outputs them in `Introspect Response:`. 

!!! note
  `expiry`, `issued_at` and `not_before` are _not_ standard fields, but they are human readable forms of the corresponding standard fields `exp`, `iat`, `nbf` (respectively) that are expressed at Unix Timestamps.

In some case the Authorization can choose to include additional fields in the token introspection response. For that the _raw_ Introspection Response is displayed under ` Introspect Raw:`. 

## CLI Usage

```
oidc-client help introspect
```
```                                                                                   
Introspect token

Usage:
  oidc-client introspect [flags]

Flags:
  -c, --config string   oidc client config file
  -h, --help            help for introspect
      --token string    Token to introspect

Global Flags:
  -d, --debug      debug mode enabled
      --no-color   disable color output


```