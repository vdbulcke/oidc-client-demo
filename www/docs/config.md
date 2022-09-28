# Client Configuration 

You can find a complete example of the client configuration in [example/config.yaml](https://github.com/vdbulcke/oidc-client-demo/blob/main/example/config.yaml).

## Client Authentication Settings


### Client ID and Secret

!!! important 
    Mandatory (either in config file or ENV variables) **unless** using pkce flow. In which case the `client_secret` is not required.

    See section [PKCE](https://vdbulcke.github.io/oidc-client-demo/config/#pkce).

The OIDC client credentials can be passed either in the main `config.yaml` config file, or as environment variables. 

#### Config File

```yaml
## Client Credentials: (Mandatory)
### NOTE: those client_id/client_secret can be passed
###       as environment variables with: 
###
###    export OIDC_CLIENT_ID=my_client_id
###    export OIDC_CLIENT_SECRET=my_client_secret
###
client_id: my_client_id
client_secret: my_client_secret
```

#### Env Variables

```bash
export OIDC_CLIENT_ID=my_client_id
export OIDC_CLIENT_SECRET=my_client_secret
```


### Client Authentication Method

!!! important 
    Mandatory setting

Client authentication method MUST be one of 

* `client_secret_basic`: ClientID/ClientSecret are passed as Basic Authentication Header.
* `client_secret_post`: ClientID/ClientSecret are passed in the POST body as `application/x-www-form-urlencoded` parameters.


```yaml
## Client Auth Method: (Mandatory)
###  Since version v0.2.0
### Supported Auth Method
###  * client_secret_basic (Using Basic Auth Header)
###  * client_secret_post  (Using POST request)
auth_method: client_secret_basic
```

## PKCE

!!! note 
    Optional Settings

Set `use_pkce: true` to enable the Authorization Code Flow with PKCE. 


```yaml
## PKCE Flow: (Optional)
### Since version v0.5.0
### Enabled PKCE Flow
# use_pkce: true
```

!!! info
    `auth_method` needs to be set to `client_secret_post` when using PKCE.

    More information about pkce can be found [https://www.oauth.com/oauth2-servers/pkce/](https://www.oauth.com/oauth2-servers/pkce/).

#### Pkce Challenge Method

!!! note 
    Optional Settings


```yaml
### Supported challenge method 
###  * S256 (Recommended) Default if not specified
###  * plain 
# pkce_challenge_method: S256
```

## Pushed Authorization Request (PAR)

!!! note 
    Optional Settings (default disable)

Set `use_par: true` to send the Pushed Authorization Request to the Authorization Server, when doing the Authorization Code Flow. 

```yaml
## PAR (optional)
###  since v0.11.0
###  Sends a Pushed Authorization Request to 
###  Authorization Server, and redirect the user 
###  to the Authorization endpoint with a 'request_uri'.
### 
###  By default, the par endpoint is discovered from the 
###  well-known endpoint 'pushed_authorization_request_endpoint'.
###
###  reference: rfc9126
### Enable PAR
# use_par: true 
### Override PAR endpoint
# par_endpoint: "https://example.com/par"
### Custom key (other than 'pushed_authorization_request_endpoint') on well known endpoint 
# par_endpoint_wellknown_key: "par_endpoint"
### Arbitrary Key/Value parameters to include in PAR request
# par_additional_parameters: 
#   foo:  bar 
#   hello: world

```

By default, the PAR endpoint of the Authorization Server is derived from the Well Known endpoint via the `pushed_authorization_request_endpoint` property ([rfc9126#section-5](https://datatracker.ietf.org/doc/html/rfc9126#section-5)).

The PAR request sent by `oidc-client` contains the same parameters as the typical Authorization request (including extensions like PKCE, ACR Values). The `oidc-client` will display the PAR response (`request_uri`, and `expires_in`) on the terminal, and will **only** sends the received `request_uri` and `client_id` when redirecting the user to the Authorization endpoint (going to `http://127.0.0.1:5556/login`).

### Non Standard PAR Endpoint

If your Authorization Server uses another property than `pushed_authorization_request_endpoint` on its Well Known endpoint, you can set `par_endpoint_wellknown_key: "custom_par_endpoint_property"`. 

If your Authorization Server does not exposes the PAR endpoint at all on its Well Known endpoint, you can specify it via `par_endpoint: "https://example.com/par"`. 

### Additional Parameters In PAR Request

If your Authorization Server supports additional parameters on its PAR endpoints, you can specify a map of Key/Value with

```yaml
## Format Map[string]string
par_additional_parameters: 
  foo:  bar 
  hello: world
```

!!!important
    As defined in [rfc9126#section-3](https://datatracker.ietf.org/doc/html/rfc9126#section-3), if the `request` parameter is specified as `par_additional_parameters` all others parameter than `["request", "client_id", "client_secret", "client_assertion_type", "client_assertion"]` will be removed from the PAR request. 

!!!Info
    Use the `--debug` to see the PAR request payload.

## Scopes

!!! important 
    Mandatory setting

You can update the list of scopes requested using the `scopes` setting:

```yaml
## Scopes: (Mandatory)
scopes:
- openid
- profile
```


## Authorization Server 

### Issuer (and well-known configuration)

!!! important 
    Mandatory setting

You must specify the `issuer` setting that will be used to construct the OpenID Connect Discovery Configuration (`/.well-known/openid-configuration`).

```yaml
## IDP Config: (Mandatory)
### NOTE: this 'issuer' will be used to find the /.well-known/openid-configuration 
###       by adding /.well-known/openid-configuration after the issuer base url 
issuer: "https://example.com"
```

### Alternative Well Known 

!!! note 
    Optional Settings 

If you Authorization Server exposes a non compliant Well Known endpoint (i.e. not on the same domain as the `issuer`), you can specify an alternative urls via `alternative_wellknown_endpoint`, and you can disable Well Known endpoint validation with `insecure_wellknown_endpoint: true`.

```yaml
## Alternative Well-Known (Optional)
###  since v0.11.0 
### 
# alternative_wellknown_endpoint: ""
### Disable well known endpoint validation
# insecure_wellknown_endpoint: true

```


### Token Introspection Endpoint

!!! warning 
    Mandatory setting for the `oidc-client introspect` subcommand. 

    See [Token Introspection](/oidc-client-demo/flows/introspect/) for more info.

You must specify the `introspect_endpoint` setting that will be used for token introspection request to the Authorization Server.
```yaml
## Introspect: (Mandatory for 'introspect sub command')
## 
introspect_endpoint: "https://example.com/introspect"
```



### Overriding Authorization Server Endpoints

!!! note 
    Optional Settings

If you need to override some endpoints from the discovery `.well-known/openid-configuration` build from the issuer, you have the option of setting those endpoints: 

* `token_endpoint`: endpoint used for getting Access Token
* `authorize_endpoint`: endpoint used for the Authorization code flow
* `jwks_endpoint`: endpoint used for getting JSON Web Keys for signature validation

```yaml
## Override Token endpoint: (Optional)
###   You can override some endpoints after they are fetched from ./well-known/openid-configuration
### 
# token_endpoint: "https://example.com/oauth2/access_token"
# authorize_endpoint: "https://example.com/oauth2/authorize"
# jwks_endpoint: "https://example.com/oauth2/jwk.json"
```

### Skip Userinfo Call

!!! note 
    Optional Settings

Some Authorization Servers returns all the claims directly in the ID Token, or some don't even support the userinfo_endpoint. For those reasons, if you don't need to make the extra userinfo call, you can disable it by setting `skip_userinfo_call: true`.

```yaml
## Skip Userinfo: (Optional)
###   Disable call to userinfo endpoint
# skip_userinfo_call: true
```

!!!tip
    This parameter can be overridden at run time by passing `--skip-userinfo` flags for the `oidc-client client` and `oidc-client refresh-token` sub commands. 


## Security 

### Token Signing Algorithms

!!! important 
    Mandatory setting

You can list the signing algorithms that the client support for validating token signatures.

```yaml
## Token Signature Alg: (Mandatory)
###   List allowed signing algorithm for token validation
token_signing_alg: 
- "RS256"
```

!!! note
    The tokens will be validated against the `jwks_uri` metadata value from the Authorization Server `.well-known/openid-configuration`

### TLS Settings

#### Skip TLS Validation
!!! note 
    Optional Settings


```yaml
## TLS Setting: (Optional)
###   Disable TLS certificate validation
# skip_tls_verification: true
```

## Advanced Settings

### ACR Values
!!! note 
    Optional Settings

If your Authorization Server supports multiple authentication methods, you specify `acr_values` during the authorization endpooint call with:  

```yaml
## Acr Values: (Optional)
# acr_values: "urn:be:fedict:iam:fas:citizen:Level100"
```


### Additional Parameters In Authorization Request
!!! note 
    Optional Settings



If your Authorization Server supports additional parameters on its authorization endpoint, you can specify a map of Key/Value with

```yaml
## Authorize Request Additional Param (optional)
### since version 0.12.0
### 
### Arbitrary Key/Value parameters to include in Authorize request
### format map[string]string
authorize_additional_parameters:
  claims: '{"id_token": {"foo": {"values": ["bar", "baz"]}}}'
```

!!!tip
    You can also use this to override default generated parameter (like `redirect_uri`). 


### AMR Validation

!!! note 
    Optional Settings

If your Authorization Server supports multiple authentication methods, and sets the `amr` field in the id_token, you can validate allowed value with the `amr_list` setting. The client will validate that **at least one** of the configured amr value from the `amr_list` is present in the `amr` field from the id_token. 


```yaml
## AMR List: (Optional)
###  List of allowed amr value, the validation
###  will be successful if a least one of the amr
###  in the list if present in the token
# amr_list: 
# - eid
# - bmid
# - urn:be:fedict:iam:fas:Level500
# - urn:be:fedict:iam:fas:Level450
```

### ACR Validation

!!! note 
    Optional Settings

If your Authorization Server supports Authentication Context Class Reference, and sets the `acr` field in the id_token, you can validate allowed value with the `acr_list` setting. The client will validate that the value of the `acr` claim in the id_token is present in the `amr_list`. 


```yaml
## ACR List: (Optional)
### Since v0.8.0
###  List of allowed acr value, the validation
###  will be successful if 'acr' claim from id_token
###  is present in this list
###
# acr_list: 
# - "0" ## detault when acr are not implemented 
# - urn:be:fedict:iam:fas:Level500
# - urn:be:fedict:iam:fas:Level450
# - urn:be:fedict:iam:fas:Level400
# - urn:be:fedict:iam:fas:Level350
# - urn:be:fedict:iam:fas:Level200
# - urn:be:fedict:iam:fas:Level100

```


### Stateless (JWT) Access Token

!!! note 
    Optional Settings


Stateless Access Token are in JWT format that contains some information, and thus do not need to be introspected.

By setting `access_token_jwt: true` the `oidc-client` will attempt to validate the Access Token jwt signature against the JWKS endpoint of the Authorization Server, and then print the content of the Access Token.

```yaml
##  Access Token JWT: (Optional)
###   Parse and Validate access token jwt
# access_token_jwt: true
```

!!! warning
    Unlike for the ID Token, only basic JWT signature and issuer (`iss`) are validated

### Stateless (JWT) Refresh Token

!!! note 
    Optional Settings


Stateless Refresh Token are in JWT format that contains some information, and thus do not need to be introspected.

By setting `refresh_token_jwt: true` the `oidc-client` will attempt to validate the Refresh Token jwt signature against the JWKS endpoint of the Authorization Server, and then print the content of the Refresh Token.

```yaml
##  Refresh Token JWT: (Optional)
###   Parse and Validate refresh token jwt
# refresh_token_jwt: true
```

!!! warning
    Unlike for the ID Token, only basic JWT signature and issuer (`iss`) are validated
