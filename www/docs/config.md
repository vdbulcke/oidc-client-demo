# Client Configuration 

You can find a complete example of the client configuration in [example/config.yaml](https://github.com/vdbulcke/oidc-client-demo/blob/main/example/config.yaml).

## Client Authentication Settings


### Client ID and Secret

!!! important 
    Mandatory (either in config file or ENV variables)

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

You must specify the `issuer` setting that will be used for construct the OpenID Connect Discovery Configuration (`/.well-known/openid-configuration`).

```yaml
## IDP Config: (Mandatory)
### NOTE: this 'issuer' will be used to find the /.well-known/openid-configuration 
###       by adding /.well-known/openid-configuration after the issuer base url 
issuer: "https://example.com"
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
