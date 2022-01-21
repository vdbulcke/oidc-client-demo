# Troubleshooting

This page regroups some of the most common errors.

## Closing Local Server 

Use `CTL+C` to close the local http server 

```
^C2022-01-21T18:56:07.357+0100 [INFO]  oidc-client: Got signal: sig=interrupt
2022-01-21T18:56:07.358+0100 [INFO]  oidc-client: Server is shuting down: error="http: Server closed"
```

## Configuration Validation Errors

### Missing Mandatory Settings

* example missing client_id, client_secret:
```
oidc-client client --config example/wrong.yaml                                                    
Key: 'OIDCClientConfig.ClientID' Error:Field validation for 'ClientID' failed on the 'required' tag
Key: 'OIDCClientConfig.ClientSecret' Error:Field validation for 'ClientSecret' failed on the 'required' tag
2022-01-21T18:48:47.385+0100 [ERROR] oidc-client: Could not validate config
```

### Incorrect Auth Method 

If `auth_method`  is **not** one of 

* `client_secret_basic`
* `client_secret_post`


```
oidc-client client --config example/wrong.yaml
Key: 'OIDCClientConfig.AuthMethod' Error:Field validation for 'AuthMethod' failed on the 'oneof' tag
2022-01-21T18:50:34.283+0100 [ERROR] oidc-client: Could not validate config
```

## Error Well Known Endpoints

*  invalid format
```
oidc-client client --config example/wrong.yaml
2022-01-21T18:52:25.037+0100 [ERROR] oidc-client: Could create OIDC provider form WellKnown endpoint:
```

## Error Getting Access Token 

* invalid credentials

```
2022-01-21T18:54:51.511+0100 [INFO]  oidc-client: Go to http://127.0.0.1:5556/login
2022-01-21T18:55:14.556+0100 [INFO]  oidc-client: Received AuthZ Code: code=Qe5J0drIVTxMLpwKLOF-Ee-t91M
2022-01-21T18:55:14.578+0100 [ERROR] oidc-client: Failed to get Access Token:
  err=
  | oauth2: cannot fetch token: 400 Bad Request
  | Response: {"error_description":"Invalid authentication method for accessing this endpoint.","error":"invalid_client"}

```

## TLS error 

```
oidc-client client --config example/wrong.yaml 
2022-01-21T18:57:45.955+0100 [ERROR] oidc-client: Could create OIDC provider form WellKnown endpoint: err="Get \"https://expired.badssl.com/oauth2/.well-known/openid-configuration\": x509: certificate has expired or is not yet valid: current time 2022-01-21T18:57:45+01:00 is after 2015-04-12T23:59:59Z"
2022-01-21T18:57:45.955+0100 [ERROR] oidc-client: Error creating client: error="Get \"https://expired.badssl.com/oauth2/.well-known/openid-configuration\": x509: certificate has expired or is not yet valid: current time 2022-01-21T18:57:45+01:00 is after 2015-04-12T23:59:59Z"
```
