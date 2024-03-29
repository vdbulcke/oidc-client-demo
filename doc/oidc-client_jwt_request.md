## oidc-client jwt request

Generate jwt request parameter

```
oidc-client jwt request [flags]
```

### Options

```
  -a, --acr-values string           override 'acr_values' from config
  -c, --config string               oidc client config file
  -h, --help                        help for request
      --localhost                   use localhost instead of 127.0.0.1
      --mock-code-verifier string   Use static pkce 'code_verifier' value
      --mock-jwt-kid string         Use static jwt 'kid' value
      --mock-nonce string           Use static 'nonce' value
      --mock-state string           Use static 'state' value
      --pem-key string              private key (pem format) for jwt signature
  -p, --port int                    oidc jwtRequest call back port (default 5556)
```

### Options inherited from parent commands

```
  -d, --debug               debug mode enabled
      --no-color            disable color output
  -o, --output              Output results to files
      --output-dir string   Output directory (default ".")
      --skip-userinfo       Skip fetching Userinfo
```

### SEE ALSO

* [oidc-client jwt](oidc-client_jwt.md)	 - Commands for generating request or client_assertion jwt or jwks

###### Auto generated by spf13/cobra on 21-Oct-2023
