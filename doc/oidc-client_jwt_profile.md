## oidc-client jwt profile

Generate jwt profile (client_assertion)

```
oidc-client jwt profile [flags]
```

### Options

```
  -c, --config string         oidc client config file
      --endpoint string       OAuth endpoint for 'aud' audiance claims
  -h, --help                  help for profile
      --mock-jwt-kid string   Use static jwt 'kid' value
      --pem-key string        private key (pem format) for jwt signature
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

###### Auto generated by spf13/cobra on 1-Oct-2023