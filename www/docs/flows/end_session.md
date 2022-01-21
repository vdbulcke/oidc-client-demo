# End Session


!!! warning 
    EndSession call is not support by the `oidc-client` tool. However this page describe how make the call using `curl` or httpie.


1. Get the `end_session_endpoint` from the Authorization Server's `.well-known/openid-configuration` 
2. Use a previously obtained ID Token to make a call to the `end_session_endpoint`

```
http GET [end_session_endpoint]?id_token_hint=[ID TOKEN]
```

!!! info
    More info [OpenID Connect Session Management 1.0 - draft 10](https://openid.net/specs/openid-connect-session-1_0-10.html)

