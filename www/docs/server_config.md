# Server Configuration

You will need to configure the remote Authorization Server with the settings matching your client configuration. 

## Matching Configuration

You MUST provide the same setting as for your local `config.yaml` (see [Client Configuration](/config)): 

* `client_id`
* `client_secret`
* `auth_method` 
* `scopes` 

## Redirect URI

Default: `http://127.0.0.1:5556/auth/callback`

!!! warning
    You can change the port number of the local client using the `--port` or using a hostname instead of ip using `--localhost` flag. If you do so, you will need to update the redirect_uri on the Authorization Server configuration as well



