## oidc-client completion bash

Generate the autocompletion script for bash

### Synopsis

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(oidc-client completion bash)

To load completions for every new session, execute once:

#### Linux:

	oidc-client completion bash > /etc/bash_completion.d/oidc-client

#### macOS:

	oidc-client completion bash > /usr/local/etc/bash_completion.d/oidc-client

You will need to start a new shell for this setup to take effect.


```
oidc-client completion bash
```

### Options

```
  -h, --help              help for bash
      --no-descriptions   disable completion descriptions
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

* [oidc-client completion](oidc-client_completion.md)	 - Generate the autocompletion script for the specified shell

###### Auto generated by spf13/cobra on 21-Oct-2023
