# Install 

You can find the pre-compiled binaries on the release page [https://github.com/vdbulcke/oidc-client-demo/releases](https://github.com/vdbulcke/oidc-client-demo/releases)


## Getting Latest Version 


```sh
TAG=$(curl https://api.github.com/repos/vdbulcke/oidc-client-demo/releases/latest  |jq .tag_name -r )
VERSION=$(echo $TAG | cut -d 'v' -f 2)
```

!!! info
    You will need `jq` and `curl` in your `PATH`

## MacOS 

=== "Intel"
    1. Download the binary  from the [releases](https://github.com/vdbulcke/oidc-client-demo/releases) page:
      ```sh
      curl -LO "https://github.com/vdbulcke/oidc-client-demo/releases/download/${TAG}/oidc-client-demo_${VERSION}_Darwin_x86_64.tar.gz"
      
      ```
    1. Extract Binary:
      ```sh
      tar xzf "oidc-client-demo_${VERSION}_Darwin_x86_64.tar.gz"
      ```
    1. Check Version: 
      ```sh
      ./oidc-client version
      ```
    1. Install in your `PATH`: 
      ```sh
      sudo install oidc-client /usr/local/bin/
      ```
      Or
      ```sh
      sudo mv oidc-client /usr/local/bin/
      ```

=== "ARM (M1)"
    1. Download the binary  from the [releases](https://github.com/vdbulcke/oidc-client-demo/releases) page:
      ```sh
      curl -LO "https://github.com/vdbulcke/oidc-client-demo/releases/download/${TAG}/oidc-client-demo_${VERSION}_Darwin_amr64.tar.gz"
      
      ```
    1. Extract Binary:
      ```sh
      tar xzf "oidc-client-demo_${VERSION}_Darwin_amr64.tar.gz"
      ```
    1. Check Version: 
      ```sh
      ./oidc-client version
      ```
    1. Install in your `PATH`: 
      ```sh
      sudo install oidc-client /usr/local/bin/
      ```
      Or
      ```sh
      sudo mv oidc-client /usr/local/bin/
      ```
=== "Universal Binary"

    1. Download the binary  from the [releases](https://github.com/vdbulcke/oidc-client-demo/releases) page:
      ```sh
      curl -LO "https://github.com/vdbulcke/oidc-client-demo/releases/download/${TAG}/oidc-client-demo_${VERSION}_Darwin_all.tar.gz"
      
      ```
    1. Extract Binary:
      ```sh
      tar xzf "oidc-client-demo_${VERSION}_Darwin_all.tar.gz"
      ```
    1. Check Version: 
      ```sh
      ./oidc-client version
      ```
    1. Install in your `PATH`: 
      ```sh
      sudo install oidc-client /usr/local/bin/
      ```
      Or
      ```sh
      sudo mv oidc-client /usr/local/bin/
      ```



## Linux 


=== "Intel"
    1. Download the binary  from the [releases](https://github.com/vdbulcke/oidc-client-demo/releases) page:
      ```sh
      curl -LO "https://github.com/vdbulcke/oidc-client-demo/releases/download/${TAG}/oidc-client-demo_${VERSION}_Linux_x86_64.tar.gz"
      
      ```
    1. Extract Binary:
      ```sh
      tar xzf "oidc-client-demo_${VERSION}_Linux_x86_64.tar.gz"
      ```
    1. Check Version: 
      ```sh
      ./oidc-client version
      ```
    1. Install in your `PATH`: 
      ```sh
      sudo install oidc-client /usr/local/bin/
      ```
      Or
      ```sh
      sudo mv oidc-client /usr/local/bin/
      ```

=== "ARM"
    1. Download the binary  from the [releases](https://github.com/vdbulcke/oidc-client-demo/releases) page:
      ```sh
      curl -LO "https://github.com/vdbulcke/oidc-client-demo/releases/download/${TAG}/oidc-client-demo_${VERSION}_Linux_amr64.tar.gz"
      
      ```
    1. Extract Binary:
      ```sh
      tar xzf "oidc-client-demo_${VERSION}_Linux_amr64.tar.gz"
      ```
    1. Check Version: 
      ```sh
      ./oidc-client version
      ```
    1. Install in your `PATH`: 
      ```sh
      sudo install oidc-client /usr/local/bin/
      ```
      Or
      ```sh
      sudo mv oidc-client /usr/local/bin/
      ```
      
## Windows 


=== "Intel"
    1. Download the binary `oidc-client-demo_[VERSION]_Windows_x86_64.zip`  from the [releases](https://github.com/vdbulcke/oidc-client-demo/releases) page
     
    1. Unzip the Binary

    1. Check Version: 
      ```sh
      ./oidc-client.exe version
      ```

