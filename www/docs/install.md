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



## Verify Signatures With Cosign

!!! info
    Install `cosign` from [sigstore documentation](https://docs.sigstore.dev/cosign/overview/)


* Create a script `verify_signature.sh` 

```bash
#!/bin/bash

if [ -z "$1" ]; then 
    echo "Error: missing articate package as 1st input"
    echo "Usage: "
    echo "  $0 ARTIFACT_PACKAGE TAG"

    exit 1
	
fi

if [ ! -f "$1" ] ; then  
   echo "Error: artifcact $1 does not exists"
   exit 1

fi

artifcat_path=$1
artifact=$(basename $artifcat_path)

if [ -z "$2" ]; then
    echo "Error: missing tag  as 2nd input"
    echo "Usage: "
    echo "  $0 $1  TAG"

    exit 1
        
fi

TAG=$2


echo "Checking Signature for version: ${TAG}"
cosign verify-blob \
  --certificate "https://github.com/vdbulcke/oidc-client-demo/releases/download/${TAG}/${artifact}.pem" \
  --signature "https://github.com/vdbulcke/oidc-client-demo/releases/download/${TAG}/${artifact}.sig"  \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com  \
  --certificate-identity  "https://github.com/vdbulcke/oidc-client-demo/.github/workflows/release.yaml@refs/tags/${TAG}"  \
  ${artifcat_path}


```

* Update executable permission 
```bash
chmod +x ./verify_signature.sh 
```

* Run the script with the _downloaded package_ (or artifact) and _tag version_ as inputs
```bash
./verify_signature.sh ARTIFACT_PACKAGE TAG
```

For example: 
```bash
$ ./verify_signature.sh oidc-client-demo_0.14.0_Linux_x86_64.tar.gz v0.14.0 

Checking Signature for version: v0.14.0
Verified OK
```