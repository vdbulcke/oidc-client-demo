GIT_COMMIT ?= $(shell git rev-parse --short HEAD)
LD_FLAGS ?= -X main.GitCommit=${GIT_COMMIT}

all: build-linux_amd64 build-windows_amd64 build-windows_386  build-darwin_amd64

	
build-linux_amd64: 
	mkdir -p bin/
	env GOOS=linux GOARCH=amd64 CGO_ENABLED=0  go build -ldflags "${LD_FLAGS}" -o bin/oidc-client_linux_amd64 main.go 
	mkdir -p releases/
	zip releases/oidc-client_linux_amd64.zip bin/oidc-client_linux_amd64
	
build-windows_amd64: 
	mkdir -p bin/
	env GOOS=windows GOARCH=amd64 CGO_ENABLED=0  go build -ldflags "${LD_FLAGS}" -o bin/oidc-client_windows_amd64 main.go 
	mkdir -p releases/
	zip releases/oidc-client_windows_amd64.zip bin/oidc-client_windows_amd64

	
build-windows_386: 
	mkdir -p bin/
	env GOOS=windows GOARCH=386 CGO_ENABLED=0  go build -ldflags "${LD_FLAGS}" -o bin/oidc-client_windows_386 main.go 
	mkdir -p releases/
	zip releases/oidc-client_windows_386.zip bin/oidc-client_windows_386

build-darwin_amd64:
	mkdir -p bin/
	env GOOS=darwin GOARCH=amd64 CGO_ENABLED=0  go build -ldflags "${LD_FLAGS}" -o bin/oidc-client_darwin_amd64 main.go 
	mkdir -p releases/
	zip releases/oidc-client_darwin_amd64.zip bin/oidc-client_darwin_amd64