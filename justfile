

scan: 
    trivy fs . --dependency-tree

build: 
	goreleaser build --clean

build-snapshot: 
	goreleaser build --clean --snapshot --single-target


release-skip-publish: 
	goreleaser release --clean --skip=publish,sign

release-snapshot: 
	goreleaser release --clean --skip=publish,sign --snapshot


lint: 
	golangci-lint run ./...

changelog:
	git-chglog -o CHANGELOG.md

test:
	go test -v  ./...

gen-doc:
	dist/oidc-client-demo_linux_amd64_v1/oidc-client documentation --dir ./doc

doc-site: 
	podman  run --rm -it -p 8000:8000 -v ${PWD}/www:/docs:z squidfunk/mkdocs-material 
