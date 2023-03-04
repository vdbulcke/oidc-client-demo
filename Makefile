

.PHONY:	scan
scan: 
	go list -json -deps |  nancy sleuth	

.PHONY: build
build: 
	goreleaser build --clean

.PHONY: build-snapshot
build-snapshot: 
	goreleaser build --clean --snapshot --single-target


.PHONY: release-skip-publish
release-skip-publish: 
	goreleaser release --clean --skip-publish  --skip-sign

.PHONY: release-snapshot
release-snapshot: 
	goreleaser release --clean --skip-publish --snapshot --skip-sign


.PHONY: lint
lint: 
	golangci-lint run ./... 


.PHONY: changelog
changelog: 
	git-chglog -o CHANGELOG.md 

.PHONY: test
test: 
	go test -run '' ./oidc-client/ -v
	go test -run '' ./oidc-client/internal/pkce/ -v 
	go test -run '' ./oidc-client/internal/oidc/discovery/ 


.PHONY: gen-doc
gen-doc: 
	dist/oidc-client-demo_linux_amd64/oidc-client documentation --dir ./doc

.PHONY: doc-site
doc-site: 
	podman  run --rm -it -p 8000:8000 -v ${PWD}/www:/docs:z squidfunk/mkdocs-material 
