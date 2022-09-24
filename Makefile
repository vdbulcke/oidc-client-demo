

.PHONY:	scan
scan: 
	go list -json -deps |  nancy sleuth	

.PHONY: build
build: 
	goreleaser build --rm-dist

.PHONY: build-snapshot
build-snapshot: 
	goreleaser build --rm-dist --snapshot --single-target


.PHONY: release-skip-publish
release-skip-publish: 
	goreleaser release --rm-dist --skip-publish 

.PHONY: release-snapshot
release-snapshot: 
	goreleaser release --rm-dist --skip-publish --snapshot


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
