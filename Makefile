

.PHONY:	scan
scan: 
	go list -json -deps |  nancy sleuth	

.PHONY: build
build: 
	goreleaser build --rm-dist

.PHONY: build-snapshot
build-snapshot: 
	goreleaser build --rm-dist --snapshot


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
	go test -run '' ./oidc-client/

