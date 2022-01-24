# Tooling 


## Release: goreleaser

[Goreleaser](https://goreleaser.com/) is used for building, packaging, and releasing new version of the software.


!!! info
    See section "Git" for more details about git commit message

### Making Local Snapshot Build

```
make build-snapshot
```
Or 
```
goreleaser build --rm-dist --snapshot --single-target
```

### Testing Pre-release

```
make release-skip-publish

```
Or

```
goreleaser release --rm-dist --skip-publish
```

## Vulnerability Scanning

[nancy](https://github.com/sonatype-nexus-community/nancy) is used for dependency scanning.

```
make scan
```

## Linting 

[golangci-lint](https://golangci-lint.run/) is used for code linting. 

```
make lint
```

## Changelog Generator

[git-chglog](https://github.com/git-chglog/git-chglog) is used for Changelog generation

```
make changelog
```

!!! info
    See section "Git" for more details about git commit message


## Documentation 

[MkDocs](https://squidfunk.github.io/mkdocs-material/) is used for generating the documentation.
