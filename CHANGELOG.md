<a name="unreleased"></a>
## [Unreleased]


<a name="v0.7.1"></a>
## [v0.7.1] - 2022-05-20
### Features
- 54f875d - Add userinfo validation ([#18](https://github.com/vdbulcke/oidc-client-demo/issues/18))


<a name="v0.7.0"></a>
## [v0.7.0] - 2022-03-28
### Features
- b180bab - Add --localhost flag for Azure AD [#16](https://github.com/vdbulcke/oidc-client-demo/issues/16)


<a name="v0.6.1"></a>
## [v0.6.1] - 2022-03-11
### Bug Fixes
- 843f6e3 - Graceful shutdown of local http server [#14](https://github.com/vdbulcke/oidc-client-demo/issues/14)


<a name="v0.6.0"></a>
## [v0.6.0] - 2022-03-08
### Features
- 44302cd - Parse Refresh token jwt ([#11](https://github.com/vdbulcke/oidc-client-demo/issues/11))
- 58f4247 - Add decoding and verification of access token as stateless token ([#11](https://github.com/vdbulcke/oidc-client-demo/issues/11))

### NOTE


> Refresh Token validation does not check audience 'aud' claim



> Access token validation does not check audience 'aud' claim



<a name="v0.5.0"></a>
## [v0.5.0] - 2022-03-06
### Features
- d19a16a - Add pkce flow support [#4](https://github.com/vdbulcke/oidc-client-demo/issues/4)
- ff87e4c - Add option to skip userinfo + refactor [#8](https://github.com/vdbulcke/oidc-client-demo/issues/8)


<a name="v0.4.0"></a>
## [v0.4.0] - 2022-02-05
### Code Refactoring
- b65ae79 - refresh token, warning on skip TLS

### Features
- 0880017 - Add introspect command [#3](https://github.com/vdbulcke/oidc-client-demo/issues/3)


<a name="v0.3.0"></a>
## [v0.3.0] - 2022-01-24
### Bug Fixes
- 00d78ee - Remove ignored Userinfo  references [#5](https://github.com/vdbulcke/oidc-client-demo/issues/5)

### Features
- e801e24 - Add option to override jwk [#6](https://github.com/vdbulcke/oidc-client-demo/issues/6)


<a name="v0.2.0"></a>
## [v0.2.0] - 2022-01-18
### Bug Fixes
- 1a670e3 - git-chglog github url in config

### Features
- 17610ac - Add refresh-token command [#2](https://github.com/vdbulcke/oidc-client-demo/issues/2)
- ddcca06 - Add client_secret_post auth option [#1](https://github.com/vdbulcke/oidc-client-demo/issues/1)


<a name="v0.1.0"></a>
## [v0.1.0] - 2022-01-07
### Bug Fixes
- 8b8d37e - goreleaser release config

### Features
- 6acaf4e - Add amr validation
- ead0c22 - Add Cobra  cli
- 22aa244 - Add changelog generation
- e10ea39 - Add Code Linting and scanning
- f9a3d29 - CI Add goreleaser config
- 0de3798 - Add addtoken output + cleanup log


<a name="v0.0.2"></a>
## [v0.0.2] - 2021-07-23

<a name="v0.0.1"></a>
## v0.0.1 - 2021-07-23

[Unreleased]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.7.1...HEAD
[v0.7.1]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.7.0...v0.7.1
[v0.7.0]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.6.1...v0.7.0
[v0.6.1]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.6.0...v0.6.1
[v0.6.0]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.5.0...v0.6.0
[v0.5.0]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.4.0...v0.5.0
[v0.4.0]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.3.0...v0.4.0
[v0.3.0]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.0.2...v0.1.0
[v0.0.2]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.0.1...v0.0.2
