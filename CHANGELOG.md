<a name="unreleased"></a>
## [Unreleased]


<a name="v0.19.3"></a>
## [v0.19.3] - 2024-04-01
### Bug Fixes
- 09075fa - dependencies update


<a name="v0.19.2"></a>
## [v0.19.2] - 2024-01-27
### Bug Fixes
- e626762 - update dependencies


<a name="v0.19.1"></a>
## [v0.19.1] - 2023-12-26

<a name="v0.19.0"></a>
## [v0.19.0] - 2023-11-01
### Features
- 84ab65a - optional client_id on token endpoint for private_key_jwt ([#55](https://github.com/vdbulcke/oidc-client-demo/issues/55))


<a name="v0.18.0"></a>
## [v0.18.0] - 2023-10-21
### Features
- 3444088 - add ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW encryption alg ([#51](https://github.com/vdbulcke/oidc-client-demo/issues/51))
- c8abffc - add RSA-OAEP-256 and RSA-OAEP idtoken encryption ([#51](https://github.com/vdbulcke/oidc-client-demo/issues/51))
- 2780f48 - add mTLS client authentication method


<a name="v0.17.0"></a>
## [v0.17.0] - 2023-10-01
### Features
- 5d5858d - add --mock-jwt-kid flag to set a static kid for generated jwt ([#49](https://github.com/vdbulcke/oidc-client-demo/issues/49))


<a name="v0.16.0"></a>
## [v0.16.0] - 2023-09-17
### Code Refactoring
- ce3891a - put go code in src/ directory

### Features
- e99631b - add support for private_key_jwt auth method ([#46](https://github.com/vdbulcke/oidc-client-demo/issues/46)) and signed request parameter ([#47](https://github.com/vdbulcke/oidc-client-demo/issues/47))


<a name="v0.15.0"></a>
## [v0.15.0] - 2023-03-23
### Features
- f363ed0 - add optional 'override_redirect_uri' config ([#41](https://github.com/vdbulcke/oidc-client-demo/issues/41))


<a name="v0.14.0"></a>
## [v0.14.0] - 2023-03-04
### Bug Fixes
- a84a3dd - dependabot security issues ([#42](https://github.com/vdbulcke/oidc-client-demo/issues/42))

### Features
- c4eab5d - add cosign via goreleaser  ([#44](https://github.com/vdbulcke/oidc-client-demo/issues/44))
- a653cf2 - bump go version 1.20


<a name="v0.13.1"></a>
## [v0.13.1] - 2022-10-11
### Bug Fixes
- d61d439 - refresh-token output ([#39](https://github.com/vdbulcke/oidc-client-demo/issues/39))


<a name="v0.13.0"></a>
## [v0.13.0] - 2022-10-08
### Features
- 7ab90b6 - print jwt header ([#37](https://github.com/vdbulcke/oidc-client-demo/issues/37))


<a name="v0.12.0"></a>
## [v0.12.0] - 2022-09-28
### Features
- 5ccf50b - Add mock request capabilities ([#35](https://github.com/vdbulcke/oidc-client-demo/issues/35))
- 1ebd288 - Add additional param on authorize ([#33](https://github.com/vdbulcke/oidc-client-demo/issues/33))


<a name="v0.11.0"></a>
## [v0.11.0] - 2022-09-24
### Features
- 0cd5b18 - Add PAR support ([#31](https://github.com/vdbulcke/oidc-client-demo/issues/31))
- f01908e - add alternative well known ([#31](https://github.com/vdbulcke/oidc-client-demo/issues/31))


<a name="v0.10.0"></a>
## [v0.10.0] - 2022-08-31
### Features
- d49c0a1 - add json output option ([#29](https://github.com/vdbulcke/oidc-client-demo/issues/29))


<a name="v0.9.0"></a>
## [v0.9.0] - 2022-08-19
### Features
- dee346e - add fake-pkce-verifier flag  ([#25](https://github.com/vdbulcke/oidc-client-demo/issues/25))
- bfb5350 - send client_secret with pkce if defined ([#25](https://github.com/vdbulcke/oidc-client-demo/issues/25))


<a name="v0.8.0"></a>
## [v0.8.0] - 2022-06-28
### Features
- 8f1ec6d - add acr validation check ([#23](https://github.com/vdbulcke/oidc-client-demo/issues/23))
- f3895ad - add --acr-values override flag ([#22](https://github.com/vdbulcke/oidc-client-demo/issues/22))


<a name="v0.7.2"></a>
## [v0.7.2] - 2022-06-02
### Bug Fixes
- 0feda69 - Refresh/Access token jwt decode swap ([#20](https://github.com/vdbulcke/oidc-client-demo/issues/20))


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

[Unreleased]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.19.3...HEAD
[v0.19.3]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.19.2...v0.19.3
[v0.19.2]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.19.1...v0.19.2
[v0.19.1]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.19.0...v0.19.1
[v0.19.0]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.18.0...v0.19.0
[v0.18.0]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.17.0...v0.18.0
[v0.17.0]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.16.0...v0.17.0
[v0.16.0]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.15.0...v0.16.0
[v0.15.0]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.14.0...v0.15.0
[v0.14.0]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.13.1...v0.14.0
[v0.13.1]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.13.0...v0.13.1
[v0.13.0]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.12.0...v0.13.0
[v0.12.0]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.11.0...v0.12.0
[v0.11.0]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.10.0...v0.11.0
[v0.10.0]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.9.0...v0.10.0
[v0.9.0]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.8.0...v0.9.0
[v0.8.0]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.7.2...v0.8.0
[v0.7.2]: https://github.com/vdbulcke/oidc-client-demo/compare/v0.7.1...v0.7.2
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
