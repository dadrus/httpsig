# Changelog

## [0.11.1](https://github.com/dadrus/httpsig/compare/v0.11.0...v0.11.1) (2026-11-07)


### Bug Fixes

* `[@query-param](https://github.com/query-param)` canonicalization corrected according to RFC 9421. ([#198](https://github.com/dadrus/httpsig/issues/198)) ([ed3e595](https://github.com/dadrus/httpsig/commit/ed3e5950a163bc4b6569617d2dc4bf471420b6e3))
* Parsing dictionary fields directly for key components ([#200](https://github.com/dadrus/httpsig/issues/200)) ([8c7ee2d](https://github.com/dadrus/httpsig/commit/8c7ee2d536821357ad4239a51e4828c6939d2cd5))

## [0.11.0](https://github.com/dadrus/httpsig/compare/v0.10.0...v0.11.0) (2026-11-07)


### Features

* Cryptographic agility support ([#187](https://github.com/dadrus/httpsig/issues/187)) ([77420eb](https://github.com/dadrus/httpsig/commit/77420eb76e68e3994dadde009be3d7cb99abf33d))
* New `WithoutMaxAge` option for signature verification ([#186](https://github.com/dadrus/httpsig/issues/186)) ([7805c90](https://github.com/dadrus/httpsig/commit/7805c90cd7ba5accdc1975fa66759a28fecff19f))
* Supporting parsing of `Accept-Signature` header ([#176](https://github.com/dadrus/httpsig/issues/176)) by [@rosylilly](https://github.com/rosylilly) ([a0fcb76](https://github.com/dadrus/httpsig/commit/a0fcb76c5a68e1218d4d0d6de3b08d011393f3a5))


### Bug Fixes

* `"@authority"` canonicalization corrected ([#196](https://github.com/dadrus/httpsig/issues/196)) ([a572b10](https://github.com/dadrus/httpsig/commit/a572b10fd2ae9c723b7dbfbe96f9fa012b7bb583))
* HTTP field value canonicalization corrected ([#195](https://github.com/dadrus/httpsig/issues/195)) ([b6e9ce3](https://github.com/dadrus/httpsig/commit/b6e9ce3633afdececf1c93225a3c2201593d5880))
* Inconsistent handling of -1 between global and tag-specific `WithMaxAge` configurations eliminated ([#185](https://github.com/dadrus/httpsig/issues/185)) ([68bfbba](https://github.com/dadrus/httpsig/commit/68bfbba3caaddbbdcea0bfe3803d8f16475fba8f))
* More compliant component identifier validation according to RFC 9421 ([#192](https://github.com/dadrus/httpsig/issues/192)) ([8ca769e](https://github.com/dadrus/httpsig/commit/8ca769eec7cd78ffed9ba8a07f850b8f19af7f0d))
* Preserving HTTP field value bytes in bs serialization ([#194](https://github.com/dadrus/httpsig/issues/194)) ([50e1c32](https://github.com/dadrus/httpsig/commit/50e1c3261578e3f29fc1e18d42e62e85cd1ba81e))
* Preserving structured field component parameter types ([#180](https://github.com/dadrus/httpsig/issues/180)) ([33d307e](https://github.com/dadrus/httpsig/commit/33d307e80c87676f181cd525ed6762ac5b519950))
* Rejecting negative validity tolerances and eliminate inconsistent handling of -1 between global and tag-specific verifier configurations ([#184](https://github.com/dadrus/httpsig/issues/184)) ([5c43a2d](https://github.com/dadrus/httpsig/commit/5c43a2d88d4a8e54c3c41763062a11af1d62b15c))
* Validating of HTTP field names in component identifiers according to RFC 9110 ([#191](https://github.com/dadrus/httpsig/issues/191)) ([aa6ddba](https://github.com/dadrus/httpsig/commit/aa6ddba4235784f779a619716656a8c5f092b666))


### Documentation

* AGENTS.md added ([#188](https://github.com/dadrus/httpsig/issues/188)) ([1a04722](https://github.com/dadrus/httpsig/commit/1a04722e1e34cd4793e990e02ece08dceeed8ffe))
* SECURITY.md added ([#189](https://github.com/dadrus/httpsig/issues/189)) ([0fdf94e](https://github.com/dadrus/httpsig/commit/0fdf94ef69e51bce6a60943ed33b5758d656d589))

## [0.10.0](https://github.com/dadrus/httpsig/compare/v0.9.0...v0.10.0) (2026-11-05)


### ⚠ BREAKING CHANGES

* Signing and verification API refactored ([#166](https://github.com/dadrus/httpsig/issues/166))

### Features

* Supporting arbitrary signature parameters ([#156](https://github.com/dadrus/httpsig/issues/156)) ([c291c6d](https://github.com/dadrus/httpsig/commit/c291c6de11362f3a651b625f040413b92375cb79))


### Code Refactorings

* Signing and verification API refactored ([#166](https://github.com/dadrus/httpsig/issues/166)) ([bf37e1d](https://github.com/dadrus/httpsig/commit/bf37e1dd8cb67dc6f8f5f8f71a649eb77111aed9))


### Bug Fixes

* Clearing stale `Want-Content-Digest` on component override ([#178](https://github.com/dadrus/httpsig/issues/178)) ([2442d24](https://github.com/dadrus/httpsig/commit/2442d2420b8811e12753f8d1a81fe356fcb4a3ee))
* Comparing complete covered component identifiers ([#179](https://github.com/dadrus/httpsig/issues/179)) ([2612e66](https://github.com/dadrus/httpsig/commit/2612e6677431454a0159907a4029eb12ed6eb0b6))
* Enforcing RSA-PSS salt length during verification ([#177](https://github.com/dadrus/httpsig/issues/177)) ([a84f87c](https://github.com/dadrus/httpsig/commit/a84f87c0d4799377c901318517060ba247988224))
* Ensuring component names are lowercase ([#172](https://github.com/dadrus/httpsig/issues/172)) ([2d41d74](https://github.com/dadrus/httpsig/commit/2d41d7498fecb62b2e58f7ff38e15450ec2fb123))
* Rejecting non-string signature component identifiers ([#171](https://github.com/dadrus/httpsig/issues/171)) ([a29c153](https://github.com/dadrus/httpsig/commit/a29c153a97d8eaf90dde17e88a8be2c557ccd063))
* Rejecting repeated query parameters in [@query-param](https://github.com/query-param) ([#173](https://github.com/dadrus/httpsig/issues/173)) ([c4b0650](https://github.com/dadrus/httpsig/commit/c4b06507c7b34abcf78231fb45d84878694fb630))


### Dependencies

* update golang to v1.26.9 ([#158](https://github.com/dadrus/httpsig/issues/158)) ([d3db29a](https://github.com/dadrus/httpsig/commit/d3db29a894019a6344b13e59d22c4f87b8132edc))
* update module github.com/dunglas/httpsfv to v1.1.2 ([#148](https://github.com/dadrus/httpsig/issues/148)) ([4a9c892](https://github.com/dadrus/httpsig/commit/4a9c892b21eba4e8e50ce3292985106b282754a2))
* update module github.com/stretchr/testify to v1.12.1 ([#143](https://github.com/dadrus/httpsig/issues/143)) ([95e9f49](https://github.com/dadrus/httpsig/commit/95e9f4901c32b5d169775caa30bedffeba30c4b0))

## [0.9.0](https://github.com/dadrus/httpsig/compare/v0.8.0...v0.9.0) (2026-05-15)


### ⚠ BREAKING CHANGES

* have nonce checker make decisions on absence of nonces in signature ([#107](https://github.com/dadrus/httpsig/issues/107))

### Bug Fixes

* have nonce checker make decisions on absence of nonces in signature ([#107](https://github.com/dadrus/httpsig/issues/107)) by [@mariusor](https://github.com/mariusor) ([25f319d](https://github.com/dadrus/httpsig/commit/25f319db37f527cdc8060ebfeab09bbec949057b))
* Minor typos in the errors for missing created and updated parameters ([#113](https://github.com/dadrus/httpsig/issues/113)) by [@mariusor](https://github.com/mariusor) ([a1ae2ef](https://github.com/dadrus/httpsig/commit/a1ae2efcc6d09f7c19969bf03d5678aa62d596d2))
* NonceChecker adapter function fixed ([#118](https://github.com/dadrus/httpsig/issues/118)) ([aeed528](https://github.com/dadrus/httpsig/commit/aeed528a6dc7cc4f377236411ac358a956304a12))
* Recompute `Content-Digest` header value when signing `content-digest` component ([#116](https://github.com/dadrus/httpsig/issues/116)) ([ebd49e0](https://github.com/dadrus/httpsig/commit/ebd49e07bb01a44be4dc5877c347607d6fcfa206))
* Rejecting duplicate component identifier as required by the RFC ([#119](https://github.com/dadrus/httpsig/issues/119)) ([f7873db](https://github.com/dadrus/httpsig/commit/f7873db1d3493476e90f5dde9b9389318ddd569a))
* Rejecting malformed ECDSA signatures ([#114](https://github.com/dadrus/httpsig/issues/114)) ([44be3a6](https://github.com/dadrus/httpsig/commit/44be3a6a9fe943c3889b9bbaf7e26c878d1d5a56))


### Documentation

* Document Content-Digest body handling and resource limits ([#117](https://github.com/dadrus/httpsig/issues/117)) ([762a89c](https://github.com/dadrus/httpsig/commit/762a89c6b79f60266c61ff35620a48ce988f6f87))
