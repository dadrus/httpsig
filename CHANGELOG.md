# Changelog

## [0.9.1](https://github.com/dadrus/httpsig/compare/v0.9.0...v0.9.1) (2026-08-29)


### Dependencies

* update module github.com/dunglas/httpsfv to v1.1.1 ([#142](https://github.com/dadrus/httpsig/issues/142)) ([8ce5985](https://github.com/dadrus/httpsig/commit/8ce598504af0506c883e6a274adb72db774412af))
* update module github.com/stretchr/testify to v1.12.1 ([#143](https://github.com/dadrus/httpsig/issues/143)) ([95e9f49](https://github.com/dadrus/httpsig/commit/95e9f4901c32b5d169775caa30bedffeba30c4b0))

## [0.9.0](https://github.com/dadrus/httpsig/compare/v0.8.0...v0.9.0) (2026-05-15)


### ⚠ BREAKING CHANGES

* have nonce checker make decisions on absence of nonces in signature ([#107](https://github.com/dadrus/httpsig/issues/107))

### Bug Fixes

* have nonce checker make decisions on absence of nonces in signature ([#107](https://github.com/dadrus/httpsig/issues/107)) ([25f319d](https://github.com/dadrus/httpsig/commit/25f319db37f527cdc8060ebfeab09bbec949057b))
* Minor typos in the errors for missing created and updated parameters ([#113](https://github.com/dadrus/httpsig/issues/113)) ([a1ae2ef](https://github.com/dadrus/httpsig/commit/a1ae2efcc6d09f7c19969bf03d5678aa62d596d2))
* NonceChecker adapter function fixed ([#118](https://github.com/dadrus/httpsig/issues/118)) ([aeed528](https://github.com/dadrus/httpsig/commit/aeed528a6dc7cc4f377236411ac358a956304a12))
* Recompute `Content-Digest` header value when signing `content-digest` component ([#116](https://github.com/dadrus/httpsig/issues/116)) ([ebd49e0](https://github.com/dadrus/httpsig/commit/ebd49e07bb01a44be4dc5877c347607d6fcfa206))
* Rejecting duplicate component identifier as required by the RFC ([#119](https://github.com/dadrus/httpsig/issues/119)) ([f7873db](https://github.com/dadrus/httpsig/commit/f7873db1d3493476e90f5dde9b9389318ddd569a))
* Rejecting malformed ECDSA signatures ([#114](https://github.com/dadrus/httpsig/issues/114)) ([44be3a6](https://github.com/dadrus/httpsig/commit/44be3a6a9fe943c3889b9bbaf7e26c878d1d5a56))


### Documentation

* Document Content-Digest body handling and resource limits ([#117](https://github.com/dadrus/httpsig/issues/117)) ([762a89c](https://github.com/dadrus/httpsig/commit/762a89c6b79f60266c61ff35620a48ce988f6f87))
