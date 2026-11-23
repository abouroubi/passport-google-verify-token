# Changelog

## [4.0.1](https://github.com/abouroubi/passport-google-verify-token/compare/v4.0.0...v4.0.1) (2026-11-23)


### Bug Fixes

* **strategy:** report every done() call to passport like other strategies ([b763983](https://github.com/abouroubi/passport-google-verify-token/commit/b7639832ef1b10ddb2934ab741b0c6aa81840b9d))
* **strategy:** report every done() call to passport like other strategies ([941cfbd](https://github.com/abouroubi/passport-google-verify-token/commit/941cfbd2ab5e547fff279b1556d62b48f8894541))

## [4.0.0](https://github.com/abouroubi/passport-google-verify-token/compare/v3.0.5...v4.0.0) (2026-11-22)


### ⚠ BREAKING CHANGES

* report google outages as errors instead of 401
* require a client id and check access token audience
* type the strategy's public api
* require node 22 and move tests to vitest

### Features

* enhance GoogleTokenStrategy with type definitions and improved error handling ([0aec481](https://github.com/abouroubi/passport-google-verify-token/commit/0aec48186fbf379df8126966745f88b5b733f1c2))
* pass the request to verify when passReqToCallback is set ([256138c](https://github.com/abouroubi/passport-google-verify-token/commit/256138ceec8114b4c8583842e23029fb58e20ff4))
* read id tokens from credential field and bearer header ([b234061](https://github.com/abouroubi/passport-google-verify-token/commit/b23406182b6b8457625eefa51dd9cab1f1cc0c1f))


### Bug Fixes

* report google outages as errors instead of 401 ([6e19a62](https://github.com/abouroubi/passport-google-verify-token/commit/6e19a62d133efb8496f057cec8f61e1cddd1f80b))
* require a client id and check access token audience ([97fcfae](https://github.com/abouroubi/passport-google-verify-token/commit/97fcfae3eac9a3f351cb7521d622856280908286))
* **strategy:** keep token contents out of id token failure messages ([9c1a09c](https://github.com/abouroubi/passport-google-verify-token/commit/9c1a09c3ed5f2f55b53afdc33bf28e637c1ddf64))
* **strategy:** settle each authentication exactly once ([313df9e](https://github.com/abouroubi/passport-google-verify-token/commit/313df9e91e9fd682a8ffc269c2f1e99a7d58d5b2))


### Miscellaneous Chores

* require node 22 and move tests to vitest ([2718a67](https://github.com/abouroubi/passport-google-verify-token/commit/2718a670ba2753c61dad5475d4d6b0a19ecf6039))


### Code Refactoring

* type the strategy's public api ([70344ac](https://github.com/abouroubi/passport-google-verify-token/commit/70344acbc783404990f9837ef44816fdc9140ea9))

## v3.0.1 – v3.0.5

Dependency updates, and fixes for the access token flow and tests.

## v3.0.0

Adds the ability to verify idTokens OR accessTokens.

### Breaking Changes
Update `google-auth-library` to version 8.7.0

Validate `acces_token` as parameter with `googleAuthClient.getTokenInfo` instead of `googleAuthClient.verifyIdToken`


## v2.0.0

Well hello 2.0 🎉 

### Breaking Changes

#### Update Google Auth Library
Update `google-auth-library` to version 7.0.4


## v1.x
Initial release
