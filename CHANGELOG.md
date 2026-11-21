# Changelog

## v4.0.0

### Breaking changes

- **Node.js 22 or later** is required, and `google-auth-library` is updated to v11.
- **`clientID` is required.** `new Strategy(verify)` without options is no longer supported, and the constructor throws if `clientID` (or an explicit `audience`) is missing or empty. Without an audience, tokens issued to any Google application were accepted.
- **Access tokens must be issued to your app.** Their tokeninfo `aud` must be one of `audience` (defaults to `clientID`). Previously any valid Google access token was accepted.
- **Google outages are errors, not failures.** When Google cannot be reached or answers with a server error, the strategy calls `error()` (HTTP 500) instead of `fail()` (HTTP 401). An exception thrown by the verify callback is also reported as an error.
- **Tokens must identify an account.** A token or profile without a `sub` fails authentication. `googleId` is always that `sub` string; it used to fall back to the whole token.
- **Types:** `ParsedToken` and `TokenRequest` describe the verified identity and the request; `audience` is exposed as a `string[]`; `done`, `verifyGoogleIdToken` and `verifyGoogleAccessToken` are no longer public methods.

### Features

- `passReqToCallback: true` now passes the request to the verify callback: `(req, parsedToken, googleId, done)`.
- The id token is read from the `credential` body field posted by Google Identity Services.
- Id tokens can be sent in an `Authorization: Bearer` header, and the `Bearer` scheme is matched case-insensitively.

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