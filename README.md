# passport-google-verify-token

[![npm version](https://img.shields.io/npm/v/passport-google-verify-token.svg)](https://www.npmjs.com/package/passport-google-verify-token)
[![License](https://img.shields.io/npm/l/passport-google-verify-token.svg)](LICENSE)

[Passport](https://www.passportjs.org/) strategy that authenticates requests carrying a Google **id token** or **access token**, verified server side with the official [Google Auth Library](https://github.com/googleapis/google-auth-library-nodejs).

Use it when a client (a mobile app, a single-page app, Google Identity Services) signs the user in with Google and sends the resulting token to your API.

## Installation

```bash
npm install passport-google-verify-token
```

Requires Node.js 22 or later.

## Usage

### Configure the strategy

```js
const { Strategy: GoogleTokenStrategy } = require('passport-google-verify-token');

passport.use(
  new GoogleTokenStrategy(
    {
      // The OAuth client ID of your app, or an array when several clients
      // (web, Android, iOS) call your API.
      clientID: process.env.GOOGLE_CLIENT_ID,
    },
    (parsedToken, googleId, done) => {
      User.findOrCreate({ googleId }, (err, user) => done(err, user));
    },
  ),
);
```

`parsedToken` holds the verified identity: the claims of an id token, or the [userinfo profile](https://developers.google.com/identity/openid-connect/openid-connect#obtainuserinfo) of an access token (`sub`, `email`, `email_verified`, `name`, `picture`, …). `googleId` is its `sub`, the account's stable Google user id.

TypeScript:

```ts
import { Strategy as GoogleTokenStrategy, type VerifyFunction } from 'passport-google-verify-token';

const verify: VerifyFunction = (parsedToken, googleId, done) => {
  /* ... */
};
passport.use(new GoogleTokenStrategy({ clientID: ['WEB_CLIENT_ID', 'IOS_CLIENT_ID'] }, verify));
```

#### Options

| Option              | Description                                                                                                                                       |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `clientID`          | **Required.** Your OAuth client ID, or an array of them. The strategy throws at startup if it is missing or empty.                                |
| `audience`          | Acceptable token audiences when they differ from `clientID`. Both id tokens and access tokens must have been issued to one of them.             |
| `passReqToCallback` | When `true`, the verify callback receives the request first: `(req, parsedToken, googleId, done)`.                                                |

### Authenticate requests

```js
app.post('/auth/google', passport.authenticate('google-verify-token', { session: false }), (req, res) => {
  res.json(req.user);
});
```

### Sending the token

The strategy looks for a token in this order:

1. `id_token` in the body, query string, headers or route params;
2. `credential` in the body, the field [Google Identity Services](https://developers.google.com/identity/gsi/web) posts the id token in;
3. `access_token` in the body, query string, headers or route params;
4. an `Authorization: Bearer <token>` header, holding either an id token or an access token.

```http
POST /auth/google
Content-Type: application/json

{ "id_token": "eyJhbGciOiJSUzI1NiIs..." }
```

```http
GET /auth/google
Authorization: Bearer ya29.a0AfH6SM...
```

If you use Google Identity Services in redirect mode (`data-login_uri`), Google also posts a `g_csrf_token` that you should compare with the `g_csrf_token` cookie before this strategy runs.

### How tokens are verified

- **Id tokens** are verified locally: signature against Google's published certificates, issuer, expiry and audience.
- **Access tokens** are checked with Google's tokeninfo endpoint, which must report an allowed audience, and the user's profile is then fetched from the userinfo endpoint.

A missing or rejected token fails authentication with `401`. If Google cannot be reached or answers with a server error, the strategy reports an error instead (Passport answers `500`), so an outage is never mistaken for a bad token.

When a token is rejected, the strategy passes Passport an info object whose `message` says why, such as `id token has expired`. It never contains the token or its claims, so it is safe to log, but show end users a generic message.

## Migrating from v3

- **Node.js 22 or later** is required, and `google-auth-library` is updated to v11.
- **`clientID` is required.** `new Strategy(verify)` without options is no longer supported, and the constructor throws if `clientID` (or an explicit `audience`) is missing or empty. Without an audience, tokens issued to any Google application were accepted.
- **Access tokens must be issued to your app.** Their tokeninfo `aud` must be one of `audience` (defaults to `clientID`). Previously any valid Google access token was accepted.
- **Google outages are errors, not failures.** When Google cannot be reached or answers with a server error, the strategy calls `error()` (HTTP 500) instead of `fail()` (HTTP 401). An exception thrown by the verify callback is also reported as an error.
- **Tokens must identify an account.** A token or profile without a `sub` fails authentication. `googleId` is always that `sub` string; it used to fall back to the whole token.
- **Types:** `ParsedToken` and `TokenRequest` describe the verified identity and the request; `audience` is exposed as a `string[]`; `done`, `verifyGoogleIdToken` and `verifyGoogleAccessToken` are no longer public methods.

## Credits

Created by [Abdou Bouroubi](https://github.com/abouroubi), inspired by Juanma Reyes' [passport-google-id-token](https://github.com/jmreyes/passport-google-id-token).

## License

[MIT](LICENSE)
