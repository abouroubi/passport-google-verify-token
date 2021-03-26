# passport-google-verify-token

[![Build Status](https://dev.azure.com/abdouslayne/Personal%20Projects/_apis/build/status/passport-google-verify-token?branchName=master)](https://dev.azure.com/abdouslayne/Personal%20Projects/_build/latest?definitionId=2?branchName=master)
[![npm version](https://badge.fury.io/js/passport-google-verify-token.svg)](https://badge.fury.io/js/passport-google-verify-token)
![License](https://img.shields.io/npm/l/passport-facebook-token.svg)


[Passport](http://passportjs.org/) strategy for authenticating with [Google](http://www.google.com/)
access tokens using the OAuth 2.0 API.

This module lets you authenticate using Google in your Node.js applications.
By plugging into Passport, Google authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Installation

    $ npm install passport-google-verify-token

## Usage

### Configure Strategy

The Google authentication strategy leverages the [Google Auth Library for Node.js](https://github.com/googleapis/google-auth-library-nodejs) to authenticates users. 
Applications must supply a `verify` callback which accepts the `idToken`
coming from the user to be authenticated, and then calls the `done` callback
supplying a `parsedToken` (with all its information in visible form) and the
`googleId`.

```js
var GoogleTokenStrategy = require("passport-google-verify-token").Strategy;

passport.use(new GoogleTokenStrategy({
      clientID: '12345.abcdefghijkl.apps.googleusercontent.com'// Specify the CLIENT_ID of the backend
     // If other clients (such as android / ios apps) also access the google api:
     // audience: [CLIENT_ID_FOR_THE_BACKEND, CLIENT_ID_ANDROID, CLIENT_ID_IOS, CLIENT_ID_SPA]
    },
    function(parsedToken, googleId, done) {
      User.findOrCreate(..., function (err, user) {
        done(err, user);
      });
    }
  ));
```

### Authenticate Requests

Use `passport.authenticate()`, specifying the `'google-verify-token'` strategy, to authenticate requests.

```js
app.post('/auth/google/token',
  passport.authenticate('google-verify-token'),
  function (req, res) {
    // do something with req.user
    res.send(req.user? 200 : 401);
  }
);
```

Or using Sails framework:

```javascript
// api/controllers/AuthController.js
module.exports = {
  facebook: function(req, res) {
    passport.authenticate('google-verify-token', function(error, user, info) {
      // do stuff with user
      res.ok();
    })(req, res);
  }
};
```

### Client Requests

Clients can send requests to routes that use google-verify-token authentication using query parms, body, or HTTP headers. Clients will need to transmit the `access_token` or the `id_token` that are received from Google after user logs in.

#### Sending access_token as a Query parameter

```
GET /auth/google/token?access_token=<TOKEN_HERE>
```

#### Sending access token as an HTTP header

Clients can choose to send the access token using the Oauth2 Bearer token (RFC 6750) compliant format

```
GET /resource HTTP/1.1
Host: server.example.com
Authorization: Bearer base64_access_token_string
```


#### Sending access token as an HTTP body

Clients can transmit the access token via the body

```
POST /resource HTTP/1.1
Host: server.example.com

access_token=base64_access_token_string
```
  

## Credits

  - [Abdou BOUROUBI](http://github.com/abouroubi)

## Thanks

This project is inspired by [Juanma Reyes](http://github.com/jmreyes)' [Passport Google Id Token](https://github.com/jmreyes/passport-google-id-token).

## License

The MIT License (MIT)

Copyright (c) 2018 Abdou Bouroubi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
