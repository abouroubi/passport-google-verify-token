/**
 * Module dependencies.
 */
import { OAuth2Client } from 'google-auth-library';
import { Strategy } from 'passport-strategy';

export type VerifyDone = (error: Error | null, user?: unknown, info?: unknown) => void;
export type ParsedToken = Record<string, unknown>;
export type VerifyFunction = (
  parsedToken: ParsedToken,
  googleId: string | ParsedToken,
  done: VerifyDone,
) => void;

/**
 * Options accepted by GoogleTokenStrategy
 *
 * - clientID: A single Google OAuth client ID, or an array of client IDs
 * - audience: Optional audience override (string or array). Defaults to `clientID`.
 * - passReqToCallback: If true, the request object will be passed to the verify callback
 */
export interface GoogleTokenStrategyOptions {
  clientID: string | string[];
  passReqToCallback?: boolean;
  audience?: string | string[];
}

/**
 * `Strategy` constructor.
 *
 * The Google authentication strategy authenticates requests by verifying the
 * signature and fields of the token.
 *
 * Applications must supply a `verify` callback which accepts the `idToken`
 * coming from the user to be authenticated, and then calls the `done` callback
 * supplying a `parsedToken` (with all its information in visible form) and the
 * `googleId`.
 *
 * Options:
 * - clientID: your Google application's client id (or several as Array)
 * - audience: optional string or string[] of acceptable audiences; defaults to clientID
 *
 * Notes:
 * - The underlying Google OAuth2 client is created using the options object
 *   (OAuth2ClientOptions) to avoid deprecated constructor signatures.
 *
 * Examples:
 *
 * passport.use(new GoogleTokenStrategy({
 *     clientID: '12345.abcdefghijkl.apps.googleusercontent.com'// Specify the CLIENT_ID of the app that accesses the backend
 *    // Or, if multiple clients access the backend:
 *    //[CLIENT_ID_1, CLIENT_ID_2, CLIENT_ID_3]
 *   },
 *   function(parsedToken, googleId, done) {
 *     User.findOrCreate(..., function (err, user) {
 *       done(err, user);
 *     });
 *   }
 * ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
export class GoogleTokenStrategy extends Strategy {
  public name: string;
  public googleAuthClient: OAuth2Client;
  public verify: VerifyFunction;
  public clientID: string | string[] | undefined;
  public passReqToCallback?: boolean;
  public audience: string | string[] | undefined;

  constructor(options: GoogleTokenStrategyOptions | VerifyFunction, verify?: VerifyFunction) {
    super();

    let opts: GoogleTokenStrategyOptions | undefined;
  if (typeof options === 'function') {
      verify = options;
      opts = undefined;
    } else {
      opts = options;
    }

    if (!verify) {
      throw new Error('GoogleVerifyTokenStrategy requires a verify function');
    }

  this.passReqToCallback = opts?.passReqToCallback;

  this.clientID = opts?.clientID;

    this.name = 'google-verify-token';
    const oauthOptions: { clientId?: string } = {};
    if (typeof this.clientID === 'string') {
      oauthOptions.clientId = this.clientID;
    }
    this.googleAuthClient = new OAuth2Client(oauthOptions);
  this.verify = verify as VerifyFunction;
  this.audience = opts?.audience ?? this.clientID;
  }

  /**
   * Internal function that handles successes/failures
   * 
   * @param {any} err 
   * @param {any?} parsedToken 
   * @param {any?} info
   */
  public done(err: any, parsedToken?: any, info?: any) {
    if (err) {
      return this.fail({ message: err.message }, 401);
    }

    if (!parsedToken) {
      return this.fail(info);
    }

    const verified = (error: any, user: any, infoOnUser: any) => {
      if (error) {
        return this.error(error);
      }
      if (!user) {
        return this.fail(infoOnUser);
      }
      this.success(user, infoOnUser);
    };

    if (parsedToken.sub) this.verify(parsedToken, parsedToken.sub, verified);
    else {
      this.verify(parsedToken, parsedToken, verified)
    }
  }

  /**
   * Authenticate request by verifying the token
   *
   * @param {Object} req
   * @param {Object} options
   * @api protected
   */
  public authenticate(req: any, _options?: any) {
    // options currently unused but kept for API symmetry with passport strategies

    const accessToken =
      this.paramFromRequest(req, 'access_token') ||
      this.getBearerToken(req.headers);
    const idToken = this.paramFromRequest(req, 'id_token');

    if (idToken) this.verifyGoogleIdToken(idToken)
    else if (accessToken) this.verifyGoogleAccessToken(accessToken)
    else {
      return this.fail({ message: 'no Google authentication token provided' }, 401);
    }
  }

  /**
   * Verify signature and token fields for an id_token using google-auth-library.
   *
   * @param {String} idToken
   * @api protected
   */
  public verifyGoogleIdToken(idToken: string) {
    (async () => {
      try {
        const loginTicket = await this.googleAuthClient.verifyIdToken({
          audience: this.audience,
          idToken,
        });
        const payload = loginTicket.getPayload();
        if (payload) {
          this.done(null, payload);
        } else {
          this.done(null, false, { message: 'No login ticket returned' });
        }
      } catch (err: any) {
        this.done(null, false, { message: err?.message ?? 'Failed to verify id token' });
      }
    })();
  }

  /**
   * Validate access token with google-auth-library, then fetch userinfo from
   * Google's OIDC endpoint using a Bearer Authorization header.
   *
   * @param {String} accessToken
   * @api protected
   */
  public verifyGoogleAccessToken(accessToken: string) {
    (async () => {
      try {
        const tokenInfo = await this.googleAuthClient.getTokenInfo(accessToken);
        if (!tokenInfo) {
          this.done(null, false, { message: 'invalid access token' });
          return;
        }

        // Retrieve user info using the access token
        try {
          const resp = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
            headers: { Authorization: `Bearer ${accessToken}` },
          });
          if (!resp.ok) {
            this.done(null, false, { message: 'failed to get userinfo' });
            return;
          }
          const userinfo = await resp.json();
          this.done(null, userinfo);
    } catch {
          this.done(null, false, { message: 'failed to get userinfo' });
        }
      } catch (e: any) {
        this.done(null, false, { message: e?.message ?? 'failed to verify access token' });
      }
    })();
  }

  /**
   * Gets the id token value from req using name for lookup in req.body, req.query,
   * and req.params.
   * @param {express.Request} req
   * @param {string} name  the key to use to lookup id token in req.
   * @api protected
   */
  private paramFromRequest(req: any, name: string) {
    const body = req.body || {};
    const query = req.query || {};
    const params = req.params || {};
    const headers = req.headers || {};
    if (body[name]) {
      return body[name];
    }
    if (query[name]) {
      return query[name];
    }
    if (headers[name]) {
      return headers[name];
    }
    return params[name] || '';
  }

  private getBearerToken(headers: any) {
    if (headers && headers.authorization) {
      const parts = headers.authorization.split(' ');
      return parts.length === 2 && parts[0] === 'Bearer' ? parts[1] : undefined;
    }
  }
}
