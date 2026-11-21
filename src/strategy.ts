import type { IncomingHttpHeaders } from 'node:http';
import { GaxiosError } from 'gaxios';
import { OAuth2Client } from 'google-auth-library';
import { Strategy } from 'passport-strategy';

const USER_INFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo';

/**
 * The parts of an incoming HTTP request the strategy reads tokens from.
 * Express, Fastify and NestJS requests all satisfy it.
 */
export interface TokenRequest {
  headers: IncomingHttpHeaders;
  body?: Record<string, unknown> | null;
  query?: Record<string, unknown>;
  params?: Record<string, unknown>;
}

/**
 * The verified identity handed to the verify callback: the claims of an id token,
 * or the Google userinfo profile of an access token.
 */
export interface ParsedToken {
  /** The Google account's unique, stable user id. */
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  locale?: string;
  hd?: string;
  [claim: string]: unknown;
}

export type VerifyDone = (error: Error | null, user?: unknown, info?: unknown) => void;
export type VerifyFunction = (parsedToken: ParsedToken, googleId: string, done: VerifyDone) => void;

export interface GoogleTokenStrategyOptions {
  /** The OAuth client ID of your app, or several (e.g. web, Android and iOS). */
  clientID: string | string[];
  /** Acceptable token audiences, for both id and access tokens. Defaults to `clientID`. */
  audience?: string | string[];
  passReqToCallback?: boolean;
}

type TokenCheck = { valid: true; parsedToken: ParsedToken } | { valid: false; message: string };

/**
 * Passport strategy that authenticates requests carrying a Google id token or
 * access token, verified server side with the official Google Auth Library.
 *
 * A token that is missing or that Google rejects fails authentication (401).
 * When Google itself cannot be reached or answers with a server error, the
 * strategy reports an error instead, so an outage is never mistaken for a
 * bad token.
 *
 * @example
 * passport.use(new GoogleTokenStrategy(
 *   { clientID: '12345.apps.googleusercontent.com' },
 *   (parsedToken, googleId, done) => {
 *     User.findOrCreate({ googleId }, (err, user) => done(err, user));
 *   },
 * ));
 */
export class GoogleTokenStrategy extends Strategy {
  public name = 'google-verify-token';
  public readonly googleAuthClient: OAuth2Client;
  public readonly clientID: string | string[];
  public readonly audience: readonly string[];
  public readonly passReqToCallback: boolean | undefined;
  private readonly verify: VerifyFunction;

  constructor(options: GoogleTokenStrategyOptions, verify: VerifyFunction) {
    super();

    if (typeof options !== 'object' || options === null) {
      throw new Error('GoogleTokenStrategy requires an options object with a clientID');
    }
    if (typeof verify !== 'function') {
      throw new Error('GoogleTokenStrategy requires a verify function');
    }
    // Without an audience Google accepts tokens minted for any application, which
    // would let another app's users sign in here with their own tokens.
    if (toList(options.clientID).length === 0) {
      throw new Error('GoogleTokenStrategy requires a clientID');
    }
    const audience = toList(options.audience ?? options.clientID);
    if (audience.length === 0) {
      throw new Error('GoogleTokenStrategy requires a non-empty audience');
    }

    this.verify = verify;
    this.clientID = options.clientID;
    this.audience = audience;
    this.passReqToCallback = options.passReqToCallback;
    this.googleAuthClient = new OAuth2Client(
      typeof options.clientID === 'string' ? { clientId: options.clientID } : {},
    );
  }

  public authenticate(req: TokenRequest): void {
    // Passport ignores authenticate()'s return value, so async failures (Google being
    // unreachable, a throwing verify callback) must reach this.error() instead of
    // becoming unhandled rejections.
    this.authenticateRequest(req).catch((err: unknown) => this.error(toError(err)));
  }

  private async authenticateRequest(req: TokenRequest): Promise<void> {
    const idToken = readTokenParam(req, 'id_token');
    const accessToken = readTokenParam(req, 'access_token') ?? readBearerToken(req.headers);

    let check: TokenCheck;
    if (idToken) {
      check = await this.checkIdToken(idToken);
    } else if (accessToken) {
      check = await this.checkAccessToken(accessToken);
    } else {
      this.fail({ message: 'no Google authentication token provided' }, 401);
      return;
    }

    if (!check.valid) {
      this.fail({ message: check.message }, 401);
      return;
    }

    const { parsedToken } = check;
    this.verify(parsedToken, parsedToken.sub, (error, user, info) => {
      if (error) {
        this.error(error);
      } else if (!user) {
        this.fail(info, 401);
      } else {
        this.success(user, info);
      }
    });
  }

  private async checkIdToken(idToken: string): Promise<TokenCheck> {
    let payload: unknown;
    try {
      const ticket = await this.googleAuthClient.verifyIdToken({ idToken, audience: [...this.audience] });
      payload = ticket.getPayload();
    } catch (err) {
      // The only HTTP request verifyIdToken() makes is for Google's signing certificates;
      // every other error it throws is about the token itself.
      if (err instanceof GaxiosError) {
        throw new Error('Could not fetch Google signing certificates', { cause: err });
      }
      return { valid: false, message: errorMessage(err, 'Failed to verify id token') };
    }
    return toTokenCheck(payload);
  }

  private async checkAccessToken(accessToken: string): Promise<TokenCheck> {
    let tokenAudience: string;
    try {
      tokenAudience = (await this.googleAuthClient.getTokenInfo(accessToken)).aud;
    } catch (err) {
      if (isTokenRejection(err)) {
        return { valid: false, message: 'invalid access token' };
      }
      throw new Error('Could not verify the access token with Google', { cause: err });
    }
    if (!this.audience.includes(tokenAudience)) {
      return { valid: false, message: 'access token was not issued to an allowed audience' };
    }

    let response: Response;
    try {
      response = await fetch(USER_INFO_URL, { headers: { Authorization: `Bearer ${accessToken}` } });
    } catch (err) {
      throw new Error('Could not reach the Google userinfo endpoint', { cause: err });
    }
    if (response.status === 401 || response.status === 403) {
      return { valid: false, message: 'failed to get userinfo' };
    }
    if (!response.ok) {
      throw new Error(`Google userinfo endpoint responded with HTTP ${response.status}`);
    }
    let profile: unknown;
    try {
      profile = await response.json();
    } catch (err) {
      throw new Error('Google userinfo endpoint returned invalid JSON', { cause: err });
    }
    return toTokenCheck(profile);
  }
}

/** Reads a non-empty string token from the body, query string, headers or route params, in that order. */
function readTokenParam(req: TokenRequest, name: string): string | undefined {
  for (const source of [req.body, req.query, req.headers, req.params]) {
    const value = source?.[name];
    if (typeof value === 'string' && value !== '') {
      return value;
    }
  }
  return undefined;
}

function toList(value: string | string[] | undefined): string[] {
  const values = Array.isArray(value) ? value : [value];
  return values.filter((item): item is string => typeof item === 'string' && item !== '');
}

function readBearerToken(headers: IncomingHttpHeaders): string | undefined {
  const parts = headers.authorization?.split(' ');
  return parts?.length === 2 && parts[0] === 'Bearer' && parts[1] !== '' ? parts[1] : undefined;
}

function toTokenCheck(claims: unknown): TokenCheck {
  return isParsedToken(claims)
    ? { valid: true, parsedToken: { ...claims } }
    : { valid: false, message: 'token does not identify a Google account' };
}

function isParsedToken(value: unknown): value is ParsedToken {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const sub: unknown = Reflect.get(value, 'sub');
  return typeof sub === 'string' && sub !== '';
}

function isTokenRejection(err: unknown): boolean {
  return err instanceof GaxiosError && (err.status === 400 || err.status === 401);
}

function toError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err));
}

function errorMessage(err: unknown, fallback: string): string {
  return err instanceof Error && err.message !== '' ? err.message : fallback;
}
