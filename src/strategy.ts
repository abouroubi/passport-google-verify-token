import type { IncomingHttpHeaders } from 'node:http';
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
  sub?: string;
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
export type VerifyFunction = (parsedToken: ParsedToken, googleId: string | ParsedToken, done: VerifyDone) => void;

export interface GoogleTokenStrategyOptions {
  /** The OAuth client ID of your app, or several (e.g. web, Android and iOS). */
  clientID: string | string[];
  /** Acceptable token audiences. Defaults to `clientID`. */
  audience?: string | string[];
  passReqToCallback?: boolean;
}

type TokenCheck = { valid: true; parsedToken: ParsedToken } | { valid: false; message: string };

/**
 * Passport strategy that authenticates requests carrying a Google id token or
 * access token, verified server side with the official Google Auth Library.
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
  public readonly clientID: string | string[] | undefined;
  public readonly audience: string | string[] | undefined;
  public readonly passReqToCallback: boolean | undefined;
  private readonly verify: VerifyFunction;

  constructor(verify: VerifyFunction);
  constructor(options: GoogleTokenStrategyOptions, verify: VerifyFunction);
  constructor(optionsOrVerify: GoogleTokenStrategyOptions | VerifyFunction, verify?: VerifyFunction) {
    super();

    const options = typeof optionsOrVerify === 'function' ? undefined : optionsOrVerify;
    const verifyCallback = typeof optionsOrVerify === 'function' ? optionsOrVerify : verify;
    if (!verifyCallback) {
      throw new Error('GoogleVerifyTokenStrategy requires a verify function');
    }

    this.verify = verifyCallback;
    this.clientID = options?.clientID;
    this.audience = options?.audience ?? this.clientID;
    this.passReqToCallback = options?.passReqToCallback;
    this.googleAuthClient = new OAuth2Client(typeof this.clientID === 'string' ? { clientId: this.clientID } : {});
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
    this.verify(parsedToken, parsedToken.sub ?? parsedToken, (error, user, info) => {
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
    try {
      const ticket = await this.googleAuthClient.verifyIdToken({ idToken, audience: this.audience });
      const payload = ticket.getPayload();
      return payload
        ? { valid: true, parsedToken: { ...payload } }
        : { valid: false, message: 'No login ticket returned' };
    } catch (err) {
      return { valid: false, message: errorMessage(err, 'Failed to verify id token') };
    }
  }

  private async checkAccessToken(accessToken: string): Promise<TokenCheck> {
    try {
      await this.googleAuthClient.getTokenInfo(accessToken);
    } catch (err) {
      return { valid: false, message: errorMessage(err, 'failed to verify access token') };
    }

    try {
      const response = await fetch(USER_INFO_URL, { headers: { Authorization: `Bearer ${accessToken}` } });
      if (!response.ok) {
        return { valid: false, message: 'failed to get userinfo' };
      }
      const profile: unknown = await response.json();
      return isParsedToken(profile)
        ? { valid: true, parsedToken: profile }
        : { valid: false, message: 'failed to get userinfo' };
    } catch {
      return { valid: false, message: 'failed to get userinfo' };
    }
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

function readBearerToken(headers: IncomingHttpHeaders): string | undefined {
  const parts = headers.authorization?.split(' ');
  return parts?.length === 2 && parts[0] === 'Bearer' && parts[1] !== '' ? parts[1] : undefined;
}

function isParsedToken(value: unknown): value is ParsedToken {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    ['string', 'undefined'].includes(typeof Reflect.get(value, 'sub'))
  );
}

function toError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err));
}

function errorMessage(err: unknown, fallback: string): string {
  return err instanceof Error && err.message !== '' ? err.message : fallback;
}
