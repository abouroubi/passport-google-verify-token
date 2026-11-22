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
export type VerifyFunctionWithRequest = (
  req: TokenRequest,
  parsedToken: ParsedToken,
  googleId: string,
  done: VerifyDone,
) => void;

interface CommonOptions {
  /** The OAuth client ID of your app, or several (e.g. web, Android and iOS). */
  clientID: string | string[];
  /** Acceptable token audiences, for both id and access tokens. Defaults to `clientID`. */
  audience?: string | string[];
}

export interface GoogleTokenStrategyOptions extends CommonOptions {
  passReqToCallback?: false;
}

export interface GoogleTokenStrategyOptionsWithRequest extends CommonOptions {
  /** Pass the request to the verify callback as its first argument. */
  passReqToCallback: true;
}

type StrategyArguments =
  | [options: GoogleTokenStrategyOptions, verify: VerifyFunction]
  | [options: GoogleTokenStrategyOptionsWithRequest, verify: VerifyFunctionWithRequest];

type ExtractedToken = { kind: 'id' | 'access'; token: string };
type Settle = (report: () => void, discardedError?: Error | null) => void;
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
  public readonly passReqToCallback: boolean;
  private readonly verify: VerifyFunctionWithRequest;

  constructor(options: GoogleTokenStrategyOptions, verify: VerifyFunction);
  constructor(options: GoogleTokenStrategyOptionsWithRequest, verify: VerifyFunctionWithRequest);
  constructor(...args: StrategyArguments) {
    super();

    const [options, verify] = args;
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

    if (passesRequest(args)) {
      this.verify = args[1];
    } else {
      const verifyWithoutRequest = args[1];
      this.verify = (_req, parsedToken, googleId, done) => verifyWithoutRequest(parsedToken, googleId, done);
    }
    this.passReqToCallback = options.passReqToCallback === true;
    this.clientID = options.clientID;
    this.audience = audience;
    this.googleAuthClient = new OAuth2Client(
      typeof options.clientID === 'string' ? { clientId: options.clientID } : {},
    );
  }

  public authenticate(req: TokenRequest): void {
    // Passport responds to the request on its first success/fail/error call, so each
    // request must report exactly one outcome.
    let settled = false;
    const settle: Settle = (report, discardedError) => {
      if (settled) {
        throw new Error(
          'GoogleTokenStrategy: the verify callback called done() after the request was already settled',
          discardedError ? { cause: discardedError } : undefined,
        );
      }
      settled = true;
      report();
    };

    // Passport ignores authenticate()'s return value, so async failures must reach
    // this.error(). Once the request is settled there is no outcome left to report
    // them through, so they are rethrown rather than swallowed.
    this.authenticateRequest(req, settle).catch((err: unknown) => {
      if (settled) {
        throw err;
      }
      settle(() => this.error(toError(err)));
    });
  }

  private async authenticateRequest(req: TokenRequest, settle: Settle): Promise<void> {
    const extracted = extractToken(req);
    if (!extracted) {
      settle(() => this.fail({ message: 'no Google authentication token provided' }, 401));
      return;
    }

    const check =
      extracted.kind === 'id' ? await this.checkIdToken(extracted.token) : await this.checkAccessToken(extracted.token);

    if (!check.valid) {
      settle(() => this.fail({ message: check.message }, 401));
      return;
    }

    const { parsedToken } = check;
    this.verify(req, parsedToken, parsedToken.sub, (error, user, info) =>
      settle(() => {
        if (error) {
          this.error(error);
        } else if (!user) {
          this.fail(info, 401);
        } else {
          this.success(user, info);
        }
      }, error),
    );
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

/**
 * Finds the token to verify, in order of precedence:
 * 1. `id_token` in the body, query string, headers or route params;
 * 2. `credential` in the body, the field Google Identity Services posts the id token in;
 * 3. `access_token` in the body, query string, headers or route params;
 * 4. an `Authorization: Bearer` header, holding either kind of token.
 */
function extractToken(req: TokenRequest): ExtractedToken | undefined {
  const idToken = readTokenParam(req, 'id_token') ?? readField(req.body, 'credential');
  if (idToken) {
    return { kind: 'id', token: idToken };
  }
  const accessToken = readTokenParam(req, 'access_token');
  if (accessToken) {
    return { kind: 'access', token: accessToken };
  }
  const bearerToken = readBearerToken(req.headers);
  if (bearerToken) {
    return { kind: looksLikeJwt(bearerToken) ? 'id' : 'access', token: bearerToken };
  }
  return undefined;
}

/** Reads a non-empty string token from the body, query string, headers or route params, in that order. */
function readTokenParam(req: TokenRequest, name: string): string | undefined {
  for (const source of [req.body, req.query, req.headers, req.params]) {
    const value = readField(source, name);
    if (value) {
      return value;
    }
  }
  return undefined;
}

function readField(source: Record<string, unknown> | null | undefined, name: string): string | undefined {
  const value = source?.[name];
  return typeof value === 'string' && value !== '' ? value : undefined;
}

function passesRequest(
  args: StrategyArguments,
): args is [GoogleTokenStrategyOptionsWithRequest, VerifyFunctionWithRequest] {
  return args[0].passReqToCallback === true;
}

function toList(value: string | string[] | undefined): string[] {
  const values = Array.isArray(value) ? value : [value];
  return values.filter((item): item is string => typeof item === 'string' && item !== '');
}

/** The auth scheme is case-insensitive (RFC 9110 §11.1). */
function readBearerToken(headers: IncomingHttpHeaders): string | undefined {
  return /^Bearer +(\S+)$/i.exec(headers.authorization?.trim() ?? '')?.[1];
}

/**
 * Id tokens are JWTs: three base64url segments, the first a JSON header (`eyJ` is
 * base64 for `{"`). Google access tokens are opaque strings such as `ya29.…`.
 */
function looksLikeJwt(token: string): boolean {
  return /^eyJ[\w-]*\.[\w-]+\.[\w-]+$/.test(token);
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
