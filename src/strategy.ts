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
    void this.authenticateRequest(req);
  }

  private async authenticateRequest(req: TokenRequest): Promise<void> {
    // Passport ignores authenticate()'s return value, so a token check that rejects
    // must be reported through this.error().
    let check: TokenCheck;
    try {
      check = await this.checkRequest(req);
    } catch (err) {
      this.error(toError(err));
      return;
    }
    this.verifyChecked(req, check);
  }

  private async checkRequest(req: TokenRequest): Promise<TokenCheck> {
    const extracted = extractToken(req);
    if (!extracted) {
      return { valid: false, message: 'no Google authentication token provided' };
    }
    return extracted.kind === 'id' ? this.checkIdToken(extracted.token) : this.checkAccessToken(extracted.token);
  }

  private verifyChecked(req: TokenRequest, check: TokenCheck): void {
    if (!check.valid) {
      this.fail({ message: check.message }, 401);
      return;
    }

    const { parsedToken } = check;
    const verified: VerifyDone = (error, user, info) => {
      if (error) {
        this.error(error);
      } else if (!user) {
        this.fail(info, 401);
      } else {
        this.success(user, info);
      }
    };
    try {
      this.verify(req, parsedToken, parsedToken.sub, verified);
    } catch (err) {
      this.error(toError(err));
    }
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
      return { valid: false, message: idTokenRejectionMessage(err) };
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

// google-auth-library's id token errors embed the token or its decoded claims (the
// user's email, name and Google id), and apps log failure info.
const ID_TOKEN_REJECTIONS: ReadonlyArray<readonly [libraryMessagePrefix: string, message: string]> = [
  ['Wrong number of segments in token', 'id token is malformed'],
  ["Can't parse token envelope", 'id token is malformed'],
  ["Can't parse token payload", 'id token is malformed'],
  ['No issue time in token', 'id token is malformed'],
  ['No expiration time in token', 'id token is malformed'],
  ['iat field using invalid format', 'id token is malformed'],
  ['exp field using invalid format', 'id token is malformed'],
  ['No pem found for envelope', 'id token signature is invalid'],
  ['Invalid token signature', 'id token signature is invalid'],
  ['Expiration time too far in future', 'id token expires too far in the future'],
  ['Token used too early', 'id token is not valid yet'],
  ['Token used too late', 'id token has expired'],
  ['Invalid issuer', 'id token was not issued by Google'],
  ['Wrong recipient', 'id token was not issued to an allowed audience'],
];

function idTokenRejectionMessage(err: unknown): string {
  const libraryMessage = err instanceof Error ? err.message : '';
  const rejection = ID_TOKEN_REJECTIONS.find(([prefix]) => libraryMessage.startsWith(prefix));
  return rejection?.[1] ?? 'invalid id token';
}
