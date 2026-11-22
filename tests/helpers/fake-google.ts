import { createSign, generateKeyPairSync } from 'node:crypto';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';

export const CLIENT_ID = 'backend-client.apps.googleusercontent.com';
export const OTHER_CLIENT_ID = 'someone-elses-app.apps.googleusercontent.com';
export const GOOGLE_USER_ID = '109876543210987654321';

export const CERTS_URL = 'https://www.googleapis.com/oauth2/v1/certs';
export const TOKEN_INFO_URL = 'https://oauth2.googleapis.com/tokeninfo';
export const USER_INFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo';

const KEY_ID = 'fake-google-key';
const signingKey = generateKeyPairSync('rsa', { modulusLength: 2048 });
const untrustedKey = generateKeyPairSync('rsa', { modulusLength: 2048 });

const base64url = (value: string | Buffer) => Buffer.from(value).toString('base64url');
const nowInSeconds = () => Math.floor(Date.now() / 1000);

export type IdTokenClaims = Record<string, unknown>;

export function idTokenClaims(overrides: IdTokenClaims = {}): IdTokenClaims {
  return {
    iss: 'https://accounts.google.com',
    aud: CLIENT_ID,
    azp: CLIENT_ID,
    sub: GOOGLE_USER_ID,
    email: 'ada@example.com',
    email_verified: true,
    iat: nowInSeconds(),
    exp: nowInSeconds() + 3600,
    ...overrides,
  };
}

/** Signs an id token the way Google does (RS256), with a key the fake certs endpoint publishes. */
export function signIdToken(overrides: IdTokenClaims = {}, { trusted = true } = {}): string {
  const header = base64url(JSON.stringify({ alg: 'RS256', kid: KEY_ID, typ: 'JWT' }));
  const payload = base64url(JSON.stringify(idTokenClaims(overrides)));
  const signer = createSign('RSA-SHA256');
  signer.update(`${header}.${payload}`);
  const signature = signer.sign((trusted ? signingKey : untrustedKey).privateKey);
  return `${header}.${payload}.${base64url(signature)}`;
}

export interface IssuedAccessToken {
  tokenInfo: Record<string, unknown>;
  userInfo: Record<string, unknown>;
}

const accessTokens = new Map<string, IssuedAccessToken>();
let issuedCount = 0;

/** Registers an opaque access token that the fake tokeninfo and userinfo endpoints recognise. */
export function issueAccessToken({
  tokenInfo = {},
  userInfo = {},
}: { tokenInfo?: Record<string, unknown>; userInfo?: Record<string, unknown> } = {}): string {
  issuedCount += 1;
  const token = `ya29.fake-access-token-${issuedCount}`;
  accessTokens.set(token, {
    tokenInfo: {
      aud: CLIENT_ID,
      azp: CLIENT_ID,
      sub: GOOGLE_USER_ID,
      scope: 'openid https://www.googleapis.com/auth/userinfo.email',
      expires_in: 3599,
      ...tokenInfo,
    },
    userInfo: { sub: GOOGLE_USER_ID, email: 'ada@example.com', name: 'Ada Lovelace', ...userInfo },
  });
  return token;
}

const bearerToken = (request: Request) => request.headers.get('authorization')?.replace(/^Bearer /, '') ?? '';

export const googleServer = setupServer(
  http.get(CERTS_URL, () =>
    HttpResponse.json({ [KEY_ID]: signingKey.publicKey.export({ type: 'spki', format: 'pem' }) }),
  ),
  http.post(TOKEN_INFO_URL, ({ request }) => {
    const issued = accessTokens.get(bearerToken(request));
    return issued
      ? HttpResponse.json(issued.tokenInfo)
      : HttpResponse.json({ error: 'invalid_token', error_description: 'Invalid Value' }, { status: 400 });
  }),
  http.get(USER_INFO_URL, ({ request }) => {
    const issued = accessTokens.get(bearerToken(request));
    return issued
      ? HttpResponse.json(issued.userInfo)
      : HttpResponse.json({ error: 'invalid_request' }, { status: 401 });
  }),
);

export { http, HttpResponse };
