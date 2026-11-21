import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { Strategy } from '../src';
import type { GoogleTokenStrategyOptions, VerifyDone, VerifyFunction } from '../src';
import {
  CLIENT_ID,
  GOOGLE_USER_ID,
  OTHER_CLIENT_ID,
  USER_INFO_URL,
  googleServer,
  http,
  HttpResponse,
  issueAccessToken,
  signIdToken,
} from './helpers/fake-google';
import { runStrategy } from './helpers/run-strategy';

beforeAll(() => googleServer.listen({ onUnhandledFrame: 'error' }));
afterEach(() => googleServer.resetHandlers());
afterAll(() => googleServer.close());

const USER = { id: 'user-1' };
const INFO = { scope: 'read' };

const acceptingVerify = () =>
  vi.fn<VerifyFunction>((_parsedToken, _googleId, done: VerifyDone) => done(null, USER, INFO));

function createStrategy(options: Partial<GoogleTokenStrategyOptions> = {}, verify = acceptingVerify()) {
  return { strategy: new Strategy({ clientID: CLIENT_ID, ...options }, verify), verify };
}

describe('GoogleTokenStrategy', () => {
  describe('construction', () => {
    it('is registered under the name google-verify-token', () => {
      expect(createStrategy().strategy.name).toBe('google-verify-token');
    });

    it('throws when no verify callback is given', () => {
      // @ts-expect-error -- JavaScript callers can omit the callback
      expect(() => new Strategy({ clientID: CLIENT_ID })).toThrow(
        'GoogleVerifyTokenStrategy requires a verify function',
      );
    });
  });

  describe('when no token is sent', () => {
    it('fails with 401', async () => {
      const outcome = await runStrategy(createStrategy().strategy, { headers: {} });
      expect(outcome).toEqual({
        kind: 'fail',
        challenge: { message: 'no Google authentication token provided' },
        status: 401,
      });
    });

    it('treats empty token values as missing', async () => {
      const outcome = await runStrategy(createStrategy().strategy, {
        headers: {},
        body: { id_token: '', access_token: '' },
      });
      expect(outcome).toMatchObject({ kind: 'fail', status: 401 });
    });

    it('treats non-string token values, such as repeated query parameters, as missing', async () => {
      const outcome = await runStrategy(createStrategy().strategy, {
        headers: {},
        query: { id_token: [signIdToken(), signIdToken()], access_token: { nested: 'value' } },
      });
      expect(outcome).toMatchObject({ kind: 'fail', status: 401 });
    });
  });

  describe('id tokens', () => {
    it('passes the verified claims and Google user id to the verify callback', async () => {
      const { strategy, verify } = createStrategy();
      const outcome = await runStrategy(strategy, { headers: {}, body: { id_token: signIdToken() } });

      expect(outcome).toEqual({ kind: 'success', user: USER, info: INFO });
      expect(verify).toHaveBeenCalledOnce();
      const [parsedToken, googleId] = verify.mock.calls[0];
      expect(parsedToken).toMatchObject({ sub: GOOGLE_USER_ID, email: 'ada@example.com', aud: CLIENT_ID });
      expect(googleId).toBe(GOOGLE_USER_ID);
    });

    it.each([
      { source: 'body', req: (token: string) => ({ headers: {}, body: { id_token: token } }) },
      { source: 'query string', req: (token: string) => ({ headers: {}, query: { id_token: token } }) },
      { source: 'id_token header', req: (token: string) => ({ headers: { id_token: token } }) },
      { source: 'route params', req: (token: string) => ({ headers: {}, params: { id_token: token } }) },
    ])('reads the token from the $source', async ({ req }) => {
      const outcome = await runStrategy(createStrategy().strategy, req(signIdToken()));
      expect(outcome.kind).toBe('success');
    });

    it('prefers the body over the query string', async () => {
      const outcome = await runStrategy(createStrategy().strategy, {
        headers: {},
        body: { id_token: signIdToken() },
        query: { id_token: 'not-a-jwt' },
      });
      expect(outcome.kind).toBe('success');
    });

    it('verifies the id token rather than the access token when both are sent', async () => {
      const outcome = await runStrategy(createStrategy().strategy, {
        headers: {},
        body: { id_token: signIdToken(), access_token: 'ya29.unknown-to-google' },
      });
      expect(outcome.kind).toBe('success');
    });

    it('accepts a token issued to any client ID in the clientID array', async () => {
      const { strategy } = createStrategy({ clientID: [OTHER_CLIENT_ID, CLIENT_ID] });
      const outcome = await runStrategy(strategy, { headers: {}, body: { id_token: signIdToken() } });
      expect(outcome.kind).toBe('success');
    });

    it('checks the token against `audience` instead of `clientID` when both are set', async () => {
      const { strategy } = createStrategy({ clientID: CLIENT_ID, audience: OTHER_CLIENT_ID });
      const accepted = await runStrategy(strategy, {
        headers: {},
        body: { id_token: signIdToken({ aud: OTHER_CLIENT_ID }) },
      });
      const rejected = await runStrategy(strategy, { headers: {}, body: { id_token: signIdToken() } });

      expect(accepted.kind).toBe('success');
      expect(rejected.kind).toBe('fail');
    });

    it.each([
      { problem: 'is issued to another client', token: () => signIdToken({ aud: OTHER_CLIENT_ID }) },
      { problem: 'has expired', token: () => signIdToken({ iat: 1_000_000, exp: 1_003_600 }) },
      { problem: 'has a foreign issuer', token: () => signIdToken({ iss: 'https://evil.example.com' }) },
      { problem: 'is signed with an untrusted key', token: () => signIdToken({}, { trusted: false }) },
      { problem: 'is not a JWT', token: () => 'not-a-jwt' },
    ])('fails without calling verify when the token $problem', async ({ token }) => {
      const { strategy, verify } = createStrategy();
      const outcome = await runStrategy(strategy, { headers: {}, body: { id_token: token() } });

      expect(outcome).toMatchObject({ kind: 'fail', challenge: { message: expect.any(String) } });
      expect(verify).not.toHaveBeenCalled();
    });
  });

  describe('access tokens', () => {
    it('passes the Google userinfo profile and user id to the verify callback', async () => {
      const { strategy, verify } = createStrategy();
      const token = issueAccessToken({ userInfo: { name: 'Ada Lovelace' } });
      const outcome = await runStrategy(strategy, { headers: {}, body: { access_token: token } });

      expect(outcome).toEqual({ kind: 'success', user: USER, info: INFO });
      const [profile, googleId] = verify.mock.calls[0];
      expect(profile).toEqual({ sub: GOOGLE_USER_ID, email: 'ada@example.com', name: 'Ada Lovelace' });
      expect(googleId).toBe(GOOGLE_USER_ID);
    });

    it.each([
      { source: 'body', req: (token: string) => ({ headers: {}, body: { access_token: token } }) },
      { source: 'query string', req: (token: string) => ({ headers: {}, query: { access_token: token } }) },
      { source: 'access_token header', req: (token: string) => ({ headers: { access_token: token } }) },
      {
        source: 'Bearer authorization header',
        req: (token: string) => ({ headers: { authorization: `Bearer ${token}` } }),
      },
    ])('reads the token from the $source', async ({ req }) => {
      const outcome = await runStrategy(createStrategy().strategy, req(issueAccessToken()));
      expect(outcome.kind).toBe('success');
    });

    it('ignores authorization headers that are not Bearer credentials', async () => {
      const outcome = await runStrategy(createStrategy().strategy, {
        headers: { authorization: `Basic ${Buffer.from('user:pass').toString('base64')}` },
      });
      expect(outcome).toMatchObject({ kind: 'fail', status: 401 });
    });

    it('fails without calling verify when Google does not recognise the token', async () => {
      const { strategy, verify } = createStrategy();
      const outcome = await runStrategy(strategy, { headers: {}, body: { access_token: 'ya29.revoked' } });

      expect(outcome).toMatchObject({ kind: 'fail', challenge: { message: expect.any(String) } });
      expect(verify).not.toHaveBeenCalled();
    });

    it('fails without calling verify when Google rejects the token at the userinfo endpoint', async () => {
      googleServer.use(http.get(USER_INFO_URL, () => HttpResponse.json({ error: 'invalid_token' }, { status: 401 })));
      const { strategy, verify } = createStrategy();
      const outcome = await runStrategy(strategy, { headers: {}, body: { access_token: issueAccessToken() } });

      expect(outcome).toMatchObject({ kind: 'fail', challenge: { message: 'failed to get userinfo' } });
      expect(verify).not.toHaveBeenCalled();
    });
  });

  describe('verify callback outcomes', () => {
    it('reports an error passed to done() as an error', async () => {
      const failure = new Error('database is down');
      const { strategy } = createStrategy(
        {},
        vi.fn<VerifyFunction>((_t, _id, done) => done(failure)),
      );
      const outcome = await runStrategy(strategy, { headers: {}, body: { id_token: signIdToken() } });
      expect(outcome).toEqual({ kind: 'error', error: failure });
    });

    it('fails with the info passed to done() when no user is returned', async () => {
      const { strategy } = createStrategy(
        {},
        vi.fn<VerifyFunction>((_t, _id, done) => done(null, false, { message: 'account disabled' })),
      );
      const outcome = await runStrategy(strategy, { headers: {}, body: { id_token: signIdToken() } });
      expect(outcome).toMatchObject({ kind: 'fail', challenge: { message: 'account disabled' } });
    });

    it.each([
      { token: 'id token', req: () => ({ headers: {}, body: { id_token: signIdToken() } }) },
      { token: 'access token', req: () => ({ headers: {}, body: { access_token: issueAccessToken() } }) },
    ])('reports an exception thrown by the verify callback as a single error ($token)', async ({ req }) => {
      const failure = new Error('bug in verify');
      const { strategy } = createStrategy(
        {},
        vi.fn<VerifyFunction>(() => {
          throw failure;
        }),
      );
      const outcome = await runStrategy(strategy, req());
      expect(outcome).toEqual({ kind: 'error', error: failure });
    });

    it('wraps a non-Error thrown by the verify callback in an Error', async () => {
      const { strategy } = createStrategy(
        {},
        vi.fn<VerifyFunction>(() => {
          // eslint-disable-next-line @typescript-eslint/only-throw-error -- simulating careless user code
          throw 'plain string';
        }),
      );
      const outcome = await runStrategy(strategy, { headers: {}, body: { id_token: signIdToken() } });
      expect(outcome).toEqual({ kind: 'error', error: new Error('plain string') });
    });
  });
});
