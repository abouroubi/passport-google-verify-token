import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { Strategy } from '../src';
import type { GoogleTokenStrategyOptions, VerifyDone, VerifyFunction, VerifyFunctionWithRequest } from '../src';
import {
  CERTS_URL,
  CLIENT_ID,
  GOOGLE_USER_ID,
  OTHER_CLIENT_ID,
  TOKEN_INFO_URL,
  USER_INFO_URL,
  googleServer,
  http,
  HttpResponse,
  issueAccessToken,
  nowInSeconds,
  signIdToken,
} from './helpers/fake-google';
import { captureUncaughtExceptions, captureUnhandledRejections } from './helpers/capture-process-errors';
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
      expect(() => new Strategy({ clientID: CLIENT_ID })).toThrow('GoogleTokenStrategy requires a verify function');
    });

    it('throws when called with only a verify callback', () => {
      // @ts-expect-error -- the options-less signature was removed; JavaScript callers can still use it
      expect(() => new Strategy(acceptingVerify())).toThrow(
        'GoogleTokenStrategy requires an options object with a clientID',
      );
    });

    it.each([
      { problem: 'missing', clientID: undefined },
      { problem: 'an empty string', clientID: '' },
      { problem: 'an empty array', clientID: [] },
      { problem: 'an array of empty strings', clientID: ['', ''] },
    ])('throws when clientID is $problem', ({ clientID }) => {
      // @ts-expect-error -- JavaScript callers, or an unset environment variable, can pass anything here
      expect(() => new Strategy({ clientID }, acceptingVerify())).toThrow('GoogleTokenStrategy requires a clientID');
    });

    it('throws when audience is explicitly empty', () => {
      expect(() => new Strategy({ clientID: CLIENT_ID, audience: [] }, acceptingVerify())).toThrow(
        'GoogleTokenStrategy requires a non-empty audience',
      );
    });

    it('exposes the accepted audiences as a list', () => {
      expect(createStrategy().strategy.audience).toEqual([CLIENT_ID]);
      expect(createStrategy({ audience: [OTHER_CLIENT_ID, CLIENT_ID] }).strategy.audience).toEqual([
        OTHER_CLIENT_ID,
        CLIENT_ID,
      ]);
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

    it('reads the `credential` field Google Identity Services posts', async () => {
      const { strategy, verify } = createStrategy();
      const outcome = await runStrategy(strategy, {
        headers: {},
        body: { credential: signIdToken(), g_csrf_token: 'csrf' },
      });

      expect(outcome.kind).toBe('success');
      expect(verify.mock.calls[0][1]).toBe(GOOGLE_USER_ID);
    });

    it('only reads `credential` from the body', async () => {
      const outcome = await runStrategy(createStrategy().strategy, {
        headers: {},
        query: { credential: signIdToken() },
      });
      expect(outcome).toMatchObject({ kind: 'fail', status: 401 });
    });

    it('prefers `id_token` over `credential`', async () => {
      const outcome = await runStrategy(createStrategy().strategy, {
        headers: {},
        body: { id_token: signIdToken(), credential: 'not-a-jwt' },
      });
      expect(outcome.kind).toBe('success');
    });

    it.each(['Bearer', 'bearer', 'BEARER'])('reads an id token sent as a `%s` authorization header', async (scheme) => {
      const outcome = await runStrategy(createStrategy().strategy, {
        headers: { authorization: `${scheme} ${signIdToken()}` },
      });
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

    // Exact messages also prove that neither the token nor its claims (email, user id)
    // end up in the failure info, which apps log.
    it.each([
      {
        problem: 'is issued to another client',
        token: () => signIdToken({ aud: OTHER_CLIENT_ID }),
        message: 'id token was not issued to an allowed audience',
      },
      {
        problem: 'has expired',
        token: () => signIdToken({ iat: 1_000_000, exp: 1_003_600 }),
        message: 'id token has expired',
      },
      {
        problem: 'is not valid yet',
        token: () => signIdToken({ iat: nowInSeconds() + 3600, exp: nowInSeconds() + 7200 }),
        message: 'id token is not valid yet',
      },
      {
        problem: 'expires more than a day after now',
        token: () => signIdToken({ exp: nowInSeconds() + 2 * 86_400 }),
        message: 'id token expires too far in the future',
      },
      {
        problem: 'has a foreign issuer',
        token: () => signIdToken({ iss: 'https://evil.example.com' }),
        message: 'id token was not issued by Google',
      },
      {
        problem: 'is signed with an untrusted key',
        token: () => signIdToken({}, { trusted: false }),
        message: 'id token signature is invalid',
      },
      {
        problem: 'names a signing key Google does not publish',
        token: () => signIdToken({}, { header: { kid: 'retired-key' } }),
        message: 'id token signature is invalid',
      },
      {
        problem: 'has no issue time',
        token: () => signIdToken({ iat: undefined }),
        message: 'id token is malformed',
      },
      {
        problem: 'has an issue time that is not a number',
        token: () => signIdToken({ iat: 'yesterday' }),
        message: 'id token is malformed',
      },
      {
        problem: 'has no expiry time',
        token: () => signIdToken({ exp: undefined }),
        message: 'id token is malformed',
      },
      {
        problem: 'has an expiry time that is not a number',
        token: () => signIdToken({ exp: 'tomorrow' }),
        message: 'id token is malformed',
      },
      {
        problem: 'has a header that is not JSON',
        token: () => `bm90IGpzb24.${signIdToken().split('.')[1]}.c2ln`,
        message: 'id token is malformed',
      },
      {
        problem: 'has a payload that is not JSON',
        token: () => `${signIdToken().split('.')[0]}.bm90IGpzb24.c2ln`,
        message: 'id token is malformed',
      },
      { problem: 'is not a JWT', token: () => 'not-a-jwt', message: 'id token is malformed' },
      {
        problem: 'is rejected with an error the strategy does not recognise (a malformed ES256 signature)',
        token: () => signIdToken({}, { header: { alg: 'ES256' } }),
        message: 'invalid id token',
      },
    ])('fails without calling verify when the token $problem', async ({ token, message }) => {
      const { strategy, verify } = createStrategy();
      const outcome = await runStrategy(strategy, { headers: {}, body: { id_token: token() } });

      expect(outcome).toEqual({ kind: 'fail', challenge: { message }, status: 401 });
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

    it('fails without calling verify when the token was issued to another application', async () => {
      const { strategy, verify } = createStrategy();
      const token = issueAccessToken({ tokenInfo: { aud: OTHER_CLIENT_ID, azp: OTHER_CLIENT_ID } });
      const outcome = await runStrategy(strategy, { headers: {}, body: { access_token: token } });

      expect(outcome).toEqual({
        kind: 'fail',
        challenge: { message: 'access token was not issued to an allowed audience' },
        status: 401,
      });
      expect(verify).not.toHaveBeenCalled();
    });

    it('accepts a token issued to any client ID in the clientID array', async () => {
      const { strategy } = createStrategy({ clientID: [OTHER_CLIENT_ID, CLIENT_ID] });
      const token = issueAccessToken({ tokenInfo: { aud: OTHER_CLIENT_ID } });
      const outcome = await runStrategy(strategy, { headers: {}, body: { access_token: token } });
      expect(outcome.kind).toBe('success');
    });

    it('checks the token against `audience` instead of `clientID` when both are set', async () => {
      const { strategy } = createStrategy({ clientID: CLIENT_ID, audience: OTHER_CLIENT_ID });
      const accepted = await runStrategy(strategy, {
        headers: {},
        body: { access_token: issueAccessToken({ tokenInfo: { aud: OTHER_CLIENT_ID } }) },
      });
      const rejected = await runStrategy(strategy, { headers: {}, body: { access_token: issueAccessToken() } });

      expect(accepted.kind).toBe('success');
      expect(rejected.kind).toBe('fail');
    });

    it.each(['bearer', 'BEARER'])('accepts the `%s` scheme, which is case-insensitive', async (scheme) => {
      const outcome = await runStrategy(createStrategy().strategy, {
        headers: { authorization: `${scheme} ${issueAccessToken()}` },
      });
      expect(outcome.kind).toBe('success');
    });

    it('tolerates extra whitespace around the Bearer credentials', async () => {
      const outcome = await runStrategy(createStrategy().strategy, {
        headers: { authorization: `  Bearer   ${issueAccessToken()}  ` },
      });
      expect(outcome.kind).toBe('success');
    });

    it('prefers an `access_token` parameter over the Bearer header', async () => {
      const outcome = await runStrategy(createStrategy().strategy, {
        headers: { authorization: 'Bearer ya29.revoked' },
        body: { access_token: issueAccessToken() },
      });
      expect(outcome.kind).toBe('success');
    });

    it.each(['Bearer', 'Bearer ', 'Bearer a b'])(
      'ignores the malformed authorization header %j',
      async (authorization) => {
        const outcome = await runStrategy(createStrategy().strategy, { headers: { authorization } });
        expect(outcome).toEqual({
          kind: 'fail',
          challenge: { message: 'no Google authentication token provided' },
          status: 401,
        });
      },
    );

    it('ignores authorization headers that are not Bearer credentials', async () => {
      const outcome = await runStrategy(createStrategy().strategy, {
        headers: { authorization: `Basic ${Buffer.from('user:pass').toString('base64')}` },
      });
      expect(outcome).toMatchObject({ kind: 'fail', status: 401 });
    });

    it('fails without calling verify when Google does not recognise the token', async () => {
      const { strategy, verify } = createStrategy();
      const outcome = await runStrategy(strategy, { headers: {}, body: { access_token: 'ya29.revoked' } });

      expect(outcome).toEqual({ kind: 'fail', challenge: { message: 'invalid access token' }, status: 401 });
      expect(verify).not.toHaveBeenCalled();
    });

    it.each([401, 403])('fails without calling verify when the userinfo endpoint answers %i', async (status) => {
      googleServer.use(http.get(USER_INFO_URL, () => HttpResponse.json({ error: 'invalid_token' }, { status })));
      const { strategy, verify } = createStrategy();
      const outcome = await runStrategy(strategy, { headers: {}, body: { access_token: issueAccessToken() } });

      expect(outcome).toMatchObject({ kind: 'fail', challenge: { message: 'failed to get userinfo' } });
      expect(verify).not.toHaveBeenCalled();
    });
  });

  describe('tokens that do not identify a Google account', () => {
    it.each([
      { problem: 'has no subject', claims: { sub: undefined } },
      { problem: 'has an empty subject', claims: { sub: '' } },
      { problem: 'has a non-string subject', claims: { sub: 42 } },
    ])('fails without calling verify when the id token $problem', async ({ claims }) => {
      const { strategy, verify } = createStrategy();
      const outcome = await runStrategy(strategy, { headers: {}, body: { id_token: signIdToken(claims) } });

      expect(outcome).toEqual({
        kind: 'fail',
        challenge: { message: 'token does not identify a Google account' },
        status: 401,
      });
      expect(verify).not.toHaveBeenCalled();
    });

    it.each([
      { body: 'null', profile: null },
      { body: 'an array', profile: [{ sub: GOOGLE_USER_ID }] },
      { body: 'a string', profile: GOOGLE_USER_ID },
    ])('fails without calling verify when the userinfo body is $body', async ({ profile }) => {
      googleServer.use(http.get(USER_INFO_URL, () => HttpResponse.json(profile)));
      const { strategy, verify } = createStrategy();
      const outcome = await runStrategy(strategy, { headers: {}, body: { access_token: issueAccessToken() } });

      expect(outcome).toMatchObject({
        kind: 'fail',
        challenge: { message: 'token does not identify a Google account' },
      });
      expect(verify).not.toHaveBeenCalled();
    });

    it('fails without calling verify when the userinfo profile has no subject', async () => {
      const { strategy, verify } = createStrategy();
      const token = issueAccessToken({ userInfo: { sub: undefined } });
      const outcome = await runStrategy(strategy, { headers: {}, body: { access_token: token } });

      expect(outcome).toMatchObject({
        kind: 'fail',
        challenge: { message: 'token does not identify a Google account' },
      });
      expect(verify).not.toHaveBeenCalled();
    });
  });

  describe('when Google is unavailable', () => {
    const serverError = () => HttpResponse.json({ error: 'backendError' }, { status: 503 });
    const networkError = () => HttpResponse.error();

    async function expectErrorWithoutVerify(req: Parameters<typeof runStrategy>[1], message: string | RegExp) {
      const { strategy, verify } = createStrategy();
      const outcome = await runStrategy(strategy, req);

      expect(outcome.kind).toBe('error');
      expect(outcome.kind === 'error' && outcome.error).toBeInstanceOf(Error);
      expect(outcome.kind === 'error' && (outcome.error as Error).message).toMatch(message);
      expect(verify).not.toHaveBeenCalled();
    }

    it.each([
      { failure: 'a server error', respond: serverError },
      { failure: 'a network error', respond: networkError },
    ])('reports an error, not a failure, when the signing certificates fetch hits $failure', async ({ respond }) => {
      googleServer.use(http.get(CERTS_URL, respond));
      await expectErrorWithoutVerify(
        { headers: {}, body: { id_token: signIdToken() } },
        'Could not fetch Google signing certificates',
      );
    });

    it.each([
      { failure: 'a server error', respond: serverError },
      { failure: 'a network error', respond: networkError },
    ])('reports an error, not a failure, when tokeninfo hits $failure', async ({ respond }) => {
      googleServer.use(http.post(TOKEN_INFO_URL, respond));
      await expectErrorWithoutVerify(
        { headers: {}, body: { access_token: issueAccessToken() } },
        'Could not verify the access token with Google',
      );
    });

    it.each([
      { failure: 'a server error', respond: serverError, message: 'Google userinfo endpoint responded with HTTP 503' },
      { failure: 'a network error', respond: networkError, message: 'Could not reach the Google userinfo endpoint' },
    ])('reports an error, not a failure, when userinfo hits $failure', async ({ respond, message }) => {
      googleServer.use(http.get(USER_INFO_URL, respond));
      await expectErrorWithoutVerify({ headers: {}, body: { access_token: issueAccessToken() } }, message);
    });

    it('reports an error when userinfo answers with a body that is not JSON', async () => {
      googleServer.use(http.get(USER_INFO_URL, () => HttpResponse.text('<html>maintenance</html>')));
      await expectErrorWithoutVerify(
        { headers: {}, body: { access_token: issueAccessToken() } },
        'Google userinfo endpoint returned invalid JSON',
      );
    });

    it('keeps the underlying error as the cause', async () => {
      googleServer.use(http.get(CERTS_URL, networkError));
      const outcome = await runStrategy(createStrategy().strategy, { headers: {}, body: { id_token: signIdToken() } });
      expect(outcome.kind === 'error' && (outcome.error as Error).cause).toBeInstanceOf(Error);
    });
  });

  describe('passReqToCallback', () => {
    it.each([
      { token: 'id token', body: () => ({ id_token: signIdToken() }) },
      { token: 'access token', body: () => ({ access_token: issueAccessToken() }) },
    ])('passes the request to the verify callback as its first argument ($token)', async ({ body }) => {
      const verify = vi.fn<VerifyFunctionWithRequest>((_req, _parsedToken, _googleId, done) => done(null, USER));
      const strategy = new Strategy({ clientID: CLIENT_ID, passReqToCallback: true }, verify);
      const req = { headers: { 'x-tenant': 'acme' }, body: body() };

      const outcome = await runStrategy(strategy, req);

      expect(outcome).toMatchObject({ kind: 'success', user: USER });
      const [receivedReq, parsedToken, googleId] = verify.mock.calls[0];
      expect(receivedReq).toBe(req);
      expect(parsedToken).toMatchObject({ sub: GOOGLE_USER_ID });
      expect(googleId).toBe(GOOGLE_USER_ID);
    });

    it.each([{ passReqToCallback: false as const }, {}])(
      'does not pass the request when passReqToCallback is %o',
      async (options) => {
        const { strategy, verify } = createStrategy(options);
        await runStrategy(strategy, { headers: {}, body: { id_token: signIdToken() } });

        expect(verify.mock.calls[0]).toHaveLength(3);
        expect(verify.mock.calls[0][0]).toMatchObject({ sub: GOOGLE_USER_ID });
      },
    );

    it('reports whether the request is passed', () => {
      const withRequest = new Strategy(
        { clientID: CLIENT_ID, passReqToCallback: true },
        vi.fn<VerifyFunctionWithRequest>(),
      );
      expect(withRequest.passReqToCallback).toBe(true);
      expect(createStrategy().strategy.passReqToCallback).toBe(false);
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

    describe('after the request is settled', () => {
      const ALREADY_SETTLED = new Error(
        'GoogleTokenStrategy: the verify callback called done() after the request was already settled',
      );
      const idTokenRequest = () => ({ headers: {}, body: { id_token: signIdToken() } });

      it('keeps the first outcome and rethrows an exception thrown after done()', async () => {
        const lateFailure = new Error('bug after done');
        const { strategy } = createStrategy(
          {},
          vi.fn<VerifyFunction>((_t, _id, done) => {
            done(null, USER, INFO);
            throw lateFailure;
          }),
        );
        const { result, processErrors } = await captureUnhandledRejections(() =>
          runStrategy(strategy, idTokenRequest()),
        );
        expect(result).toEqual({ kind: 'success', user: USER, info: INFO });
        expect(processErrors).toEqual([lateFailure]);
      });

      it('keeps the first outcome and rethrows a second done() call made synchronously', async () => {
        const secondOutcome = new Error('second outcome');
        const { strategy } = createStrategy(
          {},
          vi.fn<VerifyFunction>((_t, _id, done) => {
            done(null, USER, INFO);
            done(secondOutcome);
          }),
        );
        const { result, processErrors } = await captureUnhandledRejections(() =>
          runStrategy(strategy, idTokenRequest()),
        );
        expect(result).toEqual({ kind: 'success', user: USER, info: INFO });
        expect(processErrors).toEqual([ALREADY_SETTLED]);
        expect(processErrors[0]).toHaveProperty('cause', secondOutcome);
      });

      it('throws from a second done() call made later, in the caller of done()', async () => {
        const { strategy } = createStrategy(
          {},
          vi.fn<VerifyFunction>((_t, _id, done) => {
            done(null, USER, INFO);
            setImmediate(() => done(null, false));
          }),
        );
        const { result, processErrors } = await captureUncaughtExceptions(() =>
          runStrategy(strategy, idTokenRequest()),
        );
        expect(result).toEqual({ kind: 'success', user: USER, info: INFO });
        expect(processErrors).toEqual([ALREADY_SETTLED]);
      });

      it('throws from done() called after the verify callback threw', async () => {
        const failure = new Error('bug in verify');
        const { strategy } = createStrategy(
          {},
          vi.fn<VerifyFunction>((_t, _id, done) => {
            setImmediate(() => done(null, USER, INFO));
            throw failure;
          }),
        );
        const { result, processErrors } = await captureUncaughtExceptions(() =>
          runStrategy(strategy, idTokenRequest()),
        );
        expect(result).toEqual({ kind: 'error', error: failure });
        expect(processErrors).toEqual([ALREADY_SETTLED]);
      });
    });
  });
});
