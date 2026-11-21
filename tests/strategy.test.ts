import { describe, expect, it } from 'vitest';
import { Strategy } from '../src';
import type { VerifyDone } from '../src';
import { runStrategy } from './helpers/run-strategy';

class SuccessStrategy extends Strategy {
  public verifyGoogleIdToken(): void {
    this.done(null, { sub: 1 });
  }

  public verifyGoogleAccessToken(): void {
    this.done(null, { sub: 1 });
  }
}

class IdTokenSuccessStrategy extends SuccessStrategy {
  public verifyGoogleAccessToken(): void {
    throw new Error('The verifyGoogleAccessToken should not have been called.');
  }
}

class AccessTokenSuccessStrategy extends SuccessStrategy {
  public verifyGoogleIdToken(): void {
    throw new Error('The verifyGoogleIdToken should not have been called.');
  }
}

class ErrorStrategy extends Strategy {
  public verifyGoogleIdToken(): void {
    this.done({ message: 'Error message' });
  }

  public verifyGoogleAccessToken(): void {
    this.done({ message: 'Error message' });
  }
}

class NoParsedTokenStrategy extends Strategy {
  public verifyGoogleIdToken(): void {
    this.done(null, false, { message: 'Error message' });
  }

  public verifyGoogleAccessToken(): void {
    this.done(null, false, { message: 'Error message' });
  }
}

const verify = (_parsedToken: unknown, _googleId: unknown, done: VerifyDone) => done(null, { id: '1234' }, { scope: 'read' });
const mockToken = '123456790-POIHANPRI-KNJYHHKIIH';
const options = { clientID: 'DUMMY_CLIENT_ID' };

describe('Strategy', () => {
  it('is named google-verify-token', () => {
    expect(new IdTokenSuccessStrategy(options, verify).name).toBe('google-verify-token');
  });

  it('throws if constructed without a verify callback', () => {
    expect(() => new Strategy({ clientID: 'DUMMY_CLIENT_ID' })).toThrow(
      'GoogleVerifyTokenStrategy requires a verify function',
    );
  });

  describe.each([
    { name: 'id_token as query parameter', make: IdTokenSuccessStrategy, req: { query: { id_token: mockToken } } },
    {
      name: 'access_token as query parameter',
      make: AccessTokenSuccessStrategy,
      req: { query: { access_token: mockToken } },
    },
    { name: 'id_token as body parameter', make: IdTokenSuccessStrategy, req: { body: { id_token: mockToken } } },
    {
      name: 'access_token as body parameter',
      make: AccessTokenSuccessStrategy,
      req: { body: { access_token: mockToken } },
    },
    {
      name: 'bearer token in authorization header',
      make: AccessTokenSuccessStrategy,
      req: { headers: { authorization: `Bearer ${mockToken}` } },
    },
  ])('handling a request with $name', ({ make, req }) => {
    it('supplies the user and info from the verify callback', async () => {
      const outcome = await runStrategy(new make(options, verify), { headers: {}, ...req });
      expect(outcome).toEqual({ kind: 'success', user: { id: '1234' }, info: { scope: 'read' } });
    });
  });

  it('succeeds when clientID is an array', async () => {
    const strategy = new AccessTokenSuccessStrategy(
      { clientID: ['DUMMY_CLIENT_ID_1', 'DUMMY_CLIENT_ID_2', 'DUMMY_CLIENT_ID', 'DUMMY_CLIENT_ID_3'] },
      verify,
    );
    const outcome = await runStrategy(strategy, { headers: {}, body: { access_token: mockToken } });
    expect(outcome.kind).toBe('success');
  });

  it('fails when no token is provided', async () => {
    const outcome = await runStrategy(new IdTokenSuccessStrategy(options, verify), { headers: {} });
    expect(outcome).toEqual({
      kind: 'fail',
      challenge: { message: 'no Google authentication token provided' },
      status: 401,
    });
  });

  it('fails when token verification errors', async () => {
    const outcome = await runStrategy(new ErrorStrategy(options, verify), {
      headers: {},
      body: { access_token: mockToken },
    });
    expect(outcome).toEqual({ kind: 'fail', challenge: { message: 'Error message' }, status: 401 });
  });

  it('fails when no parsed token is returned', async () => {
    const outcome = await runStrategy(new NoParsedTokenStrategy(options, verify), {
      headers: {},
      body: { access_token: mockToken },
    });
    expect(outcome).toEqual({ kind: 'fail', challenge: { message: 'Error message' }, status: undefined });
  });
});
