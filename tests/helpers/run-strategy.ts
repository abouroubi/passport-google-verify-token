import type { GoogleTokenStrategy } from '../../src/strategy';

export type StrategyOutcome =
  | { kind: 'success'; user: unknown; info: unknown }
  | { kind: 'fail'; challenge: unknown; status: number | undefined }
  | { kind: 'error'; error: unknown };

type AuthenticateRequest = Parameters<GoogleTokenStrategy['authenticate']>[0];

/**
 * Runs `strategy.authenticate(req)` the way Passport does: on a per-request
 * instance that has the success/fail/error actions attached. Resolves with the
 * first action the strategy calls, and rejects if it calls more than one, since
 * Passport would then respond to the same request twice.
 */
export function runStrategy(strategy: GoogleTokenStrategy, req: AuthenticateRequest): Promise<StrategyOutcome> {
  return new Promise((resolve, reject) => {
    const outcomes: StrategyOutcome[] = [];
    const record = (outcome: StrategyOutcome) => {
      outcomes.push(outcome);
      if (outcomes.length > 1) {
        reject(new Error(`strategy settled more than once: ${outcomes.map((o) => o.kind).join(', ')}`));
        return;
      }
      // Give a duplicate call that follows in the same async chain a chance to surface.
      setImmediate(() => {
        if (outcomes.length === 1) resolve(outcome);
      });
    };

    const instance: GoogleTokenStrategy = Object.create(strategy);
    instance.success = (user: unknown, info?: unknown) => record({ kind: 'success', user, info });
    instance.fail = (challenge?: unknown, status?: number) =>
      typeof challenge === 'number'
        ? record({ kind: 'fail', challenge: undefined, status: challenge })
        : record({ kind: 'fail', challenge, status });
    instance.error = (error: unknown) => record({ kind: 'error', error });
    instance.redirect = (url: string) => reject(new Error(`unexpected redirect to ${url}`));
    instance.pass = () => reject(new Error('unexpected pass'));

    instance.authenticate(req);
  });
}
